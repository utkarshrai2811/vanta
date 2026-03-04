#!/usr/bin/env python3
"""
Phase 4: Remediation Engine
Autonomous Red Team Agent - VANTA

Takes exploit_results.json from Phase 3, calls Claude Sonnet to generate
actionable remediations, and produces remediations.json + a markdown report.
"""

import json
import sys
import argparse
import os
import time
from datetime import datetime

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from report_generator import generate_report

console = Console()

STATUS_PRIORITY = {"confirmed": 0, "partial": 1, "negative": 2, "error": 3}
SEVERITY_COLOR = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}

SYSTEM_PROMPT = """You are a senior security engineer writing remediation guidance for a penetration test report.
Your remediations must be specific, actionable, and immediately executable by a sysadmin.

Respond ONLY with valid JSON. No markdown, no preamble, no explanation outside the JSON."""


def build_remediation_prompt(result: dict) -> str:
    evidence_str = json.dumps(result.get("evidence", {}), indent=2)
    return f"""Generate remediation guidance for this penetration test finding.

FINDING:
  Hypothesis ID: {result["hypothesis_id"]}
  Status: {result["status"]}
  Severity: {result["severity"]}
  Technique: {result["technique_id"]} — {result.get("tactic", "")}
  Target: {result["target"]}
  Finding: {result["finding"]}

EVIDENCE:
{evidence_str}

Respond with this exact JSON structure:
{{
  "hypothesis_id": "{result["hypothesis_id"]}",
  "risk_summary": "one sentence describing the risk to a non-technical stakeholder",
  "remediation_steps": [
    "step 1 — specific action",
    "step 2 — specific action"
  ],
  "config_fix": {{
    "file_or_command": "exact file path or command to run",
    "before": "current insecure config or state (if applicable)",
    "after": "secure config or expected state after fix",
    "notes": "any caveats or context"
  }},
  "severity_rating": "critical|high|medium|low|informational",
  "cve_references": ["CVE-XXXX-XXXX"],
  "patch_confidence": 0.0,
  "patch_confidence_reason": "why you are or are not confident this fix works",
  "verification_command": "command to verify the fix was applied correctly",
  "risk_accepted": false,
  "estimated_fix_time": "e.g. 5 minutes / 30 minutes / requires change window"
}}

Rules:
- patch_confidence is 0.0 to 1.0
- config_fix must have real commands or file paths, not placeholders
- For negative/informational findings, still provide hardening guidance
- remediation_steps should be numbered actions a junior sysadmin can follow
- verification_command must actually verify the fix, not just check connectivity"""


def call_claude(client: anthropic.Anthropic, result: dict, model: str, retries: int = 2) -> dict | None:
    prompt = build_remediation_prompt(result)

    for attempt in range(retries + 1):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=1500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text.strip()
            if content.startswith("```"):
                content = "\n".join(
                    l for l in content.splitlines()
                    if not l.strip().startswith("```")
                )
            # Remove control characters that break JSON parsing
            import re
            content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", content)
            parsed = json.loads(content)
            parsed["_meta"] = {
                "model": model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "timestamp": datetime.now().isoformat(),
            }
            return parsed

        except json.JSONDecodeError as e:
            console.print(f"[yellow]JSON parse error attempt {attempt + 1}: {e}[/yellow]")
            if attempt < retries:
                time.sleep(2)
        except anthropic.APIError as e:
            console.print(f"[red]API error attempt {attempt + 1}: {e}[/red]")
            if attempt < retries:
                time.sleep(5)
    return None


def load_results(path: str) -> dict:
    if not os.path.exists(path):
        console.print(f"[bold red]Error:[/bold red] {path} not found. Run Phase 3 first.")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="VANTA Phase 4: Remediation Engine"
    )
    parser.add_argument("--input", "-i", default="exploit_results.json")
    parser.add_argument("--output", "-o", default="remediations.json")
    parser.add_argument("--report", "-r", default="report.md")
    parser.add_argument("--model", "-m", default="claude-sonnet-4-6")
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--skip-negative", action="store_true",
                        help="Skip negative findings (only remediate confirmed/partial)")
    args = parser.parse_args()

    console.print(Panel(
        Text("VANTA - Autonomous Red Team Agent\nPhase 4: Remediation Engine",
             justify="center", style="bold cyan"),
        border_style="cyan"
    ))

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/bold red] ANTHROPIC_API_KEY not set.")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    data = load_results(args.input)
    results = data.get("results", [])

    if not results:
        console.print("[bold red]No results found in exploit_results.json.[/bold red]")
        sys.exit(1)

    # Sort: confirmed first, then partial, negative, error
    results_sorted = sorted(results, key=lambda r: STATUS_PRIORITY.get(r.get("status", "error"), 99))

    if args.skip_negative:
        to_process = [r for r in results_sorted if r.get("status") in ("confirmed", "partial")]
    else:
        to_process = results_sorted

    console.print(f"\n[bold]Findings to remediate:[/bold] [cyan]{len(to_process)}[/cyan]")
    console.print(f"[bold]Model:[/bold] [yellow]{args.model}[/yellow]")
    console.print(f"[bold]Input:[/bold] [dim]{args.input}[/dim]\n")

    remediations = []
    total_tokens = {"input": 0, "output": 0}

    with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"),
                  console=console, transient=True) as progress:
        for result in to_process:
            hid = result.get("hypothesis_id", "?")
            status = result.get("status", "?")
            sev = result.get("severity", "?")
            task = progress.add_task(
                f"Remediating {hid} [{status}] [{sev}]...", total=None
            )
            remediation = call_claude(client, result, args.model)
            progress.remove_task(task)

            if remediation:
                # Attach original finding context
                remediation["original_status"] = result.get("status")
                remediation["original_finding"] = result.get("finding")
                remediation["target"] = result.get("target")
                remediation["technique_id"] = result.get("technique_id")
                remediation["tactic"] = result.get("tactic")
                remediations.append(remediation)

                meta = remediation.get("_meta", {})
                total_tokens["input"] += meta.get("input_tokens", 0)
                total_tokens["output"] += meta.get("output_tokens", 0)

                conf = remediation.get("patch_confidence", 0)
                conf_color = "green" if conf >= 0.8 else "yellow" if conf >= 0.5 else "red"
                # Use severity_rating from Claude's remediation, not original scan severity
                rated_sev = remediation.get("severity_rating", sev)
                sev_colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green", "informational": "dim"}
                sev_c = sev_colors.get(rated_sev, "white")
                console.print(
                    f"  [cyan]{hid}[/cyan]  "
                    f"severity=[{sev_c}]{rated_sev}[/{sev_c}]  "
                    f"patch_confidence=[{conf_color}]{conf:.0%}[/{conf_color}]  "
                    f"fix_time={remediation.get('estimated_fix_time', 'unknown')[:40]}"
                )
            else:
                console.print(f"  [red]{hid}[/red] — failed after retries")

    output = {
        "meta": {
            "timestamp": datetime.now().isoformat(),
            "source": args.input,
            "model": args.model,
            "findings_processed": len(remediations),
            "total_tokens": total_tokens,
        },
        "remediations": remediations,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    console.print(f"\n[dim]Saved remediations to[/dim] [bold]{args.output}[/bold]")

    # Generate markdown report
    report_path = generate_report(
        remediations=remediations,
        exploit_data=data,
        output_path=args.report,
        model=args.model,
    )
    console.print(f"[dim]Saved report to[/dim] [bold]{report_path}[/bold]")

    cost = (total_tokens["input"] * 0.000003) + (total_tokens["output"] * 0.000015)
    console.print(f"\n[dim]Tokens: {total_tokens['input']} in / {total_tokens['output']} out[/dim]")
    console.print(f"[dim]Estimated cost: ${cost:.4f}[/dim]")
    console.print(f"\n[bold green]Phase 4 complete.[/bold green] Pass [cyan]{args.output}[/cyan] to Phase 5.\n")


if __name__ == "__main__":
    main()