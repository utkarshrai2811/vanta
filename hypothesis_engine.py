#!/usr/bin/env python3
"""
Phase 2: LLM-powered Attack Hypothesis Engine
Autonomous Red Team Agent - VANTA
"""

import json
import sys
import argparse
import os
import time
from datetime import datetime
from typing import Optional

import anthropic
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from prompts import SYSTEM_PROMPT, build_host_prompt

console = Console()

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_COLOR = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}


def load_recon(path: str) -> dict:
    """Load and validate recon_state.json from Phase 1."""
    if not os.path.exists(path):
        console.print(f"[bold red]Error:[/bold red] {path} not found. Run Phase 1 first.")
        sys.exit(1)
    with open(path) as f:
        data = json.load(f)
    if not data.get("hosts"):
        console.print("[bold red]Error:[/bold red] No hosts in recon_state.json.")
        sys.exit(1)
    return data


def call_claude(client: anthropic.Anthropic, host: dict, model: str, retries: int = 2) -> Optional[dict]:
    """Call Claude API for a single host and parse the JSON response."""
    prompt = build_host_prompt(host)

    for attempt in range(retries + 1):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}]
            )
            raw = response.usage
            content = response.content[0].text.strip()

            # Strip markdown fences if model wraps response
            if content.startswith("```"):
                lines = content.split("\n")
                content = "\n".join(
                    line for line in lines
                    if not line.strip().startswith("```")
                )

            parsed = json.loads(content)
            parsed["_meta"] = {
                "model": model,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "timestamp": datetime.now().isoformat(),
            }
            return parsed

        except json.JSONDecodeError as e:
            console.print(f"[yellow]JSON parse error on attempt {attempt + 1}: {e}[/yellow]")
            if attempt < retries:
                time.sleep(2)
        except anthropic.APIError as e:
            console.print(f"[red]API error on attempt {attempt + 1}: {e}[/red]")
            if attempt < retries:
                time.sleep(5)

    return None


def priority_score(hypothesis: dict) -> float:
    """Weighted score: severity impact * confidence."""
    severity = SEVERITY_RANK.get(hypothesis.get("severity", "low"), 1)
    confidence = float(hypothesis.get("confidence", 0.0))
    return round(severity * confidence, 4)


def build_priority_queue(all_results: list[dict]) -> list[dict]:
    """Flatten all hypotheses across hosts, score and sort."""
    queue = []
    for result in all_results:
        if not result or "hypotheses" not in result:
            continue
        for h in result["hypotheses"]:
            h["host"] = result.get("host", "unknown")
            h["hostname"] = result.get("hostname", "unknown")
            h["priority_score"] = priority_score(h)
            queue.append(h)

    queue.sort(key=lambda x: x["priority_score"], reverse=True)
    return queue


def truncate(text: str, length: int) -> str:
    """Truncate text with ellipsis. Full data is always in hypotheses.json."""
    return text if len(text) <= length else text[:length - 1] + "…"


def print_summary(all_results: list[dict], queue: list[dict]):
    """Print rich CLI output."""
    console.print()
    console.print(Panel(
        "[bold cyan]Phase 2: Hypothesis Engine Complete[/bold cyan]",
        border_style="cyan"
    ))

    # Per-host summary
    for result in all_results:
        if not result:
            continue
        console.print(f"\n[cyan][bold]{result.get('host')}[/bold] ({result.get('hostname')})[/cyan]")
        console.print(f"[dim]OS:[/dim] {truncate(result.get('os_assessment', 'n/a'), 100)}")
        console.print(f"[dim]First move:[/dim] [yellow]{truncate(result.get('recommended_first_move', 'n/a'), 120)}[/yellow]")
        meta = result.get("_meta", {})
        if meta:
            console.print(f"[dim]Tokens: {meta.get('input_tokens', 0)} in / {meta.get('output_tokens', 0)} out[/dim]")

    # Priority queue table — truncated for terminal, full data in hypotheses.json
    console.print()
    table = Table(
        title=f"Attack Hypothesis Priority Queue ({len(queue)} total)",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        show_lines=True,
        box=box.SIMPLE_HEAVY,
        expand=False,
    )
    table.add_column("#", style="dim", width=3, no_wrap=True)
    table.add_column("Host", style="cyan", no_wrap=True, width=16)
    table.add_column("Hypothesis", style="white", width=38, no_wrap=True)
    table.add_column("ID", style="yellow", width=10, no_wrap=True)
    table.add_column("Tactic", style="blue", width=20, no_wrap=True)
    table.add_column("Sev", justify="center", width=8, no_wrap=True)
    table.add_column("Conf", justify="center", width=6, no_wrap=True)
    table.add_column("Score", justify="center", width=6, no_wrap=True)
    table.add_column("CVEs", style="dim", width=18, no_wrap=True)

    for i, h in enumerate(queue, 1):
        severity = h.get("severity", "low")
        color = SEVERITY_COLOR.get(severity, "white")
        cves = ", ".join(h.get("cve_references", [])) or "[dim]none[/dim]"

        table.add_row(
            str(i),
            h.get("host", ""),
            truncate(h.get("hypothesis", ""), 35),
            h.get("technique_id", ""),
            truncate(h.get("tactic", ""), 18),
            f"[{color}]{severity[:4].upper()}[/{color}]",
            f"{float(h.get('confidence', 0)):.0%}",
            f"[bold]{h.get('priority_score', 0):.2f}[/bold]",
            cves,
        )

    console.print(table)
    console.print("[dim]Full hypothesis detail (including exploit suggestions) is in hypotheses.json[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="VANTA Phase 2: LLM-powered Attack Hypothesis Engine"
    )
    parser.add_argument("--input", "-i", default="recon_state.json",
                        help="recon_state.json from Phase 1 (default: recon_state.json)")
    parser.add_argument("--output", "-o", default="hypotheses.json",
                        help="Output path (default: hypotheses.json)")
    parser.add_argument("--model", "-m", default="claude-haiku-4-5-20251001",
                        help="Claude model to use")
    parser.add_argument("--api-key", default=None,
                        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")
    args = parser.parse_args()

    console.print(Panel(
        Text("VANTA - Autonomous Red Team Agent\nPhase 2: Attack Hypothesis Engine",
             justify="center", style="bold cyan"),
        border_style="cyan"
    ))

    api_key = args.api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[bold red]Error:[/bold red] Set ANTHROPIC_API_KEY in .env or pass --api-key")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    recon_data = load_recon(args.input)
    hosts = recon_data["hosts"]

    console.print(f"\n[bold]Hosts to analyze:[/bold] [cyan]{len(hosts)}[/cyan]")
    console.print(f"[bold]Model:[/bold] [yellow]{args.model}[/yellow]")
    console.print(f"[bold]Input:[/bold] [dim]{args.input}[/dim]\n")

    all_results = []
    total_tokens = {"input": 0, "output": 0}

    with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}"), console=console, transient=True) as progress:
        for ip, host in hosts.items():
            task = progress.add_task(f"Analyzing {ip} ({host.get('port_count', 0)} services)...", total=None)
            result = call_claude(client, host, args.model)
            progress.remove_task(task)

            if result:
                all_results.append(result)
                meta = result.get("_meta", {})
                total_tokens["input"] += meta.get("input_tokens", 0)
                total_tokens["output"] += meta.get("output_tokens", 0)
                console.print(f"[green]  {ip}[/green] — {len(result.get('hypotheses', []))} hypotheses generated")
            else:
                console.print(f"[red]  {ip}[/red] — failed after retries")

    queue = build_priority_queue(all_results)

    output = {
        "meta": {
            "timestamp": datetime.now().isoformat(),
            "recon_source": args.input,
            "model": args.model,
            "hosts_analyzed": len(all_results),
            "total_hypotheses": len(queue),
            "total_tokens": total_tokens,
        },
        "host_analyses": all_results,
        "priority_queue": queue,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print_summary(all_results, queue)

    cost_estimate = (total_tokens["input"] * 0.00000025) + (total_tokens["output"] * 0.00000125)
    console.print(f"\n[dim]Total tokens: {total_tokens['input']} in / {total_tokens['output']} out[/dim]")
    console.print(f"[dim]Estimated cost: ${cost_estimate:.4f}[/dim]")
    console.print(f"\n[bold green]Phase 2 complete.[/bold green] Pass [cyan]{args.output}[/cyan] to Phase 3.\n")


if __name__ == "__main__":
    main()
