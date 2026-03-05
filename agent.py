#!/usr/bin/env python3
"""
Phase 5: Agent Orchestrator
Autonomous Red Team Agent - VANTA

Single entry point that runs the full pipeline:
recon -> hypothesize -> exploit -> remediate -> verify (loop)

Modes:
  full-auto   Run all phases unattended
  semi-auto   Pause for human approval between phases
  recon-only  Run Phase 1 only
"""

import argparse
import json
import os
import sys
import subprocess
import time
from datetime import datetime, timedelta

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.columns import Columns
from rich import box
from rich.prompt import Confirm
from rich.rule import Rule

from state_machine import StateMachine, Phase, PhaseResult, PHASE_DESCRIPTIONS

console = Console()

SEVERITY_COLOR = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green", "informational": "dim"}
STATUS_COLOR   = {"confirmed": "red", "partial": "yellow", "negative": "green", "error": "dim"}


# ── Helpers ──────────────────────────────────────────────────────────────────

def elapsed(start: str) -> str:
    delta = datetime.now() - datetime.fromisoformat(start)
    total = int(delta.total_seconds())
    return f"{total // 60}m {total % 60}s"


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def run_phase(cmd: list[str], label: str) -> tuple[int, str]:
    """Run a phase subprocess, stream output, return (returncode, error_msg)."""
    console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        return result.returncode, f"{label} exited with code {result.returncode}"
    return 0, ""


# ── Dashboard ─────────────────────────────────────────────────────────────────

def print_dashboard(sm: StateMachine, run_start: str):
    state = sm.state
    if not state:
        return

    # Phase progress row
    phase_cells = []
    for p in [Phase.RECON, Phase.HYPOTHESIZE, Phase.EXPLOIT, Phase.REMEDIATE, Phase.VERIFY]:
        if p in state.phases_completed:
            style = "bold green"
            icon = "✓"
        elif p == state.current_phase:
            style = "bold cyan"
            icon = "►"
        else:
            style = "dim"
            icon = "○"
        phase_cells.append(f"[{style}]{icon} {p.value}[/{style}]")

    console.print(Rule(f"[bold cyan]VANTA[/bold cyan]  run={state.run_id}  target={state.target}  elapsed={elapsed(run_start)}"))
    console.print("  " + "  →  ".join(phase_cells))
    console.print()

    # Findings summary if available
    fs = state.findings_summary
    if fs:
        parts = []
        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = fs.get(sev, 0)
            if count:
                c = SEVERITY_COLOR[sev]
                parts.append(f"[{c}]{count} {sev}[/{c}]")
        if parts:
            console.print("  Findings: " + "  |  ".join(parts))

        status_parts = []
        for st in ["confirmed", "partial", "negative", "error"]:
            count = fs.get(f"status_{st}", 0)
            if count:
                c = STATUS_COLOR[st]
                status_parts.append(f"[{c}]{count} {st}[/{c}]")
        if status_parts:
            console.print("  Validation: " + "  |  ".join(status_parts))
        console.print()


def print_phase_preview(phase: Phase, args) -> None:
    """Show what the next phase will do before asking for approval."""
    previews = {
        Phase.RECON: [
            f"Target: {args.target or 'auto-detected subnet'}",
            f"Scan mode: {args.scan_mode}",
            "Output: recon_state.json + topology.png",
        ],
        Phase.HYPOTHESIZE: [
            f"Input: recon_state.json",
            f"Model: {args.hypothesis_model}",
            f"Output: hypotheses.json",
        ],
        Phase.EXPLOIT: [
            f"Input: hypotheses.json",
            f"Top N hypotheses: {args.top_n}",
            f"Container timeout: {args.timeout}s",
            "Output: exploit_results.json",
            "[yellow]Requires Docker. Active network probes.[/yellow]",
        ],
        Phase.REMEDIATE: [
            "Input: exploit_results.json",
            f"Model: {args.remediation_model}",
            "Output: remediations.json + report.md",
        ],
        Phase.VERIFY: [
            "Input: recon_state.json (baseline)",
            f"Re-scan target: quick mode",
            "Output: verify_state.json — comparison against baseline",
        ],
    }
    items = previews.get(phase, [])
    console.print(f"\n[bold cyan]Next phase: {phase.value}[/bold cyan]")
    console.print(f"[dim]{PHASE_DESCRIPTIONS.get(phase, '')}[/dim]")
    for item in items:
        console.print(f"  • {item}")
    console.print()


# ── Phase runners ─────────────────────────────────────────────────────────────

def phase_recon(args, sm: StateMachine, verify_mode: bool = False) -> PhaseResult:
    started = datetime.now().isoformat()
    output = "verify_state.json" if verify_mode else "recon_state.json"
    scan_mode = "quick" if verify_mode else args.scan_mode

    cmd = [sys.executable, "recon.py",
           "--mode", scan_mode,
           "--output", output,
           "--no-map" if verify_mode else "--topology", "topology.png"]

    if args.target:
        cmd += ["--target", args.target]
    if verify_mode:
        cmd = [sys.executable, "recon.py", "--mode", "quick",
               "--output", output, "--no-map"]
        if args.target:
            cmd += ["--target", args.target]

    code, err = run_phase(["sudo"] + cmd, "recon")

    data = load_json(output)
    hosts = data.get("hosts", {})
    summary = {"hosts_found": len(hosts), "total_ports": sum(h.get("port_count", 0) for h in hosts.values())}

    return PhaseResult(
        phase=Phase.VERIFY if verify_mode else Phase.RECON,
        status="success" if code == 0 else "failed",
        started_at=started,
        completed_at=datetime.now().isoformat(),
        output_file=output,
        summary=summary,
        error=err or None,
    )


def phase_hypothesize(args, sm: StateMachine) -> PhaseResult:
    started = datetime.now().isoformat()
    cmd = [sys.executable, "hypothesis_engine.py",
           "--model", args.hypothesis_model]
    code, err = run_phase(cmd, "hypothesize")

    data = load_json("hypotheses.json")
    queue = data.get("priority_queue", [])
    summary = {
        "total_hypotheses": len(queue),
        **{sev: sum(1 for h in queue if h.get("severity") == sev)
           for sev in ["critical", "high", "medium", "low"]}
    }
    sm.update_findings(summary)

    return PhaseResult(
        phase=Phase.HYPOTHESIZE,
        status="success" if code == 0 else "failed",
        started_at=started,
        completed_at=datetime.now().isoformat(),
        output_file="hypotheses.json",
        summary=summary,
        error=err or None,
    )


def phase_exploit(args, sm: StateMachine) -> PhaseResult:
    started = datetime.now().isoformat()
    cmd = [sys.executable, "exploit_runner.py",
           "--confirm",
           "--top", str(args.top_n),
           "--timeout", str(args.timeout)]
    code, err = run_phase(cmd, "exploit")

    data = load_json("exploit_results.json")
    results = data.get("results", [])
    status_summary = {f"status_{s}": sum(1 for r in results if r.get("status") == s)
                      for s in ["confirmed", "partial", "negative", "error"]}
    sm.update_findings(status_summary)

    return PhaseResult(
        phase=Phase.EXPLOIT,
        status="success" if code == 0 else "failed",
        started_at=started,
        completed_at=datetime.now().isoformat(),
        output_file="exploit_results.json",
        summary=data.get("summary", {}),
        error=err or None,
    )


def phase_remediate(args, sm: StateMachine) -> PhaseResult:
    started = datetime.now().isoformat()
    cmd = [sys.executable, "remediation_engine.py",
           "--model", args.remediation_model]
    code, err = run_phase(cmd, "remediate")

    data = load_json("remediations.json")
    remediations = data.get("remediations", [])
    summary = {
        "remediations_generated": len(remediations),
        "risk_accepted": sum(1 for r in remediations if r.get("risk_accepted")),
        "avg_patch_confidence": round(
            sum(float(r.get("patch_confidence", 0)) for r in remediations) / len(remediations), 2
        ) if remediations else 0,
    }

    return PhaseResult(
        phase=Phase.REMEDIATE,
        status="success" if code == 0 else "failed",
        started_at=started,
        completed_at=datetime.now().isoformat(),
        output_file="remediations.json",
        summary=summary,
        error=err or None,
    )


def phase_verify(args, sm: StateMachine) -> PhaseResult:
    """Re-run a quick recon and compare against baseline."""
    result = phase_recon(args, sm, verify_mode=True)
    result.phase = Phase.VERIFY

    # Compare baseline vs verify
    baseline = load_json("recon_state.json")
    current  = load_json("verify_state.json")

    baseline_ports = sum(h.get("port_count", 0) for h in baseline.get("hosts", {}).values())
    current_ports  = sum(h.get("port_count", 0) for h in current.get("hosts", {}).values())
    delta = baseline_ports - current_ports

    result.summary["baseline_ports"] = baseline_ports
    result.summary["current_ports"]  = current_ports
    result.summary["ports_closed"]   = max(0, delta)
    result.summary["ports_opened"]   = max(0, -delta)

    return result


def print_final_summary(sm: StateMachine, run_start: str):
    state = sm.state
    console.print()
    console.print(Rule("[bold green]VANTA Run Complete[/bold green]"))
    console.print(f"[dim]Run ID:[/dim] {state.run_id}")
    console.print(f"[dim]Target:[/dim] {state.target}")
    console.print(f"[dim]Total time:[/dim] {elapsed(run_start)}")
    console.print()

    table = Table(show_header=True, header_style="bold magenta",
                  border_style="dim", box=box.SIMPLE_HEAVY)
    table.add_column("Phase", style="cyan", width=14)
    table.add_column("Status", width=10)
    table.add_column("Duration", width=10)
    table.add_column("Output", style="dim")
    table.add_column("Summary")

    for pr in state.phase_results:
        start = pr.get("started_at", "")
        end   = pr.get("completed_at", "")
        if start and end:
            dur = str(timedelta(seconds=int(
                (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
            )))
        else:
            dur = "n/a"

        status = pr.get("status", "")
        sc = "green" if status == "success" else "red"
        summary = pr.get("summary", {})
        summary_str = "  ".join(f"{k}={v}" for k, v in list(summary.items())[:3])

        table.add_row(
            pr.get("phase", ""),
            f"[{sc}]{status}[/{sc}]",
            dur,
            pr.get("output_file", "") or "",
            summary_str,
        )

    console.print(table)

    # Verify delta
    for pr in state.phase_results:
        if pr.get("phase") == Phase.VERIFY:
            s = pr.get("summary", {})
            closed = s.get("ports_closed", 0)
            opened = s.get("ports_opened", 0)
            console.print()
            if closed > 0:
                console.print(f"[bold green]Attack surface reduced:[/bold green] {closed} port(s) closed after remediation")
            elif opened > 0:
                console.print(f"[bold red]Warning:[/bold red] {opened} new port(s) detected after remediation")
            else:
                console.print("[dim]Attack surface unchanged — remediations likely require manual application[/dim]")

    console.print()
    console.print(f"[dim]State saved to:[/dim] agent_state/{state.run_id}.json")
    console.print(f"[dim]Report:[/dim] report.md")
    console.print()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="VANTA — Autonomous Red Team Agent")
    parser.add_argument("--mode", choices=["full-auto", "semi-auto", "recon-only"],
                        default="semi-auto")
    parser.add_argument("--target", "-t", default=None,
                        help="Target subnet or IP (auto-detected if omitted)")
    parser.add_argument("--scan-mode", default="standard",
                        choices=["quick", "standard", "deep"])
    parser.add_argument("--top-n", type=int, default=3,
                        help="Top N hypotheses to exploit (default: 3)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Container timeout for Phase 3 (default: 30s)")
    parser.add_argument("--hypothesis-model", default="claude-haiku-4-5-20251001")
    parser.add_argument("--remediation-model", default="claude-sonnet-4-6")
    parser.add_argument("--resume", action="store_true",
                        help="Resume last incomplete run")
    parser.add_argument("--list-runs", action="store_true",
                        help="List previous runs and exit")
    parser.add_argument("--run-id", default=None,
                        help="Resume a specific run by ID")
    args = parser.parse_args()

    console.print(Panel(
        Text("VANTA — Vulnerability ANalysis and Tactical Automation\nPhase 5: Agent Orchestrator",
             justify="center", style="bold cyan"),
        border_style="cyan"
    ))

    sm = StateMachine()

    if args.list_runs:
        runs = sm.list_runs()
        if not runs:
            console.print("[dim]No previous runs found.[/dim]")
        else:
            t = Table(border_style="dim", box=box.SIMPLE)
            t.add_column("Run ID"); t.add_column("Target"); t.add_column("Mode")
            t.add_column("Phase"); t.add_column("Started")
            for r in runs:
                t.add_row(r["run_id"], r["target"] or "auto", r["mode"],
                          r["current_phase"], r["started_at"][:19])
            console.print(t)
        sys.exit(0)

    # Resume or new run
    if args.resume or args.run_id:
        state = sm.load(args.run_id) if args.run_id else sm.load_latest()
        if not state:
            console.print("[bold red]No run found to resume.[/bold red]")
            sys.exit(1)
        console.print(f"[yellow]Resuming run[/yellow] [bold]{state.run_id}[/bold] "
                      f"(last phase: {state.current_phase})")
        run_start = state.started_at
    else:
        run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = args.target or "auto"
        sm.init(run_id, target, args.mode)
        run_start = sm.state.started_at
        console.print(f"[bold]Run ID:[/bold] {run_id}")
        console.print(f"[bold]Target:[/bold] {target}")
        console.print(f"[bold]Mode:[/bold]   {args.mode}\n")

    # Determine which phases to run
    if args.mode == "recon-only":
        phases_to_run = [Phase.RECON]
    else:
        phases_to_run = [Phase.RECON, Phase.HYPOTHESIZE, Phase.EXPLOIT,
                         Phase.REMEDIATE, Phase.VERIFY]

    phase_runners = {
        Phase.RECON:       lambda: phase_recon(args, sm),
        Phase.HYPOTHESIZE: lambda: phase_hypothesize(args, sm),
        Phase.EXPLOIT:     lambda: phase_exploit(args, sm),
        Phase.REMEDIATE:   lambda: phase_remediate(args, sm),
        Phase.VERIFY:      lambda: phase_verify(args, sm),
    }

    for phase in phases_to_run:
        # Skip completed phases on resume
        if sm.is_phase_done(phase):
            console.print(f"[dim]Skipping {phase.value} (already completed)[/dim]")
            continue

        print_dashboard(sm, run_start)
        console.print(Rule(f"[bold cyan]{phase.value.upper()}[/bold cyan]  {PHASE_DESCRIPTIONS[phase]}"))

        # Semi-auto: ask for approval
        if args.mode == "semi-auto":
            print_phase_preview(phase, args)
            if not Confirm.ask(f"[bold]Run {phase.value}?[/bold]", default=True):
                console.print(f"[yellow]Skipped {phase.value} by user[/yellow]")
                continue

        sm.transition(phase)

        runner = phase_runners.get(phase)
        if not runner:
            console.print(f"[red]No runner for phase {phase.value}[/red]")
            continue

        result = runner()
        sm.complete_phase(phase, result)

        if result.status == "failed":
            console.print(f"\n[bold red]Phase {phase.value} failed:[/bold red] {result.error}")
            sm.transition(Phase.FAILED)
            if not Confirm.ask("Continue to next phase anyway?", default=False):
                console.print("[red]Aborting run.[/red]")
                sys.exit(1)
        else:
            console.print(f"\n[bold green]{phase.value} complete[/bold green] — "
                          f"output: [cyan]{result.output_file}[/cyan]")

        time.sleep(0.5)

    sm.transition(Phase.COMPLETE)
    print_dashboard(sm, run_start)
    print_final_summary(sm, run_start)


if __name__ == "__main__":
    main()