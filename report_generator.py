#!/usr/bin/env python3
"""
report_generator.py
Markdown report generator for VANTA Phase 4.
Pure formatting — no API calls.
"""

from datetime import datetime


SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "informational": "🔵",
}

STATUS_EMOJI = {
    "confirmed": "✅ CONFIRMED",
    "partial":   "⚠️  PARTIAL",
    "negative":  "✔️  NEGATIVE",
    "error":     "❌ ERROR",
}


def _severity_order(r: dict) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return order.get(r.get("severity_rating", r.get("severity", "low")), 99)


def _patch_conf_label(conf: float) -> str:
    if conf >= 0.85:
        return f"HIGH ({conf:.0%})"
    elif conf >= 0.6:
        return f"MEDIUM ({conf:.0%})"
    else:
        return f"LOW ({conf:.0%})"


def generate_report(
    remediations: list[dict],
    exploit_data: dict,
    output_path: str,
    model: str,
) -> str:

    now = datetime.now()
    sorted_r = sorted(remediations, key=_severity_order)

    confirmed = [r for r in remediations if r.get("original_status") == "confirmed"]
    partial   = [r for r in remediations if r.get("original_status") == "partial"]
    negative  = [r for r in remediations if r.get("original_status") == "negative"]

    critical_count = sum(1 for r in remediations if r.get("severity_rating") == "critical")
    high_count     = sum(1 for r in remediations if r.get("severity_rating") == "high")
    medium_count   = sum(1 for r in remediations if r.get("severity_rating") == "medium")

    lines = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        "# VANTA Security Assessment Report",
        "",
        f"> Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"> Model: {model}  ",
        f"> Source: {exploit_data.get('meta', {}).get('hypotheses_source', 'hypotheses.json')}",
        "",
        "---",
        "",
    ]

    # ── Executive Summary ────────────────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
    ]

    if confirmed:
        lines.append(
            f"This assessment identified **{len(confirmed)} confirmed** finding(s), "
            f"**{len(partial)} partial** finding(s), and **{len(negative)} negative** finding(s) "
            f"across {exploit_data.get('meta', {}).get('hypotheses_tested', '?')} tested hypotheses."
        )
    else:
        lines.append(
            f"This assessment identified no confirmed vulnerabilities. "
            f"**{len(partial)} partial** finding(s) require manual follow-up. "
            f"**{len(negative)} finding(s)** were validated as not exploitable in current configuration."
        )

    lines += [
        "",
        f"**Critical:** {critical_count}  |  "
        f"**High:** {high_count}  |  "
        f"**Medium:** {medium_count}",
        "",
    ]

    if confirmed:
        lines += [
            "### Immediate Actions Required",
            "",
        ]
        for r in confirmed:
            sev = r.get("severity_rating", "unknown")
            emoji = SEVERITY_EMOJI.get(sev, "")
            lines.append(f"- {emoji} **{r['hypothesis_id']}** — {r.get('risk_summary', '')}")
        lines.append("")

    lines += ["---", ""]

    # ── Findings Table ───────────────────────────────────────────────────────
    lines += [
        "## Findings Summary",
        "",
        "| ID | Status | Severity | Technique | Target | Patch Confidence | Fix Time |",
        "|----|--------|----------|-----------|--------|-----------------|----------|",
    ]

    for r in sorted_r:
        hid    = r.get("hypothesis_id", "")
        status = STATUS_EMOJI.get(r.get("original_status", ""), r.get("original_status", ""))
        sev    = r.get("severity_rating", "")
        emoji  = SEVERITY_EMOJI.get(sev, "")
        tid    = r.get("technique_id", "")
        target = r.get("target", "")
        conf   = _patch_conf_label(float(r.get("patch_confidence", 0)))
        ftime  = r.get("estimated_fix_time", "unknown")

        lines.append(f"| {hid} | {status} | {emoji} {sev.upper()} | {tid} | {target} | {conf} | {ftime} |")

    lines += ["", "---", ""]

    # ── Per-finding Detail ───────────────────────────────────────────────────
    lines += ["## Findings Detail", ""]

    for r in sorted_r:
        hid    = r.get("hypothesis_id", "")
        sev    = r.get("severity_rating", "")
        emoji  = SEVERITY_EMOJI.get(sev, "")
        status = r.get("original_status", "")
        tid    = r.get("technique_id", "")
        tactic = r.get("tactic", "")

        lines += [
            f"### {hid} — {emoji} {sev.upper()}",
            "",
            f"**Status:** {STATUS_EMOJI.get(status, status)}  ",
            f"**Technique:** {tid} — {tactic}  ",
            f"**Target:** {r.get('target', '')}  ",
            f"**Finding:** {r.get('original_finding', '')}",
            "",
            f"> {r.get('risk_summary', '')}",
            "",
        ]

        # CVEs
        cves = r.get("cve_references", [])
        if cves:
            lines += [f"**CVE References:** {', '.join(cves)}", ""]

        # Remediation steps
        steps = r.get("remediation_steps", [])
        if steps:
            lines += ["**Remediation Steps:**", ""]
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        # Config fix
        cfg = r.get("config_fix", {})
        if cfg:
            lines += ["**Configuration Fix:**", ""]
            if cfg.get("file_or_command"):
                lines += [
                    f"File / Command: `{cfg['file_or_command']}`",
                    "",
                ]
            if cfg.get("before"):
                lines += [
                    "Before:",
                    "```",
                    cfg["before"],
                    "```",
                    "",
                ]
            if cfg.get("after"):
                lines += [
                    "After:",
                    "```",
                    cfg["after"],
                    "```",
                    "",
                ]
            if cfg.get("notes"):
                lines += [f"*{cfg['notes']}*", ""]

        # Verification
        verify = r.get("verification_command", "")
        if verify:
            lines += [
                "**Verification:**",
                "```bash",
                verify,
                "```",
                "",
            ]

        # Patch confidence
        conf_val = float(r.get("patch_confidence", 0))
        conf_label = _patch_conf_label(conf_val)
        conf_reason = r.get("patch_confidence_reason", "")
        lines += [
            f"**Patch Confidence:** {conf_label}  ",
            f"*{conf_reason}*",
            "",
            f"**Estimated Fix Time:** {r.get('estimated_fix_time', 'unknown')}",
            "",
            "---",
            "",
        ]

    # ── Footer ───────────────────────────────────────────────────────────────
    lines += [
        "## Methodology",
        "",
        "This report was generated by VANTA (Vulnerability ANalysis and Tactical Automation).",
        "Findings are based on non-destructive network probes and AI-assisted analysis.",
        "All tests were conducted from an isolated Docker sandbox with no persistent access.",
        "",
        "> **Disclaimer:** This report is for authorized security testing only.",
        "> Findings should be validated by a human security engineer before remediation.",
        "",
    ]

    report = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(report)

    return output_path