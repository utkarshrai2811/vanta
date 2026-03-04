# prompts.py
# Prompt templates for VANTA hypothesis engine
# Kept separate so Phase 5 orchestrator can swap or extend them

SYSTEM_PROMPT = """You are an expert penetration tester and red team operator with deep knowledge of:
- MITRE ATT&CK framework (enterprise and network matrices)
- CVE databases and exploit techniques
- Network service vulnerabilities and misconfigurations
- Offensive security tooling (Metasploit, nuclei, custom scripts)

Your job is to analyze discovered network services and generate actionable attack hypotheses.
You must respond ONLY with valid JSON. No markdown, no explanation, no preamble."""


def build_host_prompt(host: dict) -> str:
    """Build the user prompt for a single host analysis."""
    services = []
    for port, data in host["open_ports"].items():
        service_line = (
            f"Port {port}/{data['protocol']} - {data['service']} "
            f"| Product: {data['product'] or 'unknown'} "
            f"| Version: {data['version'] or 'unknown'} "
            f"| Extra: {data['extrainfo'] or 'none'}"
        )
        services.append(service_line)

    services_block = "\n".join(services) if services else "No open ports detected"

    return f"""Analyze this target and generate attack hypotheses.

TARGET INFORMATION:
  IP: {host["ip"]}
  Hostname: {host["hostname"]}
  OS Best Guess: {host["os_best_guess"]}
  OS Accuracy: {host["os_matches"][0]["accuracy"] + "%" if host["os_matches"] else "unknown"}

DISCOVERED SERVICES:
{services_block}

Generate a JSON response with this exact structure:
{{
  "host": "{host["ip"]}",
  "hostname": "{host["hostname"]}",
  "os_assessment": "brief assessment of OS confidence and what it implies",
  "hypotheses": [
    {{
      "id": "H001",
      "hypothesis": "clear description of the attack vector",
      "technique": "MITRE ATT&CK technique name",
      "technique_id": "T1xxx.xxx",
      "tactic": "MITRE tactic (e.g. Initial Access, Credential Access)",
      "target_service": "service:port",
      "confidence": 0.0,
      "severity": "critical|high|medium|low",
      "exploit_suggestion": "specific tool or method to test this",
      "cve_references": ["CVE-XXXX-XXXX"],
      "notes": "any caveats or conditions"
    }}
  ],
  "recommended_first_move": "which hypothesis to test first and why"
}}

Rules:
- confidence is a float from 0.0 to 1.0
- severity reflects impact if successful (not likelihood)
- exploit_suggestion must be specific (tool name, command pattern, or technique)
- include CVEs only if they apply to the exact version detected
- generate between 3 and 8 hypotheses depending on attack surface
- rank hypotheses by (severity * confidence) descending
- if attack surface is minimal, still generate hypotheses for what IS there"""
