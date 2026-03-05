# VANTA

> Vulnerability ANalysis and Tactical Automation

Autonomous red team agent powered by local LLM inference. Maps a network, reasons about the attack surface, validates exploits in sandboxed containers, drafts remediations, and closes the loop on a single board. Built for air-gapped environments and edge hardware (Jetson Orin Nano).

---

## Architecture

recon --> hypothesize --> exploit --> remediate --> verify (loop back to recon)

Each phase outputs a JSON state file consumed by the next. Runs fully unattended or with human approval gates between phases.

---

## Phases

| # | Module | Description | Status |
|---|--------|-------------|--------|
| 1 | recon.py | Network scan, OS fingerprinting, topology map | Done |
| 2 | hypothesis_engine.py | LLM-powered attack hypotheses ranked by MITRE TTPs | Done |
| 3 | exploit_runner.py | Sandboxed exploit validation via Docker | Done |
| 4 | remediation_engine.py | Auto-draft remediations and markdown report | Done |
| 5 | agent.py | Orchestrator, state machine, full agentic loop | Done |
| 6 | llm_provider.py | Local LLM swap (Ollama) and Jetson optimization | Upcoming |

---

## Phase 1: Network Recon and Topology Mapping

### What it does

- Auto-detects local subnet or accepts a target range
- Scans hosts with nmap: ports, services, versions, OS fingerprints
- Risk-classifies each host (red/yellow/green) based on dangerous open ports
- Generates a dark-themed visual topology map
- Saves full state to recon_state.json for Phase 2

### Requirements

- Linux (Ubuntu 20.04+)
- nmap binary: sudo apt install nmap
- Python 3.12+
- Root/sudo for OS fingerprinting (-O flag)

### Install

    python3 -m venv vanta
    source vanta/bin/activate
    pip install -r requirements.txt

### Running with sudo inside a venv

sudo does not inherit your venv environment. Running sudo python3 recon.py
will fail with ModuleNotFoundError even after pip install. Always pass the
full path to the venv interpreter:

    # While venv is active, find your interpreter path
    which python3

    # Then run with sudo using that full path
    sudo /home/kaneki/vanta/vanta/bin/python3 recon.py

    # Shorthand that works when venv is active
    sudo $(which python3) recon.py

### Usage

    # Single host - scan a VPS scanning itself
    sudo $(which python3) recon.py --target $(hostname -I | awk '{print $1}')/32 --mode deep

    # Full subnet
    sudo $(which python3) recon.py --target 192.168.1.0/24 --mode standard

    # Skip topology image
    sudo $(which python3) recon.py --no-map

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| --target / -t | Target subnet | Auto-detected |
| --mode / -m | quick / standard / deep | standard |
| --output / -o | JSON state output path | recon_state.json |
| --topology / -tp | Topology image path | topology.png |
| --no-map | Skip topology generation | off |

### Outputs

- recon_state.json: full scan state passed to Phase 2
- topology.png: visual network map

### Risk classification

| Color | Ports |
|-------|-------|
| Red | SMB 445, RDP 3389, Telnet 23, VNC 5900, Redis 6379, MongoDB 27017, MySQL 3306 |
| Yellow | SSH 22, HTTP 80, SMTP 25, IMAP 143, HTTP-Alt 8080 |
| Green | No flagged ports |

---

## Phase 2: Attack Hypothesis Engine

### What it does

- Reads recon_state.json from Phase 1
- Sends each host and its services to Claude (Haiku) for reasoning
- Returns ranked attack hypotheses with MITRE ATT&CK IDs, confidence scores, severity, and exploit suggestions
- Scores each hypothesis by severity x confidence and sorts into a priority queue
- Outputs a clean terminal table and saves full detail to hypotheses.json

### Requirements

- ANTHROPIC_API_KEY set in your .env file
- Phase 1 must have been run first (recon_state.json must exist)

### Setup

    cp .env.example .env
    # add your Anthropic API key to .env

### Usage

    export $(cat .env) && python3 hypothesis_engine.py

    # Custom input/output paths
    python3 hypothesis_engine.py --input recon_state.json --output hypotheses.json

    # Use a different model
    python3 hypothesis_engine.py --model claude-opus-4-6

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| --input / -i | recon_state.json path | recon_state.json |
| --output / -o | hypotheses output path | hypotheses.json |
| --model / -m | Claude model to use | claude-haiku-4-5-20251001 |
| --api-key | Anthropic API key | ANTHROPIC_API_KEY env var |

### Outputs

- hypotheses.json: full ranked hypothesis data passed to Phase 3
- Terminal table: priority queue ranked by severity x confidence score

### Notes

- hypotheses.json is gitignored — it contains recon data about real targets
- prompts.py holds the system prompt and host prompt builder separately so Phase 5 can swap them
- Cost per run is typically under $0.01 with Haiku

---

## Phase 3: Sandboxed Exploit Validation

### What it does

- Takes hypotheses.json from Phase 2
- Maps each hypothesis to a validator based on MITRE technique ID
- Runs each validator in an isolated Docker container (auto-destroyed after timeout)
- Captures stdout, stderr, exit codes and interprets results into confirmed/partial/negative/error
- Writes exploit_results.json with findings and evidence for Phase 4

### Validator mapping

| Technique prefix | Validator | What it checks |
|-----------------|-----------|----------------|
| T1110 | credential_check | SSH reachability and password auth availability |
| T1021, T1557 | ssh_algo_enum | Weak key exchange / cipher algorithms via KEXINIT |
| T1552, T1195 | osint_key_check | Generates manual OSINT checklist for leaked keys |
| T1548 | version_cve_check | Banner grab + static CVE lookup by version |
| T1036 | honeypot_detect | Response timing + garbage probe + banner inconsistency |
| default | banner_grab | Generic port reachability and banner capture |

### Requirements

- Docker installed and running: sudo apt install docker.io
- Add your user to the docker group: sudo usermod -aG docker $USER && newgrp docker
- Phase 2 must have been run first (hypotheses.json must exist)

### Usage

    # Dry run — shows what would be tested, does nothing
    python3 exploit_runner.py

    # Run top 3 hypotheses (default)
    python3 exploit_runner.py --confirm

    # Run top 5 with longer timeout
    python3 exploit_runner.py --confirm --top 5 --timeout 45

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| --input / -i | hypotheses.json path | hypotheses.json |
| --output / -o | results output path | exploit_results.json |
| --top / -n | number of hypotheses to test | 3 |
| --timeout / -t | container timeout in seconds | 30 |
| --confirm | required safety flag to actually run | off |

### Outputs

- exploit_results.json: full results with evidence passed to Phase 4
- Terminal table: confirmed / partial / negative / error per hypothesis

### Safety limits

- Containers run with --cap-drop ALL and no-new-privileges
- Memory capped at 128MB, CPU at 50% of one core
- No destructive payloads — validators are read-only probes
- exploit_results.json is gitignored (contains target recon data)

---

## Phase 4: Remediation Engine

### What it does

- Takes exploit_results.json from Phase 3
- Calls Claude Sonnet per finding to generate actionable remediations
- Each remediation includes: risk summary, numbered steps, exact config diffs, CVE references, patch confidence score, verification command, and estimated fix time
- Processes all findings (confirmed, partial, negative) — negative findings get hardening guidance
- Outputs remediations.json and a human-readable markdown report

### Requirements

- ANTHROPIC_API_KEY set in .env
- Phase 3 must have been run first (exploit_results.json must exist)

### Usage

    export $(cat .env) && python3 remediation_engine.py

    # Skip negative findings, only remediate confirmed and partial
    python3 remediation_engine.py --skip-negative

    # Custom paths and model
    python3 remediation_engine.py --input exploit_results.json --output remediations.json --report report.md

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| --input / -i | exploit_results.json path | exploit_results.json |
| --output / -o | remediations output path | remediations.json |
| --report / -r | markdown report output path | report.md |
| --model / -m | Claude model to use | claude-sonnet-4-6 |
| --skip-negative | skip negative findings | off |
| --api-key | Anthropic API key | ANTHROPIC_API_KEY env var |

### Outputs

- remediations.json: full remediation data passed to Phase 5 (gitignored)
- report.md: human-readable markdown report (gitignored — contains target data)
- sample_report.md: committed example report generated from real VPS findings

### Cost

Sonnet is used for higher quality remediations. Expect $0.05–0.10 per run for 5 findings.
Haiku can be substituted with --model claude-haiku-4-5-20251001 to cut costs ~10x.

---

## Phase 5: Agent Orchestrator

### What it does

- Single entry point that runs the full pipeline: recon -> hypothesize -> exploit -> remediate -> verify
- After remediation, re-runs a quick recon and compares against baseline to measure attack surface reduction
- Persists state to agent_state/ so every run is auditable and resumable
- Supports full-auto, semi-auto, and recon-only modes
- Live dashboard showing phase progress, findings counts, and severity breakdown

### Usage

    # Semi-auto (default) — pauses for approval between phases
    python3 agent.py

    # Full auto — runs entire pipeline unattended
    python3 agent.py --mode full-auto

    # Recon only
    python3 agent.py --mode recon-only

    # Resume last incomplete run
    python3 agent.py --resume

    # List all previous runs
    python3 agent.py --list-runs

    # Target a specific subnet
    python3 agent.py --mode full-auto --target 192.168.1.0/24 --scan-mode deep

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| --mode | full-auto / semi-auto / recon-only | semi-auto |
| --target / -t | target subnet or IP | auto-detected |
| --scan-mode | quick / standard / deep | standard |
| --top-n | hypotheses to exploit in Phase 3 | 3 |
| --timeout | container timeout for Phase 3 (seconds) | 30 |
| --hypothesis-model | Claude model for Phase 2 | claude-haiku-4-5-20251001 |
| --remediation-model | Claude model for Phase 4 | claude-sonnet-4-6 |
| --resume | resume last incomplete run | off |
| --run-id | resume a specific run by ID | - |
| --list-runs | list all previous runs and exit | off |

### Outputs

- agent_state/<run_id>.json: full run state (gitignored)
- recon_state.json, hypotheses.json, exploit_results.json, remediations.json, report.md
- verify_state.json: post-remediation recon for comparison

### State machine phases

    INIT -> RECON -> HYPOTHESIZE -> EXPLOIT -> REMEDIATE -> VERIFY -> COMPLETE

If any phase fails, agent prompts to continue or abort. On --resume, completed phases are skipped automatically.

### Verified run output (2026-03-05)

Full pipeline against DigitalOcean VPS (single host, SSH-only exposure):

| Phase | Duration | Key output |
|-------|----------|------------|
| recon | 14s | 1 host, 1 port |
| hypothesize | 17s | 7 hypotheses (2 critical, 2 high, 2 medium, 1 low) |
| exploit | 3s | 3 partial, 0 confirmed — hardened box |
| remediate | 69s | 3 remediations, avg patch confidence 79% |
| verify | 2s | 0 ports closed (expected — remediations are drafts) |

**Total runtime: ~1m 48s**

Attack surface unchanged on verify is expected behavior — VANTA generates remediation drafts,
a human applies them, then re-runs verify to confirm closure.

---

## Local LLM Setup (Phase 6)

VANTA is designed to run fully offline using Ollama.

    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull phi3
    python3 agent.py --llm-provider ollama

---

## Project Structure

    vanta/
    ├── recon.py                  Phase 1
    ├── hypothesis_engine.py      Phase 2
    ├── exploit_runner.py         Phase 3
    ├── docker_sandbox.py         Phase 3 helper
    ├── remediation_engine.py     Phase 4
    ├── report_generator.py       Phase 4 helper
    ├── agent.py                  Phase 5 orchestrator
    ├── state_machine.py          Phase 5 helper
    ├── llm_provider.py           Phase 6
    ├── benchmark.py              Phase 6 benchmarking
    ├── requirements.txt
    ├── .env.example
    └── README.md

---

## Disclaimer

VANTA is built for authorized penetration testing and security research only. Only run against networks you own or have explicit written permission to test.
