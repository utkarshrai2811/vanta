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
| 2 | hypothesis_engine.py | LLM-powered attack hypotheses ranked by MITRE TTPs | Upcoming |
| 3 | exploit_runner.py | Sandboxed exploit validation via Docker | Upcoming |
| 4 | remediation_engine.py | Auto-draft remediations and markdown report | Upcoming |
| 5 | agent.py | Orchestrator, state machine, full agentic loop | Upcoming |
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
- nmap: sudo apt install nmap
- Python 3.9+
- Root/sudo for OS fingerprinting

### Install

    pip install -r requirements.txt

### Usage

    sudo python3 recon.py
    sudo python3 recon.py --target 192.168.1.0/24 --mode deep
    sudo python3 recon.py --no-map

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
