#!/usr/bin/env python3
"""
state_machine.py
Phase transition management for VANTA agent.
Persists state to disk so runs are resumable and auditable.
"""

import json
import os
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional


class Phase(str, Enum):
    INIT        = "init"
    RECON       = "recon"
    HYPOTHESIZE = "hypothesize"
    EXPLOIT     = "exploit"
    REMEDIATE   = "remediate"
    VERIFY      = "verify"
    COMPLETE    = "complete"
    FAILED      = "failed"


PHASE_ORDER = [
    Phase.INIT,
    Phase.RECON,
    Phase.HYPOTHESIZE,
    Phase.EXPLOIT,
    Phase.REMEDIATE,
    Phase.VERIFY,
    Phase.COMPLETE,
]

PHASE_DESCRIPTIONS = {
    Phase.INIT:        "Initializing agent and validating environment",
    Phase.RECON:       "Scanning network — OS fingerprinting, port enumeration, topology map",
    Phase.HYPOTHESIZE: "Generating attack hypotheses via LLM — MITRE TTP mapping",
    Phase.EXPLOIT:     "Validating hypotheses in sandboxed Docker containers",
    Phase.REMEDIATE:   "Drafting remediations and generating assessment report",
    Phase.VERIFY:      "Re-scanning to verify attack surface reduction",
    Phase.COMPLETE:    "Pipeline complete",
    Phase.FAILED:      "Pipeline failed",
}


@dataclass
class PhaseResult:
    phase: str
    status: str          # success | failed | skipped
    started_at: str
    completed_at: Optional[str] = None
    output_file: Optional[str] = None
    summary: dict = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AgentState:
    run_id: str
    target: str
    mode: str
    current_phase: str = Phase.INIT
    phases_completed: list = field(default_factory=list)
    phase_results: list = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    findings_summary: dict = field(default_factory=dict)


class StateMachine:
    def __init__(self, state_dir: str = "agent_state"):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.state: Optional[AgentState] = None

    def _state_path(self, run_id: str) -> str:
        return os.path.join(self.state_dir, f"{run_id}.json")

    def init(self, run_id: str, target: str, mode: str) -> AgentState:
        self.state = AgentState(run_id=run_id, target=target, mode=mode)
        self._save()
        return self.state

    def load(self, run_id: str) -> Optional[AgentState]:
        path = self._state_path(run_id)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            data = json.load(f)
        self.state = AgentState(**data)
        return self.state

    def load_latest(self) -> Optional[AgentState]:
        files = sorted(
            [f for f in os.listdir(self.state_dir) if f.endswith(".json")],
            reverse=True
        )
        if not files:
            return None
        return self.load(files[0].replace(".json", ""))

    def transition(self, phase: Phase) -> None:
        if not self.state:
            raise RuntimeError("State not initialized")
        self.state.current_phase = phase
        self.state.updated_at = datetime.now().isoformat()
        self._save()

    def complete_phase(self, phase: Phase, result: PhaseResult) -> None:
        if not self.state:
            raise RuntimeError("State not initialized")
        self.state.phases_completed.append(phase)
        self.state.phase_results.append(asdict(result))
        self.state.updated_at = datetime.now().isoformat()
        self._save()

    def update_findings(self, summary: dict) -> None:
        if not self.state:
            raise RuntimeError("State not initialized")
        self.state.findings_summary.update(summary)
        self.state.updated_at = datetime.now().isoformat()
        self._save()

    def is_phase_done(self, phase: Phase) -> bool:
        if not self.state:
            return False
        return phase in self.state.phases_completed

    def next_phase(self) -> Optional[Phase]:
        if not self.state:
            return None
        current = self.state.current_phase
        try:
            idx = PHASE_ORDER.index(Phase(current))
            if idx + 1 < len(PHASE_ORDER):
                return PHASE_ORDER[idx + 1]
        except (ValueError, IndexError):
            pass
        return None

    def _save(self) -> None:
        if not self.state:
            return
        with open(self._state_path(self.state.run_id), "w") as f:
            json.dump(asdict(self.state), f, indent=2)

    def list_runs(self) -> list[dict]:
        runs = []
        for fname in sorted(os.listdir(self.state_dir), reverse=True):
            if fname.endswith(".json"):
                with open(os.path.join(self.state_dir, fname)) as f:
                    data = json.load(f)
                runs.append({
                    "run_id": data.get("run_id"),
                    "target": data.get("target"),
                    "mode": data.get("mode"),
                    "current_phase": data.get("current_phase"),
                    "started_at": data.get("started_at"),
                })
        return runs