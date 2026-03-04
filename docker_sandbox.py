#!/usr/bin/env python3
"""
docker_sandbox.py
Isolated container execution engine for VANTA Phase 3.
Each test runs in a fresh container, auto-destroyed after timeout.
"""

import docker
import json
import time
from dataclasses import dataclass, field
from typing import Optional


SANDBOX_IMAGE = "python:3.12-slim"
SANDBOX_TIMEOUT = 30  # seconds
SANDBOX_MEM_LIMIT = "128m"
SANDBOX_CPU_PERIOD = 100000
SANDBOX_CPU_QUOTA = 50000  # 50% of one core


@dataclass
class SandboxResult:
    hypothesis_id: str
    validator_name: str
    exit_code: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    evidence: dict = field(default_factory=dict)
    error: Optional[str] = None


class DockerSandbox:
    def __init__(self, timeout: int = SANDBOX_TIMEOUT):
        self.timeout = timeout
        try:
            self.client = docker.from_env()
            self.client.ping()
        except Exception as e:
            raise RuntimeError(
                f"Docker not available: {e}\n"
                "Install Docker and ensure it is running: https://docs.docker.com/get-docker/"
            )

    def run(
        self,
        hypothesis_id: str,
        validator_name: str,
        script: str,
        target_ip: str,
        target_port: int,
        extra_env: Optional[dict] = None,
    ) -> SandboxResult:
        """
        Spin up a container, run the validator script, capture output.
        Container is always destroyed after run regardless of outcome.
        """
        env = {
            "TARGET_IP": target_ip,
            "TARGET_PORT": str(target_port),
            "TIMEOUT": str(self.timeout - 5),  # leave 5s buffer for container overhead
        }
        if extra_env:
            env.update(extra_env)

        container = None
        start = time.time()

        try:
            container = self.client.containers.run(
                image=SANDBOX_IMAGE,
                command=["python3", "-c", script],
                environment=env,
                network_mode="bridge",
                mem_limit=SANDBOX_MEM_LIMIT,
                cpu_period=SANDBOX_CPU_PERIOD,
                cpu_quota=SANDBOX_CPU_QUOTA,
                read_only=False,
                remove=False,
                detach=True,
                # No volumes, no privileged, no host network
                security_opt=["no-new-privileges"],
                cap_drop=["ALL"],
            )

            timed_out = False
            try:
                result = container.wait(timeout=self.timeout)
                exit_code = result.get("StatusCode", -1)
            except Exception:
                timed_out = True
                exit_code = None
                try:
                    container.kill()
                except Exception:
                    pass

            duration = round(time.time() - start, 2)
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")

            # Split stdout/stderr — python:slim merges them; parse markers we inject
            stdout_lines, stderr_lines = [], []
            for line in logs.splitlines():
                if line.startswith("[STDERR]"):
                    stderr_lines.append(line[8:].strip())
                else:
                    stdout_lines.append(line)

            stdout = "\n".join(stdout_lines).strip()
            stderr = "\n".join(stderr_lines).strip()

            # Parse structured evidence if validator emits JSON on last line
            evidence = {}
            for line in reversed(stdout_lines):
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        evidence = json.loads(line)
                    except json.JSONDecodeError:
                        pass
                    break

            return SandboxResult(
                hypothesis_id=hypothesis_id,
                validator_name=validator_name,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                duration_seconds=duration,
                evidence=evidence,
            )

        except Exception as e:
            duration = round(time.time() - start, 2)
            return SandboxResult(
                hypothesis_id=hypothesis_id,
                validator_name=validator_name,
                exit_code=None,
                stdout="",
                stderr="",
                timed_out=False,
                duration_seconds=duration,
                error=str(e),
            )

        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass