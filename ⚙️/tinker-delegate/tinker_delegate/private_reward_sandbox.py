"""Local candidate sandbox for toy private-reward environments.

This is a first-pass subprocess sandbox for synthetic and local development
environments. It is not a substitute for CVM/container isolation for untrusted
third-party code, but it gives the private reward interface a bounded execution
surface with fail-closed preflight checks and capped public traces.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from tinker_delegate.private_reward import Candidate


class SandboxOutcome(str, Enum):
    PASS = "pass"
    POLICY_REJECTED = "policy_rejected"
    RUNTIME_ERROR = "runtime_error"
    TIMEOUT = "timeout"


class SandboxFailureCode(str, Enum):
    NONE = "none"
    POLICY_REJECTED = "policy_rejected"
    SYNTAX_ERROR = "syntax_error"
    RUNTIME_ERROR = "runtime_error"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class SandboxPolicy:
    timeout_seconds: float = 1.0
    max_source_bytes: int = 16_384
    max_stdout_bytes: int = 4_096
    max_stderr_bytes: int = 2_048
    timing_band_seconds: float = 0.1
    deterministic_seed: int = 0
    cpu_seconds: int = 1
    memory_megabytes: int = 128
    allow_network: bool = False
    allow_process_spawn: bool = False
    allow_filesystem: bool = False
    scratch_prefix: str = "dnai-candidate-"

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_source_bytes <= 0:
            raise ValueError("max_source_bytes must be positive")
        if self.max_stdout_bytes < 0:
            raise ValueError("max_stdout_bytes must be non-negative")
        if self.max_stderr_bytes < 0:
            raise ValueError("max_stderr_bytes must be non-negative")
        if self.timing_band_seconds <= 0:
            raise ValueError("timing_band_seconds must be positive")
        if self.cpu_seconds <= 0:
            raise ValueError("cpu_seconds must be positive")
        if self.memory_megabytes <= 0:
            raise ValueError("memory_megabytes must be positive")
        if self.allow_network:
            raise ValueError("network access is not supported by the local sandbox")
        if self.allow_process_spawn:
            raise ValueError("process spawning is not supported by the local sandbox")
        if self.allow_filesystem:
            raise ValueError("filesystem access is not supported by the local sandbox")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "max_source_bytes": self.max_source_bytes,
            "max_stdout_bytes": self.max_stdout_bytes,
            "max_stderr_bytes": self.max_stderr_bytes,
            "timing_band_seconds": self.timing_band_seconds,
            "deterministic_seed": self.deterministic_seed,
            "cpu_seconds": self.cpu_seconds,
            "memory_megabytes": self.memory_megabytes,
            "allow_network": self.allow_network,
            "allow_process_spawn": self.allow_process_spawn,
            "allow_filesystem": self.allow_filesystem,
        }


@dataclass(frozen=True)
class SandboxResult:
    candidate_hash: str
    outcome: SandboxOutcome
    failure_code: SandboxFailureCode
    exit_code: int | None
    timed_out: bool
    elapsed_band_seconds: float
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool

    @property
    def accepted(self) -> bool:
        return self.outcome == SandboxOutcome.PASS

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "candidate_hash": self.candidate_hash,
            "outcome": self.outcome.value,
            "failure_code": self.failure_code.value,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "elapsed_band_seconds": self.elapsed_band_seconds,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
        }


class PythonCandidateSandbox:
    """Execute simple Python candidates with bounded public traces."""

    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy()

    def run(self, candidate: Candidate) -> SandboxResult:
        started_at = time.monotonic()
        source = self._decode_source(candidate)
        if source is None:
            return self._reject(candidate, SandboxFailureCode.POLICY_REJECTED, started_at)
        if candidate.size_bytes > self.policy.max_source_bytes:
            return self._reject(candidate, SandboxFailureCode.POLICY_REJECTED, started_at)

        preflight_failure = _preflight_source(source)
        if preflight_failure != SandboxFailureCode.NONE:
            return self._reject(candidate, preflight_failure, started_at)

        with tempfile.TemporaryDirectory(prefix=self.policy.scratch_prefix) as scratch_dir:
            try:
                proc = subprocess.run(
                    [sys.executable, "-S", "-c", _SANDBOX_WRAPPER],
                    input=source,
                    text=True,
                    cwd=scratch_dir,
                    env={
                        "PYTHONHASHSEED": str(self.policy.deterministic_seed),
                        "PYTHONIOENCODING": "utf-8",
                        "SANDBOX_RANDOM_SEED": str(self.policy.deterministic_seed),
                        "SANDBOX_CPU_SECONDS": str(max(1, self.policy.cpu_seconds)),
                        "SANDBOX_MEMORY_MEGABYTES": str(max(1, self.policy.memory_megabytes)),
                        "SANDBOX_MAX_STDOUT_BYTES": str(self.policy.max_stdout_bytes + 1),
                        "SANDBOX_MAX_STDERR_BYTES": str(self.policy.max_stderr_bytes + 1),
                    },
                    capture_output=True,
                    timeout=self.policy.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                stdout, stdout_truncated = _cap_text(exc.stdout or "", self.policy.max_stdout_bytes)
                stderr, stderr_truncated = _cap_text("sandbox failure: timeout", self.policy.max_stderr_bytes)
                return SandboxResult(
                    candidate_hash=candidate.candidate_hash,
                    outcome=SandboxOutcome.TIMEOUT,
                    failure_code=SandboxFailureCode.TIMEOUT,
                    exit_code=None,
                    timed_out=True,
                    elapsed_band_seconds=self._elapsed_band(started_at),
                    stdout=stdout,
                    stderr=stderr,
                    stdout_truncated=stdout_truncated,
                    stderr_truncated=stderr_truncated,
                )

        stdout, stdout_truncated = _cap_text(proc.stdout, self.policy.max_stdout_bytes)
        outcome = SandboxOutcome.PASS if proc.returncode == 0 else SandboxOutcome.RUNTIME_ERROR
        failure_code = SandboxFailureCode.NONE if proc.returncode == 0 else SandboxFailureCode.RUNTIME_ERROR
        stderr = "" if proc.returncode == 0 else "sandbox failure: runtime_error"
        stderr, stderr_truncated = _cap_text(stderr, self.policy.max_stderr_bytes)
        return SandboxResult(
            candidate_hash=candidate.candidate_hash,
            outcome=outcome,
            failure_code=failure_code,
            exit_code=proc.returncode,
            timed_out=False,
            elapsed_band_seconds=self._elapsed_band(started_at),
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
        )

    def _decode_source(self, candidate: Candidate) -> str | None:
        try:
            return candidate.payload.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _reject(
        self,
        candidate: Candidate,
        failure_code: SandboxFailureCode,
        started_at: float,
    ) -> SandboxResult:
        stderr, stderr_truncated = _cap_text(
            f"sandbox failure: {failure_code.value}",
            self.policy.max_stderr_bytes,
        )
        return SandboxResult(
            candidate_hash=candidate.candidate_hash,
            outcome=SandboxOutcome.POLICY_REJECTED,
            failure_code=failure_code,
            exit_code=None,
            timed_out=False,
            elapsed_band_seconds=self._elapsed_band(started_at),
            stdout="",
            stderr=stderr,
            stdout_truncated=False,
            stderr_truncated=stderr_truncated,
        )

    def _elapsed_band(self, started_at: float) -> float:
        granularity = self.policy.timing_band_seconds
        elapsed = max(0.0, time.monotonic() - started_at)
        return (int(elapsed / granularity)) * granularity


_BANNED_IMPORT_ROOTS = {
    "builtins",
    "ctypes",
    "ftplib",
    "glob",
    "http",
    "importlib",
    "multiprocessing",
    "os",
    "pathlib",
    "resource",
    "selectors",
    "shutil",
    "socket",
    "ssl",
    "subprocess",
    "sys",
    "urllib",
}

_BANNED_CALLS = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "input",
    "open",
}


def _preflight_source(source: str) -> SandboxFailureCode:
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError:
        return SandboxFailureCode.SYNTAX_ERROR

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", maxsplit=1)[0]
                if root in _BANNED_IMPORT_ROOTS:
                    return SandboxFailureCode.POLICY_REJECTED
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", maxsplit=1)[0]
            if root in _BANNED_IMPORT_ROOTS:
                return SandboxFailureCode.POLICY_REJECTED
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _BANNED_CALLS:
                return SandboxFailureCode.POLICY_REJECTED
        elif isinstance(node, ast.Name):
            if node.id in _BANNED_CALLS or node.id == "__builtins__":
                return SandboxFailureCode.POLICY_REJECTED
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__"):
                return SandboxFailureCode.POLICY_REJECTED

    return SandboxFailureCode.NONE


def _cap_text(value: str | bytes, max_bytes: int) -> tuple[str, bool]:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if max_bytes == 0:
        return "", bool(value)
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return value, False
    clipped = encoded[:max_bytes]
    return clipped.decode("utf-8", errors="ignore"), True


_SANDBOX_WRAPPER = r"""
import math
import os
import random
import sys

try:
    import resource
except Exception:
    resource = None

seed = int(os.environ.get("SANDBOX_RANDOM_SEED", "0"))
max_stdout = int(os.environ.get("SANDBOX_MAX_STDOUT_BYTES", "4096"))
max_stderr = int(os.environ.get("SANDBOX_MAX_STDERR_BYTES", "2048"))
cpu_seconds = max(1, int(os.environ.get("SANDBOX_CPU_SECONDS", "1")))
memory_megabytes = max(1, int(os.environ.get("SANDBOX_MEMORY_MEGABYTES", "128")))

if resource is not None:
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    except Exception:
        pass
    try:
        memory_bytes = memory_megabytes * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    except Exception:
        pass

random.seed(seed)
_stdout_chunks = []
_stdout_bytes = 0

def _write_stdout(text):
    global _stdout_bytes
    encoded = str(text).encode("utf-8", errors="replace")
    if _stdout_bytes >= max_stdout:
        return
    remaining = max_stdout - _stdout_bytes
    _stdout_chunks.append(encoded[:remaining].decode("utf-8", errors="ignore"))
    _stdout_bytes += min(len(encoded), remaining)

def safe_print(*values, sep=" ", end="\n"):
    _write_stdout(sep.join(str(value) for value in values) + end)

def disabled(*_args, **_kwargs):
    raise PermissionError("sandbox disabled this operation")

safe_builtins = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "bytes": bytes,
    "dict": dict,
    "enumerate": enumerate,
    "float": float,
    "int": int,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "pow": pow,
    "print": safe_print,
    "range": range,
    "round": round,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
    "Exception": Exception,
    "ValueError": ValueError,
    "PermissionError": PermissionError,
    "open": disabled,
    "__import__": disabled,
}

namespace = {
    "__builtins__": safe_builtins,
    "math": math,
    "random": random,
}

source = sys.stdin.read()
try:
    exec(compile(source, "<candidate>", "exec"), namespace, namespace)
except BaseException as exc:
    sys.stdout.write("".join(_stdout_chunks))
    message = f"{type(exc).__name__}: {exc}"
    sys.stderr.write(message.encode("utf-8", errors="replace")[:max_stderr].decode("utf-8", errors="ignore"))
    raise SystemExit(1)

sys.stdout.write("".join(_stdout_chunks))
"""
