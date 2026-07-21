from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from redatlas.exec.audit import log_attempt
from redatlas.exec.authorization import AuthorizationError, AuthorizationScope, check_authorized

_LOCAL_TARGET_ALIASES = {"localhost", "127.0.0.1", "::1"}


class AtomicRedTeamNotAvailableError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "The Invoke-AtomicRedTeam PowerShell module was not found. Install it first:\n"
            "  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam"
            "/master/install-atomicredteam.ps1' -UseBasicParsing)\n"
            "  Install-AtomicRedTeam -getAtomics\n"
            "See https://github.com/redcanaryco/invoke-atomicredteam for details."
        )


@dataclass
class ExecutionResult:
    technique_id: str
    target: str
    dry_run: bool
    return_code: int | None
    stdout: str
    stderr: str


def _find_powershell() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


def _powershell_module_available(exe: str) -> bool:
    result = subprocess.run(
        [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-Module -ListAvailable -Name Invoke-AtomicRedTeam",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return bool(result.stdout.strip())


def run_technique(
    technique_id: str,
    target: str,
    scope: AuthorizationScope,
    *,
    test_numbers: list[int] | None = None,
    execute: bool = False,
    cleanup: bool = False,
    audit_log_path: Path | None = None,
) -> ExecutionResult:
    """Runs (or dry-runs) an Atomic Red Team test for `technique_id` against
    `target`. Authorization is checked -- and every attempt logged, allowed or
    not -- before anything else happens. `execute=False` (the default) never
    invokes PowerShell at all; it only validates authorization and reports
    what would run."""

    try:
        check_authorized(scope, target)
    except AuthorizationError as exc:
        log_attempt(
            technique_id=technique_id,
            target=target,
            engagement_name=None,
            allowed=False,
            dry_run=not execute,
            reason=str(exc),
            path=audit_log_path,
        )
        raise

    if not execute:
        log_attempt(
            technique_id=technique_id,
            target=target,
            engagement_name=scope.engagement_name,
            allowed=True,
            dry_run=True,
            reason="Dry run only; pass --execute to actually run this test.",
            path=audit_log_path,
        )
        return ExecutionResult(
            technique_id=technique_id,
            target=target,
            dry_run=True,
            return_code=None,
            stdout="",
            stderr="",
        )

    if target.strip().lower() not in _LOCAL_TARGET_ALIASES:
        raise NotImplementedError(
            "Remote execution is not implemented yet; only target 'localhost' is supported "
            "in this MVP. See the redatlas.exec module docstring."
        )

    exe = _find_powershell()
    if exe is None or not _powershell_module_available(exe):
        log_attempt(
            technique_id=technique_id,
            target=target,
            engagement_name=scope.engagement_name,
            allowed=True,
            dry_run=False,
            reason="Invoke-AtomicRedTeam is not installed.",
            path=audit_log_path,
        )
        raise AtomicRedTeamNotAvailableError()

    command_parts = [f"Invoke-AtomicTest {technique_id}"]
    if test_numbers:
        command_parts.append(f"-TestNumbers {','.join(str(n) for n in test_numbers)}")
    if cleanup:
        command_parts.append("-Cleanup")
    command_parts.append("-Confirm:$false")

    result = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-Command", " ".join(command_parts)],
        capture_output=True,
        text=True,
        timeout=600,
    )

    log_attempt(
        technique_id=technique_id,
        target=target,
        engagement_name=scope.engagement_name,
        allowed=True,
        dry_run=False,
        reason=f"Executed, exit code {result.returncode}.",
        path=audit_log_path,
    )

    return ExecutionResult(
        technique_id=technique_id,
        target=target,
        dry_run=False,
        return_code=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )
