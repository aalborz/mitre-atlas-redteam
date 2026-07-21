import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from redatlas.exec import atomic_red_team
from redatlas.exec.atomic_red_team import (
    AtomicRedTeamNotAvailableError,
    run_technique,
)
from redatlas.exec.authorization import AuthorizationError, AuthorizationScope


def _scope(**overrides) -> AuthorizationScope:
    defaults = dict(
        engagement_name="Test Engagement",
        authorized_by="Test Authorizer",
        starts_at=datetime(2020, 1, 1, tzinfo=UTC),
        ends_at=datetime(2035, 1, 1, tzinfo=UTC),
        allowed_targets=["localhost", "10.0.0.0/8"],
    )
    defaults.update(overrides)
    return AuthorizationScope.model_validate(defaults)


def _read_log(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_import_module_snippet_falls_back_to_default_install_path():
    snippet = atomic_red_team._import_module_snippet()
    # The official installer's default -InstallPath isn't on PSModulePath, so a
    # fresh PowerShell process needs an explicit fallback import from it.
    assert "Get-Module -ListAvailable -Name Invoke-AtomicRedTeam" in snippet
    assert "AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" in snippet


def test_execute_command_imports_module_before_running_test(monkeypatch, tmp_path):
    monkeypatch.setattr(atomic_red_team, "_find_powershell", lambda: "pwsh")
    monkeypatch.setattr(atomic_red_team, "_powershell_module_available", lambda exe: True)

    captured_command = {}

    def fake_run(cmd, **kwargs):
        captured_command["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(atomic_red_team.subprocess, "run", fake_run)

    run_technique(
        "T1082", "localhost", _scope(), execute=True, audit_log_path=tmp_path / "audit.log"
    )

    joined = " ".join(captured_command["cmd"])
    assert "Import-Module Invoke-AtomicRedTeam" in joined
    assert "Invoke-AtomicTest T1082" in joined


def test_dry_run_never_invokes_subprocess(monkeypatch, tmp_path):
    called = {"count": 0}
    monkeypatch.setattr(
        atomic_red_team.subprocess,
        "run",
        lambda *a, **k: called.__setitem__("count", called["count"] + 1),
    )

    log_path = tmp_path / "audit.log"
    result = run_technique("T1059", "localhost", _scope(), execute=False, audit_log_path=log_path)

    assert result.dry_run is True
    assert result.return_code is None
    assert called["count"] == 0

    entries = _read_log(log_path)
    assert entries[0]["allowed"] is True
    assert entries[0]["dry_run"] is True


def test_unauthorized_target_raises_and_logs(tmp_path):
    log_path = tmp_path / "audit.log"

    with pytest.raises(AuthorizationError):
        run_technique("T1059", "8.8.8.8", _scope(), execute=False, audit_log_path=log_path)

    entries = _read_log(log_path)
    assert entries[0]["allowed"] is False


def test_execute_against_non_localhost_raises_not_implemented(tmp_path):
    log_path = tmp_path / "audit.log"
    with pytest.raises(NotImplementedError):
        run_technique("T1059", "10.1.2.3", _scope(), execute=True, audit_log_path=log_path)


def test_execute_without_module_raises_clear_error(monkeypatch, tmp_path):
    monkeypatch.setattr(atomic_red_team, "_find_powershell", lambda: "pwsh")
    monkeypatch.setattr(atomic_red_team, "_powershell_module_available", lambda exe: False)

    log_path = tmp_path / "audit.log"
    with pytest.raises(AtomicRedTeamNotAvailableError):
        run_technique("T1059", "localhost", _scope(), execute=True, audit_log_path=log_path)

    entries = _read_log(log_path)
    assert entries[0]["allowed"] is True
    assert entries[0]["dry_run"] is False
    assert "not installed" in entries[0]["reason"]


def test_execute_success_runs_subprocess_and_logs(monkeypatch, tmp_path):
    monkeypatch.setattr(atomic_red_team, "_find_powershell", lambda: "pwsh")
    monkeypatch.setattr(atomic_red_team, "_powershell_module_available", lambda exe: True)

    captured_command = {}

    def fake_run(cmd, **kwargs):
        captured_command["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(atomic_red_team.subprocess, "run", fake_run)

    log_path = tmp_path / "audit.log"
    result = run_technique(
        "T1059",
        "localhost",
        _scope(),
        test_numbers=[1, 2],
        execute=True,
        cleanup=True,
        audit_log_path=log_path,
    )

    assert result.dry_run is False
    assert result.return_code == 0
    assert result.stdout == "ok"

    joined = " ".join(captured_command["cmd"])
    assert "Invoke-AtomicTest T1059" in joined
    assert "-TestNumbers 1,2" in joined
    assert "-Cleanup" in joined

    entries = _read_log(log_path)
    assert entries[0]["allowed"] is True
    assert entries[0]["dry_run"] is False
