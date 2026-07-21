from datetime import UTC, datetime

from typer.testing import CliRunner

from redatlas import cli
from redatlas.exec import atomic_red_team, authorization
from redatlas.exec.atomic_red_team import ExecutionResult
from redatlas.exec.authorization import AuthorizationError, AuthorizationScope

runner = CliRunner()


def _scope() -> AuthorizationScope:
    return AuthorizationScope.model_validate(
        {
            "engagement_name": "Test Engagement",
            "authorized_by": "Test Authorizer",
            "starts_at": datetime(2020, 1, 1, tzinfo=UTC),
            "ends_at": datetime(2035, 1, 1, tzinfo=UTC),
            "allowed_targets": ["localhost"],
        }
    )


def test_exec_run_dry_run(monkeypatch):
    monkeypatch.setattr(authorization, "load_authorization", lambda path: _scope())
    monkeypatch.setattr(
        atomic_red_team,
        "run_technique",
        lambda *a, **k: ExecutionResult(
            technique_id="T1059",
            target="localhost",
            dry_run=True,
            return_code=None,
            stdout="",
            stderr="",
        ),
    )

    result = runner.invoke(cli.app, ["exec", "run", "T1059"])

    assert result.exit_code == 0
    assert "Dry run" in result.stdout


def test_exec_run_missing_authorization_file(monkeypatch):
    def raise_auth_error(path):
        raise AuthorizationError(f"No authorization file found at {path}.")

    monkeypatch.setattr(authorization, "load_authorization", raise_auth_error)

    result = runner.invoke(cli.app, ["exec", "run", "T1059"])

    assert result.exit_code == 1
    assert "No authorization file found" in result.stdout


def test_exec_run_execute_success(monkeypatch):
    monkeypatch.setattr(authorization, "load_authorization", lambda path: _scope())
    monkeypatch.setattr(
        atomic_red_team,
        "run_technique",
        lambda *a, **k: ExecutionResult(
            technique_id="T1059",
            target="localhost",
            dry_run=False,
            return_code=0,
            stdout="done",
            stderr="",
        ),
    )

    result = runner.invoke(cli.app, ["exec", "run", "T1059", "--execute"])

    assert result.exit_code == 0
    assert "Executed" in result.stdout
    assert "done" in result.stdout
