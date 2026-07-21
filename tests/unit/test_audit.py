import json

from redatlas.exec.audit import log_attempt


def test_log_attempt_writes_json_line(tmp_path):
    log_path = tmp_path / "audit.log"

    entry = log_attempt(
        technique_id="T1059",
        target="localhost",
        engagement_name="Test Engagement",
        allowed=True,
        dry_run=True,
        reason="Dry run only.",
        path=log_path,
    )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["technique_id"] == "T1059"
    assert data["allowed"] is True
    assert entry.technique_id == "T1059"


def test_log_attempt_appends_multiple_entries(tmp_path):
    log_path = tmp_path / "audit.log"

    log_attempt(
        technique_id="T1059",
        target="localhost",
        engagement_name="E",
        allowed=True,
        dry_run=True,
        reason="first",
        path=log_path,
    )
    log_attempt(
        technique_id="T1566",
        target="localhost",
        engagement_name="E",
        allowed=False,
        dry_run=True,
        reason="second",
        path=log_path,
    )

    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["technique_id"] == "T1059"
    assert json.loads(lines[1])["technique_id"] == "T1566"
    assert json.loads(lines[1])["allowed"] is False


def test_log_attempt_creates_parent_directory(tmp_path):
    log_path = tmp_path / "nested" / "dir" / "audit.log"
    log_attempt(
        technique_id="T1059",
        target="localhost",
        engagement_name=None,
        allowed=True,
        dry_run=True,
        reason="x",
        path=log_path,
    )
    assert log_path.exists()
