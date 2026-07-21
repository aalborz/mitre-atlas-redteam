from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


def default_audit_log_path() -> Path:
    from redatlas.data.cache import get_cache_dir

    return get_cache_dir() / "exec-audit.log"


@dataclass
class AuditEntry:
    timestamp: str
    technique_id: str
    target: str
    engagement_name: str | None
    allowed: bool
    dry_run: bool
    reason: str


def log_attempt(
    *,
    technique_id: str,
    target: str,
    engagement_name: str | None,
    allowed: bool,
    dry_run: bool,
    reason: str,
    path: Path | None = None,
) -> AuditEntry:
    """Appends one JSON-line audit entry. Called for every execution attempt,
    allowed or refused -- this is the audit trail, not just a success log."""
    entry = AuditEntry(
        timestamp=datetime.now(UTC).isoformat(),
        technique_id=technique_id,
        target=target,
        engagement_name=engagement_name,
        allowed=allowed,
        dry_run=dry_run,
        reason=reason,
    )

    log_path = path or default_audit_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(entry)) + "\n")

    return entry
