from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator


class AuthorizationError(RuntimeError):
    """Raised whenever execution is refused for any authorization reason:
    missing/malformed file, expired/not-yet-started time window, or a target
    that isn't on the engagement's allow-list."""


class AuthorizationScope(BaseModel):
    engagement_name: str
    authorized_by: str
    starts_at: datetime
    ends_at: datetime
    allowed_targets: list[str] = Field(default_factory=list)

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _ensure_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def load_authorization(path: Path) -> AuthorizationScope:
    if not path.exists():
        raise AuthorizationError(
            f"No authorization file found at {path}. Execution is refused without an "
            "explicit, human-authored authorization file naming the engagement, its time "
            "window, and an allow-listed set of targets. See authorization.example.yaml."
        )

    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    try:
        return AuthorizationScope.model_validate(raw)
    except ValidationError as exc:
        raise AuthorizationError(f"Invalid authorization file {path}:\n{exc}") from exc


def _target_matches(target: str, allowed: str) -> bool:
    try:
        return ip_address(target) in ip_network(allowed, strict=False)
    except ValueError:
        pass
    return target.strip().lower() == allowed.strip().lower()


def check_authorized(
    scope: AuthorizationScope, target: str, *, now: datetime | None = None
) -> None:
    """Raises AuthorizationError if execution against `target` is not currently authorized."""
    now = now or datetime.now(UTC)

    if now < scope.starts_at or now > scope.ends_at:
        raise AuthorizationError(
            f"Authorization window for engagement {scope.engagement_name!r} is "
            f"{scope.starts_at.isoformat()} to {scope.ends_at.isoformat()}; "
            f"current time {now.isoformat()} is outside that window."
        )

    if not any(_target_matches(target, allowed) for allowed in scope.allowed_targets):
        raise AuthorizationError(
            f"Target {target!r} is not on the allow-list for engagement "
            f"{scope.engagement_name!r}: {scope.allowed_targets}"
        )
