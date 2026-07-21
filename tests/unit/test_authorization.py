from datetime import UTC, datetime

import pytest

from redatlas.exec.authorization import (
    AuthorizationError,
    AuthorizationScope,
    check_authorized,
    load_authorization,
)


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


def test_load_authorization_from_fixture(fixtures_dir):
    scope = load_authorization(fixtures_dir / "authorization_sample.yaml")
    assert scope.engagement_name == "Test Engagement"
    assert "localhost" in scope.allowed_targets


def test_load_authorization_missing_file(tmp_path):
    with pytest.raises(AuthorizationError, match="No authorization file found"):
        load_authorization(tmp_path / "does-not-exist.yaml")


def test_load_authorization_invalid_schema(tmp_path):
    bad_file = tmp_path / "authorization.yaml"
    bad_file.write_text("engagement_name: only-this-field\n", encoding="utf-8")
    with pytest.raises(AuthorizationError, match="Invalid authorization file"):
        load_authorization(bad_file)


def test_naive_datetimes_assumed_utc():
    scope = _scope(starts_at=datetime(2020, 1, 1), ends_at=datetime(2035, 1, 1))
    assert scope.starts_at.tzinfo is not None


def test_check_authorized_passes_for_allowed_target_in_window():
    scope = _scope()
    check_authorized(scope, "localhost", now=datetime(2026, 1, 1, tzinfo=UTC))


def test_check_authorized_matches_cidr_range():
    scope = _scope()
    check_authorized(scope, "10.1.2.3", now=datetime(2026, 1, 1, tzinfo=UTC))


def test_check_authorized_rejects_target_outside_allow_list():
    scope = _scope()
    with pytest.raises(AuthorizationError, match="not on the allow-list"):
        check_authorized(scope, "8.8.8.8", now=datetime(2026, 1, 1, tzinfo=UTC))


def test_check_authorized_rejects_before_window():
    scope = _scope()
    with pytest.raises(AuthorizationError, match="outside that window"):
        check_authorized(scope, "localhost", now=datetime(2010, 1, 1, tzinfo=UTC))


def test_check_authorized_rejects_after_window():
    scope = _scope()
    with pytest.raises(AuthorizationError, match="outside that window"):
        check_authorized(scope, "localhost", now=datetime(2040, 1, 1, tzinfo=UTC))
