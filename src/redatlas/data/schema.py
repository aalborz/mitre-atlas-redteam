from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Framework(StrEnum):
    ATTACK = "attack"
    ATLAS = "atlas"


class Domain(StrEnum):
    ENTERPRISE = "enterprise"
    ICS = "ics"
    MOBILE = "mobile"
    ATLAS = "atlas"


@dataclass(frozen=True)
class Tactic:
    id: str
    name: str
    description: str
    framework: Framework
    domain: Domain
    external_url: str | None = None


@dataclass(frozen=True)
class Mitigation:
    id: str
    name: str
    description: str
    framework: Framework
    domain: Domain
    technique_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    description: str
    framework: Framework
    domain: Domain
    tactic_ids: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    is_subtechnique: bool = False
    parent_id: str | None = None
    mitigation_ids: tuple[str, ...] = ()
    external_url: str | None = None
    # Reserved for future use (e.g. coverage-dashboard status tags). Unused in the MVP.
    tags: tuple[str, ...] = ()


@dataclass
class LoadedFramework:
    framework: Framework
    domain: Domain
    tactics: list[Tactic]
    techniques: list[Technique]
    mitigations: list[Mitigation]
