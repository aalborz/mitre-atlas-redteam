from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from redatlas.data.schema import Domain, Framework
from redatlas.data.store import DataStore


class CoverageInput(BaseModel):
    covered: list[str] = Field(default_factory=list)


def load_coverage(path: Path) -> CoverageInput:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return CoverageInput.model_validate(raw)


@dataclass
class TechniqueCoverage:
    id: str
    name: str
    framework: str
    covered: bool


@dataclass
class CoverageReport:
    total: int
    covered_count: int
    gap_count: int
    techniques: list[TechniqueCoverage] = field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        return self.covered_count / self.total if self.total else 0.0

    def gaps(self) -> list[TechniqueCoverage]:
        return [t for t in self.techniques if not t.covered]


def compute_coverage(
    store: DataStore,
    covered_ids: set[str],
    *,
    framework: Framework | None = None,
    domain: Domain | None = None,
) -> CoverageReport:
    techniques = store.all_techniques(framework=framework, domain=domain)
    entries = [
        TechniqueCoverage(
            id=t.id, name=t.name, framework=t.framework.value, covered=t.id in covered_ids
        )
        for t in techniques
    ]
    covered_count = sum(1 for e in entries if e.covered)
    return CoverageReport(
        total=len(entries),
        covered_count=covered_count,
        gap_count=len(entries) - covered_count,
        techniques=entries,
    )
