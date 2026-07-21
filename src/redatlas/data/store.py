from __future__ import annotations

from pathlib import Path

from redatlas.data.atlas_loader import AtlasLoader
from redatlas.data.attack_loader import AttackLoader
from redatlas.data.schema import Domain, Framework, LoadedFramework, Mitigation, Tactic, Technique


class DataStore:
    """Unified, in-memory query interface over ATT&CK + ATLAS data.

    This is the single composition point downstream code (CLI, threat-modeling
    retrieval, chat advisor tools, and any future coverage dashboard) should
    depend on -- it never leaks STIX or ATLAS-YAML shapes past this boundary.
    """

    def __init__(
        self,
        tactics: list[Tactic],
        techniques: list[Technique],
        mitigations: list[Mitigation],
    ) -> None:
        self._tactics = tactics
        self._techniques = techniques
        self._mitigations = mitigations
        self._techniques_by_id = {t.id: t for t in techniques}
        self._mitigations_by_id = {m.id: m for m in mitigations}

    @classmethod
    def from_loaded_frameworks(cls, loaded: list[LoadedFramework]) -> DataStore:
        tactics: list[Tactic] = []
        techniques: list[Technique] = []
        mitigations: list[Mitigation] = []
        for lf in loaded:
            tactics.extend(lf.tactics)
            techniques.extend(lf.techniques)
            mitigations.extend(lf.mitigations)
        return cls(tactics, techniques, mitigations)

    @classmethod
    def load(
        cls,
        cache_dir: Path,
        *,
        refresh: bool = False,
        attack_domains: tuple[Domain, ...] = (Domain.ENTERPRISE,),
        include_atlas: bool = True,
    ) -> DataStore:
        loaded: list[LoadedFramework] = []
        if attack_domains:
            loaded.extend(AttackLoader(cache_dir, domains=attack_domains).load(refresh=refresh))
        if include_atlas:
            loaded.append(AtlasLoader(cache_dir).load(refresh=refresh))
        return cls.from_loaded_frameworks(loaded)

    def get_technique(self, technique_id: str) -> Technique | None:
        return self._techniques_by_id.get(technique_id)

    def get_mitigations_for(self, technique_id: str) -> list[Mitigation]:
        technique = self._techniques_by_id.get(technique_id)
        if not technique:
            return []
        return [
            self._mitigations_by_id[mid]
            for mid in technique.mitigation_ids
            if mid in self._mitigations_by_id
        ]

    def get_tactics(self, framework: Framework | None = None) -> list[Tactic]:
        if framework is None:
            return list(self._tactics)
        return [t for t in self._tactics if t.framework == framework]

    def all_techniques(
        self, *, framework: Framework | None = None, domain: Domain | None = None
    ) -> list[Technique]:
        result = self._techniques
        if framework is not None:
            result = [t for t in result if t.framework == framework]
        if domain is not None:
            result = [t for t in result if t.domain == domain]
        return list(result)

    def search(
        self,
        query: str,
        *,
        framework: Framework | None = None,
        domain: Domain | None = None,
        limit: int = 10,
    ) -> list[Technique]:
        tokens = [tok for tok in query.lower().split() if tok]
        if not tokens:
            return []

        scored: list[tuple[int, Technique]] = []
        for technique in self.all_techniques(framework=framework, domain=domain):
            haystack = f"{technique.id} {technique.name} {technique.description}".lower()
            score = sum(haystack.count(tok) for tok in tokens)
            if score > 0:
                scored.append((score, technique))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [technique for _, technique in scored[:limit]]
