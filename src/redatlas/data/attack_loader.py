from __future__ import annotations

from pathlib import Path
from typing import Any

from redatlas.data.cache import download_with_cache
from redatlas.data.schema import Domain, Framework, LoadedFramework, Mitigation, Tactic, Technique

DEFAULT_ATTACK_URLS: dict[Domain, str] = {
    Domain.ENTERPRISE: "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    Domain.ICS: "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    Domain.MOBILE: "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
}


def _external_url(stix_obj: dict[str, Any]) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return None


class AttackLoader:
    """Loads MITRE ATT&CK STIX bundles (via mitreattack-python) and normalizes
    them into the shared redatlas.data.schema types."""

    def __init__(
        self,
        cache_dir: Path,
        domains: tuple[Domain, ...] = (Domain.ENTERPRISE,),
        urls: dict[Domain, str] | None = None,
    ) -> None:
        self.cache_dir = cache_dir
        self.domains = domains
        self.urls = urls or DEFAULT_ATTACK_URLS

    def load(self, *, refresh: bool = False) -> list[LoadedFramework]:
        return [self._load_domain(domain, refresh=refresh) for domain in self.domains]

    def _load_domain(self, domain: Domain, *, refresh: bool) -> LoadedFramework:
        # Imported lazily so `redatlas data` commands that don't touch ATT&CK
        # (or environments without the dependency installed yet) stay cheap to import.
        from mitreattack.stix20 import MitreAttackData

        url = self.urls[domain]
        cache_path = self.cache_dir / f"{domain.value}-attack.json"
        download_with_cache(url, cache_path, refresh=refresh)

        mad = MitreAttackData(str(cache_path))

        tactics: list[Tactic] = []
        tactic_ids_seen: set[str] = set()
        techniques: list[Technique] = []
        mitigations: list[Mitigation] = []
        mitigation_ids_seen: set[str] = set()

        stix_techniques = mad.get_techniques(include_subtechniques=True)

        for stix_tech in stix_techniques:
            if stix_tech.get("revoked") or stix_tech.get("x_mitre_deprecated"):
                continue

            stix_id = stix_tech["id"]
            attack_id = mad.get_attack_id(stix_id)
            if not attack_id:
                continue

            tactic_ids: list[str] = []
            for stix_tactic in mad.get_tactics_by_technique(stix_id) or []:
                tactic_attack_id = mad.get_attack_id(stix_tactic["id"])
                if not tactic_attack_id:
                    continue
                tactic_ids.append(tactic_attack_id)
                if tactic_attack_id not in tactic_ids_seen:
                    tactic_ids_seen.add(tactic_attack_id)
                    tactics.append(
                        Tactic(
                            id=tactic_attack_id,
                            name=stix_tactic.get("name", ""),
                            description=stix_tactic.get("description", ""),
                            framework=Framework.ATTACK,
                            domain=domain,
                            external_url=_external_url(stix_tactic),
                        )
                    )

            mitigation_ids: list[str] = []
            for entry in mad.get_mitigations_mitigating_technique(stix_id) or []:
                stix_mitigation = entry.get("object") if isinstance(entry, dict) else entry
                if not stix_mitigation:
                    continue
                mitigation_attack_id = mad.get_attack_id(stix_mitigation["id"])
                if not mitigation_attack_id:
                    continue
                mitigation_ids.append(mitigation_attack_id)
                if mitigation_attack_id not in mitigation_ids_seen:
                    mitigation_ids_seen.add(mitigation_attack_id)
                    mitigations.append(
                        Mitigation(
                            id=mitigation_attack_id,
                            name=stix_mitigation.get("name", ""),
                            description=stix_mitigation.get("description", ""),
                            framework=Framework.ATTACK,
                            domain=domain,
                        )
                    )

            is_subtechnique = bool(stix_tech.get("x_mitre_is_subtechnique", False))
            parent_id: str | None = None
            if is_subtechnique:
                parent = mad.get_parent_technique_of_subtechnique(stix_id)
                if parent:
                    parent_obj = (
                        parent[0].get("object")
                        if isinstance(parent, list)
                        else parent.get("object")
                    )
                    if parent_obj:
                        parent_id = mad.get_attack_id(parent_obj["id"])

            techniques.append(
                Technique(
                    id=attack_id,
                    name=stix_tech.get("name", ""),
                    description=stix_tech.get("description", ""),
                    framework=Framework.ATTACK,
                    domain=domain,
                    tactic_ids=tuple(tactic_ids),
                    platforms=tuple(stix_tech.get("x_mitre_platforms", [])),
                    is_subtechnique=is_subtechnique,
                    parent_id=parent_id,
                    mitigation_ids=tuple(mitigation_ids),
                    external_url=_external_url(stix_tech),
                )
            )

        # Backfill technique_ids on mitigations (schema keeps both directions).
        technique_ids_by_mitigation: dict[str, list[str]] = {}
        for tech in techniques:
            for mid in tech.mitigation_ids:
                technique_ids_by_mitigation.setdefault(mid, []).append(tech.id)
        mitigations = [
            Mitigation(
                id=m.id,
                name=m.name,
                description=m.description,
                framework=m.framework,
                domain=m.domain,
                technique_ids=tuple(technique_ids_by_mitigation.get(m.id, ())),
            )
            for m in mitigations
        ]

        return LoadedFramework(
            framework=Framework.ATTACK,
            domain=domain,
            tactics=tactics,
            techniques=techniques,
            mitigations=mitigations,
        )
