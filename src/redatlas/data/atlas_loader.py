from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import yaml

from redatlas.data.cache import DataSourceError, download_text
from redatlas.data.schema import Domain, Framework, LoadedFramework, Mitigation, Tactic, Technique

ATLAS_ENTRY_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml"
)

# GitHub serves a git symlink's raw content as the literal target path string
# (e.g. "v6/ATLAS-latest.yaml"), not the file it points to -- and that target
# can itself be another symlink. Detect "this looks like a bare relative
# filename, not YAML content" and keep following the chain.
_SYMLINK_POINTER_RE = re.compile(r"^[\w.\-/]+\.ya?ml$")


def resolve_symlink_chain(url: str, *, max_hops: int = 5) -> str:
    current_url = url
    for _ in range(max_hops):
        body = download_text(current_url)
        stripped = body.strip()
        looks_like_pointer = (
            "\n" not in stripped
            and ":" not in stripped
            and len(stripped) < 200
            and bool(_SYMLINK_POINTER_RE.match(stripped))
        )
        if not looks_like_pointer:
            return body
        current_url = urljoin(current_url, stripped)
    raise DataSourceError(f"Too many symlink hops resolving ATLAS data source starting at {url}")


def _rel_ids(rel_entry: dict[str, Any] | None, relationship_type: str) -> list[str]:
    if not rel_entry:
        return []
    return [r["target"] for r in rel_entry.get(relationship_type, []) if r.get("target")]


class AtlasLoader:
    """Loads MITRE ATLAS data (YAML, resolved through GitHub's symlink chain)
    and normalizes it into the shared redatlas.data.schema types."""

    def __init__(self, cache_dir: Path, entry_url: str = ATLAS_ENTRY_URL) -> None:
        self.cache_dir = cache_dir
        self.entry_url = entry_url

    def load(self, *, refresh: bool = False) -> LoadedFramework:
        cache_path = self.cache_dir / "atlas-latest.yaml"

        if cache_path.exists() and not refresh:
            text = cache_path.read_text(encoding="utf-8")
        else:
            text = resolve_symlink_chain(self.entry_url)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(text, encoding="utf-8")

        data = yaml.safe_load(text)
        return self._normalize(data)

    @staticmethod
    def _normalize(data: dict[str, Any]) -> LoadedFramework:
        relationships: dict[str, dict[str, list[dict[str, Any]]]] = data.get("relationships", {})

        tactics: list[Tactic] = []
        for tid, obj in data.get("tactics", {}).items():
            url = obj.get("ATT&CK-reference") or obj.get("attack-reference")
            tactics.append(
                Tactic(
                    id=tid,
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    framework=Framework.ATLAS,
                    domain=Domain.ATLAS,
                    external_url=url.get("url") if isinstance(url, dict) else None,
                )
            )

        techniques: list[Technique] = []
        for tid, obj in data.get("techniques", {}).items():
            rel = relationships.get(tid)
            tactic_ids = tuple(_rel_ids(rel, "achieves"))
            specializes = _rel_ids(rel, "specializes")
            parent_id = specializes[0] if specializes else None
            url = obj.get("ATT&CK-reference") or obj.get("attack-reference")
            techniques.append(
                Technique(
                    id=tid,
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    framework=Framework.ATLAS,
                    domain=Domain.ATLAS,
                    tactic_ids=tactic_ids,
                    platforms=tuple(obj.get("platforms", [])),
                    is_subtechnique=parent_id is not None,
                    parent_id=parent_id,
                    external_url=url.get("url") if isinstance(url, dict) else None,
                )
            )

        mitigations: list[Mitigation] = []
        technique_ids_by_mitigation: dict[str, list[str]] = {}
        for mid, obj in data.get("mitigations", {}).items():
            rel = relationships.get(mid)
            tids = _rel_ids(rel, "mitigates")
            technique_ids_by_mitigation[mid] = tids
            mitigations.append(
                Mitigation(
                    id=mid,
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    framework=Framework.ATLAS,
                    domain=Domain.ATLAS,
                    technique_ids=tuple(tids),
                )
            )

        mitigations_by_technique: dict[str, list[str]] = defaultdict(list)
        for mid, tids in technique_ids_by_mitigation.items():
            for tid in tids:
                mitigations_by_technique[tid].append(mid)

        techniques = [
            replace(t, mitigation_ids=tuple(mitigations_by_technique.get(t.id, ())))
            for t in techniques
        ]

        return LoadedFramework(
            framework=Framework.ATLAS,
            domain=Domain.ATLAS,
            tactics=tactics,
            techniques=techniques,
            mitigations=mitigations,
        )
