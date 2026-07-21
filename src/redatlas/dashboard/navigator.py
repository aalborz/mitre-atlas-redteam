from __future__ import annotations

import json
from pathlib import Path

from redatlas.dashboard.coverage import CoverageReport
from redatlas.data.schema import Domain

# ATT&CK Navigator layer format v4.5 (github.com/mitre-attack/attack-navigator,
# layers/spec/v4.5/layerformat.md). Only "name" and "domain" are strictly
# required; everything else here is optional but conventional.
#
# ATLAS techniques (AML.*) aren't renderable by the official ATT&CK Navigator --
# MITRE ATLAS publishes its own Navigator fork (atlas-navigator) that consumes
# the same layer schema with domain "mitre-atlas".
_DOMAIN_TO_NAVIGATOR: dict[Domain, str] = {
    Domain.ENTERPRISE: "enterprise-attack",
    Domain.ICS: "ics-attack",
    Domain.MOBILE: "mobile-attack",
    Domain.ATLAS: "mitre-atlas",
}

COVERED_COLOR = "#66ff66"
GAP_COLOR = "#ff6666"


def build_layer(
    report: CoverageReport, *, domain: Domain, name: str, description: str = ""
) -> dict:
    return {
        "name": name,
        "versions": {"navigator": "4.9.0", "layer": "4.5"},
        "domain": _DOMAIN_TO_NAVIGATOR[domain],
        "description": description,
        "techniques": [
            {
                "techniqueID": t.id,
                "score": 1 if t.covered else 0,
                "color": COVERED_COLOR if t.covered else GAP_COLOR,
                "comment": "Covered" if t.covered else "Gap",
                "enabled": True,
            }
            for t in report.techniques
        ],
        "gradient": {"colors": [GAP_COLOR, COVERED_COLOR], "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "Covered", "color": COVERED_COLOR},
            {"label": "Gap", "color": GAP_COLOR},
        ],
    }


def write_layer(
    report: CoverageReport, *, domain: Domain, name: str, description: str, path: Path
) -> None:
    layer = build_layer(report, domain=domain, name=name, description=description)
    path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
