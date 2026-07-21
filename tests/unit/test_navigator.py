import json

from redatlas.dashboard.coverage import compute_coverage
from redatlas.dashboard.navigator import build_layer, write_layer
from redatlas.data.schema import Domain, Framework


def test_build_layer_structure(sample_store):
    report = compute_coverage(sample_store, {"T1566"}, framework=Framework.ATTACK)
    layer = build_layer(report, domain=Domain.ENTERPRISE, name="Test Layer", description="desc")

    assert layer["name"] == "Test Layer"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"] == {"navigator": "4.9.0", "layer": "4.5"}
    assert layer["techniques"] == [
        {
            "techniqueID": "T1566",
            "score": 1,
            "color": "#66ff66",
            "comment": "Covered",
            "enabled": True,
        }
    ]


def test_build_layer_atlas_domain_mapping(sample_store):
    report = compute_coverage(sample_store, set(), framework=Framework.ATLAS, domain=Domain.ATLAS)
    layer = build_layer(report, domain=Domain.ATLAS, name="ATLAS Layer")
    assert layer["domain"] == "mitre-atlas"
    assert layer["techniques"][0]["score"] == 0
    assert layer["techniques"][0]["color"] == "#ff6666"


def test_write_layer_writes_valid_json(tmp_path, sample_store):
    report = compute_coverage(sample_store, {"T1566"}, framework=Framework.ATTACK)
    output = tmp_path / "layer.json"

    write_layer(report, domain=Domain.ENTERPRISE, name="Test", description="", path=output)

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["name"] == "Test"
    assert data["techniques"][0]["techniqueID"] == "T1566"
