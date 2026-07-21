import respx
from httpx import Response

from redatlas.data.atlas_loader import ATLAS_ENTRY_URL, AtlasLoader, resolve_symlink_chain
from redatlas.data.schema import Domain, Framework

HOP1_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-latest.yaml"
HOP2_URL = (
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-2026.06.yaml"
)


def _mock_symlink_chain(fixture_text: str):
    respx.get(ATLAS_ENTRY_URL).mock(return_value=Response(200, text="v6/ATLAS-latest.yaml"))
    respx.get(HOP1_URL).mock(return_value=Response(200, text="ATLAS-2026.06.yaml"))
    respx.get(HOP2_URL).mock(return_value=Response(200, text=fixture_text))


@respx.mock
def test_resolve_symlink_chain_follows_two_hops(fixtures_dir):
    fixture_text = (fixtures_dir / "atlas_sample.yaml").read_text(encoding="utf-8")
    _mock_symlink_chain(fixture_text)

    resolved = resolve_symlink_chain(ATLAS_ENTRY_URL)

    assert resolved == fixture_text
    assert respx.calls.call_count == 3


@respx.mock
def test_atlas_loader_load_normalizes_data(tmp_path, fixtures_dir):
    fixture_text = (fixtures_dir / "atlas_sample.yaml").read_text(encoding="utf-8")
    _mock_symlink_chain(fixture_text)

    loader = AtlasLoader(tmp_path)
    loaded = loader.load()

    assert loaded.framework == Framework.ATLAS
    assert loaded.domain == Domain.ATLAS

    techniques_by_id = {t.id: t for t in loaded.techniques}
    assert "AML.T0000" in techniques_by_id
    assert "AML.T0002" in techniques_by_id
    assert "AML.T0002.000" in techniques_by_id

    recon = techniques_by_id["AML.T0000"]
    assert recon.tactic_ids == ("AML.TA0000",)
    assert recon.mitigation_ids == ("AML.M0000",)

    subtechnique = techniques_by_id["AML.T0002.000"]
    assert subtechnique.is_subtechnique is True
    assert subtechnique.parent_id == "AML.T0002"
    assert subtechnique.tactic_ids == ("AML.TA0002",)

    mitigations_by_id = {m.id: m for m in loaded.mitigations}
    assert mitigations_by_id["AML.M0000"].technique_ids == ("AML.T0000",)

    tactic_ids = {t.id for t in loaded.tactics}
    assert tactic_ids == {"AML.TA0000", "AML.TA0002"}


@respx.mock
def test_atlas_loader_uses_cache_on_second_call(tmp_path, fixtures_dir):
    fixture_text = (fixtures_dir / "atlas_sample.yaml").read_text(encoding="utf-8")
    _mock_symlink_chain(fixture_text)

    loader = AtlasLoader(tmp_path)
    loader.load()
    assert respx.calls.call_count == 3

    loader.load(refresh=False)
    assert respx.calls.call_count == 3
