import respx
from httpx import Response

from redatlas.data.attack_loader import DEFAULT_ATTACK_URLS, AttackLoader
from redatlas.data.schema import Domain, Framework


@respx.mock
def test_load_enterprise_domain(tmp_path, fixtures_dir):
    fixture_text = (fixtures_dir / "attack_sample.json").read_text(encoding="utf-8")
    route = respx.get(DEFAULT_ATTACK_URLS[Domain.ENTERPRISE]).mock(
        return_value=Response(200, text=fixture_text)
    )

    loader = AttackLoader(tmp_path, domains=(Domain.ENTERPRISE,))
    [loaded] = loader.load()

    assert route.called
    assert loaded.framework == Framework.ATTACK
    assert loaded.domain == Domain.ENTERPRISE

    techniques_by_id = {t.id: t for t in loaded.techniques}
    assert "T1566" in techniques_by_id
    assert "T1566.001" in techniques_by_id
    assert "T1059" in techniques_by_id

    phishing = techniques_by_id["T1566"]
    assert phishing.name == "Phishing"
    assert phishing.tactic_ids == ("TA0001",)
    assert phishing.mitigation_ids == ("M1017",)
    assert phishing.is_subtechnique is False

    subtechnique = techniques_by_id["T1566.001"]
    assert subtechnique.is_subtechnique is True
    assert subtechnique.parent_id == "T1566"

    mitigations_by_id = {m.id: m for m in loaded.mitigations}
    assert "M1017" in mitigations_by_id
    assert mitigations_by_id["M1017"].technique_ids == ("T1566",)

    tactic_ids = {t.id for t in loaded.tactics}
    assert tactic_ids == {"TA0001", "TA0002"}


@respx.mock
def test_load_is_cached_on_second_call(tmp_path, fixtures_dir):
    fixture_text = (fixtures_dir / "attack_sample.json").read_text(encoding="utf-8")
    route = respx.get(DEFAULT_ATTACK_URLS[Domain.ENTERPRISE]).mock(
        return_value=Response(200, text=fixture_text)
    )

    loader = AttackLoader(tmp_path, domains=(Domain.ENTERPRISE,))
    loader.load()
    assert route.call_count == 1

    loader.load(refresh=False)
    assert route.call_count == 1

    loader.load(refresh=True)
    assert route.call_count == 2
