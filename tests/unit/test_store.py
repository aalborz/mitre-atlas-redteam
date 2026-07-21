from redatlas.data.schema import Framework


def test_get_technique(sample_store):
    assert sample_store.get_technique("T1566").name == "Phishing"
    assert sample_store.get_technique("does-not-exist") is None


def test_get_mitigations_for(sample_store):
    mitigations = sample_store.get_mitigations_for("T1566")
    assert [m.id for m in mitigations] == ["M1017"]
    assert sample_store.get_mitigations_for("AML.T0043") == []


def test_all_techniques_filters_by_framework(sample_store):
    attack_only = sample_store.all_techniques(framework=Framework.ATTACK)
    atlas_only = sample_store.all_techniques(framework=Framework.ATLAS)
    assert [t.id for t in attack_only] == ["T1566"]
    assert [t.id for t in atlas_only] == ["AML.T0043"]


def test_search_cross_framework(sample_store):
    results = sample_store.search("phishing")
    assert [t.id for t in results] == ["T1566"]

    results = sample_store.search("adversarial prompts")
    assert "AML.T0043" in [t.id for t in results]


def test_search_respects_limit(sample_store):
    results = sample_store.search("adversaries", limit=1)
    assert len(results) == 1
