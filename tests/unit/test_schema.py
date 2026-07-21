import pytest

from redatlas.data.schema import Domain, Framework, Technique


def test_technique_is_frozen():
    t = Technique(
        id="T1566",
        name="Phishing",
        description="desc",
        framework=Framework.ATTACK,
        domain=Domain.ENTERPRISE,
    )
    with pytest.raises(AttributeError):
        t.name = "Something else"


def test_technique_defaults():
    t = Technique(
        id="T1566",
        name="Phishing",
        description="desc",
        framework=Framework.ATTACK,
        domain=Domain.ENTERPRISE,
    )
    assert t.tactic_ids == ()
    assert t.platforms == ()
    assert t.is_subtechnique is False
    assert t.parent_id is None
    assert t.mitigation_ids == ()
    assert t.tags == ()
