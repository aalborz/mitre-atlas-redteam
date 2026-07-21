from redatlas.data.schema import Domain, Framework, Technique
from redatlas.modeling.inputs import SystemModel
from redatlas.modeling.retrieval import retrieve_relevant


def test_retrieve_relevant_ranks_keyword_match_higher():
    corpus = [
        Technique(
            id="T1566",
            name="Phishing",
            description="Adversaries send phishing emails to steal credentials.",
            framework=Framework.ATTACK,
            domain=Domain.ENTERPRISE,
        ),
        Technique(
            id="T1499",
            name="Endpoint Denial of Service",
            description="Adversaries may perform denial of service attacks to degrade access.",
            framework=Framework.ATTACK,
            domain=Domain.ENTERPRISE,
        ),
    ]
    system = SystemModel(
        name="Webmail",
        description="A webmail system at risk of phishing emails targeting employee credentials.",
    )

    results = retrieve_relevant(system, corpus, top_k=5)

    assert results
    assert results[0].id == "T1566"


def test_retrieve_relevant_respects_top_k():
    corpus = [
        Technique(
            id=f"T{i}",
            name=f"Technique {i}",
            description="phishing credential theft social engineering",
            framework=Framework.ATTACK,
            domain=Domain.ENTERPRISE,
        )
        for i in range(5)
    ]
    system = SystemModel(name="X", description="phishing credential theft social engineering")

    results = retrieve_relevant(system, corpus, top_k=2)
    assert len(results) == 2


def test_retrieve_relevant_empty_corpus():
    system = SystemModel(name="X", description="anything")
    assert retrieve_relevant(system, [], top_k=5) == []
