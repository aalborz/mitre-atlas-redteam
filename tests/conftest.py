from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def sample_store():
    from redatlas.data.schema import Domain, Framework, Mitigation, Tactic, Technique
    from redatlas.data.store import DataStore

    tactics = [
        Tactic(
            id="TA0001",
            name="Initial Access",
            description="Getting in.",
            framework=Framework.ATTACK,
            domain=Domain.ENTERPRISE,
        ),
    ]
    mitigations = [
        Mitigation(
            id="M1017",
            name="User Training",
            description="Train users against phishing.",
            framework=Framework.ATTACK,
            domain=Domain.ENTERPRISE,
            technique_ids=("T1566",),
        ),
    ]
    techniques = [
        Technique(
            id="T1566",
            name="Phishing",
            description="Adversaries may send phishing messages to gain access.",
            framework=Framework.ATTACK,
            domain=Domain.ENTERPRISE,
            tactic_ids=("TA0001",),
            mitigation_ids=("M1017",),
        ),
        Technique(
            id="AML.T0043",
            name="Craft Adversarial Data",
            description="Adversaries may craft adversarial prompts to manipulate an LLM.",
            framework=Framework.ATLAS,
            domain=Domain.ATLAS,
        ),
    ]
    return DataStore(tactics, techniques, mitigations)
