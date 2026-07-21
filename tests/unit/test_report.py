from redatlas.modeling.report import AttackPath, TechniqueFinding, ThreatModelReport


def _sample_report() -> ThreatModelReport:
    return ThreatModelReport(
        system_name="Test System",
        summary="A brief summary.",
        attack_paths=[AttackPath(description="Phish then pivot", technique_ids=["T1566", "T1078"])],
        applicable_techniques=[
            TechniqueFinding(
                id="T1566", name="Phishing", framework="attack", rationale="Internet-facing email."
            )
        ],
        mitigations=["Enable MFA"],
        detections=["Alert on suspicious email attachments"],
    )


def test_to_dict_round_trips_fields():
    report = _sample_report()
    data = report.to_dict()
    assert data["system_name"] == "Test System"
    assert data["attack_paths"][0]["technique_ids"] == ["T1566", "T1078"]
    assert data["applicable_techniques"][0]["id"] == "T1566"


def test_to_markdown_contains_key_sections():
    md = _sample_report().to_markdown()
    assert "# Threat Model: Test System" in md
    assert "## Likely Attack Paths" in md
    assert "T1566" in md
    assert "Enable MFA" in md
    assert "Alert on suspicious email attachments" in md


def test_to_markdown_handles_empty_sections():
    report = ThreatModelReport(system_name="Empty", summary="Nothing found.")
    md = report.to_markdown()
    assert "_None identified._" in md
