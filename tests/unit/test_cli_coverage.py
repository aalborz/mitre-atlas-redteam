import json

from typer.testing import CliRunner

from redatlas import cli

runner = CliRunner()


def test_coverage_report_writes_layer(monkeypatch, sample_store, tmp_path, fixtures_dir):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)
    output = tmp_path / "layer.json"

    result = runner.invoke(
        cli.app,
        [
            "coverage",
            "report",
            str(fixtures_dir / "covered_techniques.yaml"),
            "--domain",
            "enterprise",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert "Wrote" in result.stdout
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["techniques"][0]["techniqueID"] == "T1566"


def test_coverage_report_missing_file(monkeypatch, sample_store, tmp_path):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)

    result = runner.invoke(cli.app, ["coverage", "report", str(tmp_path / "nope.yaml")])

    assert result.exit_code == 1
    assert "File not found" in result.stdout


def test_coverage_report_unknown_domain(monkeypatch, sample_store, fixtures_dir):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)

    result = runner.invoke(
        cli.app,
        [
            "coverage",
            "report",
            str(fixtures_dir / "covered_techniques.yaml"),
            "--domain",
            "not-a-domain",
        ],
    )

    assert result.exit_code == 1
    assert "Unknown domain" in result.stdout
