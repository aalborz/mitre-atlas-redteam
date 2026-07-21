from typer.testing import CliRunner

from redatlas import cli

runner = CliRunner()


def test_data_search_uses_injected_store(monkeypatch, sample_store):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)

    result = runner.invoke(cli.app, ["data", "search", "phishing"])

    assert result.exit_code == 0
    assert "T1566" in result.stdout


def test_data_search_no_matches(monkeypatch, sample_store):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)

    result = runner.invoke(cli.app, ["data", "search", "zzz_no_such_token"])

    assert result.exit_code == 0
    assert "No matches found" in result.stdout


def test_data_show_known_technique(monkeypatch, sample_store):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)

    result = runner.invoke(cli.app, ["data", "show", "T1566"])

    assert result.exit_code == 0
    assert "Phishing" in result.stdout
    assert "M1017" in result.stdout


def test_data_show_unknown_technique(monkeypatch, sample_store):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)

    result = runner.invoke(cli.app, ["data", "show", "T9999"])

    assert result.exit_code == 1
    assert "Unknown technique id" in result.stdout


def test_data_fetch_reports_counts(monkeypatch, sample_store):
    monkeypatch.setattr(cli, "_load_store", lambda **kwargs: sample_store)

    result = runner.invoke(cli.app, ["data", "fetch"])

    assert result.exit_code == 0
    assert "Loaded" in result.stdout
