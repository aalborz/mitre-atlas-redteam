from redatlas.dashboard.coverage import compute_coverage, load_coverage
from redatlas.data.schema import Domain, Framework


def test_load_coverage(fixtures_dir):
    coverage_input = load_coverage(fixtures_dir / "covered_techniques.yaml")
    assert coverage_input.covered == ["T1566"]


def test_compute_coverage_marks_covered_and_gap(sample_store):
    report = compute_coverage(sample_store, {"T1566"}, framework=Framework.ATTACK)

    assert report.total == 1
    assert report.covered_count == 1
    assert report.gap_count == 0
    assert report.coverage_ratio == 1.0
    assert report.techniques[0].covered is True


def test_compute_coverage_reports_gaps(sample_store):
    report = compute_coverage(sample_store, set(), framework=Framework.ATLAS, domain=Domain.ATLAS)

    assert report.total == 1
    assert report.covered_count == 0
    assert report.gap_count == 1
    assert report.coverage_ratio == 0.0
    gaps = report.gaps()
    assert len(gaps) == 1
    assert gaps[0].id == "AML.T0043"


def test_compute_coverage_empty_corpus_ratio_is_zero(sample_store):
    report = compute_coverage(sample_store, set(), framework=Framework.ATTACK, domain=Domain.MOBILE)
    assert report.total == 0
    assert report.coverage_ratio == 0.0
