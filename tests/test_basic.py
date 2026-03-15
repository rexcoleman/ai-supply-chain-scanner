"""Basic tests for FP-10 AI supply chain scanner."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_risk_categories():
    from src.core.risk_categories import RISK_CATEGORIES, Severity
    assert len(RISK_CATEGORIES) == 7
    assert "serialization_risk" in RISK_CATEGORIES
    assert RISK_CATEGORIES["serialization_risk"]["default_severity"] == Severity.CRITICAL


def test_dependency_scanner_on_empty(tmp_path):
    from src.scanners.dependency_scanner import scan_project
    result = scan_project(str(tmp_path))
    assert result.packages_scanned == 0


def test_dependency_scanner_finds_pickle(tmp_path):
    from src.scanners.dependency_scanner import scan_project
    (tmp_path / "model.py").write_text("import pickle\nmodel = pickle.load(open('model.pkl', 'rb'))")
    result = scan_project(str(tmp_path))
    assert any(f.category == "serialization_risk" for f in result.findings)


def test_dependency_scanner_finds_cve(tmp_path):
    from src.scanners.dependency_scanner import scan_project
    (tmp_path / "requirements.txt").write_text("langchain>=0.3.0\ntorch>=2.0")
    result = scan_project(str(tmp_path))
    assert any(f.cve_id is not None for f in result.findings)


def test_model_scanner_offline():
    from src.scanners.model_scanner import scan_model, check_provenance
    # Test with synthetic model info
    fake_info = {"cardData": {}, "siblings": [{"rfilename": "model.pkl"}], "author": "unknown"}
    findings = check_provenance("test/model", fake_info)
    assert len(findings) > 0  # Should find missing provenance


def test_findings_exists():
    assert Path("FINDINGS.md").exists()
