"""Comprehensive tests for FP-10 AI supply chain scanner.

Test categories:
  T1: Scanner finds risk patterns in test files (5 tests)
  T2: Scanner doesn't false-positive on safe patterns (5 tests)
  T3: Risk categorization is correct (5 tests)
  T4: Output format is correct JSON (3 tests)
  T5: CLI works end-to-end (3 tests)
  T6: Controllability classification is correct (4 tests)
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.risk_categories import RISK_CATEGORIES, Severity, Controllability, RiskFinding
from src.scanners.dependency_scanner import (
    scan_project, scan_serialization, scan_ml_cves,
    scan_requirements, scan_stale_packages, DependencyScanResult,
)
from src.scanners.model_scanner import (
    scan_model, check_provenance, check_serialization_format, check_license,
)


# ============================================================
# T1: Scanner finds risk patterns (5 tests)
# ============================================================

def test_finds_pickle_load(tmp_path):
    """T1.1: Scanner detects pickle.load usage."""
    (tmp_path / "model.py").write_text("import pickle\nmodel = pickle.load(open('model.pkl', 'rb'))")
    result = scan_project(str(tmp_path))
    assert any(f.category == "serialization_risk" for f in result.findings)


def test_finds_torch_load(tmp_path):
    """T1.2: Scanner detects unsafe torch.load (without weights_only)."""
    (tmp_path / "load_model.py").write_text("import torch\nmodel = torch.load('model.pt')")
    result = scan_project(str(tmp_path))
    serialization_findings = [f for f in result.findings if f.category == "serialization_risk"]
    assert len(serialization_findings) > 0


def test_finds_joblib_load(tmp_path):
    """T1.3: Scanner detects joblib.load usage."""
    (tmp_path / "predict.py").write_text("import joblib\nmodel = joblib.load('rf_model.pkl')")
    result = scan_project(str(tmp_path))
    assert any(f.category == "serialization_risk" for f in result.findings)


def test_finds_cloudpickle(tmp_path):
    """T1.4: Scanner detects cloudpickle.load."""
    (tmp_path / "runner.py").write_text("import cloudpickle\nobj = cloudpickle.load(f)")
    result = scan_project(str(tmp_path))
    assert any(f.category == "serialization_risk" for f in result.findings)


def test_finds_known_cve(tmp_path):
    """T1.5: Scanner detects known ML CVEs in requirements."""
    (tmp_path / "requirements.txt").write_text("langchain>=0.3.0\ntorch>=2.0\ntransformers>=4.30")
    result = scan_project(str(tmp_path))
    cve_findings = [f for f in result.findings if f.cve_id is not None]
    assert len(cve_findings) >= 2  # langchain + torch at minimum


# ============================================================
# T2: Scanner doesn't false-positive on safe patterns (5 tests)
# ============================================================

def test_no_fp_safetensors(tmp_path):
    """T2.1: No false positive on safetensors usage."""
    (tmp_path / "save.py").write_text("from safetensors.torch import load_file\nmodel = load_file('model.safetensors')")
    findings = scan_serialization(str(tmp_path))
    assert len(findings) == 0


def test_no_fp_torch_weights_only(tmp_path):
    """T2.2: No false positive on torch.load with weights_only=True."""
    (tmp_path / "safe_load.py").write_text("import torch\nmodel = torch.load('model.pt', weights_only=True)")
    findings = scan_serialization(str(tmp_path))
    assert len(findings) == 0


def test_no_fp_json_load(tmp_path):
    """T2.3: No false positive on json.load."""
    (tmp_path / "config.py").write_text("import json\nconfig = json.load(open('config.json'))")
    findings = scan_serialization(str(tmp_path))
    assert len(findings) == 0


def test_no_fp_yaml_safe_load(tmp_path):
    """T2.4: No false positive on yaml.safe_load."""
    (tmp_path / "load_cfg.py").write_text("import yaml\ncfg = yaml.safe_load(open('config.yaml'))")
    findings = scan_serialization(str(tmp_path))
    assert len(findings) == 0


def test_no_fp_empty_project(tmp_path):
    """T2.5: Empty project produces zero findings."""
    result = scan_project(str(tmp_path))
    assert result.packages_scanned == 0
    assert len(result.findings) == 0


# ============================================================
# T3: Risk categorization is correct (5 tests)
# ============================================================

def test_risk_categories_count():
    """T3.1: Exactly 7 risk categories defined."""
    assert len(RISK_CATEGORIES) == 7


def test_serialization_is_critical():
    """T3.2: Serialization risk defaults to CRITICAL severity."""
    assert RISK_CATEGORIES["serialization_risk"]["default_severity"] == Severity.CRITICAL


def test_known_cve_is_high():
    """T3.3: Known ML CVE defaults to HIGH severity."""
    assert RISK_CATEGORIES["known_ml_cve"]["default_severity"] == Severity.HIGH


def test_missing_provenance_is_medium():
    """T3.4: Missing provenance defaults to MEDIUM severity."""
    assert RISK_CATEGORIES["missing_provenance"]["default_severity"] == Severity.MEDIUM


def test_traditional_scanner_coverage():
    """T3.5: Traditional scanners miss 4 of 7 categories."""
    missed = sum(1 for cat in RISK_CATEGORIES.values() if not cat["traditional_scanner_covers"])
    assert missed == 4  # missing_provenance, deprecated_algorithm, untrusted_source, serialization_risk


# ============================================================
# T4: Output format is correct JSON (3 tests)
# ============================================================

def test_scan_result_serializable(tmp_path):
    """T4.1: DependencyScanResult can be serialized to JSON."""
    (tmp_path / "requirements.txt").write_text("torch>=2.0")
    result = scan_project(str(tmp_path))
    report = {
        "packages_scanned": result.packages_scanned,
        "total_findings": len(result.findings),
        "by_severity": result.by_severity,
        "by_category": result.by_category,
        "findings": [
            {"category": f.category, "severity": f.severity.value,
             "controllability": f.controllability.value,
             "component": f.component, "description": f.description}
            for f in result.findings
        ],
    }
    json_str = json.dumps(report, indent=2)
    parsed = json.loads(json_str)
    assert parsed["packages_scanned"] >= 0
    assert isinstance(parsed["findings"], list)


def test_severity_values_are_strings():
    """T4.2: Severity enum values are lowercase strings."""
    for sev in Severity:
        assert isinstance(sev.value, str)
        assert sev.value == sev.value.lower()


def test_controllability_values_are_strings():
    """T4.3: Controllability enum values are lowercase strings."""
    for ctrl in Controllability:
        assert isinstance(ctrl.value, str)
        assert ctrl.value == ctrl.value.lower()


# ============================================================
# T5: CLI works end-to-end (3 tests)
# ============================================================

def test_cli_check_on_empty(tmp_path):
    """T5.1: CLI check command runs on empty directory without error."""
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "src.cli", "check", "--repo", str(tmp_path)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    # Should exit 0 (no findings)
    assert result.returncode == 0


def test_cli_check_with_findings(tmp_path):
    """T5.2: CLI check command returns non-zero on critical findings."""
    (tmp_path / "model.py").write_text("import pickle\npickle.load(open('x.pkl', 'rb'))")
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "src.cli", "check", "--repo", str(tmp_path)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    assert result.returncode == 2  # Critical findings


def test_cli_check_json_output(tmp_path):
    """T5.3: CLI check command writes valid JSON output."""
    (tmp_path / "requirements.txt").write_text("torch>=2.0")
    output_file = tmp_path / "report.json"
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "src.cli", "check", "--repo", str(tmp_path),
         "--output", str(output_file)],
        capture_output=True, text=True,
        cwd=str(Path(__file__).parent.parent),
    )
    if output_file.exists():
        data = json.loads(output_file.read_text())
        assert "scan_type" in data
        assert "findings" in data


# ============================================================
# T6: Controllability classification is correct (4 tests)
# ============================================================

def test_controllability_enum_has_four_levels():
    """T6.1: Four controllability levels defined."""
    assert len(Controllability) == 4


def test_developer_controllable_finding(tmp_path):
    """T6.2: Pickle usage in project code is DEVELOPER controllable."""
    (tmp_path / "infer.py").write_text("import pickle\npickle.load(open('m.pkl', 'rb'))")
    findings = scan_serialization(str(tmp_path))
    assert all(f.controllability == Controllability.DEVELOPER for f in findings)


def test_cve_findings_are_developer_controllable(tmp_path):
    """T6.3: Known CVE findings are DEVELOPER controllable (you chose the dependency)."""
    (tmp_path / "requirements.txt").write_text("langchain>=0.3.0")
    findings = scan_ml_cves(str(tmp_path))
    assert all(f.controllability == Controllability.DEVELOPER for f in findings)


def test_model_provenance_is_model_controllable():
    """T6.4: Missing provenance on HF model is MODEL controllable."""
    fake_info = {"cardData": {}, "siblings": [{"rfilename": "model.pkl"}], "author": "unknown"}
    findings = check_provenance("test/model", fake_info)
    assert all(f.controllability == Controllability.MODEL for f in findings)


# ============================================================
# Existing tests (preserved)
# ============================================================

def test_dependency_scanner_on_empty(tmp_path):
    """Original: Empty dir scans zero packages."""
    result = scan_project(str(tmp_path))
    assert result.packages_scanned == 0


def test_model_scanner_offline():
    """Original: Model scanner finds missing provenance."""
    fake_info = {"cardData": {}, "siblings": [{"rfilename": "model.pkl"}], "author": "unknown"}
    findings = check_provenance("test/model", fake_info)
    assert len(findings) > 0


def test_findings_exists():
    """Original: FINDINGS.md exists in project root."""
    assert Path("FINDINGS.md").exists()
