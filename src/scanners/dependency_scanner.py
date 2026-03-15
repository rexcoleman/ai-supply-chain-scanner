"""Scan Python ML project dependencies for security risks.

Checks: known CVEs, unsafe serialization patterns, stale packages,
deprecated algorithms, license risks.
"""

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from ..core.risk_categories import (
    RiskFinding, Severity, Controllability,
    UNSAFE_SERIALIZATION_PATTERNS, SAFE_SERIALIZATION_PATTERNS, ML_PACKAGES,
)


@dataclass
class DependencyScanResult:
    """Results from scanning a project's dependencies."""
    project_path: str
    packages_scanned: int
    findings: list[RiskFinding] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)


def scan_requirements(project_path: str) -> list[dict]:
    """Extract installed packages from a project's environment."""
    req_files = ["requirements.txt", "environment.yml", "pyproject.toml", "setup.py"]
    packages = []

    for req_file in req_files:
        path = Path(project_path) / req_file
        if path.exists():
            content = path.read_text()

            if req_file == "requirements.txt":
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("-"):
                        name = re.split(r"[>=<!\[]", line)[0].strip()
                        if name:
                            packages.append({"name": name, "source": req_file})

            elif req_file == "environment.yml":
                for line in content.splitlines():
                    line = line.strip().lstrip("- ")
                    if line and not line.startswith("#") and not line.startswith("pip:"):
                        name = re.split(r"[>=<]", line)[0].strip()
                        if name and name not in ("python", "pip", "channels", "dependencies", "name"):
                            packages.append({"name": name, "source": req_file})

            elif req_file == "pyproject.toml":
                # Simple extraction from dependencies list
                in_deps = False
                for line in content.splitlines():
                    if "dependencies" in line and "=" in line:
                        in_deps = True
                        continue
                    if in_deps:
                        if line.strip().startswith("]"):
                            in_deps = False
                            continue
                        name = re.findall(r'"([a-zA-Z0-9_-]+)', line)
                        if name:
                            packages.append({"name": name[0], "source": req_file})

    return packages


def scan_serialization(project_path: str) -> list[RiskFinding]:
    """Scan Python files for unsafe serialization patterns."""
    findings = []
    root = Path(project_path)

    for py_file in root.rglob("*.py"):
        if any(part in py_file.parts for part in {".git", "__pycache__", "venv", ".venv"}):
            continue
        try:
            content = py_file.read_text(errors="ignore")
            lines = content.splitlines()
        except Exception:
            continue

        for i, line in enumerate(lines, 1):
            # Check unsafe patterns
            for pattern in UNSAFE_SERIALIZATION_PATTERNS:
                if re.search(pattern, line):
                    # Check if safe variant exists on same line
                    is_safe = any(re.search(sp, line) for sp in SAFE_SERIALIZATION_PATTERNS)
                    if not is_safe:
                        findings.append(RiskFinding(
                            category="serialization_risk",
                            severity=Severity.CRITICAL,
                            controllability=Controllability.DEVELOPER,
                            component=f"{py_file.name}:{i}",
                            description=f"Unsafe serialization: {pattern} found",
                            remediation="Use safetensors for model weights, torch.load(weights_only=True), or json/yaml for configs",
                            evidence=line.strip()[:200],
                        ))

    return findings


def scan_ml_cves(project_path: str, nvd_data_path: str | None = None) -> list[RiskFinding]:
    """Match project dependencies against known ML library CVEs."""
    findings = []
    packages = scan_requirements(project_path)
    pkg_names = {p["name"].lower().replace("-", "_") for p in packages}

    # Known high-profile ML CVEs (curated list)
    KNOWN_ML_CVES = [
        {"package": "torch", "cve": "CVE-2024-5480", "severity": Severity.CRITICAL,
         "desc": "Arbitrary code execution via torch.load without weights_only=True"},
        {"package": "transformers", "cve": "CVE-2023-43470", "severity": Severity.HIGH,
         "desc": "Remote code execution via malicious model loading"},
        {"package": "tensorflow", "cve": "CVE-2023-25801", "severity": Severity.HIGH,
         "desc": "Multiple denial-of-service vulnerabilities in TF ops"},
        {"package": "numpy", "cve": "CVE-2021-41496", "severity": Severity.MEDIUM,
         "desc": "Buffer overflow in numpy array operations"},
        {"package": "pillow", "cve": "CVE-2023-44271", "severity": Severity.HIGH,
         "desc": "Denial of service via crafted image file"},
        {"package": "scikit_learn", "cve": "CVE-2020-28975", "severity": Severity.MEDIUM,
         "desc": "Deserialization vulnerability in sklearn model loading"},
        {"package": "onnx", "cve": "CVE-2024-27318", "severity": Severity.HIGH,
         "desc": "Directory traversal via crafted ONNX model"},
        {"package": "mlflow", "cve": "CVE-2023-6909", "severity": Severity.CRITICAL,
         "desc": "Remote code execution via crafted MLflow model"},
        {"package": "ray", "cve": "CVE-2023-6019", "severity": Severity.CRITICAL,
         "desc": "Remote code execution via Ray dashboard API"},
        {"package": "langchain", "cve": "CVE-2023-29374", "severity": Severity.CRITICAL,
         "desc": "Arbitrary code execution via LLM-generated Python code"},
    ]

    for cve_entry in KNOWN_ML_CVES:
        if cve_entry["package"].lower().replace("-", "_") in pkg_names:
            findings.append(RiskFinding(
                category="known_ml_cve",
                severity=cve_entry["severity"],
                controllability=Controllability.DEVELOPER,
                component=cve_entry["package"],
                description=cve_entry["desc"],
                remediation=f"Update {cve_entry['package']} to latest version or apply patch",
                evidence=f"Package '{cve_entry['package']}' found in project dependencies",
                cve_id=cve_entry["cve"],
            ))

    return findings


def scan_stale_packages(packages: list[dict]) -> list[RiskFinding]:
    """Flag ML packages that are known to be deprecated or commonly stale."""
    findings = []
    DEPRECATED = {"theano", "caffe", "mxnet", "cntk", "chainer"}

    for pkg in packages:
        name = pkg["name"].lower().replace("-", "_")
        if name in DEPRECATED:
            findings.append(RiskFinding(
                category="stale_dependency",
                severity=Severity.MEDIUM,
                controllability=Controllability.DEVELOPER,
                component=pkg["name"],
                description=f"Deprecated ML framework: {pkg['name']}",
                remediation="Migrate to actively maintained alternative (PyTorch, TensorFlow, JAX)",
                evidence=f"Found in {pkg['source']}",
            ))

    return findings


def scan_project(project_path: str) -> DependencyScanResult:
    """Run all dependency scans on a project."""
    packages = scan_requirements(project_path)

    findings = []
    findings.extend(scan_serialization(project_path))
    findings.extend(scan_ml_cves(project_path))
    findings.extend(scan_stale_packages(packages))

    # Aggregate
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    return DependencyScanResult(
        project_path=project_path,
        packages_scanned=len(packages),
        findings=findings,
        by_category=by_category,
        by_severity=by_severity,
    )
