"""Scan Hugging Face models for supply chain risks.

Checks: model provenance, unsafe serialization, license, author trust signals.
"""

import json
from dataclasses import dataclass, field
from typing import Any

import requests

from ..core.risk_categories import RiskFinding, Severity, Controllability


HF_API = "https://huggingface.co/api/models"


@dataclass
class ModelScanResult:
    model_id: str
    findings: list[RiskFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def fetch_model_info(model_id: str) -> dict | None:
    """Fetch model metadata from Hugging Face Hub API."""
    try:
        resp = requests.get(f"{HF_API}/{model_id}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None


def check_provenance(model_id: str, info: dict) -> list[RiskFinding]:
    """Check model provenance and documentation quality."""
    findings = []

    # Check model card
    card_data = info.get("cardData", {})
    has_card = bool(card_data) or bool(info.get("description", ""))

    if not has_card:
        findings.append(RiskFinding(
            category="missing_provenance",
            severity=Severity.MEDIUM,
            controllability=Controllability.MODEL,
            component=model_id,
            description="No model card found — training data, methodology, and limitations are undocumented",
            remediation="Choose a model with a complete model card, or document provenance yourself",
            evidence="cardData is empty and no description field",
        ))

    # Check training dataset documentation
    datasets = card_data.get("datasets", [])
    if not datasets:
        findings.append(RiskFinding(
            category="missing_provenance",
            severity=Severity.MEDIUM,
            controllability=Controllability.MODEL,
            component=model_id,
            description="Training datasets not documented in model card",
            remediation="Verify training data independently or choose a model with documented datasets",
            evidence="cardData.datasets is empty",
        ))

    # Check author/organization
    author = info.get("author", "")
    if "/" not in model_id:
        findings.append(RiskFinding(
            category="untrusted_source",
            severity=Severity.LOW,
            controllability=Controllability.MODEL,
            component=model_id,
            description="Model not published under an organization namespace",
            remediation="Prefer models from verified organizations (e.g., google/, meta-llama/, microsoft/)",
            evidence=f"Author: {author or 'unknown'}",
        ))

    return findings


def check_serialization_format(model_id: str, info: dict) -> list[RiskFinding]:
    """Check if model uses safe serialization formats."""
    findings = []

    siblings = info.get("siblings", [])
    file_names = [s.get("rfilename", "") for s in siblings]

    has_pickle = any(f.endswith((".pkl", ".pickle", ".bin")) for f in file_names)
    has_safetensors = any(f.endswith(".safetensors") for f in file_names)
    has_pt = any(f.endswith(".pt") or f.endswith(".pth") for f in file_names)

    if has_pickle and not has_safetensors:
        findings.append(RiskFinding(
            category="serialization_risk",
            severity=Severity.CRITICAL,
            controllability=Controllability.MODEL,
            component=model_id,
            description="Model uses pickle serialization without safetensors alternative. Loading = arbitrary code execution risk.",
            remediation="Use safetensors format: model.save_pretrained(path, safe_serialization=True)",
            evidence=f"Pickle files found: {[f for f in file_names if f.endswith(('.pkl', '.pickle', '.bin'))]}",
        ))
    elif has_pt and not has_safetensors:
        findings.append(RiskFinding(
            category="serialization_risk",
            severity=Severity.HIGH,
            controllability=Controllability.MODEL,
            component=model_id,
            description="Model uses PyTorch .pt/.pth format without safetensors. torch.load without weights_only=True is unsafe.",
            remediation="Convert to safetensors format or ensure torch.load(weights_only=True)",
            evidence=f"PyTorch files: {[f for f in file_names if f.endswith(('.pt', '.pth'))]}",
        ))

    return findings


def check_license(model_id: str, info: dict) -> list[RiskFinding]:
    """Check model license for commercial use restrictions."""
    findings = []

    card_data = info.get("cardData", {})
    license_id = card_data.get("license", info.get("license", ""))

    RESTRICTIVE_LICENSES = {
        "cc-by-nc-4.0": "Non-commercial use only",
        "cc-by-nc-sa-4.0": "Non-commercial, share-alike",
        "gpl-3.0": "Copyleft — derivative works must be GPL",
        "agpl-3.0": "Copyleft — network use triggers GPL",
        "cc-by-nc-nd-4.0": "Non-commercial, no derivatives",
        "other": "Custom/unknown license — review manually",
    }

    if not license_id:
        findings.append(RiskFinding(
            category="license_risk",
            severity=Severity.MEDIUM,
            controllability=Controllability.MODEL,
            component=model_id,
            description="No license specified — usage rights are undefined",
            remediation="Contact model author for licensing terms or choose a licensed model",
            evidence="No license field in model card or metadata",
        ))
    elif license_id.lower() in RESTRICTIVE_LICENSES:
        findings.append(RiskFinding(
            category="license_risk",
            severity=Severity.LOW,
            controllability=Controllability.MODEL,
            component=model_id,
            description=f"Restrictive license: {license_id} — {RESTRICTIVE_LICENSES[license_id.lower()]}",
            remediation="Verify license compatibility with your use case before deploying",
            evidence=f"License: {license_id}",
        ))

    return findings


def scan_model(model_id: str, offline_info: dict | None = None) -> ModelScanResult:
    """Scan a single Hugging Face model for supply chain risks."""
    info = offline_info or fetch_model_info(model_id)

    if info is None:
        return ModelScanResult(
            model_id=model_id,
            findings=[RiskFinding(
                category="untrusted_source",
                severity=Severity.INFO,
                controllability=Controllability.PLATFORM,
                component=model_id,
                description="Could not fetch model info from Hugging Face Hub",
                remediation="Check model ID and network connectivity",
                evidence="API returned non-200 or timeout",
            )],
        )

    findings = []
    findings.extend(check_provenance(model_id, info))
    findings.extend(check_serialization_format(model_id, info))
    findings.extend(check_license(model_id, info))

    return ModelScanResult(
        model_id=model_id,
        findings=findings,
        metadata={
            "author": info.get("author", ""),
            "downloads": info.get("downloads", 0),
            "likes": info.get("likes", 0),
            "tags": info.get("tags", [])[:10],
            "pipeline_tag": info.get("pipeline_tag", ""),
        },
    )
