"""AI Supply Chain risk categories and severity definitions.

Defines the 7 risk categories that traditional scanners miss.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"   # Active exploitation or trivial to exploit
    HIGH = "high"           # Known vulnerability, exploit likely
    MEDIUM = "medium"       # Risk exists, exploitation requires effort
    LOW = "low"             # Informational or best-practice violation
    INFO = "info"           # Metadata observation, no direct risk


class Controllability(Enum):
    """Who controls whether this risk can be mitigated."""
    DEVELOPER = "developer"       # Direct dependency — you chose it, you can change it
    TRANSITIVE = "transitive"     # Pulled in by your dependency — harder to change
    MODEL = "model"               # Model weights you downloaded — replace model or retrain
    PLATFORM = "platform"         # Hugging Face / PyPI platform-level — report and wait


@dataclass
class RiskFinding:
    """A single supply chain risk finding."""
    category: str            # e.g., "missing_provenance"
    severity: Severity
    controllability: Controllability
    component: str           # e.g., "transformers==4.38.0" or "bert-base-uncased"
    description: str
    remediation: str
    evidence: str            # What triggered the finding
    cve_id: str | None = None


# The 7 risk categories traditional scanners miss
RISK_CATEGORIES = {
    "missing_provenance": {
        "name": "Missing Model Provenance",
        "description": "Model lacks training data documentation, author verification, or reproducibility info",
        "why_matters": "Can't verify what data was used to train the model. Poisoned training data = poisoned model.",
        "default_severity": Severity.MEDIUM,
        "traditional_scanner_covers": False,
    },
    "known_ml_cve": {
        "name": "Known ML Library CVE",
        "description": "ML library has a known vulnerability in NVD/GitHub Advisory DB",
        "why_matters": "Exploitable vulnerabilities in ML frameworks (PyTorch, TensorFlow, transformers).",
        "default_severity": Severity.HIGH,
        "traditional_scanner_covers": True,  # Snyk covers this partially
    },
    "deprecated_algorithm": {
        "name": "Deprecated or Insecure Algorithm",
        "description": "Model or library uses deprecated crypto, hash, or serialization (e.g., pickle, MD5)",
        "why_matters": "Pickle deserialization = arbitrary code execution. MD5 = collision attacks.",
        "default_severity": Severity.HIGH,
        "traditional_scanner_covers": False,
    },
    "untrusted_source": {
        "name": "Untrusted Model Source",
        "description": "Model from unverified author, no organization affiliation, recently created account",
        "why_matters": "Hugging Face has no mandatory identity verification. Anyone can upload models.",
        "default_severity": Severity.MEDIUM,
        "traditional_scanner_covers": False,
    },
    "license_risk": {
        "name": "License Incompatibility or Restriction",
        "description": "Model or library license restricts commercial use, requires attribution, or is copyleft",
        "why_matters": "Using a GPL model in a commercial product without compliance = legal risk.",
        "default_severity": Severity.LOW,
        "traditional_scanner_covers": True,  # Some license scanners exist
    },
    "stale_dependency": {
        "name": "Stale or Unmaintained Dependency",
        "description": "ML library hasn't been updated in >12 months, or latest version is >2 major versions behind",
        "why_matters": "Unmaintained libraries accumulate unpatched vulnerabilities.",
        "default_severity": Severity.LOW,
        "traditional_scanner_covers": True,  # Dependabot covers this
    },
    "serialization_risk": {
        "name": "Unsafe Serialization Format",
        "description": "Model uses pickle, joblib, or other unsafe serialization that allows arbitrary code execution on load",
        "why_matters": "Loading a pickled model = running arbitrary Python code. This is the #1 ML supply chain attack vector.",
        "default_severity": Severity.CRITICAL,
        "traditional_scanner_covers": False,
    },
}

# Patterns for detecting unsafe serialization in ML projects
UNSAFE_SERIALIZATION_PATTERNS = [
    r"pickle\.load",
    r"pickle\.loads",
    r"torch\.load",           # Unsafe without weights_only=True
    r"joblib\.load",
    r"cloudpickle\.load",
    r"dill\.load",
    r"\.pkl\b",
    r"\.pickle\b",
]

SAFE_SERIALIZATION_PATTERNS = [
    r"safetensors",
    r"torch\.load.*weights_only\s*=\s*True",
    r"\.safetensors\b",
    r"json\.load",
    r"yaml\.safe_load",
]

# ML-specific PyPI packages to scan
ML_PACKAGES = [
    "torch", "torchvision", "torchaudio",
    "tensorflow", "keras",
    "transformers", "tokenizers", "datasets", "accelerate",
    "scikit-learn", "xgboost", "lightgbm", "catboost",
    "numpy", "pandas", "scipy",
    "langchain", "langchain-core", "langgraph",
    "openai", "anthropic",
    "huggingface-hub", "safetensors",
    "onnx", "onnxruntime",
    "mlflow", "wandb",
    "ray", "dask",
    "pillow", "opencv-python",
]
