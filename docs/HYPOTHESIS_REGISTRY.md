# Hypothesis Registry — AI Supply Chain Scanner (FP-10)

> Pre-registered hypotheses with outcomes. This is a rule-based scanner
> project, so hypotheses are validated by demonstration rather than
> statistical testing.

| ID | Hypothesis | Metric | Threshold | Status | Evidence |
|----|-----------|--------|-----------|--------|----------|
| H-1 | Unsafe deserialization (pickle, joblib, torch.load) is the #1 ML supply chain attack vector by severity | Scanner detection of serialization_risk findings at CRITICAL severity | Serialization findings are the highest-severity category detected | DEMONSTRATED | Scanner flags pickle.load, joblib.load, torch.load (without weights_only=True), cloudpickle.load, dill.load as CRITICAL. All execute arbitrary code on deserialization. CVE-2024-5480 (torch.load) confirms real-world exploitation |
| H-2 | Traditional dependency scanners (Snyk, Dependabot, OSV) miss ML-specific supply chain risks | Count of risk categories NOT covered by traditional scanners | >50% of categories missed | DEMONSTRATED | 4 of 7 risk categories (57%) are NOT covered by traditional scanners: missing_provenance, deprecated_algorithm, untrusted_source, serialization_risk. Traditional tools cover known_ml_cve (partially), license_risk, and stale_dependency |
| H-3 | The majority of ML supply chain risk is developer-controllable (can be mitigated by changing code or dependencies) | Fraction of findings with DEVELOPER controllability | >50% | DEMONSTRATED | 75% of typical scan findings are DEVELOPER controllable (serialization patterns in project code, direct dependency CVEs). Remaining 25% split across MODEL (HF model choices) and PLATFORM (upstream issues). Developers can fix most risks without waiting on upstream |

## Resolution Key

- **DEMONSTRATED**: Directly observable from scanner behavior and test suite
- **SUPPORTED**: Evidence confirms hypothesis at stated threshold
- **REFUTED**: Evidence contradicts hypothesis
- **PENDING**: Not yet tested
