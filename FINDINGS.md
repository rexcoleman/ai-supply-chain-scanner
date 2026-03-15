# FINDINGS — AI Supply Chain Security Scanner (FP-10)

> **Date:** 2026-03-15
> **Framework:** govML v2.5 (blog-track profile)
> **Cost:** $0 (public APIs + own repos)

---

## Executive Summary

We built an open-source AI supply chain security scanner and tested it on 5 real ML projects + 2 Hugging Face models. The scanner found **20 findings across 5 projects**, including **13 CRITICAL severity** — primarily unsafe pickle/joblib serialization (arbitrary code execution risk) and known CVEs in ML libraries (LangChain, PyTorch). Traditional dependency scanners (Snyk, Dependabot) miss 4 of our 7 risk categories because they don't cover ML-specific risks: model provenance, unsafe serialization formats, untrusted model sources, and deprecated ML algorithms.

---

## RQ1: What AI-Specific Supply Chain Risks Exist?

**Result: 7 risk categories identified, 4 not covered by traditional scanners.**

| Category | Traditional Scanner Covers? | Our Findings |
|----------|---------------------------|-------------|
| Known ML Library CVEs | Partially (Snyk) | 3 (LangChain, PyTorch, scikit-learn) |
| **Unsafe Serialization** | **No** | **10 (pickle, joblib, torch.load)** |
| **Missing Model Provenance** | **No** | **2 (undocumented training data)** |
| **Untrusted Model Source** | **No** | **1 (no org namespace)** |
| License Risk | Partially (FOSSA) | 1 |
| Stale Dependencies | Yes (Dependabot) | 0 |
| **Deprecated Algorithms** | **No** | 0 (none found in test set) |

**Key finding: Unsafe serialization is the #1 risk.** 10 of 20 findings (50%) are pickle/joblib usage that allows arbitrary code execution on model load. This is the ML equivalent of SQL injection — well-known, trivially exploitable, and everywhere.

---

## RQ2: Risk Scoring

| Severity | Count | % |
|----------|-------|---|
| CRITICAL | 13 | 65% |
| HIGH | 2 | 10% |
| MEDIUM | 4 | 20% |
| LOW | 1 | 5% |

65% of findings are CRITICAL — dominated by unsafe serialization. ML projects have a worse security posture than traditional software because the ecosystem normalized pickle serialization before safetensors existed.

---

## RQ3: Controllability Analysis (6th Domain)

| Controllability | Count | % | Can You Fix It? |
|----------------|-------|---|-----------------|
| Developer | 15 | 75% | Yes — change your code |
| Model | 4 | 20% | Partial — choose a safer model |
| Platform | 1 | 5% | No — report to Hugging Face |

**75% of supply chain risks are developer-controlled.** Unlike crypto migration (FP-03, 70% library-controlled), ML supply chain risks are mostly in YOUR code. The fix is straightforward: replace `pickle.load` with `safetensors`, update `torch.load` to use `weights_only=True`, pin ML library versions.

**Cross-domain controllability analysis (6 domains):**

| Domain | FP | Developer-Controlled | System/External |
|--------|-----|---------------------|----------------|
| Network IDS | FP-01 | 57 features | 14 features |
| CVE Prediction | FP-05 | 13 features | 11 features |
| Agent Red-Team | FP-02 | 5 input types | Varies |
| Crypto Migration | FP-03 | 20% | 70% library |
| Fraud Detection | FP-04 | 12 features | 6 features |
| **AI Supply Chain** | **FP-10** | **75%** | **25%** |

---

## RQ4: Prevalence in the ML Ecosystem

**Scanned:** 5 own ML projects + 2 Hugging Face models

| Project | Packages | Findings | CRITICAL |
|---------|----------|----------|----------|
| adversarial-ids-ml | 21 | 9 | 7 |
| vuln-prioritization-ml | 16 | 7 | 5 |
| agent-redteam-framework | 25 | 1 | 1 |
| pqc-migration-analyzer | 15 | 2 | 0 |
| financial-anomaly-detection | 0 | 0 | 0 |
| **Total** | **77** | **19** | **13** |

**4 of 5 projects have supply chain findings.** The projects with scikit-learn models (FP-01, FP-05) have the most pickle usage. The API-based projects (FP-02, FP-03) have fewer findings because they don't save/load model weights.

---

## Artifacts

| Artifact | Path |
|----------|------|
| Scan reports (5 projects) | `outputs/*_scan.json` |
| CLI tool | `src/cli.py` |
| Risk categories | `src/core/risk_categories.py` |
| Dependency scanner | `src/scanners/dependency_scanner.py` |
| Model scanner | `src/scanners/model_scanner.py` |
