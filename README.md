# AI Supply Chain Security Scanner

**65% of ML supply chain findings are CRITICAL severity, and 4 of 7 risk categories are invisible to Snyk and Dependabot. Unsafe pickle/joblib serialization accounts for half of all findings across 5 ML projects.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-green.svg)](https://www.python.org/downloads/)

> **Note:** This scanner uses rule-based pattern matching and static analysis, not machine learning. It is a security tool FOR AI/ML projects, applying adversarial control analysis to categorize supply chain risks by controllability, but the detection methodology itself is deterministic.

## Key Results

| Metric | Value |
|--------|-------|
| Total findings | 20 across 5 ML projects |
| CRITICAL severity | 13 (65%) |
| #1 risk | Unsafe pickle/joblib serialization (10 of 20 findings) |
| Risk categories missed by traditional scanners | 4 of 7 |
| Developer-fixable | 75% of all findings |
| Known ML CVEs found | 3 (LangChain, PyTorch, scikit-learn) |

## What Traditional Scanners Miss

| Risk Category | Snyk/Dependabot? | This Scanner |
|---------------|-----------------|--------------|
| Unsafe Serialization (pickle/joblib) | No | CRITICAL |
| Known ML Library CVEs | Partial | HIGH |
| Missing Model Provenance | No | MEDIUM |
| Untrusted Model Source | No | MEDIUM |
| Deprecated ML Algorithm | No | MEDIUM |
| License Risk | Partial (FOSSA) | LOW |
| Stale Dependencies | Yes | LOW |

**Core insight:** 65% of findings are CRITICAL severity, and 4 of 7 risk categories are invisible to traditional supply chain scanners. Unsafe serialization (pickle/joblib) is the dominant risk in ML projects.

## Quick Start

```bash
git clone https://github.com/rexcoleman/ai-supply-chain-scanner.git
cd ai-supply-chain-scanner
conda env create -f environment.yml
conda activate ai-supply-scan

# Scan project dependencies
python src/cli.py check --repo ~/your-ml-project

# Scan a Hugging Face model
python src/cli.py model --id bert-base-uncased

# Verbose with remediation advice
python src/cli.py check --repo ~/your-ml-project --verbose --output report.json
```

## Architecture

```
src/
  cli.py                       # CLI entry point
  scanners/
    dependency_scanner.py      # Project dependency + serialization scanning
    model_scanner.py           # Hugging Face model metadata scanning
  scoring/                     # Risk scoring engine
  core/
    risk_categories.py         # 7 risk categories + severity definitions
```

## Methodology

This project validates the **adversarial controllability analysis** methodology (6th domain). Supply chain risk factors are classified by controllability:
- **Developer-controlled (75%):** serialization format choice, dependency pinning, model source selection
- **Library-controlled:** upstream patches, CVE remediation
- **Uncontrollable:** zero-day supply chain attacks, compromised model registries

See [FINDINGS.md](FINDINGS.md) for detailed results.

## Related Work

- [controllability-bound](https://github.com/rexcoleman/controllability-bound) — Defense difficulty decomposition (this scanner validates the 6th domain)
- [cycle9-broadcast-contagion](https://github.com/rexcoleman/cycle9-broadcast-contagion) — Phase transitions in supply chain contagion
- Blog post: [Scanning Agent Skills Results](https://rexcoleman.dev/posts/scanning-agent-skills-results/)

## Governed by [govML](https://github.com/rexcoleman/govML)

Built with reproducibility and decision traceability enforced across the entire pipeline.

## Citation

```bibtex
@software{coleman2026supplychain,
  title = {AI Supply Chain Security Scanner},
  author = {Coleman, Rex},
  year = {2026},
  url = {https://github.com/rexcoleman/ai-supply-chain-scanner},
  license = {MIT}
}
```

## License

[MIT](LICENSE)
