# AI Supply Chain Security Scanner

**The Snyk for AI models. Scan ML project dependencies and Hugging Face models for supply chain risks that traditional scanners miss.**

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

## Governed by [govML](https://github.com/rexcoleman/govML)

Built with reproducibility and decision traceability enforced across the entire pipeline.

## License

[MIT](LICENSE)
