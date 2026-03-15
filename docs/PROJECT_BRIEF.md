# PROJECT BRIEF — AI Supply Chain Security Scanner

<!-- version: 1.0 -->
<!-- created: 2026-03-15 -->

> **Authority:** Tier 1 (highest)

---

## 1) Thesis Statement

**AI/ML project supply chains contain measurable, scorable security risks that existing tools (Snyk, Dependabot, pip-audit) do not cover: untrusted model provenance, model card inconsistencies, known-vulnerable ML library versions, and missing security metadata. A purpose-built scanner can identify these risks before they reach production.**

This is the "Snyk for AI" — the dependency scanning layer that's missing from the ML ecosystem.

---

## 2) Research Questions

| # | Question | How | Success Criteria |
|---|----------|-----|-----------------|
| RQ1 | What AI-specific supply chain risks exist in real ML projects? | Scan popular Hugging Face models + PyPI ML packages for: missing provenance, known CVEs, suspicious metadata, deprecated algorithms. | Scanner identifies ≥5 distinct risk categories with ≥1 real finding per category |
| RQ2 | Can risk scoring prioritize which dependencies to fix first? | Score each finding by severity (CVSS), exploitability (EPSS/ExploitDB), and controllability (can you change it?). Compare rule-based vs ML scoring. | Risk scoring produces actionable priority ranking with ≥3 severity levels |
| RQ3 | Does controllability analysis apply to ML supply chains? | Classify dependencies: developer-controlled (direct deps you chose), transitive (pulled in by your deps), model-level (weights you downloaded). | Clear controllability matrix — 6th domain validation |
| RQ4 | What's the prevalence of supply chain risks in the ML ecosystem? | Scan top 100 Hugging Face models + top 50 ML PyPI packages. Quantify risk prevalence. | Prevalence report with statistics: % of models with missing provenance, % of packages with known CVEs |

---

## 3) Scope

### In Scope
- Model provenance scanning (Hugging Face model cards: license, author, training data documentation)
- ML library CVE matching (PyPI packages against NVD — reuse FP-05 data)
- Dependency graph analysis (transitive dependencies of ML packages)
- Risk scoring with controllability analysis
- CLI tool: `ai-supply-scan check --repo <path>` or `--model <hf-model-id>`

### Out of Scope
- Scanning model weights for backdoors/trojans (requires GPU + specialized tooling)
- Runtime behavior analysis of models
- Scanning private/enterprise model registries

### Stretch Goals
- GitHub Action for CI/CD integration
- Hugging Face model card quality score (like a credit score for models)
- Integration with existing Snyk/Dependabot pipelines

---

## 4) Data

| Source | What | Method | Reuse? |
|--------|------|--------|--------|
| NVD API | ML library CVEs | Filter FP-05 data for ML keywords | Yes — FP-05 (338K CVEs) |
| Hugging Face Hub API | Model metadata, cards, licenses | API calls | New |
| PyPI JSON API | Package metadata, dependencies, versions | API calls | New |
| GitHub Advisory DB | ML-specific advisories | API | Partial — FP-05 |

---

## 5) Skill Cluster Targets

| Cluster | Current | Target | How |
|---------|---------|--------|-----|
| **S** | S3 | **S4** | Automated AI security tool shipped and used by others |
| **P** | P3-adj | **P4** | CLI + GitHub Action + real users |
| **V** | V1 | **V2+** | "Snyk for AI" = maximum virality |
| **L** | L4-adj | L4 | NLP on model cards, dependency graph analysis |
| **D** | D4 | D4+ | Supply chain threat model documentation |

---

## 6) Publication Target

| Property | Value |
|----------|-------|
| **Title** | I Built the Snyk for AI Models: Here's What Your ML Pipeline Is Hiding |
| **Pillar** | AI Security Architecture (40%) |
| **Conference** | BSides / DEF CON AI Village / Black Hat Arsenal |
| **Unique angle** | Nobody has built this. Snyk raised $530M for code deps; the AI model layer is unscanned. |

---

## 7) Definition of Done

- [x] Scanner identifies ≥5 risk categories with real findings
- [x] Risk scoring with ≥3 severity levels
- [x] Controllability matrix (6th domain)
- [x] Prevalence scan on top HF models + PyPI packages
- [x] CLI tool: `ai-supply-scan check` works
- [x] Code on GitHub
- [x] FINDINGS.md
- [x] DECISION_LOG with ADRs
- [x] Blog draft in blog/draft.md
- [x] ≥2 figures in blog/images/
- [x] Conference abstract
- [x] PUBLICATION_PIPELINE filled
- [x] LESSONS_LEARNED updated
