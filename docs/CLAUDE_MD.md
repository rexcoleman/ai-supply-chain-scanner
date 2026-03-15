# AI Supply Chain Security Scanner — Claude Code Context

> **govML v2.5** | Profile: blog-track (blog-track)

## Project Purpose

I Built the Snyk for AI Models: Here's What Your ML Pipeline Is Hiding

- **Context:** Self-directed research (AI Supply Chain Security Scanner)
- **Profile:** blog-track
- **Python:** 3.11 | **Env:** ai-supply-scan
- **Brand pillar:** AI Security Architecture
- **Workload type:** io_bound

## Authority Hierarchy

| Tier | Source | Path |
|------|--------|------|
| 1 (highest) | Project Brief | `docs/PROJECT_BRIEF.md` |
| 2 | — | No external FAQ |
| 3 | Advisory methodology | `docs/ADVERSARIAL_EVALUATION.md` |
| Contracts | Governance docs | `docs/*.md` |

## Current Phase

**Phase:** 0 — Environment & Setup

### Phase Progression

| Phase | Name | Status |
|-------|------|--------|
| 0 | Phase 0 — Environment & Data | **CURRENT** |
| 1 | Phase 1 — Scanner Engine | Not started |
| 2 | Phase 2 — Risk Scoring | Not started |
| 3 | Phase 3 — Findings & Publication | Not started |
| 4 | Phase 4 — Publication Artifacts | Not started |

## Experiment Summary

Seeds: [42, 123, 456]

- **model_scanning:** metadata_scanner, weight_hash_verifier, provenance_checker
- **dependency_scanning:** pip_audit, cve_matcher, license_checker
- **risk_scoring:** rule_based, ml_scorer

## Key Files

| File | Purpose |
|------|---------|
| `docs/PROJECT_BRIEF.md` | **READ FIRST** — thesis, RQs, scope |
| `docs/PUBLICATION_PIPELINE.md` | Blog post governance + distribution |
| `docs/DECISION_LOG.md` | All tradeoff decisions (mandatory at every phase gate) |
| `config/base.yaml` | Experiment configuration |

## AI Division of Labor

### Permitted
- **Claude Code:** Coding copilot, CVE matching, model card parsing
  - Prohibited: Must not access private model weights or proprietary datasets. Must not make security claims about specific commercial models.

### Prohibited (all projects)
- Modifying PROJECT_BRIEF thesis or research questions
- Writing interpretation/analysis prose (human insight)

## Conventions

- **Seeds:** [42, 123, 456]
- **Smoke test first:** `--sample-frac 0.01` or `--dry-run` before full runs
- **Decisions:** Log in DECISION_LOG at every phase gate (mandatory per v2.5)
- **Commit early:** Phase 0a scaffold → commit → Phase 0b research → commit
