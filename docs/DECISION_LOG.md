# DECISION LOG

<!-- version: 2.0 -->
<!-- created: 2026-02-20 -->
<!-- last_validated_against: CS_7641_Machine_Learning_OL_Report -->

> **Authority Hierarchy**
>
> | Priority | Document | Role |
> |----------|----------|------|
> | Tier 1 | `{{TIER1_DOC}}` | Primary spec — highest authority |
> | Tier 2 | `{{TIER2_DOC}}` | Clarifications — cannot override Tier 1 |
> | Tier 3 | `{{TIER3_DOC}}` | Advisory only — non-binding if inconsistent with Tier 1/2 |
> | Contract | This document | Implementation detail — subordinate to all tiers above |
>
> **Conflict rule:** When a higher-tier document and this contract disagree, the higher tier wins.
> Update this contract via `CONTRACT_CHANGE` or align implementation to the higher tier.

### Companion Contracts

**Upstream (this contract depends on):**
- None — decisions may reference any contract but have no structural dependency.

**Downstream (depends on this contract):**
- See [CHANGELOG](CHANGELOG.tmpl.md) for CONTRACT_CHANGE entries triggered by decisions (cross-reference ADR IDs)
- See [RISK_REGISTER](RISK_REGISTER.tmpl.md) for risk entries mitigated by decisions
- See [IMPLEMENTATION_PLAYBOOK](IMPLEMENTATION_PLAYBOOK.tmpl.md) §5 for change control procedure referencing ADR entries

## Purpose

This log records architectural and methodological decisions for the **AI Supply Chain Security Scanner** project using a lightweight ADR (Architecture Decision Record) format. Each decision captures the context, alternatives, rationale, and consequences so that future changes are informed rather than accidental.

**Relationship to CHANGELOG:** When a decision triggers a `CONTRACT_CHANGE` commit, the change MUST also be logged in CHANGELOG with a cross-reference to the ADR ID.

---

## When to Create an ADR

Create a new ADR when:
- A decision affects multiple contracts or specs
- A decision resolves an ambiguity in authority documents
- A decision involves tradeoffs that future contributors need to understand
- A `CONTRACT_CHANGE` commit is triggered by a methodological choice
- A risk mitigation strategy is selected from multiple options

Do NOT create an ADR for routine implementation choices that follow directly from a single contract requirement with no alternatives.

---

## Status Lifecycle

```
Proposed → Accepted → [Superseded by ADR-YYYY]
```

- **Proposed:** Under discussion; not yet binding.
- **Accepted:** Binding; implementation may proceed.
- **Superseded:** Replaced by a newer ADR. MUST cite the superseding ADR ID. Do NOT delete superseded entries.

---

## Decision Record Template

Copy this block for each new decision:

```markdown
## ADR-XXXX: [Short title]

- **Date:** YYYY-MM-DD
- **Status:** Proposed | Accepted | Superseded by ADR-YYYY

### Context
[Problem statement and constraints. Cite authority documents by tier and section.]

### Decision
[The chosen approach. Be specific enough that someone can implement it without ambiguity.]

### Alternatives Considered

| Option | Description | Verdict | Reason |
|--------|-------------|---------|--------|
| A (chosen) | [approach] | **Accepted** | [why best] |
| B | [approach] | Rejected | [why not] |
| C | [approach] | Rejected | [why not] |

### Rationale
[Why this approach is best given the project constraints. Cite authority documents.]

### Consequences
[Tradeoffs and risks. Reference RISK_REGISTER entries if applicable.]

### Contracts Affected

| Contract | Section | Change Required |
|----------|---------|----------------|
| [contract name] | §N | [what changes] |

### Evidence Plan

| Validation | Command / Artifact | Expected Result |
|------------|-------------------|-----------------|
| [what to verify] | [command or file path] | [pass criteria] |
```

---

## Decisions

*(Record decisions below. Number sequentially: ADR-0001, ADR-0002, etc.)*

---

## ADR-0001: Two scan surfaces (dependencies + models) with shared risk taxonomy

- **Date:** 2026-03-15
- **Status:** Accepted

### Decision
Scanner has two entry points: `check --repo` (dependencies) and `model --id` (Hugging Face models). Both use the same 7-category risk taxonomy and produce the same RiskFinding output format.

### Rationale
ML supply chain risks span two distinct surfaces — what you install (packages) and what you download (models). A unified risk taxonomy makes findings comparable and aggregatable across both surfaces. The FP-03 PQC scanner pattern (detection → risk scoring → CLI output) transfers directly.

---

## ADR-0002: Curated CVE list instead of full NVD matching

- **Date:** 2026-03-15
- **Status:** Accepted

### Decision
Use a curated list of 10 high-profile ML-specific CVEs rather than matching against the full NVD. Full NVD matching is a stretch goal.

### Rationale
The curated list covers the most impactful ML CVEs (LangChain RCE, PyTorch deserialization, TensorFlow DoS, MLflow RCE, Ray RCE). Full NVD matching adds complexity (338K CVEs × package name matching) for diminishing returns — most critical ML CVEs are in the curated list. FP-05 NVD data is available for the stretch goal.

---

## ADR-0003: Scan own projects first for validation

- **Date:** 2026-03-15
- **Status:** Accepted

### Decision
Validated the scanner on 5 own ML projects before scanning public repos. This produced real findings (20 across 5 projects) and proved the scanner works on actual ML codebases, not synthetic test fixtures.

### Rationale
Scanning your own code first is more honest than scanning stranger repos. The blog post angle "I scanned my own projects and found 13 CRITICAL" is more compelling and credible than "I scanned random repos." Also, this is the "builder-in-public" pillar — transparency about your own security posture.
