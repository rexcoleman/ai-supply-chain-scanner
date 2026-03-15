# PUBLICATION PIPELINE — AI Supply Chain Security Scanner

<!-- version: 2.0 -->
<!-- created: 2026-03-15 -->

> **Authority:** Subordinate to PROJECT_BRIEF (Tier 1)

## 1) Target Venue
- [x] Blog (Hugo canonical)
- [x] Conference: BSides / DEF CON AI Village / Black Hat Arsenal
- [x] LinkedIn + Hacker News (highest-virality topic)

## 2) Content Identity

| Property | Value |
|----------|-------|
| **Title** | I Built the Snyk for AI Models: Here's What Your ML Pipeline Is Hiding |
| **Pillar** | AI Security Architecture (40%) |
| **Audience** | P1: ML engineers using Hugging Face. P2: Security teams. P3: AI hiring managers. |
| **Thesis** | Traditional scanners miss 4 of 7 AI supply chain risk categories. pickle.load is the SQL injection of ML. |
| **Shipped** | github.com/rexcoleman/ai-supply-chain-scanner |

### Voice Check
| Test | Pass? |
|------|-------|
| References built artifact | [x] Scanner with real findings |
| Shows work | [x] 20 findings across 5 projects |
| Avoids pundit framing | [x] "Here's What Your Pipeline Is Hiding" |
| Architecture diagram | [x] Cross-domain ACA (6 domains) |
| Links to repo | [x] |

## 4) Evidence Inventory

| Claim | Source |
|-------|--------|
| 20 findings across 5 projects | `outputs/*_scan.json` |
| 13 CRITICAL | Same |
| 50% are unsafe serialization | FINDINGS.md |
| 75% developer-controlled | FINDINGS.md §RQ3 |
| 6th domain ACA | FINDINGS.md §RQ3 |
| Traditional scanners miss 4 of 7 categories | `src/core/risk_categories.py` |

## 5) Distribution
- [ ] Hugo, Substack, dev.to, Hashnode, LinkedIn, HN (pending brand infra)
