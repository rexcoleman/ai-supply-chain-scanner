# Substack Email Intro

> Paste BEFORE the full blog post content in Substack editor.

**Subject line:** pickle.load is the #1 ML supply chain risk. Your scanner doesn't check for it.

---

I scanned 5 of my own ML projects for supply chain risks. Found 20 findings — 13 critical. The #1 risk isn't a model poisoning attack. It's `pickle.load` — half of all findings are unsafe serialization that gives attackers arbitrary code execution when you load a model.

Snyk and Dependabot don't check for this. I built a scanner that does.

The full post covers the 7 risk categories, why 4 are invisible to traditional tools, and why 75% of the fixes are one-line code changes.
