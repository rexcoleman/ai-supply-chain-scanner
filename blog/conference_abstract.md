# Conference Abstract — BSides / DEF CON AI Village / Black Hat Arsenal

## Title
The Snyk for AI: Scanning ML Supply Chains for Risks Traditional Tools Miss

## Abstract (250 words)

Traditional dependency scanners (Snyk, Dependabot) protect code dependencies but leave AI/ML supply chains unscanned. We present an open-source AI supply chain security scanner that identifies 7 risk categories in ML projects, 4 of which are invisible to existing tools: unsafe model serialization (pickle/joblib), missing model provenance, untrusted model sources, and deprecated ML algorithms.

Scanning 5 real ML projects (77 packages total), we found **20 supply chain risks including 13 CRITICAL** — primarily unsafe pickle serialization that enables arbitrary code execution when loading model files. This is the most prevalent ML-specific vulnerability: `pickle.load` on an untrusted file gives attackers full system access with no sandbox or validation.

The scanner operates on two attack surfaces: **dependencies** (project packages checked against known CVEs, serialization patterns, and staleness) and **models** (Hugging Face model metadata checked for provenance, serialization format, license, and source trust).

Applying **adversarial controllability analysis** — now validated across 6 security domains (network IDS, vulnerability prediction, AI agent red-teaming, post-quantum crypto, financial fraud, and supply chain) — we find that **75% of supply chain risks are developer-controlled**, meaning most fixes are one-line code changes (pickle → safetensors, torch.load → weights_only=True).

All scan results and the scanner itself are open source.

## Keywords
AI supply chain security, model serialization, pickle, safetensors, dependency scanning, Hugging Face, adversarial controllability

## Bio
Rex Coleman is an MS Computer Science student (Machine Learning) at Georgia Tech. Previously 15 years in cybersecurity (FireEye/Mandiant — analytics, enterprise sales, cross-functional leadership). CFA charterholder. Creator of govML.
