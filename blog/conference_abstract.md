# Conference Abstract — BSides / DEF CON AI Village / Black Hat Arsenal

## Title
The Snyk for AI: Scanning ML Supply Chains for Risks Traditional Tools Miss

## Abstract (250 words)

Traditional dependency scanners (Snyk, Dependabot) protect code dependencies but leave AI/ML supply chains unscanned. Four critical risk categories are invisible to existing tools: unsafe model serialization (pickle/joblib), missing model provenance, untrusted model sources, and deprecated ML algorithms. A single pickle.load on an untrusted model file gives attackers full system access.

We built an open-source scanner covering 7 risk categories across two attack surfaces — dependencies (CVEs, serialization patterns, staleness) and models (Hugging Face provenance, format, license, trust). Scanning 5 real ML projects (77 packages), we found 20 supply chain risks including 13 CRITICAL, primarily unsafe pickle serialization. Adversarial controllability analysis — validated across 6 security domains — shows 75% of these risks are developer-controlled, meaning most fixes are one-line code changes (pickle to safetensors, torch.load with weights_only=True).

Attendees will leave with a working scanner they can run against their own ML projects, a 7-category risk taxonomy for ML supply chains, and concrete one-line fixes for the most prevalent vulnerabilities. All code and scan results are open source.

## Keywords
AI supply chain security, model serialization, pickle, safetensors, dependency scanning, Hugging Face, adversarial controllability

## Bio
Rex Coleman is an MS Computer Science student (Machine Learning) at Georgia Tech. Previously 15 years in cybersecurity (FireEye/Mandiant — analytics, enterprise sales, cross-functional leadership). CFA charterholder. Creator of govML.
