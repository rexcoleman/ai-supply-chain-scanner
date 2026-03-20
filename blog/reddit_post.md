# I scanned 5 ML projects for supply chain risks — found 20 findings, 13 critical, and half are just pickle.load

I built a scanner for AI/ML supply chain risks and pointed it at 5 of my own projects. Found 20 findings total, 13 critical. The number one risk isn't a sophisticated model poisoning attack — it's `pickle.load`. Half of all findings are unsafe serialization that gives attackers arbitrary code execution when you load a model. Traditional scanners like Snyk and Dependabot don't check for any of this.

The scanner covers two attack surfaces: dependencies (CVEs, unsafe serialization patterns in code, stale libraries) and models (Hugging Face provenance gaps, unsafe formats like .pkl vs .safetensors, license risks, untrusted sources). 4 of my 5 projects had findings, and the worst offenders use scikit-learn's default joblib/pickle serialization — which is what everyone uses.

Key findings:

- **65% of findings are CRITICAL severity** — because pickle.load on an untrusted file = arbitrary code execution with no sandbox, no validation, no defense
- **75% of findings are developer-fixable today** — replace pickle with safetensors, update torch.load to use weights_only=True, pin dependency versions
- **Traditional scanners miss the entire AI supply chain** — Snyk watches requirements.txt but nobody scans your model files or serialization patterns
- **Governance frameworks miss it too** — I built these projects with extensive research governance (experiment design, data splits, reproducibility) and none of it caught pickle.load because it's a supply chain issue, not an experiment design issue
- **The fix is usually one line** — `torch.load("model.pt", weights_only=True)` or switching to safetensors format

The irony of building AI security research projects that are themselves vulnerable to the most basic supply chain attack is not lost on me. pickle.load is the SQL injection of ML — boring, widespread, and the thing that'll actually get you.

Methodology: static analysis scanning for unsafe serialization patterns, dependency CVE checking, Hugging Face model provenance analysis. Controllability analysis shows 75% developer-controlled, 20% model-controlled, 5% platform-controlled.

Repo: [github.com/rexcoleman/ai-supply-chain-scanner](https://github.com/rexcoleman/ai-supply-chain-scanner)

Scanner is open source. Happy to answer questions or hear about what your ML supply chain looks like.
