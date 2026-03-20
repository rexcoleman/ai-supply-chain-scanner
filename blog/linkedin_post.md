# LinkedIn Post — AI Supply Chain Scanner

65% of ML supply chain findings are CRITICAL severity. 4 of 7 risk categories are invisible to Snyk and Dependabot.

The #1 finding across 5 ML projects: unsafe pickle serialization. Half of all findings are `pickle.load` calls that give attackers arbitrary code execution when you load a model file. One line of code. Full system access.

Traditional scanners watch your requirements.txt. Nobody watches your models.

I built an open-source scanner that covers both surfaces — dependencies AND models. Key results:

- 20 findings across 5 projects, 13 CRITICAL
- pickle/joblib serialization = 50% of all findings
- 75% of risks are developer-fixable (one-line changes)
- 4 risk categories that Snyk/Dependabot miss entirely

The fix for most findings: `pickle.load` → `safetensors`, `torch.load` → `weights_only=True`.

Are you scanning your ML models for supply chain risks? Or just your code dependencies?

*Link in first comment*
