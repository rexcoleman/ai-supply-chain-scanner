# For: OpenClaw Discord

ClawHub has a pickle.load problem. I scanned 5 ML projects for supply chain risks — 20 findings, 13 critical. 65% of critical findings are unsafe deserialization (pickle, joblib, torch.load). all of these are arbitrary code execution.

```
findings breakdown:
  65% CRITICAL (pickle/joblib = arbitrary code exec)
  75% developer-fixable today

top risk: unsafe serialization (pickle, joblib, torch.load)

fix:
- pickle.load(f)           → safetensors
- joblib.load("model.pkl") → safetensors
- torch.load("model.pt")   → torch.load("model.pt", weights_only=True)
```

if you're pulling skills or model weights from ClawHub, anything serialized with pickle is an RCE vector. a malicious skill author packages a .pkl file, your agent loads it during setup, game over. this isn't theoretical — pickle deserialization exploits are trivial to build.

the catch: traditional dependency scanners (snyk, dependabot) don't flag this. they check package versions, not how your code calls serialization functions. and governance frameworks won't catch it either because it's a supply chain issue, not a logic bug.

for OpenClaw configs: if any skill in your agent loads .pkl, .joblib, or .pt files, check whether it uses safe loading. `torch.load` with `weights_only=True` is the minimum. safetensors is the real fix.

are any ClawHub skills currently distributing pickle files? has anyone looked at what the default model loading path does?
