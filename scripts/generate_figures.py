#!/usr/bin/env python
"""Generate publication figures for FP-10."""
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path

def risk_categories():
    cats = ["Unsafe\nSerialization", "Known\nML CVEs", "Missing\nProvenance", "License\nRisk", "Untrusted\nSource"]
    counts = [10, 3, 2, 1, 1]
    traditional = [False, True, False, True, False]
    colors = ["#e74c3c" if not t else "#3498db" for t in traditional]
    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(cats, counts, color=colors, edgecolor="#2c3e50", linewidth=1.2)
    for bar, count in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2, str(count),
                ha="center", fontweight="bold", fontsize=12)
    ax.set_ylabel("Findings", fontsize=12)
    ax.set_title("AI Supply Chain Risks: What Traditional Scanners Miss", fontsize=13, fontweight="bold")
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    legend = [mpatches.Patch(facecolor="#e74c3c", label="Not covered by Snyk/Dependabot"),
              mpatches.Patch(facecolor="#3498db", label="Partially covered")]
    ax.legend(handles=legend, fontsize=10)
    plt.tight_layout()
    for p in ["outputs/figures/risk_categories.png", "blog/images/risk_categories.png"]:
        Path(p).parent.mkdir(parents=True, exist_ok=True); plt.savefig(p, dpi=150)
    print("Generated: risk_categories.png")

def project_findings():
    projects = ["FP-01\nIDS", "FP-05\nVuln", "FP-02\nAgents", "FP-03\nPQC", "FP-04\nFraud"]
    findings = [9, 7, 1, 2, 0]
    critical = [7, 5, 1, 0, 0]
    x = np.arange(len(projects)); width = 0.35
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width/2, findings, width, label="Total Findings", color="#3498db", edgecolor="#2c3e50")
    ax.bar(x + width/2, critical, width, label="Critical", color="#e74c3c", edgecolor="#2c3e50")
    for i, (f, c) in enumerate(zip(findings, critical)):
        ax.text(x[i]-width/2, f+0.2, str(f), ha="center", fontsize=10, fontweight="bold")
        ax.text(x[i]+width/2, c+0.2, str(c), ha="center", fontsize=10, fontweight="bold", color="#c0392b")
    ax.set_ylabel("Count", fontsize=12)
    ax.set_title("Supply Chain Findings Across 5 ML Projects", fontsize=13, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(projects); ax.legend(fontsize=11)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    plt.tight_layout()
    for p in ["outputs/figures/project_findings.png", "blog/images/project_findings.png"]:
        plt.savefig(p, dpi=150)
    print("Generated: project_findings.png")

def cross_domain():
    domains = ["FP-01\nIDS", "FP-05\nCVE", "FP-02\nAgents", "FP-03\nCrypto", "FP-04\nFraud", "FP-10\nSupply"]
    dev_ctrl = [57, 13, 3, 20, 12, 75]
    sys_ctrl = [14, 11, 2, 70, 6, 25]
    x = np.arange(len(domains)); width = 0.35
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(x - width/2, dev_ctrl, width, label="Attacker/Developer-Controlled", color="#e74c3c", edgecolor="#2c3e50")
    ax.bar(x + width/2, sys_ctrl, width, label="System/External-Controlled", color="#3498db", edgecolor="#2c3e50")
    for i, (d, s) in enumerate(zip(dev_ctrl, sys_ctrl)):
        ax.text(x[i]-width/2, d+1, str(d), ha="center", fontsize=9, fontweight="bold")
        ax.text(x[i]+width/2, s+1, str(s), ha="center", fontsize=9, fontweight="bold")
    ax.set_ylabel("Count / %", fontsize=11)
    ax.set_title("Adversarial Control Analysis: 6 Domains, 1 Methodology", fontsize=13, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels(domains, fontsize=10); ax.legend(fontsize=10)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    plt.tight_layout()
    for p in ["outputs/figures/cross_domain_6.png", "blog/images/cross_domain_6.png"]:
        plt.savefig(p, dpi=150)
    print("Generated: cross_domain_6.png")

if __name__ == "__main__":
    print("Generating FP-10 figures...")
    risk_categories(); project_findings(); cross_domain()
    print("Done.")
