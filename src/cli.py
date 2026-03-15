"""CLI for AI Supply Chain Security Scanner.

Usage:
    ai-supply-scan check --repo ~/my-project          # Scan project dependencies
    ai-supply-scan model --id bert-base-uncased        # Scan a HF model
    ai-supply-scan model --id meta-llama/Llama-2-7b    # Scan with org namespace
    ai-supply-scan report --input scan_report.json     # Generate report from saved scan
"""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanners.dependency_scanner import scan_project
from src.scanners.model_scanner import scan_model
from src.core.risk_categories import Severity


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="ai-supply-scan")
def cli():
    """AI Supply Chain Security Scanner — find risks in your ML pipeline."""
    pass


@cli.command()
@click.option("--repo", required=True, help="Path to ML project to scan")
@click.option("--output", default=None, help="Save JSON report")
@click.option("--verbose", is_flag=True)
def check(repo, output, verbose):
    """Scan an ML project's dependencies for supply chain risks."""
    repo_path = Path(repo).expanduser()
    if not repo_path.exists():
        console.print(f"[red]Error: {repo_path} does not exist[/red]")
        sys.exit(1)

    console.print(f"\n[bold]AI Supply Chain Scanner v0.1.0[/bold]")
    console.print(f"Scanning: {repo_path}\n")

    result = scan_project(str(repo_path))

    # Summary
    table = Table(title="Dependency Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Packages scanned", str(result.packages_scanned))
    table.add_row("Total findings", str(len(result.findings)))
    table.add_row("[red]Critical[/red]", str(result.by_severity.get("critical", 0)))
    table.add_row("[yellow]High[/yellow]", str(result.by_severity.get("high", 0)))
    table.add_row("Medium", str(result.by_severity.get("medium", 0)))
    table.add_row("Low", str(result.by_severity.get("low", 0)))
    console.print(table)

    # Category breakdown
    if result.by_category:
        console.print("\n[bold]Risk Categories:[/bold]")
        cat_table = Table()
        cat_table.add_column("Category")
        cat_table.add_column("Count", justify="right")
        for cat, count in sorted(result.by_category.items(), key=lambda x: -x[1]):
            cat_table.add_row(cat, str(count))
        console.print(cat_table)

    # Findings detail
    if result.findings:
        console.print(f"\n[bold]Findings ({len(result.findings)}):[/bold]")
        for f in result.findings:
            sev_color = {"critical": "red bold", "high": "yellow", "medium": "cyan", "low": "dim"}.get(
                f.severity.value, "white")
            console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] "
                         f"[{f.category}] {f.component}: {f.description[:100]}")
            if verbose:
                console.print(f"    Remediation: {f.remediation}")
                console.print(f"    Evidence: {f.evidence[:150]}")
                if f.cve_id:
                    console.print(f"    CVE: {f.cve_id}")

    if output:
        report = {
            "scan_type": "dependency",
            "project": str(repo_path),
            "packages_scanned": result.packages_scanned,
            "total_findings": len(result.findings),
            "by_severity": result.by_severity,
            "by_category": result.by_category,
            "findings": [
                {"category": f.category, "severity": f.severity.value,
                 "controllability": f.controllability.value,
                 "component": f.component, "description": f.description,
                 "cve_id": f.cve_id}
                for f in result.findings
            ],
        }
        with open(output, "w") as fp:
            json.dump(report, fp, indent=2)
        console.print(f"\n[green]Report saved: {output}[/green]")

    # Exit code
    criticals = result.by_severity.get("critical", 0)
    if criticals > 0:
        console.print(f"\n[red bold]⚠ {criticals} CRITICAL findings[/red bold]")
        sys.exit(2)
    elif result.by_severity.get("high", 0) > 0:
        sys.exit(1)


@cli.command()
@click.option("--id", "model_id", required=True, help="Hugging Face model ID")
@click.option("--output", default=None, help="Save JSON report")
@click.option("--verbose", is_flag=True)
def model(model_id, output, verbose):
    """Scan a Hugging Face model for supply chain risks."""
    console.print(f"\n[bold]AI Supply Chain Scanner v0.1.0[/bold]")
    console.print(f"Scanning model: {model_id}\n")

    result = scan_model(model_id)

    # Metadata
    if result.metadata:
        meta_table = Table(title="Model Metadata")
        meta_table.add_column("Property")
        meta_table.add_column("Value")
        for k, v in result.metadata.items():
            meta_table.add_row(k, str(v)[:80])
        console.print(meta_table)

    # Findings
    console.print(f"\n[bold]Findings ({len(result.findings)}):[/bold]")
    for f in result.findings:
        sev_color = {"critical": "red bold", "high": "yellow", "medium": "cyan",
                     "low": "dim", "info": "dim"}.get(f.severity.value, "white")
        console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] "
                     f"[{f.category}] {f.description[:120]}")
        if verbose:
            console.print(f"    Remediation: {f.remediation}")

    if output:
        report = {
            "scan_type": "model",
            "model_id": model_id,
            "metadata": result.metadata,
            "total_findings": len(result.findings),
            "findings": [
                {"category": f.category, "severity": f.severity.value,
                 "controllability": f.controllability.value,
                 "description": f.description}
                for f in result.findings
            ],
        }
        with open(output, "w") as fp:
            json.dump(report, fp, indent=2)
        console.print(f"\n[green]Report saved: {output}[/green]")


if __name__ == "__main__":
    cli()
