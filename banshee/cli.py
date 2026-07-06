"""
BANSHEE CLI — command-line interface for the BANSHEE toolkit.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="banshee",
    help="BANSHEE — memory security, integrity, and forensics toolkit.",
    add_completion=False,
)
console = Console()


@app.command("version")
def version() -> None:
    """Print the BANSHEE version."""
    from banshee import __version__
    console.print(f"banshee v{__version__}")


@app.command("scan")
def scan(
    input_file: Path = typer.Argument(..., help="Path to a JSON file containing memory entries."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write scan report to this JSON file."),
) -> None:
    """Run a full security scan on a memory store loaded from a JSON file."""
    import uuid
    from banshee.models import MemoryEntry
    from banshee.security.scanner import MemoryScanner

    if not input_file.exists():
        console.print(f"[red]File not found:[/red] {input_file}")
        raise typer.Exit(code=1)

    raw = json.loads(input_file.read_text(encoding="utf-8"))
    entries = [MemoryEntry(**item) for item in raw]

    scanner = MemoryScanner()
    report = scanner.scan(entries)
    summary = report.summary()

    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="dim")
    table.add_column("Value", justify="right")

    for key, value in summary.items():
        color = "red" if key in ("critical_findings", "tampered") and value > 0 else "green"
        table.add_row(key.replace("_", " ").title(), f"[{color}]{value}[/{color}]")

    console.print(table)

    if output:
        result = {
            "summary": summary,
            "findings": [f.model_dump(mode="json") for f in report.forensic_findings],
        }
        output.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")


@app.command("verify")
def verify_entry(
    content: str = typer.Argument(..., help="Content string to verify."),
    checksum: str = typer.Argument(..., help="Expected checksum in format 'algorithm:digest'."),
) -> None:
    """Verify a content string against a stored checksum."""
    from banshee.integrity.checksums import verify_checksum

    try:
        ok = verify_checksum(content, checksum)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

    if ok:
        console.print("[green]✓ Checksum verified — content is intact.[/green]")
    else:
        console.print("[red]✗ Checksum mismatch — content may have been tampered with.[/red]")
        raise typer.Exit(code=2)


@app.command("checksum")
def checksum_cmd(
    content: str = typer.Argument(..., help="Content to hash."),
    algorithm: str = typer.Option("sha256", "--algorithm", "-a", help="Hash algorithm (sha256, sha512, blake2b)."),
) -> None:
    """Compute and print the checksum of a content string."""
    from banshee.integrity.checksums import compute_checksum

    try:
        result = compute_checksum(content, algorithm=algorithm)  # type: ignore[arg-type]
        console.print(result)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1)

@app.command("timeline")
def timeline(
    start_time: str = typer.Argument(..., help="Start time in ISO format (e.g., 2026-01-01T00:00:00)"),
    end_time: str = typer.Argument(..., help="End time in ISO format"),
    db_path: str = typer.Option("banshee_audit.db", "--db", "-d", help="Path to the SQLite audit database"),
) -> None:
    """Reconstruct an incident timeline from the Banshee Audit SQLite Database."""
    from banshee.forensics.timeline import TimelineGenerator
    
    generator = TimelineGenerator(db_path)
    events = generator.generate_timeline(start_time, end_time)
    
    if not events:
        console.print(f"[yellow]No events found between {start_time} and {end_time}[/yellow]")
        return
        
    table = Table(title="Incident Timeline", show_header=True, header_style="bold magenta")
    table.add_column("Timestamp", style="dim")
    table.add_column("Category")
    table.add_column("Action")
    table.add_column("Risk")
    table.add_column("Decision")
    
    for e in events:
        risk = e.get("aggregate_risk", "none")
        color = "red" if risk in ("critical", "high") else "green" if risk == "none" else "yellow"
        table.add_row(
            e["timestamp"],
            e["event_category"],
            e["event_action"],
            f"[{color}]{risk}[/{color}]",
            e["decision_action"]
        )
        
    console.print(table)


if __name__ == "__main__":
    app()
