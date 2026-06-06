"""
app.py — CLI Entry Point

Commands:
  nano-siem run                  Start the full pipeline (network listeners)
  nano-siem tail <file>          Tail a local log file through the pipeline
  nano-siem parse <line>         Parse and normalize a single log line (debug)
  nano-siem stats                Show stats from the SQLite ring buffer
"""

from __future__ import annotations
import asyncio
import json
import sys
import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

app = typer.Typer(
    name="nano-siem",
    help="Lightweight SIEM engine — Sigma + Correlation + ML + STIX",
    add_completion=False,
)
console = Console()


@app.command()
def run(
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Start nano-siem with network listeners (UDP syslog + TCP JSON)."""
    from nano_siem.main import run as _run
    asyncio.run(_run(config_path=config))


@app.command()
def tail(
    file: str = typer.Argument(..., help="Log file to tail"),
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Tail a local log file through the pipeline."""
    from nano_siem.main import run as _run
    asyncio.run(_run(config_path=config, tail_file=file))


@app.command()
def parse_line(
    line: str = typer.Argument(..., help="Raw log line to parse"),
) -> None:
    """Parse and normalize a single log line — useful for testing."""
    from nano_siem.ingestion.parser import parse
    from nano_siem.ingestion.normalizer import normalize

    parsed = parse(line)
    event = normalize(parsed)
    event_dict = event.to_dict()

    table = Table(title="Normalized Event", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    for key, val in event_dict.items():
        if val is None or val == [] or val == {}:
            continue
        display_val = json.dumps(val) if isinstance(val, (dict, list)) else str(val)
        if len(display_val) > 120:
            display_val = display_val[:117] + "..."
        table.add_row(key, display_val)

    console.print(table)


@app.command()
def stats(
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Show event counts from the SQLite ring buffer."""
    import yaml
    from nano_siem.storage.ringbuffer import EventRingBuffer

    with open(config) as f:
        cfg = yaml.safe_load(f)

    db_path = cfg.get("storage", {}).get("db_path", "data/events.db")
    max_events = cfg.get("storage", {}).get("max_events", 100_000)
    buf = EventRingBuffer(db_path, max_events)

    count = asyncio.run(buf.count())
    rprint(f"[cyan]Ring buffer:[/cyan] {db_path}")
    rprint(f"[green]Total events stored:[/green] {count:,} / {max_events:,}")
    buf.close()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
