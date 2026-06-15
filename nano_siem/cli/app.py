"""
app.py — NanoSIEM CLI

v1.0 commands:
  nano-siem run                    Start network listeners
  nano-siem tail <file>            Tail a local log file
  nano-siem parse-line <line>      Debug single log line
  nano-siem stats                  Show ring buffer stats

v2.0 commands (Detection Engineering):
  nano-siem validate <path>        Validate Sigma rule(s)
  nano-siem test-rule <path>       Run rule unit tests
  nano-siem coverage               Show ATT&CK coverage report
  nano-siem coverage --json        Output coverage as JSON
  nano-siem coverage --markdown    Output coverage as Markdown
  nano-siem list-rules             List all loaded rules

v3.0 commands (SOC Operations):
  nano-siem api                    Start REST API + WebSocket server
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    name="nano-siem",
    help="NanoSIEM v4.0 — AI Reasoning Edition\n\nSigma detection · Attack chain correlation · ML anomaly scoring · STIX 2.1 · SOC Dashboard · AI Reasoning",
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()

VERSION = "4.1.0"


# ── v1.0 Commands ─────────────────────────────────────────────────────────────

@app.command()
def run(
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Start NanoSIEM with network listeners (UDP/TCP syslog + TCP JSON)."""
    from nano_siem.main import run as _run
    asyncio.run(_run(config_path=config))


@app.command()
def tail(
    file: str = typer.Argument(..., help="Log file to tail"),
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config.yaml"),
) -> None:
    """Tail a local log file through the full detection pipeline."""
    from nano_siem.main import run as _run
    asyncio.run(_run(config_path=config, tail_file=file))


@app.command(name="parse-line")
def parse_line(
    line: str = typer.Argument(..., help="Raw log line to parse and normalize"),
) -> None:
    """Parse and normalize a single log line — useful for debugging rules."""
    from nano_siem.ingestion.normalizer import normalize
    from nano_siem.ingestion.parser import parse

    parsed = parse(line)
    event = normalize(parsed)
    event_dict = event.to_dict()

    table = Table(title="Normalized Event", show_header=True, header_style="bold cyan")
    table.add_column("Field", style="cyan", width=16)
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
    rprint(f"[green]Events stored:[/green] {count:,} / {max_events:,}")
    buf.close()


# ── v2.0 Commands ─────────────────────────────────────────────────────────────

@app.command()
def validate(
    path: str = typer.Argument(..., help="Path to a .yml rule file or directory of rules"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as errors"),
) -> None:
    """
    Validate Sigma rule(s) — schema, AST, MITRE tags, completeness.

    [bold]Examples:[/bold]
      nano-siem validate rules/sample/ssh_brute_force.yml
      nano-siem validate rules/
      nano-siem validate rules/ --strict
    """
    from nano_siem.detection.validator import Severity, validate_rule, validate_rules_dir

    target = Path(path)
    if target.is_dir():
        reports = validate_rules_dir(target)
    else:
        reports = [validate_rule(target)]

    if not reports:
        rprint("[yellow]No .yml files found.[/yellow]")
        raise typer.Exit(1)

    total_errors = 0
    total_warnings = 0

    for report in reports:
        errors = report.errors
        warnings = report.warnings
        total_errors += len(errors)
        total_warnings += len(warnings)

        if strict:
            total_errors += len(warnings)

        status = "[green]✓ PASS[/green]" if report.passed else "[red]✗ FAIL[/red]"
        console.print(f"\n{status} [bold]{report.rule_title}[/bold]  [dim]{report.path}[/dim]")

        for result in report.results:
            if result.severity == Severity.ERROR:
                console.print(f"  [red]  ERROR[/red]   [{result.check}] {result.message}")
            elif result.severity == Severity.WARNING:
                console.print(f"  [yellow]  WARN[/yellow]    [{result.check}] {result.message}")
            else:
                console.print(f"  [dim]  INFO    [{result.check}] {result.message}[/dim]")

    console.print()
    console.print(f"[bold]Results:[/bold] {len(reports)} rules | "
                  f"[red]{total_errors} errors[/red] | "
                  f"[yellow]{total_warnings} warnings[/yellow]")

    if total_errors > 0:
        raise typer.Exit(1)


@app.command(name="test-rule")
def test_rule(
    path: str = typer.Argument(..., help="Path to a .yml rule file or directory"),
    fixture: str = typer.Option(None, "--fixture", "-f", help="Explicit fixture file path"),
) -> None:
    """
    Run unit tests for Sigma rule(s) against test fixtures.

    [bold]Examples:[/bold]
      nano-siem test-rule rules/sample/ssh_brute_force.yml
      nano-siem test-rule rules/
    """
    from nano_siem.detection.rule_tester import run_all_rule_tests, run_rule_tests

    target = Path(path)

    if target.is_dir():
        reports = run_all_rule_tests(target)
        if not reports:
            rprint("[yellow]No rules with fixture files found in directory.[/yellow]")
            rprint("[dim]Create tests/fixtures/<rule_name>.fixture.yml to add tests.[/dim]")
            raise typer.Exit(0)
    else:
        reports = [run_rule_tests(target, fixture_path=fixture)]

    total_pass = 0
    total_fail = 0

    for report in reports:
        status = "[green]✓ PASS[/green]" if report.passed else "[red]✗ FAIL[/red]"

        if report.load_error:
            console.print(f"\n[yellow]⚠ SKIP[/yellow] [bold]{report.rule_title}[/bold] — {report.load_error}")
            continue

        console.print(f"\n{status} [bold]{report.rule_title}[/bold]  "
                      f"[dim]({report.pass_count}/{report.total} tests)[/dim]")

        for result in report.results:
            icon = "[green]✓[/green]" if result.passed else "[red]✗[/red]"
            console.print(f"  {icon} {result.test_case.description}  "
                          f"[dim]({result.elapsed_ms:.2f}ms)[/dim]")
            if not result.passed and not result.error:
                expected = "MATCH" if result.test_case.should_match else "NO MATCH"
                got = "MATCH" if result.actually_matched else "NO MATCH"
                console.print(f"    [red]Expected: {expected}, Got: {got}[/red]")
                console.print(f"    [dim]Log: {result.test_case.log[:100]}[/dim]")
            if result.error:
                console.print(f"    [red]Error: {result.error}[/red]")

        if report.passed:
            total_pass += 1
        else:
            total_fail += 1

    console.print()
    console.print(f"[bold]Results:[/bold] {total_pass} passed, {total_fail} failed")

    if total_fail > 0:
        raise typer.Exit(1)


@app.command()
def coverage(
    rules_dir: str = typer.Option("rules/", "--rules", "-r", help="Rules directory"),
    output_format: str = typer.Option("table", "--format", "-f",
                                      help="Output format: table | json | markdown"),
    output_file: str = typer.Option(None, "--output", "-o", help="Write output to file"),
) -> None:
    """
    Show MITRE ATT&CK coverage across all loaded Sigma rules and correlation chains.

    [bold]Examples:[/bold]
      nano-siem coverage
      nano-siem coverage --format json --output coverage.json
      nano-siem coverage --format markdown --output coverage.md
    """
    from nano_siem.correlation.chains import BUILTIN_CHAINS
    from nano_siem.detection.coverage import TACTIC_ORDER, build_coverage_report
    from nano_siem.detection.mitre import REGISTRY
    from nano_siem.sigma.loader import load_rules_dir

    rules = load_rules_dir(rules_dir)
    report = build_coverage_report(rules, BUILTIN_CHAINS)

    if output_format == "json":
        content = report.to_json()
        if output_file:
            Path(output_file).write_text(content)
            rprint(f"[green]Coverage report written to {output_file}[/green]")
        else:
            print(content)

    elif output_format == "markdown":
        content = report.to_markdown()
        if output_file:
            Path(output_file).write_text(content)
            rprint(f"[green]Coverage report written to {output_file}[/green]")
        else:
            print(content)

    else:
        console.print()
        console.print(Panel(
            f"[bold]NanoSIEM ATT&CK Coverage Report[/bold]\n"
            f"Rules: [cyan]{report.total_rules}[/cyan]  "
            f"Chains: [cyan]{report.total_chains}[/cyan]  "
            f"Techniques covered: [green]{report.total_techniques_covered}[/green] / "
            f"{len(REGISTRY)}  "
            f"Coverage: [{'green' if report.coverage_percent > 30 else 'yellow'}]"
            f"{report.coverage_percent:.1f}%[/]",
            title="ATT&CK Coverage",
        ))

        for tactic in TACTIC_ORDER:
            entries = report.tactics.get(tactic, [])
            if not entries:
                continue

            table = Table(title=f"[bold]{tactic}[/bold]", show_header=True,
                          header_style="bold magenta", expand=False)
            table.add_column("Technique", style="cyan", width=35)
            table.add_column("ID", style="yellow", width=12)
            table.add_column("Covered By", style="white")

            for entry in entries:
                covered = []
                covered.extend(f"Rule: {r}" for r in entry.covered_by_rules)
                covered.extend(f"Chain: {c}" for c in entry.covered_by_chains)
                table.add_row(
                    entry.technique.name,
                    entry.technique.full_id,
                    "\n".join(covered) if covered else "—",
                )
            console.print(table)
            console.print()


@app.command(name="list-rules")
def list_rules(
    rules_dir: str = typer.Option("rules/", "--rules", "-r", help="Rules directory"),
    level: str = typer.Option(None, "--level", "-l",
                              help="Filter by level: informational|low|medium|high|critical"),
) -> None:
    """List all Sigma rules in the rules directory."""
    from nano_siem.sigma.loader import load_rules_dir

    rules = load_rules_dir(rules_dir)

    if level:
        rules = [r for r in rules if r.level.lower() == level.lower()]

    if not rules:
        rprint("[yellow]No rules found.[/yellow]")
        raise typer.Exit(0)

    table = Table(title=f"Sigma Rules ({len(rules)} loaded)", header_style="bold cyan")
    table.add_column("Level", width=10)
    table.add_column("Title", width=45)
    table.add_column("Status", width=12)
    table.add_column("MITRE Tags", width=30)
    table.add_column("File", width=30)

    level_colors = {
        "critical": "red", "high": "red", "medium": "yellow",
        "low": "blue", "informational": "dim",
    }
    level_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}

    for rule in sorted(rules, key=lambda r: -level_rank.get(r.level.lower(), 0)):
        color = level_colors.get(rule.level.lower(), "white")
        attack_tags = [t for t in rule.tags if t.startswith("attack.t")][:2]
        tags_str = ", ".join(attack_tags) if attack_tags else "—"
        table.add_row(
            f"[{color}]{rule.level.upper()}[/{color}]",
            rule.title,
            rule.status,
            tags_str,
            Path(rule.source_file).name,
        )

    console.print(table)
    console.print(f"\n[dim]Rules directory: {rules_dir}[/dim]")


# ── v3.0 Commands ─────────────────────────────────────────────────────────────

@app.command()
def api(
    host: str = typer.Option("0.0.0.0", "--host", help="API server host"),
    port: int = typer.Option(8000, "--port", "-p", help="API server port"),
    config: str = typer.Option("config.yaml", "--config", "-c", help="Path to config.yaml"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code changes (dev mode)"),
) -> None:
    """
    Start the NanoSIEM REST API + WebSocket server for the SOC dashboard.

    [bold]Examples:[/bold]
      nano-siem api
      nano-siem api --port 8080
      nano-siem api --reload   (dev mode)
    """
    import os
    os.environ["NANOSIEM_CONFIG"] = config
    try:
        import uvicorn
    except ImportError:
        rprint("[red]uvicorn not installed. Run: pip install uvicorn[/red]")
        raise typer.Exit(1)

    rprint(f"[bold cyan]NanoSIEM API v{VERSION}[/bold cyan] starting on [green]http://{host}:{port}[/green]")
    rprint(f"[dim]Docs: http://{host}:{port}/docs[/dim]")
    rprint(f"[dim]WebSocket: ws://{host}:{port}/ws/events[/dim]")
    rprint("[dim]Dashboard: http://localhost:5173 (run: cd dashboard && npm run dev)[/dim]")
    rprint()

    uvicorn.run(
        "nano_siem.api.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ── Main callback ─────────────────────────────────────────────────────────────


@app.command()
def quality(
    rules_dir: str = typer.Option("rules/", "--rules", "-r", help="Rules directory"),
    sort_by: str = typer.Option("maintenance", "--sort", "-s",
                                help="Sort by: maintenance | specificity | complexity | fp_risk"),
) -> None:
    """
    Show rule quality metrics — complexity, specificity, FP risk, overlaps.

    [bold]Examples:[/bold]
      nano-siem quality
      nano-siem quality --sort fp_risk
    """
    from nano_siem.detection.quality import assess_all_rules
    from nano_siem.sigma.loader import load_rules_dir

    rules = load_rules_dir(rules_dir)
    if not rules:
        rprint("[yellow]No rules found.[/yellow]")
        raise typer.Exit(0)

    reports = assess_all_rules(rules)

    sort_keys = {
        "maintenance": lambda r: r.maintenance_score,
        "specificity": lambda r: r.specificity_score,
        "complexity": lambda r: -r.complexity_score,
        "fp_risk": lambda r: {"high": 0, "medium": 1, "low": 2}[r.fp_risk],
    }
    reports.sort(key=sort_keys.get(sort_by, sort_keys["maintenance"]))

    table = Table(title=f"Rule Quality Report ({len(reports)} rules)", header_style="bold cyan")
    table.add_column("Maintenance", width=12)
    table.add_column("Rule", width=38)
    table.add_column("Specificity", width=12)
    table.add_column("Complexity", width=11)
    table.add_column("FP Risk", width=9)
    table.add_column("Overlaps", width=30)

    risk_colors = {"low": "green", "medium": "yellow", "high": "red"}

    for r in reports:
        score_color = "green" if r.maintenance_score >= 70 else "yellow" if r.maintenance_score >= 40 else "red"
        risk_color = risk_colors[r.fp_risk]
        overlaps = ", ".join(r.overlaps_with[:2]) if r.overlaps_with else "—"
        if len(r.overlaps_with) > 2:
            overlaps += f" (+{len(r.overlaps_with)-2})"
        table.add_row(
            f"[{score_color}]{r.maintenance_score}/100[/{score_color}]",
            r.rule_title,
            f"{r.specificity_score:.0f}/100",
            str(r.complexity_score),
            f"[{risk_color}]{r.fp_risk.upper()}[/{risk_color}]",
            overlaps,
        )

    console.print(table)

    high_risk = [r for r in reports if r.fp_risk == "high"]
    if high_risk:
        console.print("\n[bold red]High FP-risk rules — reasons:[/bold red]")
        for r in high_risk:
            console.print(f"  [bold]{r.rule_title}[/bold]")
            for reason in r.fp_risk_reasons:
                console.print(f"    [dim]- {reason}[/dim]")

    avg_score = sum(r.maintenance_score for r in reports) / len(reports)
    console.print(f"\n[bold]Average maintenance score:[/bold] {avg_score:.1f}/100")


@app.command(name="watch-rules")
def watch_rules(
    rules_dir: str = typer.Option("rules/", "--rules", "-r", help="Rules directory"),
    interval: float = typer.Option(5.0, "--interval", "-i", help="Check interval (seconds)"),
    once: bool = typer.Option(False, "--once", help="Check once and exit (don't loop)"),
) -> None:
    """
    Watch a rules directory for changes and hot-reload (validates before swapping).

    [bold]Examples:[/bold]
      nano-siem watch-rules
      nano-siem watch-rules --once
      nano-siem watch-rules --interval 2
    """
    import time as _time

    from nano_siem.detection.hot_reload import HotReloadManager

    manager = HotReloadManager(rules_dir, check_interval=interval)
    rprint(f"[cyan]Watching[/cyan] {rules_dir} ({manager.rule_count} rules loaded) "
          f"[dim]every {interval}s[/dim]")

    if once:
        changed, rules, event = manager.check_once()
        if not changed:
            rprint("[dim]No changes detected.[/dim]")
        elif event and event.success:
            rprint(f"[green]✓ Reloaded[/green] — {event.rule_count} rules, "
                  f"changed: {', '.join(event.changed_files)}")
        elif event:
            rprint("[red]✗ Reload aborted[/red] — validation errors:")
            for err in event.errors:
                rprint(f"  [red]{err}[/red]")
        raise typer.Exit(0)

    rprint("[dim]Press Ctrl+C to stop.[/dim]\n")
    try:
        while True:
            changed, rules, event = manager.check_once()
            if changed and event:
                if event.success:
                    rprint(f"[green]✓ Reloaded[/green] — {event.rule_count} rules, "
                          f"changed: {', '.join(event.changed_files)}")
                else:
                    rprint("[red]✗ Reload aborted[/red] — keeping previous rule set")
                    for err in event.errors:
                        rprint(f"  [red]{err}[/red]")
            _time.sleep(interval)
    except KeyboardInterrupt:
        stats = manager.get_stats()
        rprint(f"\n[dim]Stopped. Total reloads: {stats['total_reloads']} "
              f"({stats['successful_reloads']} ok, {stats['failed_reloads']} failed)[/dim]")


@app.command()
def enrich(
    ip: str = typer.Argument(..., help="IP address to enrich"),
) -> None:
    """
    Enrich an IP address with geolocation and reputation data.

    [bold]Examples:[/bold]
      nano-siem enrich 8.8.8.8
      nano-siem enrich 192.168.1.1
    """
    from nano_siem.enrichment.threat_intel import ThreatIntelEnricher

    enricher = ThreatIntelEnricher()
    result = asyncio.run(enricher.enrich(ip))

    if result.is_private:
        rprint(f"[cyan]{ip}[/cyan] is a [dim]private/reserved[/dim] address — no external lookup performed")
        raise typer.Exit(0)

    if result.error and not result.sources:
        rprint(f"[red]Enrichment failed:[/red] {result.error}")
        raise typer.Exit(1)

    risk_colors = {"low": "green", "medium": "yellow", "high": "red", "unknown": "dim"}
    risk_color = risk_colors[result.risk_level]

    panel_lines = []
    if result.country:
        panel_lines.append(f"Location: {result.city}, {result.region}, {result.country} ({result.country_code})")
    if result.isp:
        panel_lines.append(f"ISP: {result.isp}")
    if result.org:
        panel_lines.append(f"Org: {result.org}")
    if result.asn:
        panel_lines.append(f"ASN: {result.asn}")
    if result.is_proxy:
        panel_lines.append("[yellow]⚠ Known proxy/VPN[/yellow]")
    if result.is_hosting:
        panel_lines.append("[yellow]⚠ Hosting/datacenter IP[/yellow]")
    if result.abuse_score is not None:
        panel_lines.append(f"Abuse Score: [{risk_color}]{result.abuse_score}/100[/{risk_color}] "
                          f"({result.abuse_reports} reports)")
        if result.abuse_categories:
            panel_lines.append(f"Categories: {', '.join(result.abuse_categories)}")
    elif not enricher.has_abuseipdb:
        panel_lines.append("[dim]Set ABUSEIPDB_API_KEY for reputation data[/dim]")

    console.print(Panel(
        "\n".join(panel_lines),
        title=f"[bold]{ip}[/bold] — [{risk_color}]{result.risk_level.upper()} RISK[/{risk_color}]",
    ))
    console.print(f"[dim]Sources: {', '.join(result.sources)}[/dim]")


@app.command()
def replay(
    alert_file: str = typer.Argument(..., help="Path to a saved alert JSON (STIX bundle or NDJSON line)"),
    with_ai: bool = typer.Option(False, "--ai", help="Add AI commentary per step (requires GEMINI_API_KEY)"),
) -> None:
    """
    Replay a correlation alert step-by-step.

    [bold]Examples:[/bold]
      nano-siem replay alerts/2026-06-09/alert-abc123-correlation.json
      nano-siem replay alert.json --ai
    """
    from nano_siem.reasoning.replay import build_replay, build_replay_with_commentary

    path = Path(alert_file)
    if not path.exists():
        rprint(f"[red]File not found: {alert_file}[/red]")
        raise typer.Exit(1)

    data = json.loads(path.read_text())

    if data.get("type") == "bundle":
        alert = {}
        for obj in data.get("objects", []):
            if obj.get("type") == "observed-data":
                custom = obj.get("custom_properties", {})
                alert = {
                    "alert_id": custom.get("x_nano_siem_alert_id", ""),
                    "alert_type": custom.get("x_nano_siem_alert_type", ""),
                    "severity": custom.get("x_nano_siem_severity", ""),
                    "title": next((o.get("name", "") for o in data["objects"] if o.get("type") == "indicator"), ""),
                    "source_key": custom.get("x_nano_siem_source", ""),
                    "mitre_tactic": custom.get("x_nano_siem_mitre_tactic", ""),
                    "mitre_techniques": custom.get("x_nano_siem_mitre_techniques", []),
                    "duration_seconds": custom.get("x_nano_siem_duration_seconds", 0),
                    "chain_steps": custom.get("x_nano_siem_chain_steps", []),
                    "chain_id": custom.get("x_nano_siem_chain_id", ""),
                    "timestamp": 0,
                }
    else:
        alert = data

    try:
        if with_ai:
            from nano_siem.reasoning.engine import ReasoningEngine
            engine = ReasoningEngine()
            if not engine.is_configured:
                rprint("[yellow]GEMINI_API_KEY not set — replaying without AI commentary[/yellow]")
                session = build_replay(alert)
            else:
                session = asyncio.run(build_replay_with_commentary(alert, engine))
        else:
            session = build_replay(alert)
    except ValueError as e:
        rprint(f"[red]{e}[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold]{session.chain_title}[/bold]\n"
        f"Severity: {session.severity.upper()} | Source: {session.source_key} | "
        f"Duration: {session.duration_seconds:.0f}s | "
        f"MITRE: {session.mitre_tactic} ({', '.join(session.mitre_techniques)})",
        title="Attack Replay",
    ))

    for step in session.steps:
        console.print(f"\n[bold cyan]Step {step.index + 1}/{session.step_count}[/bold cyan] — [bold]{step.step_name}[/bold]")
        console.print(f"  [dim]Log:[/dim] {step.message}")
        if step.commentary:
            console.print(f"  [green]AI:[/green] {step.commentary}")

    if session.summary:
        console.print(Panel(session.summary, title="[bold]Threat Narrative[/bold]"))


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version and exit"),
) -> None:
    """NanoSIEM — Production-grade SIEM engine with Sigma detection, attack chain correlation, ML anomaly scoring, STIX 2.1 export, SOC dashboard, and AI-powered incident reasoning."""
    if version:
        rprint(f"[bold cyan]NanoSIEM[/bold cyan] v{VERSION}")
        raise typer.Exit(0)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
