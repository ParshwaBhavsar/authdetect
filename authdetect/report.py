"""
Report rendering: turns Alert objects into analyst-friendly output.

Modes:
  render_terminal   – colour-coded rich table, one row per alert
  render_json       – NDJSON stream, one JSON object per alert (pipe to jq etc.)
  render_summary    – concise stats block after a batch run
"""

from __future__ import annotations

import json
from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .model import Alert, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH:     "bold red",
    Severity.MEDIUM:   "bold yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim",
}

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


def render_terminal(alerts: list[Alert], console: Console | None = None) -> None:
    """Print a colour-coded table of alerts to the terminal."""
    console = console or Console()
    if not alerts:
        console.print("[dim]No alerts triggered.[/dim]")
        return

    table = Table(title=f"authdetect — {len(alerts)} alert(s)", expand=True)
    table.add_column("Sev",      width=8)
    table.add_column("Rule ID",  style="dim", width=16)
    table.add_column("Timestamp", width=20)
    table.add_column("Src IP",   width=16)
    table.add_column("User",     width=14)
    table.add_column("Alert",    ratio=1)

    for alert in sorted(alerts, key=lambda a: (
        list(Severity).index(a.severity), a.timestamp
    )):
        sev_text = Text(
            f"{_SEVERITY_ICON[alert.severity]} {alert.severity.value.upper()}",
            style=_SEVERITY_STYLE[alert.severity],
        )
        ts = alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        body = Text()
        body.append(alert.rule_title + "\n", style="bold")
        if alert.context:
            detail = _format_context(alert.context)
            body.append(detail, style="dim")
        if alert.mitre.get("techniques"):
            techs = ", ".join(alert.mitre["techniques"])
            body.append(f"\n[MITRE] {techs}", style="dim cyan")

        table.add_row(
            sev_text,
            alert.rule_id,
            ts,
            alert.src_ip or "—",
            alert.user or "—",
            body,
        )

    console.print(table)


def render_json(alerts: list[Alert], console: Console | None = None) -> None:
    """Emit one JSON object per alert — NDJSON for piping into a SIEM or jq."""
    console = console or Console(highlight=False)
    for alert in alerts:
        console.print(json.dumps(alert.to_dict()))


def render_summary(
    alerts: list[Alert],
    total_events: int,
    console: Console | None = None,
) -> None:
    """Print a brief stats block (total events, alert counts by severity)."""
    console = console or Console()
    sev_counts = Counter(a.severity for a in alerts)
    rule_counts = Counter(a.rule_title for a in alerts)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", width=24)
    grid.add_column()

    grid.add_row("Events processed:", f"{total_events:,}")
    grid.add_row("Total alerts:", str(len(alerts)))
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO):
        if sev in sev_counts:
            icon = _SEVERITY_ICON[sev]
            style = _SEVERITY_STYLE[sev]
            grid.add_row(
                f"  {icon} {sev.value.upper()}:",
                Text(str(sev_counts[sev]), style=style),
            )

    if rule_counts:
        grid.add_row("Top rules:", "")
        for rule_title, count in rule_counts.most_common(5):
            grid.add_row(f"  {rule_title[:40]}", str(count))

    console.print(Panel(grid, title="Summary", expand=False))


def _format_context(ctx: dict) -> str:
    parts = []
    if "count" in ctx and "timeframe_s" in ctx:
        parts.append(f"{ctx['count']} events in {ctx['timeframe_s']}s")
    if "group_value" in ctx and ctx["group_value"] != "_all_":
        parts.append(f"{ctx.get('group_by', 'key')}={ctx['group_value']}")
    return " · ".join(parts) if parts else ""
