"""
CLI for authdetect.

Commands:
  analyze        – process a log file and report alerts
  watch          – tail a growing log file in real time (Ctrl-C to stop)
  validate       – syntax-check all rules in a directory
  generate-logs  – write synthetic auth logs for testing/demos
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

from rich.console import Console

from . import __version__
from .engine import Engine
from .model import Severity
from .parsers import AuthLogParser, CombinedLogParser, JSONParser, auto_detect
from .report import render_json, render_summary, render_terminal
from .rule_loader import RuleLoadError, load_rule, load_rules_dir

_DEFAULT_RULES = os.path.join(os.path.dirname(__file__), "..", "rules")


# ── analyze ───────────────────────────────────────────────────────────────────

def _cmd_analyze(args: argparse.Namespace) -> int:
    console = Console()
    rules = _load_rules(args.rules, console)
    if not rules:
        console.print("[red]No rules loaded — nothing to evaluate.[/red]")
        return 1

    parser = _pick_parser(args)
    engine = Engine(rules)

    try:
        events = list(parser.parse_file(args.logfile))
    except FileNotFoundError:
        console.print(f"[red]Log file not found:[/red] {args.logfile}")
        return 2

    alerts = engine.process_events(events)

    if args.min_severity:
        order = list(Severity)
        min_idx = order.index(Severity(args.min_severity))
        alerts = [a for a in alerts if order.index(a.severity) <= min_idx]

    if args.format == "json":
        render_json(alerts)
    else:
        render_terminal(alerts, console)
        render_summary(alerts, total_events=len(events), console=console)

    return 1 if alerts else 0


# ── watch ─────────────────────────────────────────────────────────────────────

def _cmd_watch(args: argparse.Namespace) -> int:
    console = Console()
    rules = _load_rules(args.rules, console)
    if not rules:
        return 1

    parser = _pick_parser(args)
    engine = Engine(rules)

    console.print(
        f"[bold]authdetect watch[/bold] — tailing [cyan]{args.logfile}[/cyan]  "
        f"([dim]Ctrl-C to stop[/dim])"
    )

    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)   # seek to end — only process new lines
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                event = parser.parse_line(line.rstrip("\n"))
                if not event:
                    continue
                for alert in engine.process_event(event):
                    if args.format == "json":
                        print(json.dumps(alert.to_dict()))
                    else:
                        render_terminal([alert], console)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")
    except FileNotFoundError:
        console.print(f"[red]File not found:[/red] {args.logfile}")
        return 2
    return 0


# ── validate ──────────────────────────────────────────────────────────────────

def _cmd_validate(args: argparse.Namespace) -> int:
    console = Console()
    import glob

    paths: list[str] = []
    for pattern in (args.rules if isinstance(args.rules, list) else [args.rules]):
        if os.path.isdir(pattern):
            paths.extend(
                str(p)
                for p in __import__("pathlib").Path(pattern).rglob("*.y*ml")
            )
        else:
            paths.extend(glob.glob(pattern))

    ok = err = 0
    for path in sorted(paths):
        try:
            rule = load_rule(path)
            console.print(f"[green]✓[/green]  {rule.id:<24} {rule.title}")
            ok += 1
        except RuleLoadError as exc:
            console.print(f"[red]✗[/red]  {path}\n     [red]{exc}[/red]")
            err += 1

    console.print(f"\n{ok} valid, {err} errors")
    return 0 if err == 0 else 1


# ── generate-logs ─────────────────────────────────────────────────────────────

def _cmd_generate_logs(args: argparse.Namespace) -> int:
    """
    Write synthetic JSON auth logs that exercise all bundled detection rules.
    Safe — no real credentials or IPs; data is entirely fabricated.
    """
    import random

    console = Console()
    out_path = args.output
    now = datetime.now(tz=timezone.utc)

    lines: list[str] = []

    def _ts(offset_s: int) -> str:
        return (now - timedelta(seconds=offset_s)).isoformat()

    # 1. Brute force: 8 failed logins from 1.2.3.4 in 30s
    for i in range(8):
        lines.append(json.dumps({
            "timestamp": _ts(30 - i * 3),
            "src_ip": "1.2.3.4",
            "user": "admin",
            "method": "POST",
            "path": "/auth/login",
            "status_code": 401,
            "user_agent": "python-requests/2.31",
            "message": "Login failed",
        }))

    # 2. Password spray: 1 attempt each against 12 different accounts
    spray_users = [f"user{i:02d}@example.com" for i in range(12)]
    for i, user in enumerate(spray_users):
        lines.append(json.dumps({
            "timestamp": _ts(120 - i * 8),
            "src_ip": "5.6.7.8",
            "user": user,
            "method": "POST",
            "path": "/auth/login",
            "status_code": 401,
            "user_agent": "Mozilla/5.0",
            "message": "Login failed",
        }))

    # 3. Successful login (benign — should not alert)
    lines.append(json.dumps({
        "timestamp": _ts(200),
        "src_ip": "10.0.0.1",
        "user": "alice@example.com",
        "method": "POST",
        "path": "/auth/login",
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "message": "Login successful",
    }))

    # 4. JWT with alg:none
    import base64
    fake_header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    fake_payload = base64.urlsafe_b64encode(b'{"sub":"admin","exp":9999999999}').rstrip(b"=").decode()
    fake_token   = f"{fake_header}.{fake_payload}."
    lines.append(json.dumps({
        "timestamp": _ts(10),
        "src_ip": "9.8.7.6",
        "user": "attacker",
        "method": "GET",
        "path": "/api/admin/users",
        "status_code": 200,
        "Authorization": f"Bearer {fake_token}",
        "message": "Admin endpoint accessed",
    }))

    # 5. Token in URL
    lines.append(json.dumps({
        "timestamp": _ts(15),
        "src_ip": "11.22.33.44",
        "user": "bob",
        "method": "GET",
        "path": "/api/data?token=eyJhbGciOiJIUzI1NiJ9.e30.abc",
        "status_code": 200,
        "user_agent": "curl/7.88",
        "message": "API request with token in URL",
    }))

    # 6. Suspicious user agent (sqlmap / nikto)
    lines.append(json.dumps({
        "timestamp": _ts(5),
        "src_ip": "77.88.99.11",
        "user": None,
        "method": "GET",
        "path": "/auth/login",
        "status_code": 200,
        "user_agent": "sqlmap/1.7.8#stable (https://sqlmap.org)",
        "message": "Scan tool detected",
    }))

    # 7. API key brute force: rapid 403s on /api/ endpoints
    for i in range(6):
        lines.append(json.dumps({
            "timestamp": _ts(40 - i * 5),
            "src_ip": "33.44.55.66",
            "method": "GET",
            "path": f"/api/v1/resource/{random.randint(1, 100)}",
            "status_code": 403,
            "user_agent": "Burp Suite Community Edition",
            "message": "Forbidden",
        }))

    # 8. Session fixation attempt: session_id provided in a GET before login
    lines.append(json.dumps({
        "timestamp": _ts(60),
        "src_ip": "22.33.44.55",
        "user": None,
        "method": "GET",
        "path": "/auth/login?sessionid=ATTACKER_SUPPLIED_SESSION_12345",
        "status_code": 200,
        "session_id": "ATTACKER_SUPPLIED_SESSION_12345",
        "user_agent": "Mozilla/5.0",
        "message": "Pre-auth session ID in request",
    }))

    # shuffle slightly to test timestamp ordering
    random.shuffle(lines)

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    console.print(
        f"[green]Wrote {len(lines)} synthetic log events →[/green] {out_path}"
    )
    console.print("[dim]Run:[/dim]  python -m authdetect analyze --logfile "
                  f"{out_path} --rules rules/")
    return 0


# ── helpers ───────────────────────────────────────────────────────────────────

def _load_rules(rules_path: str, console: Console) -> list:
    path = rules_path or _DEFAULT_RULES
    if os.path.isdir(path):
        rules = load_rules_dir(path)
    else:
        try:
            rules = [load_rule(path)]
        except RuleLoadError as exc:
            console.print(f"[red]{exc}[/red]")
            return []
    console.print(f"[dim]Loaded {len(rules)} rule(s) from {path}[/dim]")
    return rules


def _pick_parser(args: argparse.Namespace):
    fmt = getattr(args, "format_input", None) or getattr(args, "input_format", None)
    if fmt == "json":
        return JSONParser()
    if fmt == "clf":
        return CombinedLogParser()
    if fmt == "auth":
        return AuthLogParser()
    try:
        return auto_detect(args.logfile)
    except FileNotFoundError:
        return JSONParser()


def _sev_choices():
    return [s.value for s in Severity]


# ── parser factory ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="authdetect",
        description="Stream auth logs through Sigma-compatible detection rules "
                    "and generate structured alerts. Defensive / blue-team use only.",
    )
    p.add_argument("--version", action="version", version=f"authdetect {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # -- analyze
    a = sub.add_parser("analyze", help="process a log file")
    a.add_argument("--logfile",  "-l", required=True, help="path to log file")
    a.add_argument("--rules",    "-r", default=_DEFAULT_RULES, help="rules dir or single .yml")
    a.add_argument("--format",   "-f", choices=["table", "json"], default="table")
    a.add_argument("--input-format", choices=["auto", "json", "clf", "auth"],
                   default="auto", dest="input_format")
    a.add_argument("--min-severity", choices=_sev_choices(), default=None,
                   dest="min_severity")
    a.set_defaults(func=_cmd_analyze)

    # -- watch
    w = sub.add_parser("watch", help="tail a log file in real time")
    w.add_argument("--logfile",  "-l", required=True)
    w.add_argument("--rules",    "-r", default=_DEFAULT_RULES)
    w.add_argument("--format",   "-f", choices=["table", "json"], default="table")
    w.add_argument("--input-format", choices=["auto", "json", "clf", "auth"],
                   default="auto", dest="input_format")
    w.set_defaults(func=_cmd_watch)

    # -- validate
    v = sub.add_parser("validate", help="syntax-check rule files")
    v.add_argument("rules", help="rules directory or glob")
    v.set_defaults(func=_cmd_validate)

    # -- generate-logs
    g = sub.add_parser("generate-logs", help="write synthetic test logs")
    g.add_argument("--output", "-o", default="sample_auth.ndjson",
                   help="output path (default: sample_auth.ndjson)")
    g.set_defaults(func=_cmd_generate_logs)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
