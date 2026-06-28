# authdetect

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-30%20passing-brightgreen)
![Rules](https://img.shields.io/badge/detection%20rules-12-orange)
![Type](https://img.shields.io/badge/type-defensive%20%2F%20blue--team-informational)

**Stream authentication logs through Sigma-compatible detection rules and get structured alerts with MITRE ATT&CK mappings.**

Point `authdetect` at any auth log — JSON, nginx Combined Log Format, or Linux `auth.log` — and it evaluates every event against a library of detection rules, firing severity-graded alerts when attack patterns emerge. Output is a `rich` terminal table for humans or NDJSON for piping into a SIEM, Slack webhook, or `jq`.

> **Defensive / blue-team tool only.** This detects attacks in log streams; it does not execute, simulate, or assist any attack. See [Ethics & scope](#ethics--scope).

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Install](#install)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Example output](#example-output)
- [How it works](#how-it-works)
- [Detection rule format](#detection-rule-format)
- [Bundled rule library](#bundled-rule-library)
- [Supported log formats](#supported-log-formats)
- [Testing](#testing)
- [Project structure](#project-structure)
- [Concepts demonstrated](#concepts-demonstrated)
- [Extending authdetect](#extending-authdetect)
- [Honest limitations](#honest-limitations)
- [Roadmap](#roadmap)
- [Ethics & scope](#ethics--scope)
- [License](#license)

---

## Why this exists

Detection engineering is the practice of translating attacker behaviour into rules that a monitoring system can evaluate in real time. The most common standard for expressing those rules is [Sigma](https://github.com/SigmaHQ/sigma) — a vendor-neutral YAML format that describes detection logic once and lets you compile it to Splunk, Elastic, Sentinel, or any other backend.

`authdetect` implements a Sigma-compatible detection engine in pure Python, focused specifically on authentication and session-management attack patterns: the class of threats that appears in every OWASP Top 10 list and constitutes the majority of account-takeover incidents.

By implementing the engine from scratch (rather than wrapping an existing SIEM), the project demonstrates a full understanding of how detection rules actually work — from condition parsing to sliding-window aggregation to alert enrichment — rather than just how to configure a managed service.

---

## Features

- **Sigma-compatible rule format** — YAML rules with field matching, boolean logic (`and` / `or` / `not`), and aggregation conditions
- **Sliding-window aggregation** — time-bounded count-based rules (e.g. "5+ failed logins from one IP in 60s") with per-group state
- **Field modifiers** — `contains`, `startswith`, `endswith`, `re` (regex), and plain equality / list membership
- **Three log format parsers** — auto-detected: JSON/NDJSON, Combined Log Format (nginx/Apache), Linux `auth.log`
- **JWT field extraction** — automatically decodes the algorithm and JTI from a Bearer token in `Authorization` headers
- **MITRE ATT&CK enrichment** — every alert carries tactic and technique IDs
- **CWE / OWASP references** on every rule
- **Two output modes** — `rich` terminal table (human) and NDJSON stream (machine / SIEM ingest)
- **`watch` mode** — tail a growing log file and stream alerts in real time
- **`validate` command** — syntax-check all rules before deployment
- **`generate-logs` command** — produce synthetic test logs that exercise every bundled rule

---

## Install

```bash
git clone https://github.com/ParshwaBhavsar/authdetect.git
cd authdetect
pip install -r requirements.txt
pip install -e .          # optional: installs the `authdetect` command
```

Requires Python 3.10+. Runtime dependencies: `pyyaml`, `rich`.

---

## Quick start

```bash
# 1. generate synthetic logs (no real credentials — entirely fabricated data)
python -m authdetect generate-logs --output sample.ndjson

# 2. run detection against the logs with all bundled rules
python -m authdetect analyze --logfile sample.ndjson --rules rules/

# 3. validate that all rules parse cleanly
python -m authdetect validate rules/
```

---

## Usage

```bash
# analyze a log file — rich terminal output
python -m authdetect analyze --logfile /var/log/nginx/access.log --rules rules/

# JSON output for piping to jq or a SIEM
python -m authdetect analyze --logfile auth.ndjson --rules rules/ --format json

# filter to HIGH and above only
python -m authdetect analyze --logfile auth.ndjson --rules rules/ --min-severity high

# specify log format explicitly (default: auto-detect)
python -m authdetect analyze --logfile auth.log --rules rules/ --input-format auth

# tail a live log file and stream alerts as they fire
python -m authdetect watch --logfile /var/log/app/auth.ndjson --rules rules/

# validate rule syntax
python -m authdetect validate rules/

# write 31 synthetic events covering all bundled detection scenarios
python -m authdetect generate-logs --output test.ndjson
```

---

## Example output

Running against the synthetic logs (31 events, 12 rules, 15 alerts):

```
Loaded 12 rule(s) from rules/
                        authdetect — 15 alert(s)
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Sev      ┃ Rule ID        ┃ Timestamp           ┃ Src IP         ┃ User        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ 🔴       │ AUTHDET-007    │ 2025-06-01 12:00:00 │ 9.8.7.6        │ attacker    │
│ CRITICAL │                │                     │                │             │
│          │                │ JWT Algorithm None — Signature Bypass Attempt       │
│          │                │ [MITRE] T1550.001                                   │
│ 🟠 HIGH  │ AUTHDET-001    │ 2025-06-01 11:59:57 │ 1.2.3.4        │ admin       │
│          │                │ Brute Force Authentication Attempt                  │
│          │                │ 8 events in 60s · src_ip=1.2.3.4                   │
│ 🟠 HIGH  │ AUTHDET-005    │ 2025-06-01 11:59:00 │ 22.33.44.55    │ —           │
│          │                │ Session Fixation Attempt                            │
│ 🟡 MED   │ AUTHDET-009    │ 2025-06-01 11:59:45 │ 11.22.33.44    │ bob         │
│          │                │ Authentication Token Transmitted in URL             │
└──────────┴────────────────┴─────────────────────┴────────────────┴─────────────┘

╭─────────────── Summary ────────────────╮
│ Events processed:                   31 │
│ Total alerts:                       15 │
│   🔴 CRITICAL:                       1 │
│   🟠 HIGH:                           6 │
│   🟡 MEDIUM:                         8 │
│ Top rules:                             │
│   Known Attack Tool User Agent       7 │
│   Brute Force Authentication         3 │
│   JWT Algorithm None — Bypass        1 │
╰────────────────────────────────────────╯
```

---

## How it works

```
log file
    │
    ▼
parsers.py          auto-detect format → normalise to LogEvent
    │                (JSON / Combined Log Format / auth.log)
    ▼
engine.py           for each event, evaluate all loaded rules
    │
    ├── SIMPLE rule        match field values with modifiers
    │   (single event)     resolve boolean condition string
    │
    └── AGGREGATION rule   maintain per-rule sliding time window
        (time-bounded)     count events grouped by a field
                           fire when threshold is crossed
    │
    ▼
model.py            build Alert with context, severity, MITRE
    │
    ▼
report.py           render rich terminal table  /  NDJSON stream
```

**Sliding-window state** is kept per `(rule_id, group_value)` pair using an in-memory `deque`. When an aggregation threshold is crossed the window is cleared, so the engine won't re-fire on every subsequent event.

**Condition parser** is a recursive-descent mini-language supporting `and`, `or`, `not`, and bare selection names. It handles compound conditions like `selection and not filter` or `sel1 or sel2`.

---

## Detection rule format

Rules are Sigma-inspired YAML. A minimal rule:

```yaml
title: Failed Login
id: EXAMPLE-001
detection:
  selection:
    status_code: 401
  condition: selection
level: low
```

### Field modifiers

```yaml
detection:
  selection:
    path|contains: /admin          # substring
    path|startswith: /api/         # prefix
    path|endswith: .php            # suffix
    path|re: ".*token=[A-Za-z0-9]{8,}.*"  # regex
    status_code: [401, 403]        # list → OR
    user_agent: sqlmap             # exact match
```

### Aggregation (time-windowed threshold)

```yaml
detection:
  selection:
    status_code: 401
    path|contains: login
  condition: selection | count(src_ip) > 5
  timeframe: 60s                   # also: 5m, 1h, 1d
level: high
```

### Boolean logic

```yaml
detection:
  selection:
    status_code: 401
  filter:
    src_ip: 10.0.0.1       # known-good internal scanner
  condition: selection and not filter
```

### Full rule schema

```yaml
title: Human-readable name                  # required
id: AUTHDET-NNN                             # required
status: stable | experimental | deprecated
description: |
  Multi-line explanation of what this detects and why.
author: your-name
date: YYYY-MM-DD
logsource:
  category: authentication | web | syslog

detection:
  <selection_name>:             # any name; 'filter*' names are for exclusions
    <field>: <value>            # or list of values (OR)
    <field>|<modifier>: <value>
  condition: <boolean expression> [| count(<field>) > <N>]
  timeframe: <duration>         # required for aggregation rules

level: info | low | medium | high | critical

mitre_attack:
  tactics: [credential-access, defense-evasion]
  techniques: [T1110.001, T1110.003]

references:
  - cwe: CWE-307
  - owasp: "A07:2021 – Identification and Authentication Failures"
  - url: https://attack.mitre.org/techniques/T1110/

false_positives:
  - Automated load-testing suites
  - Legitimate shared NAT addresses

tags: [attack.credential_access, attack.t1110.001]
```

---

## Bundled rule library

| ID            | Title                                      | Level    | MITRE Technique |
|---------------|--------------------------------------------|----------|-----------------|
| AUTHDET-001   | Brute Force Authentication Attempt         | HIGH     | T1110.001       |
| AUTHDET-002   | Password Spray Attack                      | HIGH     | T1110.003       |
| AUTHDET-003   | Credential Stuffing — High Volume          | CRITICAL | T1110.004       |
| AUTHDET-004   | Account Enumeration via Login Endpoint     | MEDIUM   | T1589.001       |
| AUTHDET-005   | Session Fixation Attempt                   | HIGH     | T1563           |
| AUTHDET-006   | Known Attack Tool User Agent               | MEDIUM   | T1595.002       |
| AUTHDET-007   | JWT Algorithm None — Signature Bypass      | CRITICAL | T1550.001       |
| AUTHDET-008   | JWT Unexpected or Weak Signing Algorithm   | HIGH     | T1550.001       |
| AUTHDET-009   | Authentication Token Transmitted in URL    | MEDIUM   | T1552.001       |
| AUTHDET-010   | API Key Brute Force — Repeated 403s        | HIGH     | T1110.001       |
| AUTHDET-011   | OAuth Flow Without State Parameter         | MEDIUM   | T1550           |
| AUTHDET-012   | Distributed Authentication Failure Burst   | CRITICAL | T1110           |

All rules include CWE numbers, OWASP category references, false-positive guidance, and MITRE ATT&CK tactic/technique tags.

---

## Supported log formats

| Format               | Parser class        | Auto-detected by            |
|----------------------|---------------------|-----------------------------|
| JSON / NDJSON        | `JSONParser`        | Line starts with `{`        |
| Combined Log Format  | `CombinedLogParser` | Matches CLF regex           |
| Linux auth.log       | `AuthLogParser`     | Matches syslog timestamp    |

**JSON field aliases** — the JSON parser resolves common field-name variants automatically:

| Canonical field | Also recognised as |
|----------------|--------------------|
| `src_ip`       | `remote_addr`, `client_ip`, `ip`, `source_ip` |
| `user`         | `username`, `user_id`, `account` |
| `status_code`  | `status`, `response_code`, `http_status` |
| `user_agent`   | `ua`, `http_user_agent` |

**JWT extraction** — if a JSON log line contains an `Authorization: Bearer <token>` header, the parser attempts to base64-decode the JWT header and payload and populates `token_alg` and `token_jti` fields automatically.

---

## Testing

```bash
pip install pytest
pytest -q
```

```
30 passed in 0.17s
```

Test coverage includes:

- JSON, CLF, and `auth.log` parsers (field mapping, aliases, JWT extraction, malformed input)
- Rule loader: valid rules, missing required fields, bad level values, aggregation condition parsing
- Engine: simple match / no-match, aggregation threshold, grouping by field, all field modifiers (`contains`, `startswith`, `endswith`, `re`, list OR), `and not` boolean logic
- Bundled rules: AUTHDET-007 (JWT alg:none) fires on `token_alg=none`, does not fire on `HS256`
- Alert enrichment: MITRE fields propagated correctly

---

## Project structure

```
authdetect/
├── authdetect/
│   ├── model.py         # LogEvent, RuleSpec, Alert dataclasses
│   ├── rule_loader.py   # YAML → RuleSpec with full validation
│   ├── parsers.py       # JSON / CLF / auth.log parsers
│   ├── engine.py        # simple + aggregation detection engine
│   ├── report.py        # rich terminal table + NDJSON renderer
│   └── cli.py           # analyze / watch / validate / generate-logs
├── rules/
│   ├── auth/            # brute force, spray, enumeration, session, UA
│   ├── jwt/             # alg:none, unexpected algorithm
│   ├── token/           # token-in-URL, API key brute force
│   └── oauth/           # missing state parameter
├── tests/
│   └── test_authdetect.py
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Concepts demonstrated

For anyone reviewing this as a portfolio piece:

- **Sigma rule format** — the community standard for vendor-neutral detection logic, used by SOC teams at every major security vendor
- **MITRE ATT&CK framework** — tactic/technique mapping on every alert; how defenders translate attacker behaviour into observable patterns
- **Sliding-window aggregation** — the statistical backbone of most rate-based detections (brute force, credential stuffing); implemented from scratch with per-group deque state
- **Boolean condition parsing** — recursive-descent parser for `and / or / not` logic over named selections; same concept as Sigma's condition compiler
- **Log normalisation** — mapping heterogeneous log formats to a unified event model so detection logic is format-agnostic
- **JWT internals** — base64url decoding, header/payload structure, the `alg` claim and why `none` is a critical misconfiguration
- **Detection engineering workflow** — writing rules, testing them against labelled samples, measuring false-positive risk, documenting remediation
- Clean Python architecture: dataclasses, abstract base classes, `pathlib`, full type annotations

---

## Extending authdetect

**Add a new rule** — create a `.yml` file anywhere under `rules/` and run `authdetect validate rules/` to check it. The engine picks it up automatically on next run.

**Add a new log format** — subclass `BaseParser` in `parsers.py`, implement `parse_line(line: str) -> LogEvent | None`, and add a detection branch to `auto_detect()`.

**Ship alerts to a SIEM** — pipe JSON output:

```bash
python -m authdetect analyze --logfile auth.ndjson --format json \
  | curl -X POST https://your-siem/ingest -d @-
```

**Run in a cron / CI pipeline** — the exit code is `1` when any alert fires, `0` when clean; combine with `--min-severity high` to gate on severity.

---

## Honest limitations

- **No persistence between runs** — aggregation state is in-memory only. Restarting the process resets all sliding windows. For production use, back the state with Redis or a time-series DB.
- **Single-threaded, file-based** — the `watch` mode tails one file. A production equivalent would consume from Kafka, Kinesis, or a log shipper.
- **No machine learning** — all rules are deterministic. Anomaly detection (baseline deviation, user-behaviour analytics) would require a separate model layer.
- **Rule tuning is manual** — false-positive rates depend on environment. Every rule ships with `false_positives` guidance, but thresholds need tuning against your own traffic.

---

## Roadmap

- [ ] Redis-backed window state for persistence across restarts
- [ ] Compiled Sigma → Elastic / Splunk / Chronicle query export
- [ ] Webhook / Slack alert delivery adapter
- [ ] `sigma import` command to pull from the SigmaHQ community rule repository
- [ ] Prometheus metrics endpoint (`/metrics`) for Grafana dashboards
- [ ] More rule categories: exfiltration, privilege escalation, lateral movement

---

## Ethics & scope

Built for defensive use: security operations, detection engineering, incident response, and security education. `authdetect` reads log files and reports findings. It does not generate traffic, probe endpoints, or assist any offensive action.

Analyse only log data you are authorised to process.

---

## License

[MIT](LICENSE)
