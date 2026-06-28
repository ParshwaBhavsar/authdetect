"""
Rule loader: reads YAML files from disk and produces validated RuleSpec objects.

The format is Sigma-inspired so analysts who already know Sigma can write rules
immediately. Key design choices:
  - Hard validation at load time so broken rules never reach the engine
  - Clear error messages that say *which field* is wrong and *why*
  - Aggregation conditions parsed from a mini-DSL:
      "selection | count(src_ip) > 5"  →  AggregationSpec(group_by='src_ip', …)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .model import (
    AggregationSpec,
    ConditionType,
    RuleSpec,
    SelectionClause,
    Severity,
)

# Matches: <selections> | count(field) > threshold
_AGG_PATTERN = re.compile(
    r"^(?P<sel>[\w\s,]+)\|\s*"
    r"(?P<func>count|distinct)\((?P<field>\w+)\)\s*"
    r"(?P<op>[><=!]+)\s*"
    r"(?P<threshold>\d+)$"
)

_VALID_SEVERITY = {s.value for s in Severity}


class RuleLoadError(Exception):
    """Raised when a rule file is malformed or fails validation."""


def load_rule(path: str | Path) -> RuleSpec:
    """Parse and validate a single YAML rule file."""
    p = Path(path)
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"{p.name}: invalid YAML — {exc}") from exc

    if not isinstance(raw, dict):
        raise RuleLoadError(f"{p.name}: top-level must be a YAML mapping")

    def req(key: str) -> Any:
        if key not in raw:
            raise RuleLoadError(f"{p.name}: missing required field '{key}'")
        return raw[key]

    rule_id    = str(req("id"))
    title      = str(req("title"))
    desc       = str(raw.get("description", ""))
    status     = str(raw.get("status", "experimental"))
    author     = str(raw.get("author", "unknown"))
    date       = str(raw.get("date", ""))

    # logsource
    ls_raw = raw.get("logsource", {})
    logsource = {k: str(v) for k, v in ls_raw.items()} if isinstance(ls_raw, dict) else {}

    # detection block
    det = req("detection")
    if not isinstance(det, dict):
        raise RuleLoadError(f"{p.name}: 'detection' must be a mapping")
    if "condition" not in det:
        raise RuleLoadError(f"{p.name}: 'detection.condition' is required")

    condition_str = str(det["condition"]).strip()

    # parse selections — every key in detection except 'condition' and 'timeframe'
    selections: list[SelectionClause] = []
    for sel_name, sel_body in det.items():
        if sel_name in ("condition", "timeframe"):
            continue
        negated = sel_name.startswith("filter")
        if not isinstance(sel_body, dict):
            raise RuleLoadError(
                f"{p.name}: selection '{sel_name}' must be a mapping"
            )
        selections.append(SelectionClause(
            name=sel_name, negated=negated, fields=sel_body
        ))

    # parse condition + timeframe
    agg_match = _AGG_PATTERN.match(condition_str.replace("\n", " "))
    if agg_match:
        ctype = ConditionType.AGGREGATION
        tf_raw = det.get("timeframe", "60s")
        agg = AggregationSpec(
            function=agg_match.group("func"),
            group_by=agg_match.group("field"),
            operator=agg_match.group("op"),
            threshold=int(agg_match.group("threshold")),
            timeframe=_parse_timeframe(str(tf_raw), p.name),
        )
    else:
        ctype = ConditionType.SIMPLE
        agg = None

    # severity / level
    raw_level = str(raw.get("level", raw.get("severity", "medium"))).lower()
    if raw_level not in _VALID_SEVERITY:
        raise RuleLoadError(
            f"{p.name}: 'level' must be one of {sorted(_VALID_SEVERITY)}, "
            f"got '{raw_level}'"
        )
    severity = Severity(raw_level)

    # tags
    tags = [str(t) for t in raw.get("tags", [])]

    # mitre
    mitre_raw = raw.get("mitre_attack", {})
    mitre: dict[str, list[str]] = {
        "tactics":    [str(x) for x in mitre_raw.get("tactics", [])],
        "techniques": [str(x) for x in mitre_raw.get("techniques", [])],
    }

    # references
    refs_raw = raw.get("references", [])
    references: list[dict[str, str]] = []
    for r in refs_raw:
        if isinstance(r, dict):
            references.append({str(k): str(v) for k, v in r.items()})
        else:
            references.append({"url": str(r)})

    fps = [str(x) for x in raw.get("false_positives", [])]

    return RuleSpec(
        id=rule_id,
        title=title,
        description=desc,
        status=status,
        author=author,
        date=date,
        logsource=logsource,
        selections=selections,
        condition=condition_str,
        condition_type=ctype,
        aggregation=agg,
        severity=severity,
        tags=tags,
        mitre=mitre,
        references=references,
        false_positives=fps,
        source_file=str(p),
    )


def load_rules_dir(directory: str | Path) -> list[RuleSpec]:
    """
    Recursively load all *.yml / *.yaml files under *directory*.
    Returns successfully-loaded rules; prints a warning for each failure.
    """
    directory = Path(directory)
    rules: list[RuleSpec] = []
    errors: list[str] = []

    for path in sorted(directory.rglob("*.y*ml")):
        try:
            rules.append(load_rule(path))
        except RuleLoadError as exc:
            errors.append(str(exc))

    if errors:
        import sys
        for err in errors:
            print(f"[WARN] rule load error: {err}", file=sys.stderr)

    return rules


def _parse_timeframe(value: str, rule_name: str) -> int:
    """Convert a human timeframe string to seconds. e.g. '5m' → 300."""
    value = value.strip()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if value[-1] in units:
        try:
            return int(value[:-1]) * units[value[-1]]
        except ValueError:
            pass
    try:
        return int(value)
    except ValueError:
        raise RuleLoadError(
            f"{rule_name}: invalid timeframe '{value}' "
            "(use e.g. '30s', '5m', '1h')"
        )
