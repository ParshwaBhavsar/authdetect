"""
Shared data models.

Everything in authdetect flows through three core types:
  LogEvent   – a single normalised auth event parsed from any log format
  RuleSpec   – a parsed, validated detection rule loaded from YAML
  Alert      – a triggered detection with full context for an analyst
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class ConditionType(str, Enum):
    SIMPLE      = "simple"       # match on field values
    AGGREGATION = "aggregation"  # count / distinct within a time window


# ---------------------------------------------------------------------------
# Log event — the normalised representation of one line from any log source.
# Parsers fill in whatever fields they can; the engine works with what's there.
# ---------------------------------------------------------------------------

@dataclass
class LogEvent:
    timestamp:   datetime
    src_ip:      str | None    = None
    user:        str | None    = None
    method:      str | None    = None
    path:        str | None    = None
    status_code: int | None    = None
    user_agent:  str | None    = None
    session_id:  str | None    = None
    token_alg:   str | None    = None   # JWT alg claim if parseable
    token_jti:   str | None    = None   # JWT jti claim
    message:     str | None    = None   # raw message / syslog line
    extra:       dict[str, Any] = field(default_factory=dict)

    def get(self, field_name: str) -> Any:
        """Unified field accessor used by the rule engine."""
        if hasattr(self, field_name):
            return getattr(self, field_name)
        return self.extra.get(field_name)


# ---------------------------------------------------------------------------
# Rule specification — what comes out of loading a YAML rule file.
# ---------------------------------------------------------------------------

@dataclass
class SelectionClause:
    """A single named selection block from the YAML `detection:` section."""
    name:    str
    negated: bool
    fields:  dict[str, Any]   # field_name (with optional |modifier) -> value(s)


@dataclass
class AggregationSpec:
    function:   str   # "count" | "distinct"
    group_by:   str   # field to group on
    operator:   str   # ">" | ">=" | "==" | "<=" | "<"
    threshold:  int
    timeframe:  int   # seconds


@dataclass
class RuleSpec:
    id:          str
    title:       str
    description: str
    status:      str
    author:      str
    date:        str
    logsource:   dict[str, str]
    selections:  list[SelectionClause]
    condition:   str              # raw condition string
    condition_type: ConditionType
    aggregation: AggregationSpec | None
    severity:    Severity
    tags:        list[str]
    mitre:       dict[str, list[str]]   # {tactics:[…], techniques:[…]}
    references:  list[dict[str, str]]
    false_positives: list[str]
    source_file: str = ""


# ---------------------------------------------------------------------------
# Alert — one triggered detection, ready to ship to an analyst or SIEM.
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    rule_id:       str
    rule_title:    str
    severity:      Severity
    timestamp:     datetime            # event time that triggered the alert
    src_ip:        str | None
    user:          str | None
    message:       str
    matched_events: list[LogEvent]
    tags:          list[str]
    mitre:         dict[str, list[str]]
    references:    list[dict[str, str]]
    false_positives: list[str]
    context:       dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "rule_title":  self.rule_title,
            "severity":    self.severity.value,
            "timestamp":   self.timestamp.isoformat(),
            "src_ip":      self.src_ip,
            "user":        self.user,
            "message":     self.message,
            "tags":        self.tags,
            "mitre":       self.mitre,
            "references":  self.references,
            "false_positives": self.false_positives,
            "context":     self.context,
            "event_count": len(self.matched_events),
        }
