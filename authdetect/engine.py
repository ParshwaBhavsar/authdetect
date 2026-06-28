"""
Detection engine.

Two evaluation paths:
  Simple      – a single event either matches or it doesn't (field/value checks)
  Aggregation – events accumulate in a sliding time-window; an alert fires when
                a threshold is crossed (e.g. 5+ failed logins from one IP in 60s)

Field modifiers (appended after '|' in rule YAML):
  contains   – substring check
  startswith – prefix check
  endswith   – suffix check
  re         – regex full-match
  (none)     – exact equality, or membership if the value is a list
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from .model import (
    Alert,
    AggregationSpec,
    ConditionType,
    LogEvent,
    RuleSpec,
    SelectionClause,
    Severity,
)


class Engine:
    def __init__(self, rules: list[RuleSpec]) -> None:
        self.rules = rules
        # per-rule sliding windows:  rule_id -> group_value -> deque[LogEvent]
        self._windows: dict[str, dict[str, deque[LogEvent]]] = defaultdict(
            lambda: defaultdict(deque)
        )

    # ── public API ────────────────────────────────────────────────────────────

    def process_event(self, event: LogEvent) -> list[Alert]:
        """Evaluate one event against all loaded rules; return any new alerts."""
        alerts: list[Alert] = []
        for rule in self.rules:
            alert = self._evaluate(rule, event)
            if alert:
                alerts.append(alert)
        return alerts

    def process_events(self, events: list[LogEvent]) -> list[Alert]:
        """Bulk-process a list of events (e.g. from a log file)."""
        alerts: list[Alert] = []
        for event in events:
            alerts.extend(self.process_event(event))
        return alerts

    # ── internal dispatch ────────────────────────────────────────────────────

    def _evaluate(self, rule: RuleSpec, event: LogEvent) -> Alert | None:
        if rule.condition_type == ConditionType.SIMPLE:
            return self._eval_simple(rule, event)
        return self._eval_aggregation(rule, event)

    # ── simple matching ───────────────────────────────────────────────────────

    def _eval_simple(self, rule: RuleSpec, event: LogEvent) -> Alert | None:
        """
        Resolve the condition string with AND/OR/NOT logic over named selections.
        Supported syntax:
          selection
          selection and not filter
          sel1 or sel2
          sel1 and sel2
        """
        condition = rule.condition.lower()
        sel_map = {s.name: s for s in rule.selections}

        # parse the condition into tokens
        try:
            matched = self._resolve_condition(condition, sel_map, event)
        except Exception:
            return None

        if not matched:
            return None

        triggering = [s for s in rule.selections if not s.negated
                      and self._match_selection(s, event)]
        return self._make_alert(rule, event, [event], context={})

    def _resolve_condition(
        self,
        condition: str,
        sel_map: dict[str, SelectionClause],
        event: LogEvent,
    ) -> bool:
        """Recursive descent parser for simple boolean conditions."""
        condition = condition.strip()

        # OR: split on ' or ' (lowest precedence)
        or_parts = re.split(r"\bor\b", condition)
        if len(or_parts) > 1:
            return any(
                self._resolve_condition(p, sel_map, event) for p in or_parts
            )

        # AND: split on ' and '
        and_parts = re.split(r"\band\b", condition)
        if len(and_parts) > 1:
            return all(
                self._resolve_condition(p, sel_map, event) for p in and_parts
            )

        # NOT
        if condition.startswith("not "):
            inner = condition[4:].strip()
            return not self._resolve_condition(inner, sel_map, event)

        # atom: bare selection name — negation is handled by the "not " prefix
        # above; never apply sel.negated here or we get double-negation.
        name = condition.strip()
        if name not in sel_map:
            return False
        return self._match_selection(sel_map[name], event)

    def _match_selection(self, sel: SelectionClause, event: LogEvent) -> bool:
        """Return True if ALL field criteria in a selection match the event."""
        for field_expr, expected in sel.fields.items():
            field_name, _, modifier = field_expr.partition("|")
            actual = event.get(field_name.strip())
            if not self._match_field(actual, modifier.strip(), expected):
                return False
        return True

    @staticmethod
    def _match_field(actual: Any, modifier: str, expected: Any) -> bool:
        if actual is None:
            return False

        actual_str = str(actual).lower()

        def _one(exp: Any) -> bool:
            exp_str = str(exp).lower()
            if modifier == "contains":
                return exp_str in actual_str
            if modifier == "startswith":
                return actual_str.startswith(exp_str)
            if modifier == "endswith":
                return actual_str.endswith(exp_str)
            if modifier == "re":
                return bool(re.search(exp_str, actual_str))
            # exact / numeric
            if isinstance(actual, (int, float)):
                try:
                    return actual == type(actual)(exp)
                except (ValueError, TypeError):
                    pass
            return actual_str == exp_str

        if isinstance(expected, list):
            return any(_one(e) for e in expected)
        return _one(expected)

    # ── aggregation matching ──────────────────────────────────────────────────

    def _eval_aggregation(self, rule: RuleSpec, event: LogEvent) -> Alert | None:
        agg: AggregationSpec = rule.aggregation  # type: ignore[assignment]

        # check that the event passes the base selection(s)
        sel_map = {s.name: s for s in rule.selections}
        # extract selection names from the condition (before the pipe)
        cond_before_pipe = rule.condition.split("|")[0].strip()
        try:
            base_match = self._resolve_condition(cond_before_pipe, sel_map, event)
        except Exception:
            return None

        if not base_match:
            return None

        # group key
        group_key = str(event.get(agg.group_by) or "_all_")
        window = self._windows[rule.id][group_key]

        # evict events outside the time window
        cutoff = event.timestamp - timedelta(seconds=agg.timeframe)
        while window and window[0].timestamp < cutoff:
            window.popleft()

        window.append(event)

        # compute the aggregate
        if agg.function == "count":
            value = len(window)
        elif agg.function == "distinct":
            value = len({str(e.get(agg.group_by)) for e in window})
        else:
            value = len(window)

        if not self._compare(value, agg.operator, agg.threshold):
            return None

        # fire — clear window so we don't immediately re-fire for every next event
        triggered = list(window)
        window.clear()

        context = {
            "group_by":    agg.group_by,
            "group_value": group_key,
            "count":       value,
            "threshold":   agg.threshold,
            "timeframe_s": agg.timeframe,
        }
        return self._make_alert(rule, event, triggered, context)

    @staticmethod
    def _compare(value: int, operator: str, threshold: int) -> bool:
        ops = {
            ">": value > threshold,
            ">=": value >= threshold,
            "<": value < threshold,
            "<=": value <= threshold,
            "==": value == threshold,
            "!=": value != threshold,
        }
        return ops.get(operator, False)

    # ── alert construction ────────────────────────────────────────────────────

    @staticmethod
    def _make_alert(
        rule: RuleSpec,
        trigger_event: LogEvent,
        matched: list[LogEvent],
        context: dict,
    ) -> Alert:
        msg_parts = [rule.title]
        if context.get("group_value") and context.get("count"):
            grp = context["group_by"]
            val = context["group_value"]
            cnt = context["count"]
            tf  = context.get("timeframe_s", 0)
            msg_parts.append(
                f"{cnt} event(s) for {grp}={val} in {tf}s"
            )
        src_ip = trigger_event.src_ip or (
            next((e.src_ip for e in matched if e.src_ip), None)
        )
        user = trigger_event.user or (
            next((e.user for e in matched if e.user), None)
        )
        return Alert(
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.severity,
            timestamp=trigger_event.timestamp,
            src_ip=src_ip,
            user=user,
            message=" — ".join(msg_parts),
            matched_events=matched,
            tags=rule.tags,
            mitre=rule.mitre,
            references=rule.references,
            false_positives=rule.false_positives,
            context=context,
        )
