"""
Tests for authdetect: parsers, rule loader, and detection engine.
All fixtures use synthetic log data — no real credentials or IPs.
"""

from __future__ import annotations

import base64
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from authdetect.engine import Engine
from authdetect.model import ConditionType, LogEvent, Severity
from authdetect.parsers import AuthLogParser, CombinedLogParser, JSONParser
from authdetect.rule_loader import RuleLoadError, load_rule, load_rules_dir

RULES_DIR = Path(__file__).parent.parent / "rules"


# ── helpers ───────────────────────────────────────────────────────────────────

def _ts(offset_s: int = 0) -> datetime:
    from datetime import timedelta
    return datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc) - timedelta(seconds=offset_s)


def _evt(**kwargs) -> LogEvent:
    return LogEvent(timestamp=kwargs.pop("timestamp", _ts()), **kwargs)


def _write_rule(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "test_rule.yml"
    p.write_text(textwrap.dedent(content))
    return p


# ── JSON parser ───────────────────────────────────────────────────────────────

class TestJSONParser:
    P = JSONParser()

    def test_basic_fields(self):
        line = json.dumps({
            "timestamp": "2025-06-01T12:00:00Z",
            "src_ip": "1.2.3.4",
            "user": "alice",
            "method": "POST",
            "path": "/login",
            "status_code": 401,
            "user_agent": "curl/8.0",
        })
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.src_ip == "1.2.3.4"
        assert ev.user == "alice"
        assert ev.status_code == 401

    def test_aliases_resolved(self):
        line = json.dumps({"remote_addr": "5.6.7.8", "http_status": 200})
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.src_ip == "5.6.7.8"
        assert ev.status_code == 200

    def test_jwt_alg_extracted(self):
        header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"admin"}').rstrip(b"=").decode()
        token   = f"{header}.{payload}."
        line    = json.dumps({"Authorization": f"Bearer {token}"})
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.token_alg == "none"

    def test_invalid_json_returns_none(self):
        assert self.P.parse_line("not json at all") is None

    def test_empty_line_returns_none(self):
        assert self.P.parse_line("") is None

    def test_unix_timestamp(self):
        line = json.dumps({"timestamp": 1748779200, "src_ip": "1.1.1.1"})
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.timestamp.year == 2025


# ── Combined Log Format parser ────────────────────────────────────────────────

class TestCombinedLogParser:
    P = CombinedLogParser()

    def test_standard_line(self):
        line = ('127.0.0.1 - frank [10/Oct/2024:13:55:36 +0000] '
                '"GET /index.html HTTP/1.1" 200 1234 '
                '"http://referer.example.com" "Mozilla/5.0"')
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.src_ip == "127.0.0.1"
        assert ev.user == "frank"
        assert ev.status_code == 200
        assert ev.method == "GET"

    def test_anonymous_user(self):
        line = ('10.0.0.1 - - [01/Jan/2025:00:00:00 +0000] '
                '"POST /login HTTP/1.1" 401 512 "-" "-"')
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.user is None
        assert ev.status_code == 401

    def test_non_clf_line_returns_none(self):
        assert self.P.parse_line('{"json": "line"}') is None


# ── auth.log parser ───────────────────────────────────────────────────────────

class TestAuthLogParser:
    P = AuthLogParser()

    def test_failed_ssh(self):
        line = "Jun  1 12:00:01 myhost sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2"
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.src_ip == "192.168.1.1"
        assert ev.user == "root"
        assert ev.status_code == 401

    def test_accepted_ssh(self):
        line = "Jun  1 12:05:00 myhost sshd[2000]: Accepted publickey for alice from 10.0.0.5 port 55123"
        ev = self.P.parse_line(line)
        assert ev is not None
        assert ev.status_code == 200

    def test_unparseable_returns_none(self):
        assert self.P.parse_line("") is None


# ── rule loader ───────────────────────────────────────────────────────────────

class TestRuleLoader:
    def test_load_bundled_rules(self):
        if not RULES_DIR.exists():
            pytest.skip("rules directory not found")
        rules = load_rules_dir(RULES_DIR)
        assert len(rules) >= 6, "expected at least 6 bundled rules"

    def test_all_bundled_rules_have_mitre(self):
        if not RULES_DIR.exists():
            pytest.skip("rules directory not found")
        rules = load_rules_dir(RULES_DIR)
        for rule in rules:
            assert rule.mitre.get("techniques"), \
                f"{rule.id} has no MITRE techniques"

    def test_missing_required_field_raises(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: No ID Rule
            detection:
              selection:
                status_code: 401
              condition: selection
            level: low
        """)
        with pytest.raises(RuleLoadError, match="missing required field 'id'"):
            load_rule(p)

    def test_invalid_level_raises(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: Bad Level
            id: TEST-BAD
            detection:
              selection:
                status_code: 401
              condition: selection
            level: extreme
        """)
        with pytest.raises(RuleLoadError, match="level"):
            load_rule(p)

    def test_aggregation_condition_parsed(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: Agg Rule
            id: TEST-AGG
            detection:
              selection:
                status_code: 401
              condition: selection | count(src_ip) > 3
              timeframe: 30s
            level: high
        """)
        rule = load_rule(p)
        assert rule.condition_type == ConditionType.AGGREGATION
        assert rule.aggregation is not None
        assert rule.aggregation.threshold == 3
        assert rule.aggregation.timeframe == 30

    def test_simple_condition_parsed(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: Simple Rule
            id: TEST-SIMPLE
            detection:
              selection:
                token_alg: none
              condition: selection
            level: critical
        """)
        rule = load_rule(p)
        assert rule.condition_type == ConditionType.SIMPLE


# ── detection engine ──────────────────────────────────────────────────────────

class TestEngine:
    def _simple_rule(self, tmp_path: Path):
        p = _write_rule(tmp_path, """
            title: Test 401 Detector
            id: TEST-001
            detection:
              selection:
                status_code: 401
              condition: selection
            level: medium
        """)
        from authdetect.rule_loader import load_rule
        return load_rule(p)

    def _brute_rule(self, tmp_path: Path):
        p = tmp_path / "brute.yml"
        p.write_text(textwrap.dedent("""
            title: Brute Force Test
            id: TEST-BRUTE
            detection:
              selection:
                status_code: 401
              condition: selection | count(src_ip) > 3
              timeframe: 60s
            level: high
        """))
        from authdetect.rule_loader import load_rule
        return load_rule(p)

    def test_simple_rule_matches(self, tmp_path):
        rule = self._simple_rule(tmp_path)
        engine = Engine([rule])
        event = _evt(status_code=401, src_ip="1.2.3.4")
        alerts = engine.process_event(event)
        assert len(alerts) == 1
        assert alerts[0].rule_id == "TEST-001"

    def test_simple_rule_no_match(self, tmp_path):
        rule = self._simple_rule(tmp_path)
        engine = Engine([rule])
        event = _evt(status_code=200, src_ip="1.2.3.4")
        assert engine.process_event(event) == []

    def test_aggregation_fires_at_threshold(self, tmp_path):
        rule = self._brute_rule(tmp_path)
        engine = Engine([rule])
        # 4 events from same IP — threshold is >3, so fires on the 4th
        events = [_evt(status_code=401, src_ip="9.9.9.9", timestamp=_ts(i)) for i in range(4)]
        all_alerts = []
        for ev in events:
            all_alerts.extend(engine.process_event(ev))
        assert len(all_alerts) == 1
        assert all_alerts[0].severity == Severity.HIGH

    def test_aggregation_does_not_fire_below_threshold(self, tmp_path):
        rule = self._brute_rule(tmp_path)
        engine = Engine([rule])
        events = [_evt(status_code=401, src_ip="2.2.2.2", timestamp=_ts(i)) for i in range(3)]
        alerts = []
        for ev in events:
            alerts.extend(engine.process_event(ev))
        assert alerts == []

    def test_aggregation_groups_by_field(self, tmp_path):
        rule = self._brute_rule(tmp_path)
        engine = Engine([rule])
        # 4 events but from two different IPs — neither should breach threshold alone
        events = (
            [_evt(status_code=401, src_ip="1.1.1.1", timestamp=_ts(i)) for i in range(2)] +
            [_evt(status_code=401, src_ip="2.2.2.2", timestamp=_ts(i + 10)) for i in range(2)]
        )
        alerts = []
        for ev in events:
            alerts.extend(engine.process_event(ev))
        assert alerts == []

    def test_modifier_contains(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: Path Contains
            id: TEST-PATH
            detection:
              selection:
                path|contains: /admin
              condition: selection
            level: low
        """)
        from authdetect.rule_loader import load_rule
        rule = load_rule(p)
        engine = Engine([rule])
        assert engine.process_event(_evt(path="/admin/users")) != []
        assert engine.process_event(_evt(path="/home/page"))   == []

    def test_modifier_startswith(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: API Startswith
            id: TEST-START
            detection:
              selection:
                path|startswith: /api/
              condition: selection
            level: low
        """)
        from authdetect.rule_loader import load_rule
        rule = load_rule(p)
        engine = Engine([rule])
        assert engine.process_event(_evt(path="/api/v1/users")) != []
        assert engine.process_event(_evt(path="/web/page"))     == []

    def test_modifier_regex(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: Regex Match
            id: TEST-RE
            detection:
              selection:
                path|re: ".*token=[A-Za-z0-9]{8,}.*"
              condition: selection
            level: medium
        """)
        from authdetect.rule_loader import load_rule
        rule = load_rule(p)
        engine = Engine([rule])
        assert engine.process_event(_evt(path="/api?token=abcdefghij")) != []
        assert engine.process_event(_evt(path="/api?id=123"))           == []

    def test_list_value_or_match(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: List OR
            id: TEST-LIST
            detection:
              selection:
                status_code: [401, 403]
              condition: selection
            level: low
        """)
        from authdetect.rule_loader import load_rule
        rule = load_rule(p)
        engine = Engine([rule])
        assert engine.process_event(_evt(status_code=401)) != []
        assert engine.process_event(_evt(status_code=403)) != []
        assert engine.process_event(_evt(status_code=200)) == []

    def test_and_not_condition(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: AND NOT
            id: TEST-ANDNOT
            detection:
              selection:
                status_code: 401
              filter:
                src_ip: 10.0.0.1
              condition: selection and not filter
            level: low
        """)
        from authdetect.rule_loader import load_rule
        rule = load_rule(p)
        engine = Engine([rule])
        # external IP — should fire
        assert engine.process_event(_evt(status_code=401, src_ip="1.2.3.4")) != []
        # internal IP — filter should suppress
        assert engine.process_event(_evt(status_code=401, src_ip="10.0.0.1")) == []

    def test_bundled_jwt_alg_none_rule(self):
        if not RULES_DIR.exists():
            pytest.skip("rules directory not found")
        rules = load_rules_dir(RULES_DIR)
        jwt_rules = [r for r in rules if "AUTHDET-007" in r.id]
        assert jwt_rules, "AUTHDET-007 not found in bundled rules"
        engine = Engine(jwt_rules)
        assert engine.process_event(_evt(token_alg="none")) != []
        assert engine.process_event(_evt(token_alg="HS256")) == []

    def test_alert_has_mitre_fields(self, tmp_path):
        p = _write_rule(tmp_path, """
            title: MITRE Test
            id: TEST-MITRE
            detection:
              selection:
                status_code: 401
              condition: selection
            level: medium
            mitre_attack:
              tactics: [credential-access]
              techniques: [T1110.001]
        """)
        from authdetect.rule_loader import load_rule
        rule = load_rule(p)
        engine = Engine([rule])
        alerts = engine.process_event(_evt(status_code=401))
        assert alerts[0].mitre["techniques"] == ["T1110.001"]
