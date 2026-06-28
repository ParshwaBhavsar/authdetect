"""
Log parsers: turn raw log lines into normalised LogEvent objects.

Three formats supported out of the box:
  JSONParser       – one JSON object per line (common in modern apps / k8s)
  CombinedLogParser – nginx / Apache Combined Log Format
  AuthLogParser    – Linux /var/log/auth.log (sshd, sudo, PAM entries)

The auto_detect() function sniffs the first non-empty line to pick the right
parser so the CLI can work without the user specifying --format.
"""

from __future__ import annotations

import base64
import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Iterator

from .model import LogEvent

# ── Combined Log Format ──────────────────────────────────────────────────────
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/…"
_CLF_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+\S+'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_CLF_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# ── Linux auth.log ───────────────────────────────────────────────────────────
# Jun 15 10:23:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2
_AUTH_PATTERN = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.+)"
)
_AUTH_IP     = re.compile(r"from\s+(\d+\.\d+\.\d+\.\d+)")
_AUTH_USER   = re.compile(r"(?:for|user)\s+(\S+)")
_AUTH_STATUS = re.compile(r"(Failed|Accepted|Invalid|failure|succeeded)", re.I)


def _try_jwt_fields(token_str: str) -> tuple[str | None, str | None]:
    """Best-effort extraction of alg and jti from a raw JWT string."""
    try:
        parts = token_str.split(".")
        if len(parts) < 2:
            return None, None
        padding = "=" * (4 - len(parts[0]) % 4)
        header  = json.loads(base64.urlsafe_b64decode(parts[0] + padding))
        payload_pad = "=" * (4 - len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + payload_pad))
        return header.get("alg"), payload.get("jti")
    except Exception:
        return None, None


# ── Base class ───────────────────────────────────────────────────────────────

class BaseParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> LogEvent | None:
        ...

    def parse_file(self, path: str) -> Iterator[LogEvent]:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line:
                    continue
                event = self.parse_line(line)
                if event:
                    yield event

    def parse_lines(self, lines: list[str]) -> Iterator[LogEvent]:
        for line in lines:
            line = line.rstrip("\n")
            if not line:
                continue
            ev = self.parse_line(line)
            if ev:
                yield ev


# ── JSON parser ──────────────────────────────────────────────────────────────

class JSONParser(BaseParser):
    """
    Parses NDJSON log streams. Maps common field names automatically and
    dumps anything unrecognised into LogEvent.extra so no data is lost.
    """

    # Field aliases: normalised_name -> [possible source field names]
    _ALIASES: dict[str, list[str]] = {
        "src_ip":      ["src_ip", "remote_addr", "client_ip", "ip", "source_ip", "remote_ip"],
        "user":        ["user", "username", "user_id", "account"],
        "method":      ["method", "http_method", "request_method"],
        "path":        ["path", "uri", "url", "request_path", "endpoint"],
        "status_code": ["status_code", "status", "response_code", "http_status"],
        "user_agent":  ["user_agent", "ua", "http_user_agent"],
        "session_id":  ["session_id", "session", "sid"],
        "message":     ["message", "msg", "log", "text"],
    }

    def parse_line(self, line: str) -> LogEvent | None:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None

        def pick(keys: list[str]):
            for k in keys:
                if k in obj:
                    return obj[k]
            return None

        ts = self._parse_timestamp(obj)
        status_raw = pick(self._ALIASES["status_code"])
        try:
            status = int(status_raw) if status_raw is not None else None
        except (ValueError, TypeError):
            status = None

        # check for JWT bearer in Authorization header
        auth_header = obj.get("Authorization") or obj.get("authorization") or ""
        token_alg, token_jti = None, None
        if isinstance(auth_header, str) and auth_header.lower().startswith("bearer "):
            token_alg, token_jti = _try_jwt_fields(auth_header[7:])

        known_keys = {k for keys in self._ALIASES.values() for k in keys}
        known_keys |= {"timestamp", "@timestamp", "time", "date", "Authorization",
                       "authorization", "level", "severity"}
        extra = {k: v for k, v in obj.items() if k not in known_keys}

        return LogEvent(
            timestamp=ts,
            src_ip=str(pick(self._ALIASES["src_ip"]) or "") or None,
            user=str(pick(self._ALIASES["user"]) or "") or None,
            method=str(pick(self._ALIASES["method"]) or "") or None,
            path=str(pick(self._ALIASES["path"]) or "") or None,
            status_code=status,
            user_agent=str(pick(self._ALIASES["user_agent"]) or "") or None,
            session_id=str(pick(self._ALIASES["session_id"]) or "") or None,
            token_alg=token_alg,
            token_jti=token_jti,
            message=str(pick(self._ALIASES["message"]) or "") or None,
            extra=extra,
        )

    @staticmethod
    def _parse_timestamp(obj: dict) -> datetime:
        for key in ("timestamp", "@timestamp", "time", "date"):
            val = obj.get(key)
            if not val:
                continue
            if isinstance(val, (int, float)):
                return datetime.fromtimestamp(val, tz=timezone.utc)
            if isinstance(val, str):
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%d %H:%M:%S",
                ):
                    try:
                        dt = datetime.strptime(val, fmt)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt
                    except ValueError:
                        continue
        return datetime.now(tz=timezone.utc)


# ── Combined Log Format (nginx / Apache) ─────────────────────────────────────

class CombinedLogParser(BaseParser):
    def parse_line(self, line: str) -> LogEvent | None:
        m = _CLF_PATTERN.match(line)
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group("time"), _CLF_TIME_FMT)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)
        user = m.group("user")
        return LogEvent(
            timestamp=ts,
            src_ip=m.group("ip"),
            user=None if user == "-" else user,
            method=m.group("method"),
            path=m.group("path"),
            status_code=int(m.group("status")),
            user_agent=m.group("ua"),
        )


# ── Linux auth.log ────────────────────────────────────────────────────────────

class AuthLogParser(BaseParser):
    _YEAR = datetime.now().year   # auth.log omits the year

    def parse_line(self, line: str) -> LogEvent | None:
        m = _AUTH_PATTERN.match(line)
        if not m:
            return None
        try:
            ts_str = f"{m.group('month')} {m.group('day')} {self._YEAR} {m.group('time')}"
            ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            ts = datetime.now(tz=timezone.utc)

        msg  = m.group("msg")
        ip   = (_AUTH_IP.search(msg) or ["", None])[1] if _AUTH_IP.search(msg) else None
        user = (_AUTH_USER.search(msg) or ["", None])[1] if _AUTH_USER.search(msg) else None
        status_str = _AUTH_STATUS.search(msg)

        status = None
        if status_str:
            word = status_str.group(1).lower()
            if word in ("failed", "invalid", "failure"):
                status = 401
            elif word in ("accepted", "succeeded"):
                status = 200

        ip_match = _AUTH_IP.search(msg)
        user_match = _AUTH_USER.search(msg)

        return LogEvent(
            timestamp=ts,
            src_ip=ip_match.group(1) if ip_match else None,
            user=user_match.group(1) if user_match else None,
            status_code=status,
            message=msg,
        )


# ── Format auto-detection ─────────────────────────────────────────────────────

def auto_detect(path: str) -> BaseParser:
    """Sniff the first non-empty line and return the appropriate parser."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                return JSONParser()
            if _CLF_PATTERN.match(line):
                return CombinedLogParser()
            if _AUTH_PATTERN.match(line):
                return AuthLogParser()
            break
    return JSONParser()   # fallback — most modern logs are JSON
