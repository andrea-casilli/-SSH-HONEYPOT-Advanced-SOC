"""
Thread-safe logger — writes JSON lines (JSONL) for each event type.
The dashboard reads these files directly.
"""

import json
import os
import threading
from datetime import datetime, timezone
from collections import defaultdict


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class HoneypotLogger:

    def __init__(self, config):
        self.config = config
        self._lock  = threading.Lock()

        self.f_attempts = os.path.join(config.logdir, "attempts.jsonl")
        self.f_sessions = os.path.join(config.logdir, "sessions.jsonl")
        self.f_commands = os.path.join(config.logdir, "commands.jsonl")
        self.f_ttps     = os.path.join(config.logdir, "ttps.jsonl")
        self.f_geoip    = os.path.join(config.logdir, "geoip.jsonl")

        # in-memory stats for live dashboard SSE
        self.recent: list = []           # last 50 events
        self.ip_stats: dict = defaultdict(lambda: {"attempts": 0, "logins": 0})
        self._session_start = _now()

    # ── internal ──────────────────────────────────────────────────────────
    def _write(self, path: str, record: dict):
        with self._lock:
            with open(path, "a") as f:
                f.write(json.dumps(record) + "\n")
            self.recent.append(record)
            if len(self.recent) > 200:
                self.recent = self.recent[-200:]

    # ── public API ────────────────────────────────────────────────────────
    def log_attempt(self, ip: str, username: str, password: str, success: bool):
        self.ip_stats[ip]["attempts"] += 1
        if success:
            self.ip_stats[ip]["logins"] += 1
        self._write(self.f_attempts, {
            "ts": _now(), "type": "attempt",
            "ip": ip, "username": username,
            "password": password, "success": success,
        })

    def log_command(self, ip: str, username: str, command: str):
        self._write(self.f_commands, {
            "ts": _now(), "type": "command",
            "ip": ip, "username": username, "command": command,
        })

    def log_ttp(self, ip: str, username: str, ttp: str, command: str):
        self._write(self.f_ttps, {
            "ts": _now(), "type": "ttp",
            "ip": ip, "username": username, "ttp": ttp, "command": command,
        })

    def log_session(self, ip: str, username: str, commands: list, duration: int):
        self._write(self.f_sessions, {
            "ts": _now(), "type": "session",
            "ip": ip, "username": username,
            "duration": duration, "commands_count": len(commands),
            "commands": commands,
        })

    def log_geoip(self, ip: str, info: dict):
        self._write(self.f_geoip, {"ts": _now(), "ip": ip, **info})

    # ── helpers for dashboard ─────────────────────────────────────────────
    def read_all(self, path: str) -> list:
        if not os.path.exists(path):
            return []
        with self._lock:
            lines = open(path).readlines()
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
        return out
