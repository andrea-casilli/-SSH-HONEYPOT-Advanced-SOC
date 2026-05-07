"""
HTTP Dashboard — Flask web app that reads JSONL logs and
exposes a real-time dashboard with Server-Sent Events (SSE).
"""

import json
import os
import time
import queue
from collections import Counter
from datetime import datetime, timezone
from flask import Flask, Response, render_template, jsonify


app = Flask(__name__)
_logger    = None   # injected by honeypot.py
_config    = None
_sse_queue = queue.Queue(maxsize=500)


def init(config, logger):
    global _config, _logger
    _config = config
    _logger = logger


def push_event(event: dict):
    """Called by logger to push live events to SSE clients."""
    try:
        _sse_queue.put_nowait(event)
    except queue.Full:
        pass


# ── helpers ────────────────────────────────────────────────────────────────
def _load(filename: str) -> list:
    if _logger is None:
        return []
    return _logger.read_all(os.path.join(_config.logdir, filename))


def _stats():
    attempts  = _load("attempts.jsonl")
    sessions  = _load("sessions.jsonl")
    commands  = _load("commands.jsonl")
    ttps      = _load("ttps.jsonl")
    geoip     = _load("geoip.jsonl")

    total     = len(attempts)
    success   = sum(1 for a in attempts if a.get("success"))
    unique_ip = len(set(a["ip"] for a in attempts))

    top_pw  = Counter(a["password"]  for a in attempts).most_common(10)
    top_usr = Counter(a["username"]  for a in attempts).most_common(10)
    top_ip  = Counter(a["ip"]        for a in attempts).most_common(10)
    top_cmd = Counter(c["command"]   for c in commands).most_common(10)
    top_ttp = Counter(t["ttp"]       for t in ttps).most_common()
    top_cnt = Counter(g.get("country","?") for g in geoip).most_common(10)

    # attempts over time (last 60 minutes, grouped by minute)
    now   = datetime.now(timezone.utc).timestamp()
    buckets: dict = {}
    for a in attempts:
        try:
            ts  = datetime.fromisoformat(a["ts"].replace("Z", "+00:00")).timestamp()
            age = int((now - ts) / 60)
            if 0 <= age < 60:
                bucket = 60 - age
                buckets[bucket] = buckets.get(bucket, 0) + 1
        except Exception:
            pass
    timeline = [{"t": k, "v": v} for k, v in sorted(buckets.items())]

    return {
        "total": total, "success": success,
        "unique_ip": unique_ip, "sessions": len(sessions),
        "commands": len(commands), "ttps": len(ttps),
        "top_pw":   [{"k": k, "v": v} for k, v in top_pw],
        "top_usr":  [{"k": k, "v": v} for k, v in top_usr],
        "top_ip":   [{"k": k, "v": v} for k, v in top_ip],
        "top_cmd":  [{"k": k, "v": v} for k, v in top_cmd],
        "top_ttp":  [{"k": k, "v": v} for k, v in top_ttp],
        "top_cnt":  [{"k": k, "v": v} for k, v in top_cnt],
        "timeline": timeline,
        "recent":   (_logger.recent[-50:] if _logger else [])[::-1],
        "sessions_list": sessions[-20:][::-1],
    }


# ── routes ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html",
                           ssh_port=_config.ssh_port if _config else 2222)


@app.route("/api/stats")
def api_stats():
    return jsonify(_stats())


@app.route("/api/attempts")
def api_attempts():
    return jsonify(_load("attempts.jsonl")[-500:][::-1])


@app.route("/api/sessions")
def api_sessions():
    return jsonify(_load("sessions.jsonl")[-100:][::-1])


@app.route("/api/ttps")
def api_ttps():
    return jsonify(_load("ttps.jsonl")[-200:][::-1])


@app.route("/stream")
def stream():
    """Server-Sent Events — live feed of new honeypot events."""
    def generate():
        yield "data: {\"type\": \"connected\"}\n\n"
        while True:
            try:
                event = _sse_queue.get(timeout=25)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield "data: {\"type\": \"ping\"}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


def run(config, logger):
    init(config, logger)
    app.run(host=config.dash_host, port=config.dash_port,
            debug=False, threaded=True, use_reloader=False)
