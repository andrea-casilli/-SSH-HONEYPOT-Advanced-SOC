#!/usr/bin/env python3
"""
SSH Honeypot — CLI Analytics
Usage: python analyze.py [--top-ips] [--top-pass] [--commands] [--ip 1.2.3.4]
"""

import argparse
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from config import Config
from database import Database


def hr(char="─", width=72):
    print(char * width)


def table(rows, headers, widths):
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    hr()
    print(fmt.format(*headers))
    hr("·")
    for row in rows:
        print(fmt.format(*[str(v)[:w] for v, w in zip(row, widths)]))
    hr()


def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot Analyzer")
    parser.add_argument("--top-ips",   action="store_true", help="Top attacker IPs")
    parser.add_argument("--top-pass",  action="store_true", help="Top passwords tried")
    parser.add_argument("--top-user",  action="store_true", help="Top usernames tried")
    parser.add_argument("--top-cmds",  action="store_true", help="Top commands captured")
    parser.add_argument("--recent",    action="store_true", help="Recent attempts")
    parser.add_argument("--commands",  action="store_true", help="Recent commands")
    parser.add_argument("--alerts",    action="store_true", help="Recent alerts")
    parser.add_argument("--stats",     action="store_true", help="Overall statistics")
    parser.add_argument("--ip",        metavar="IP",        help="Filter by IP address")
    parser.add_argument("--limit",     type=int, default=20, help="Row limit (default 20)")
    parser.add_argument("--all",       action="store_true", help="Show all reports")
    args = parser.parse_args()

    cfg = Config()
    db  = Database(cfg.DB_PATH)

    show_all = args.all or not any([
        args.top_ips, args.top_pass, args.top_user, args.top_cmds,
        args.recent, args.commands, args.alerts, args.stats, args.ip,
    ])

    print("\n🍯  SSH HONEYPOT — SOC Analytics\n")

    if args.stats or show_all:
        s = db.stats()
        print("📊  Summary")
        hr()
        print(f"  Total attempts  : {s['total_attempts']:,}")
        print(f"  Unique IPs      : {s['unique_ips']:,}")
        print(f"  Commands caught : {s['total_commands']:,}")
        print(f"  Last attempt    : {s['last_attempt_at'] or 'n/a'}")
        hr()
        print()

    if args.top_ips or show_all:
        rows = [(r["ip"], r["cnt"]) for r in db.top_ips(args.limit)]
        print("🌐  Top Attacker IPs")
        table(rows, ["IP Address", "Attempts"], [42, 10])
        print()

    if args.top_pass or show_all:
        rows = [(r["password"], r["cnt"]) for r in db.top_passwords(args.limit)]
        print("🔑  Top Passwords")
        table(rows, ["Password", "Count"], [42, 10])
        print()

    if args.top_user or show_all:
        rows = [(r["username"], r["cnt"]) for r in db.top_usernames(args.limit)]
        print("👤  Top Usernames")
        table(rows, ["Username", "Count"], [42, 10])
        print()

    if args.top_cmds or show_all:
        rows = [(r["command"], r["cnt"]) for r in db.top_commands(args.limit)]
        print("💻  Top Commands")
        table(rows, ["Command", "Count"], [52, 10])
        print()

    if args.recent or show_all:
        records = db.get_attempts(limit=args.limit, ip=args.ip)
        print("🕐  Recent Attempts")
        table(
            [(r["timestamp"], r["ip"], r["username"], r["password"]) for r in records],
            ["Timestamp", "IP", "Username", "Password"],
            [22, 18, 16, 28],
        )
        print()

    if args.commands or show_all:
        records = db.get_commands(limit=args.limit)
        print("⌨️  Recent Commands")
        table(
            [(r["timestamp"], r["session_id"], r["command"]) for r in records],
            ["Timestamp", "Session", "Command"],
            [22, 9, 48],
        )
        print()

    if args.alerts or show_all:
        records = db.get_alerts(limit=args.limit)
        print("🚨  Recent Alerts")
        table(
            [(r["timestamp"], r["ip"], r["reason"]) for r in records],
            ["Timestamp", "IP", "Reason"],
            [22, 18, 44],
        )
        print()

    db.close()


if __name__ == "__main__":
    main()
