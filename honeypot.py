#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════╗
║       SSH HONEYPOT — Advanced SOC Edition        ║
║       github.com/andrea-casilli                  ║
╚══════════════════════════════════════════════════╝

Usage:
  python3 honeypot.py
  python3 honeypot.py --ssh-port 22 --dash-port 8080
  python3 honeypot.py --verbose
  ABUSEIPDB_KEY=your_key python3 honeypot.py
"""

import argparse
import sys
import threading

BANNER = """
\033[91m
  ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
  ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
  ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║   
  ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║   
  ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║   
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝   
\033[0m
\033[93m  Advanced SSH Honeypot — SOC Edition\033[0m
\033[90m  github.com/andrea-casilli/ssh-honeypot\033[0m
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="Advanced SSH Honeypot with HTTP Dashboard")
    p.add_argument("--ssh-port",  type=int, default=2222,
                   help="SSH listen port (default: 2222)")
    p.add_argument("--ssh-host",  default="0.0.0.0",
                   help="SSH bind address (default: 0.0.0.0)")
    p.add_argument("--dash-port", type=int, default=8080,
                   help="Dashboard HTTP port (default: 8080)")
    p.add_argument("--dash-host", default="0.0.0.0",
                   help="Dashboard bind address (default: 0.0.0.0)")
    p.add_argument("--logdir",    default="logs",
                   help="Log directory (default: logs/)")
    p.add_argument("--verbose",   action="store_true",
                   help="Verbose output")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    # Import here to catch missing-dependency errors clearly
    try:
        import paramiko  # noqa
    except ImportError:
        print("\033[91m[!] paramiko not installed.\033[0m")
        print("    Run: pip install paramiko flask\n")
        sys.exit(1)
    try:
        from flask import Flask  # noqa
    except ImportError:
        print("\033[91m[!] flask not installed.\033[0m")
        print("    Run: pip install paramiko flask\n")
        sys.exit(1)

    from config  import Config
    from logger  import HoneypotLogger
    from server  import HoneypotServer
    import dashboard

    config = Config(
        ssh_host=args.ssh_host,
        ssh_port=args.ssh_port,
        dash_host=args.dash_host,
        dash_port=args.dash_port,
        logdir=args.logdir,
    )

    logger = HoneypotLogger(config)

    # Patch logger so it also pushes events to SSE queue
    _orig_write = logger._write
    def _patched_write(path, record):
        _orig_write(path, record)
        dashboard.push_event(record)
    logger._write = _patched_write

    print(f"\033[92m[+] SSH  honeypot → {args.ssh_host}:{args.ssh_port}\033[0m")
    print(f"\033[92m[+] HTTP dashboard → http://{args.dash_host}:{args.dash_port}\033[0m")
    print(f"\033[92m[+] Logs → {args.logdir}/\033[0m")
    print(f"\033[90m[*] CTRL+C to stop\033[0m\n")

    # Start SSH server in background thread
    server = HoneypotServer(config, logger)
    t = threading.Thread(target=server.start, daemon=True)
    t.start()

    # Start Flask dashboard (blocking, main thread)
    try:
        dashboard.run(config, logger)
    except KeyboardInterrupt:
        print("\n\033[93m[!] Stopping honeypot...\033[0m")
        logger.print_summary()


if __name__ == "__main__":
    main()
