# SSH HONEYPOT Advanced SOC
# 🍯 SSH Honeypot — Advanced SOC Edition

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SOC Tool](https://img.shields.io/badge/type-SOC%20Tool-red.svg)]()

Advanced SSH honeypot for threat intelligence collection, attacker TTP analysis and SOC research. Built with Paramiko — simulates a fully interactive Linux shell to keep attackers engaged while logging every action.

---

## Features

- **Realistic SSH server** — fake OpenSSH banner, RSA host key, full PTY support
- **Interactive fake shell** — simulates Linux commands (ls, cat, ps, netstat, ifconfig...)
- **Fake filesystem** — `/etc/passwd`, `/proc/cpuinfo`, `/var/log/` and more
- **TTP Detection** — automatically classifies attacker behavior (recon, persistence, C2...)
