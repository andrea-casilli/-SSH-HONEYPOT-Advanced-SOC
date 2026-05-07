"""
SSH Honeypot server — Paramiko-based, handles connections in threads.
"""

import socket
import threading
import time
import paramiko
from fake_shell import FakeShell
from threat_intel import ThreatIntel


class _Interface(paramiko.ServerInterface):

    def __init__(self, ip, config, logger):
        self.ip      = ip
        self.config  = config
        self.logger  = logger
        self.event   = threading.Event()
        self.username = ""
        self.password = ""
        self.success  = False

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" \
               else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password

        for u, p in self.config.lure_creds:
            if username == u and password == p:
                self.success = True
                self.logger.log_attempt(self.ip, username, password, success=True)
                return paramiko.AUTH_SUCCESSFUL

        self.logger.log_attempt(self.ip, username, password, success=False)
        time.sleep(self.config.login_delay)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, w, h, pw, ph, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self.event.set()
        return True


class HoneypotServer:

    def __init__(self, config, logger):
        self.config  = config
        self.logger  = logger
        self.ti      = ThreatIntel(config)
        self.host_key = self._load_or_create_key()

    def _load_or_create_key(self) -> paramiko.RSAKey:
        path = self.config.key_path
        if __import__("os").path.exists(path):
            return paramiko.RSAKey(filename=path)
        key = paramiko.RSAKey.generate(self.config.rsa_key_bits)
        key.write_private_key_file(path)
        print(f"[+] RSA host key generated → {path}")
        return key

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.config.ssh_host, self.config.ssh_port))
        srv.listen(128)

        while True:
            try:
                client, addr = srv.accept()
                ip = addr[0]
                threading.Thread(
                    target=self._handle, args=(client, ip), daemon=True
                ).start()
                threading.Thread(
                    target=self._enrich, args=(ip,), daemon=True
                ).start()
            except Exception as e:
                print(f"[!] Accept error: {e}")

    def _enrich(self, ip: str):
        info = self.ti.lookup(ip)
        if info:
            self.logger.log_geoip(ip, info)
            parts = [info.get("country", ""), info.get("city", ""),
                     info.get("isp", "")]
            desc  = " | ".join(p for p in parts if p)
            score = info.get("abuse_score", 0)
            color = "\033[91m" if score > 50 else "\033[90m"
            print(f"{color}    └─ {ip} → {desc}"
                  + (f" | AbuseScore: {score}%" if score else "") + "\033[0m")

    def _handle(self, client, ip: str):
        transport = None
        try:
            transport = paramiko.Transport(client)
            transport.local_version = self.config.ssh_version
            transport.add_server_key(self.host_key)

            iface = _Interface(ip, self.config, self.logger)
            transport.start_server(server=iface)

            channel = transport.accept(self.config.auth_timeout)
            if channel is None:
                return

            iface.event.wait(10)

            if iface.success:
                color = "\033[91m"
                print(f"{color}[SHELL] {ip} logged in as "
                      f"{iface.username}:{iface.password}\033[0m")
                FakeShell(channel, ip, iface.username,
                          self.config, self.logger).run()
            else:
                try:
                    channel.close()
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            try:
                if transport:
                    transport.close()
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass
