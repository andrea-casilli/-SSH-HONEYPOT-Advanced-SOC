import os
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class Config:
    # Network
    ssh_host:  str = "0.0.0.0"
    ssh_port:  int = 2222
    dash_host: str = "0.0.0.0"
    dash_port: int = 8080

    # Paths
    logdir:   str = "logs"
    key_path: str = "data/server.key"

    # SSH behaviour
    rsa_key_bits:     int = 2048
    auth_timeout:     int = 30
    session_timeout:  int = 180
    login_delay:      float = 1.5   # slow brute-force tools

    # Fake identity
    fake_hostname: str = "ubuntu-server"
    fake_os:       str = "Ubuntu 22.04.3 LTS"
    ssh_version:   str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

    # Threat intel
    abuseipdb_key: str = field(default_factory=lambda: os.getenv("ABUSEIPDB_KEY", ""))

    # Credentials accepted for full shell session
    lure_creds: List[Tuple[str, str]] = field(default_factory=lambda: [
        ("root",  "root"),   ("root",  "toor"),    ("root",   "password"),
        ("root",  "123456"), ("root",  "admin"),   ("root",   "1234"),
        ("admin", "admin"),  ("admin", "password"),("ubuntu", "ubuntu"),
        ("pi",    "raspberry"), ("user", "user"),  ("test",   "test"),
    ])

    def __post_init__(self):
        os.makedirs(self.logdir, exist_ok=True)
        os.makedirs("data", exist_ok=True)

    @property
    def prompt(self) -> str:
        return f"root@{self.fake_hostname}:~# "
