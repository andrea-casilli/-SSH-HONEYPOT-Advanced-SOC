"""
Fake interactive Linux shell — keeps attackers engaged, logs every command
and automatically classifies TTPs (Tactics, Techniques, Procedures).
"""

import time
import random

# ── Fake filesystem ────────────────────────────────────────────────────────
FS: dict = {
    "/":           ["bin","boot","dev","etc","home","lib","media","mnt",
                    "opt","proc","root","run","sbin","srv","sys","tmp","usr","var"],
    "/root":       [".bash_history",".bashrc",".profile",".ssh"],
    "/root/.ssh":  ["authorized_keys","known_hosts"],
    "/home":       ["ubuntu","admin"],
    "/etc":        ["apt","cron.d","crontab","hostname","hosts","mysql","nginx",
                    "passwd","resolv.conf","shadow","ssh"],
    "/tmp":        [],
    "/var":        ["log","mail","spool","www"],
    "/var/log":    ["auth.log","dpkg.log","kern.log","syslog"],
    "/proc":       ["cpuinfo","meminfo","net","version"],
}

FILES: dict = {
    "/etc/hostname":    "ubuntu-server\n",
    "/etc/hosts":       "127.0.0.1\tlocalhost\n127.0.1.1\tubuntu-server\n",
    "/etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 1.1.1.1\n",
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "admin:x:1001:1001:Admin:/home/admin:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$rounds=5000$saltsaltsalt$HASH:19000:0:99999:7:::\n"
        "ubuntu:$6$rounds=5000$saltsaltsalt$HASH:19000:0:99999:7:::\n"
    ),
    "/root/.bash_history": (
        "ls\nwhoami\nuname -a\ncat /etc/passwd\nifconfig\nps aux\nnetstat -an\n"
    ),
    "/proc/version": (
        "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-059) "
        "(gcc (Ubuntu 11.4.0) 11.4.0) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n"
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
        "cpu MHz\t\t: 2399.988\ncache size\t: 30720 KB\ncpu cores\t: 4\n"
    ),
    "/proc/meminfo": (
        "MemTotal:        8192000 kB\nMemFree:         2048512 kB\n"
        "MemAvailable:    4096000 kB\nBuffers:          128000 kB\n"
        "Cached:          819200 kB\nSwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n"
    ),
}

# ── TTP signatures ─────────────────────────────────────────────────────────
TTP_SIGNATURES: dict = {
    "Recon — system info":      ["uname","hostname","id","whoami","env","lscpu"],
    "Recon — network":          ["ifconfig","ip a","netstat","ss ","route","arp"],
    "Credential harvest":       ["/etc/passwd","/etc/shadow","cat /etc/"],
    "Persistence — cron":       ["crontab","cron.d"],
    "Persistence — user add":   ["useradd","adduser","usermod","passwd"],
    "Persistence — SSH key":    ["authorized_keys","ssh-keygen","echo.*>>.*ssh"],
    "Download / C2":            ["wget ","curl ","nc ","ncat","bash -i","python -c",
                                  "perl -e","ruby -e","php -r"],
    "Lateral movement":         ["ssh ","scp ","rsync"],
    "Privilege escalation":     ["sudo","chmod +s","chmod 4","SUID","setuid"],
    "Rootkit / malware":        ["./","chmod +x","base64 -d","dd if=","cat >"],
}


class FakeShell:

    def __init__(self, channel, ip: str, username: str, config, logger):
        self.channel  = channel
        self.ip       = ip
        self.username = username
        self.config   = config
        self.logger   = logger
        self.cwd      = "/root"
        self.cmds_run: list = []
        self._t0      = time.time()
        self._prompt  = config.prompt

    # ── public ────────────────────────────────────────────────────────────
    def run(self):
        self._send(self._motd())
        self._send(self._prompt)
        buf = ""
        while True:
            try:
                self.channel.settimeout(self.config.session_timeout)
                data = self.channel.recv(1024)
                if not data:
                    break
                ch = data.decode("utf-8", errors="ignore")

                if ch in ("\x03", "\x04"):
                    self._send("\r\nlogout\r\n")
                    break

                if ch in ("\r", "\n"):
                    self._send("\r\n")
                    cmd = buf.strip()
                    buf = ""
                    if cmd:
                        result = self._dispatch(cmd)
                        if result is None:
                            break
                        if result:
                            self._send(result + "\r\n")
                    self._send(self._prompt)

                elif ch == "\x7f":
                    if buf:
                        buf = buf[:-1]
                        self._send("\b \b")
                else:
                    buf += ch
                    self._send(ch)

            except Exception:
                break

        duration = int(time.time() - self._t0)
        self.logger.log_session(self.ip, self.username, self.cmds_run, duration)
        try:
            self.channel.close()
        except Exception:
            pass

    # ── internal ──────────────────────────────────────────────────────────
    def _send(self, text: str):
        try:
            self.channel.send(text.encode("utf-8"))
        except Exception:
            pass

    def _motd(self) -> str:
        procs = random.randint(150, 280)
        mem   = random.randint(30, 75)
        disk  = random.randint(20, 65)
        load  = f"0.{random.randint(5, 50)}"
        ip4   = f"10.0.0.{random.randint(2, 254)}"
        ts    = time.strftime("%a %b %d %H:%M:%S UTC %Y")
        last  = time.strftime("%a %b %d %H:%M:%S %Y")
        return (
            f"\r\nWelcome to {self.config.fake_os} "
            f"(GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n\r\n"
            f"  System information as of {ts}\r\n\r\n"
            f"  System load:   {load}            Processes:             {procs}\r\n"
            f"  Memory usage:  {mem}%              IPv4 address for eth0: {ip4}\r\n"
            f"  Usage of /:    {disk}.2% of 20.00GB\r\n\r\n"
            f"Last login: {last} from 192.168.1.1\r\n\r\n"
        )

    def _dispatch(self, cmd: str):
        self.cmds_run.append(cmd)
        self.logger.log_command(self.ip, self.username, cmd)
        self._classify_ttp(cmd)

        base = cmd.split()[0] if cmd.split() else ""
        args = cmd.split()[1:]

        TABLE = {
            "ls": self._ls,           "dir": self._ls,
            "pwd": self._pwd,         "cd": self._cd,
            "cat": self._cat,         "more": self._cat,    "less": self._cat,
            "whoami": lambda a: "root",
            "id": lambda a: "uid=0(root) gid=0(root) groups=0(root)",
            "uname": self._uname,     "hostname": lambda a: self.config.fake_hostname,
            "ifconfig": self._ifconfig,"ip": self._ip_cmd,
            "ps": self._ps,           "top": self._ps,
            "netstat": self._netstat, "ss": self._netstat,
            "history": self._history, "w": self._w,
            "who": self._w,           "last": self._last,
            "uptime": self._uptime,   "df": self._df,
            "free": self._free,       "env": self._env,
            "echo": self._echo,       "export": lambda a: "",
            "which": self._which,     "find": self._find,
            "wget": self._download,   "curl": self._download,
            "python": self._python,   "python3": self._python,
            "perl": self._perl,       "bash": self._bash,
            "sh": self._bash,         "nc": self._nc,
            "chmod": lambda a: "",    "chown": lambda a: "",
            "mkdir": lambda a: "",    "touch": lambda a: "",
            "rm": self._rm,           "mv": lambda a: "",
            "cp": lambda a: "",       "ln": lambda a: "",
            "crontab": self._crontab, "useradd": self._useradd,
            "passwd": lambda a: "passwd: Authentication token manipulation error",
            "sudo": self._sudo,       "su": self._su,
            "service": self._service, "systemctl": self._service,
            "clear": lambda a: "\033[2J\033[H",
            "exit": lambda a: None,   "logout": lambda a: None,
            "quit": lambda a: None,
        }

        fn = TABLE.get(base)
        if fn:
            return fn(args)
        # Pipe / complex command — just log it
        if "|" in cmd or ">" in cmd or "&&" in cmd or ";" in cmd:
            return ""
        return f"-bash: {base}: command not found"

    def _classify_ttp(self, cmd: str):
        for ttp, patterns in TTP_SIGNATURES.items():
            for p in patterns:
                if p in cmd:
                    self.logger.log_ttp(self.ip, self.username, ttp, cmd)
                    print(f"\033[93m[TTP] {self.ip} — {ttp}: {cmd[:70]}\033[0m")
                    return

    # ── command implementations ────────────────────────────────────────────
    def _ls(self, args):
        path    = self.cwd
        entries = FS.get(path, [])
        if not entries:
            return ""
        long = any(a in args for a in ["-l", "-la", "-al", "-lh"])
        if long:
            ts = time.strftime("%b %d %H:%M")
            lines = [f"total {len(entries) * 4}",
                     f"drwx------  3 root root 4096 {ts} .",
                     f"drwxr-xr-x 20 root root 4096 {ts} .."]
            for e in entries:
                perm = "drwxr-xr-x" if "." not in e else "-rw-r--r--"
                size = random.randint(512, 9999)
                lines.append(f"{perm}  1 root root {size:6d} {ts} {e}")
            return "\r\n".join(lines)
        return "  ".join(entries)

    def _pwd(self, args):
        return self.cwd

    def _cd(self, args):
        if not args or args[0] == "~":
            self.cwd = "/root"
        elif args[0] == "..":
            parts = self.cwd.rstrip("/").split("/")
            self.cwd = "/".join(parts[:-1]) or "/"
        elif args[0].startswith("/"):
            self.cwd = args[0]
        else:
            self.cwd = self.cwd.rstrip("/") + "/" + args[0]
        self._prompt = f"root@{self.config.fake_hostname}:{self.cwd}# "
        return ""

    def _cat(self, args):
        if not args:
            return ""
        path = args[0] if args[0].startswith("/") else self.cwd.rstrip("/") + "/" + args[0]
        return FILES.get(path, f"cat: {args[0]}: No such file or directory")

    def _uname(self, args):
        if "-a" in args:
            return ("Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP "
                    "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux")
        if "-r" in args:
            return "5.15.0-91-generic"
        return "Linux"

    def _ifconfig(self, args):
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\r\n"
            "        inet 10.0.0.12  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
            "        inet6 fe80::17:b4ff:fe81:2a29  prefixlen 64\r\n"
            "        ether 02:17:b4:81:2a:29  txqueuelen 1000\r\n"
            "        RX packets 428916  bytes 234869431 (234.8 MB)\r\n"
            "        TX packets 197432  bytes 28491823 (28.4 MB)\r\n\r\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
        )

    def _ip_cmd(self, args):
        if args and args[0] in ("a", "addr", "address"):
            return self._ifconfig([])
        return ""

    def _ps(self, args):
        pid = random.randint(1200, 9999)
        return (
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:03 systemd\r\n"
            "  412 ?        00:00:00 sshd\r\n"
            f" {pid} pts/0    00:00:00 bash\r\n"
            f" {pid+1} pts/0    00:00:00 ps\r\n"
        )

    def _netstat(self, args):
        return (
            "Active Internet connections (only servers)\r\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n"
            f"tcp        0      0 10.0.0.12:22            {self.ip}:*          ESTABLISHED\r\n"
        )

    def _history(self, args):
        entries = ["ls","whoami","id","uname -a","cat /etc/passwd",
                   "ifconfig","ps aux","netstat -an","cat /etc/shadow","history"]
        return "\r\n".join(f"  {i+1}  {c}" for i, c in enumerate(entries))

    def _w(self, args):
        ts = time.strftime("%H:%M:%S")
        return (
            f" {ts} up 14 days,  3:22,  1 user,  load average: 0.15, 0.08, 0.10\r\n"
            "USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\r\n"
            f"root     pts/0    {self.ip:<16}  {ts}  0.00s  0.02s  0.00s w\r\n"
        )

    def _last(self, args):
        ts = time.strftime("%a %b %d %H:%M")
        return (
            f"root     pts/0        {self.ip:<16} {ts}   still logged in\r\n"
            f"root     pts/0        192.168.1.1      {ts}   00:01\r\n"
            "\r\nwtmp begins Mon Jan  1 00:00:00 2024\r\n"
        )

    def _uptime(self, args):
        ts = time.strftime("%H:%M:%S")
        return f" {ts} up 14 days,  3:22,  1 user,  load average: 0.15, 0.08, 0.10"

    def _df(self, args):
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\r\n"
            "/dev/xvda1       20G   12G  7.1G  62% /\r\n"
            "tmpfs           3.9G     0  3.9G   0% /dev/shm\r\n"
            "/dev/xvda15     105M  6.1M   99M   6% /boot/efi\r\n"
        )

    def _free(self, args):
        return (
            "               total        used        free      shared  buff/cache   available\r\n"
            "Mem:         8192000     3241428     2048000      145672     2902572     4521344\r\n"
            "Swap:        2097148           0     2097148\r\n"
        )

    def _env(self, args):
        return (
            "SHELL=/bin/bash\r\nTERM=xterm-256color\r\nUSER=root\r\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
            "HOME=/root\r\nLANG=en_US.UTF-8\r\nLOGNAME=root\r\n"
        )

    def _echo(self, args):
        return " ".join(args)

    def _which(self, args):
        known = {
            "python3":"/usr/bin/python3","python":"/usr/bin/python3",
            "wget":"/usr/bin/wget","curl":"/usr/bin/curl",
            "nc":"/usr/bin/nc","nmap":"/usr/bin/nmap","bash":"/bin/bash",
            "perl":"/usr/bin/perl","find":"/usr/bin/find",
        }
        if args:
            return known.get(args[0], "")
        return ""

    def _find(self, args):
        time.sleep(0.8)
        return ""

    def _download(self, args):
        url = next((a for a in args if a.startswith("http")), args[-1] if args else "")
        self.logger.log_ttp(self.ip, self.username, "Download / C2", f"DOWNLOAD: {url}")
        time.sleep(2)
        return (
            f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n"
            "Resolving host... failed: Temporary failure in name resolution.\r\n"
            "wget: unable to resolve host address\r\n"
        )

    def _python(self, args):
        if not args:
            return (
                "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\r\n"
                "Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n"
                ">>> "
            )
        return ""

    def _perl(self, args):
        return ""

    def _bash(self, args):
        if args and "-c" in args:
            idx = args.index("-c")
            if idx + 1 < len(args):
                sub = args[idx + 1]
                self.logger.log_ttp(self.ip, self.username, "Download / C2", f"bash -c: {sub}")
        return ""

    def _nc(self, args):
        self.logger.log_ttp(self.ip, self.username, "Download / C2", f"nc {' '.join(args)}")
        return ""

    def _rm(self, args):
        if "-rf" in args or "-fr" in args:
            return ""
        return ""

    def _crontab(self, args):
        if "-l" in args:
            return "no crontab for root"
        return ""

    def _useradd(self, args):
        user = args[-1] if args else "hacker"
        self.logger.log_ttp(self.ip, self.username, "Persistence — user add", f"useradd {user}")
        return ""

    def _sudo(self, args):
        return "-bash: sudo: command not found"

    def _su(self, args):
        return "su: Authentication failure"

    def _service(self, args):
        if args:
            return f"● {args[0]} - service\r\n   Loaded: loaded\r\n   Active: active (running)"
        return ""
