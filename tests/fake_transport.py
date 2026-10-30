"""A scripted Transport with canned, realistic Ubuntu 22.04 command output, so
System Scan collectors/checks run deterministically without touching a machine."""
from scanner.system_collectors import Transport, CommandResult, FileRead, StatInfo

OS_RELEASE_2204 = 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n'
OS_RELEASE_1804 = 'PRETTY_NAME="Ubuntu 18.04.6 LTS"\nNAME="Ubuntu"\nVERSION_ID="18.04"\nID=ubuntu\n'

DPKG_OUT = (
    "libssl3\t3.0.2-0ubuntu1.15\tamd64\tii \n"
    "openssl\t3.0.2-0ubuntu1.15\tamd64\tii \n"
    "openssh-server\t1:8.9p1-3ubuntu0.7\tamd64\tii \n"
    "coreutils\t8.32-4.1ubuntu1\tamd64\tii \n"
    "postgresql\t14+238\tall\tii \n"
    "postgresql-14\t14.11-0ubuntu0.22.04.1\tamd64\tii \n"
    "oldpkg\t1.0-1\tamd64\trc \n"
)
SS_OUT = (
    "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
    'tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=812,fd=3))\n'
    'tcp   LISTEN 0      128             [::]:22            [::]:*     users:(("sshd",pid=812,fd=4))\n'
    'tcp   LISTEN 0      511          0.0.0.0:6379       0.0.0.0:*     users:(("redis-server",pid=900,fd=6))\n'
    'tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*     users:(("systemd-resolve",pid=500,fd=14))\n'
    'tcp   LISTEN 0      244        127.0.0.1:5432       0.0.0.0:*     users:(("postgres",pid=700,fd=5))\n'
    'udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*\n'
)
SSHD_CONFIG = "Port 22\nPermitRootLogin yes\nPasswordAuthentication no\nX11Forwarding yes\nMaxAuthTries 10\n"
APT_SIM = (
    "NOTE: This is only a simulation!\n"
    "Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])\n"
    "Inst vim [2:8.2] (2:8.2.1 Ubuntu:22.04/jammy-updates [amd64])\n"
    "Conf libssl3 (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-updates [amd64])\n"
)
SYSCTL_GOOD = {
    "kernel/randomize_va_space": "2", "net/ipv4/tcp_syncookies": "1", "net/ipv4/conf/all/accept_source_route": "0",
    "net/ipv4/conf/all/accept_redirects": "0", "fs/suid_dumpable": "0", "kernel/kptr_restrict": "1",
    "net/ipv4/ip_forward": "0",
}
PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n"
SHADOW = "root:$6$abc:19000:0:99999:7:::\nalice:$6$def:19000:0:99999:7:::\n"


def st(mode, uid=0, owner="root", mtime=None):
    import time
    return StatInfo(mode, uid, 0, owner, mtime if mtime is not None else int(time.time()) - 86400)


class FakeTransport(Transport):
    mode = "local"
    description = "fake machine"

    def __init__(self, uid=1000, sudo_enabled=False, sudo_works=True, os_release=OS_RELEASE_2204,
                 uname="Linux web01 5.15.0-91-generic x86_64"):
        super().__init__(sudo_enabled)
        self.uid, self.sudo_works = uid, sudo_works
        self.commands = {
            ("uname", "-snrm"): CommandResult(0, uname + "\n", ""),
            ("dpkg-query", "-W", "-f", r"${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"):
                CommandResult(0, DPKG_OUT, ""),
            ("ss", "-tulnp"): CommandResult(0, SS_OUT, ""),
            ("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager", "--plain"):
                CommandResult(0, "ssh.service loaded active running OpenBSD Secure Shell\ncron.service loaded active running Cron\n", ""),
            ("systemctl", "is-active", "firewalld"): CommandResult(3, "inactive\n", ""),
            ("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"): CommandResult(0, APT_SIM, ""),
            ("ls", "-1", "--", "/etc/ssh/sshd_config.d"): CommandResult(2, "", "No such file"),
        }
        self.files = {
            "/etc/os-release": os_release, "/proc/uptime": "864000.00 1000.00\n",
            "/etc/ssh/sshd_config": SSHD_CONFIG, "/etc/passwd": PASSWD,
            **{f"/proc/sys/{k}": v + "\n" for k, v in SYSCTL_GOOD.items()},
        }
        self.denied = {"/etc/shadow"}                      # readable only by root
        self.files_priv = {"/etc/shadow": SHADOW}
        self.stats = {"/etc/passwd": st(0o644), "/etc/shadow": st(0o640), "/etc/sudoers": st(0o440),
                      "/etc/ssh/sshd_config": st(0o644), "/var/lib/apt/lists": st(0o755)}
        self.ran = []                                      # every argv actually executed (sudo prefix included)

    def _uid(self):
        return self.uid

    def _run(self, argv, timeout):
        self.ran.append(tuple(argv))
        if argv[:3] == ["sudo", "-n", "true"] or argv[:2] == ["sudo", "-n"] and len(argv) == 3 and argv[2] == "true":
            return CommandResult(0 if self.sudo_works else 1, "", "" if self.sudo_works else "sudo: a password is required")
        if argv[:3] == ["sudo", "-n", "--"]:
            inner = tuple(argv[3:])
            if inner[:2] == ("cat", "--"):
                content = self.files_priv.get(inner[2])
                return CommandResult(0, content, "") if content is not None else CommandResult(1, "", "No such file")
            return self.commands.get(inner, CommandResult(127, "", f"{inner[0]}: command not found"))
        return self.commands.get(tuple(argv), CommandResult(127, "", f"{argv[0]}: command not found"))

    def _read(self, path):
        if path in self.denied:
            return FileRead(None, "denied")
        if path in self.files:
            return FileRead(self.files[path], None)
        return FileRead(None, "missing")

    def _stat(self, path):
        return self.stats.get(path)


def as_root(t):
    t.uid = 0
    t.files.update(t.files_priv)
    t.denied.clear()
    return t
