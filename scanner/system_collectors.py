"""System Scan: transports, collectors and security checks.

A System Scan inspects the machine ITSELF (OS, installed packages, listening
sockets, configuration, permissions) - unlike the Network Scan, which only
looks at what a remote host exposes on the wire. Two modes share one code path:

  LOCAL   the machine running SentriX (reads /proc, /etc, runs read-only
          commands as the SentriX process user)
  REMOTE  another Linux machine, over SSH with KEY authentication only

Both modes use a Transport (run a fixed command / read a file / stat a path),
so every collector and check behaves identically in either mode.

HONESTY RULES
  * Every check ends as pass / fail / unknown / info / not_applicable.
    A check that could not be performed (needs root, tool missing, file
    unreadable, unsupported platform) is 'unknown' with the reason and what it
    requires - NEVER 'pass'.
  * Absence of evidence is not evidence of safety: a failed read is not a pass.
  * Only fixed, read-only commands are ever executed. No user-supplied text is
    interpolated into a command line.
  * Linux only. Other platforms fail the scan with an explicit message.

CREDENTIALS (remote mode)
  SSH private key only (no passwords, no agent). The key is written to a
  mode-0600 file in a private temp dir for the duration of the scan and
  shredded afterwards; it is never stored in the database or logged. Host keys
  are verified against a fingerprint supplied by the user (or the user must
  explicitly accept an unverified key, which is recorded on the scan).
"""
import contextlib
import datetime as dt
import logging
import os
import re
import shlex
import shutil
import stat as statmod
import subprocess
import tempfile
from collections import namedtuple

logger = logging.getLogger(__name__)

CommandResult = namedtuple("CommandResult", "rc out err")
FileRead = namedtuple("FileRead", "content error")          # error: None | missing | denied | error
StatInfo = namedtuple("StatInfo", "mode uid gid owner mtime")

SEVERITY_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
MAX_FILE_BYTES = 2_000_000


class SystemScanError(RuntimeError):
    """A failure whose message is safe and useful to show the user."""


class UnsupportedPlatform(SystemScanError):
    pass


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------
class Transport:
    """Run fixed read-only commands / read files on the target machine."""
    mode = "local"
    description = "local machine"

    def __init__(self, sudo_enabled=False):
        self.sudo_enabled = sudo_enabled
        self._elevate = None

    # -- primitives subclasses implement --
    def _run(self, argv, timeout):
        raise NotImplementedError

    def _stat(self, path):
        raise NotImplementedError

    def _uid(self):
        raise NotImplementedError

    def _read(self, path):
        raise NotImplementedError

    # -- shared behaviour --
    @property
    def is_root(self):
        return self._uid() == 0

    @property
    def can_elevate(self):
        """True if privileged checks can run: already root, or sudo was enabled
        for this scan AND passwordless sudo actually works for this account."""
        if self.is_root:
            return True
        if not self.sudo_enabled:
            return False
        if self._elevate is None:
            r = self._run(["sudo", "-n", "true"], 15)
            self._elevate = r.rc == 0
        return self._elevate

    def run(self, argv, timeout=30, sudo=False):
        """Run a fixed command. sudo=True prefixes `sudo -n` when not root and
        sudo is usable; otherwise the command runs as the plain user (the
        caller inspects rc/stderr and decides how to report a denial)."""
        if sudo and not self.is_root and self.can_elevate:
            argv = ["sudo", "-n", "--"] + list(argv)
        return self._run(list(argv), timeout)

    def read_file(self, path, sudo=False):
        fr = self._read(path)
        if fr.error == "denied" and sudo and not self.is_root and self.can_elevate:
            r = self._run(["sudo", "-n", "--", "cat", "--", path], 30)
            if r.rc == 0:
                return FileRead(r.out[:MAX_FILE_BYTES], None)
        return fr

    def stat(self, path):
        return self._stat(path)


class LocalTransport(Transport):
    mode = "local"
    description = "local machine"

    def _run(self, argv, timeout):
        env = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
            return CommandResult(p.returncode, p.stdout, p.stderr)
        except FileNotFoundError:
            return CommandResult(127, "", f"{argv[0]}: command not found")
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", "timed out")
        except OSError as e:
            # e.g. PermissionError when a directory on PATH (or the binary) is not accessible to this
            # user. That is a failed command, not a crash - callers report the check as not assessed.
            return CommandResult(126, "", f"{argv[0]}: cannot execute ({e.__class__.__name__})")

    def _uid(self):
        return os.geteuid() if hasattr(os, "geteuid") else -1

    def _read(self, path):
        try:
            with open(path, "r", errors="replace") as f:
                return FileRead(f.read(MAX_FILE_BYTES), None)
        except FileNotFoundError:
            return FileRead(None, "missing")
        except PermissionError:
            return FileRead(None, "denied")
        except OSError:
            return FileRead(None, "error")

    def _stat(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return None
        try:
            import pwd
            owner = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            owner = None
        return StatInfo(statmod.S_IMODE(st.st_mode), st.st_uid, st.st_gid, owner, int(st.st_mtime))


class SSHTransport(Transport):
    mode = "remote"

    def __init__(self, host, port, user, key_path, known_hosts_path, host_key_verified, sudo_enabled=False):
        super().__init__(sudo_enabled)
        self.host, self.port, self.user = host, port, user
        self.host_key_verified = host_key_verified
        self.description = f"{user}@{host}:{port} (SSH)"
        self._uid_cache = None
        self._base = [
            "ssh", "-T", "-F", "/dev/null", "-p", str(port), "-i", key_path,
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
            "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "LogLevel=ERROR",
            "-o", "StrictHostKeyChecking=" + ("yes" if host_key_verified else "no"),
            "-o", "UserKnownHostsFile=" + (known_hosts_path if host_key_verified else "/dev/null"),
            f"{user}@{host}",
        ]

    def _run(self, argv, timeout):
        cmd = self._base + [shlex.join(argv)]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout + 15)
        except subprocess.TimeoutExpired:
            return CommandResult(124, "", "timed out")
        if p.returncode == 255:                      # ssh itself failed (not the remote command)
            raise SystemScanError(_ssh_error_message(p.stderr))
        return CommandResult(p.returncode, p.stdout, p.stderr)

    def _uid(self):
        if self._uid_cache is None:
            r = self._run(["id", "-u"], 15)
            self._uid_cache = int(r.out.strip()) if r.rc == 0 and r.out.strip().isdigit() else -1
        return self._uid_cache

    def _read(self, path):
        r = self._run(["cat", "--", path], 30)
        if r.rc == 0:
            return FileRead(r.out[:MAX_FILE_BYTES], None)
        err = r.err.lower()
        if "no such file" in err:
            return FileRead(None, "missing")
        if "permission denied" in err:
            return FileRead(None, "denied")
        return FileRead(None, "error")

    def _stat(self, path):
        r = self._run(["stat", "-c", "%a|%u|%g|%U|%Y", "--", path], 15)
        if r.rc != 0:
            return None
        try:
            mode, uid, gid, owner, mtime = r.out.strip().split("|")
            return StatInfo(int(mode, 8), int(uid), int(gid), owner, int(mtime))
        except ValueError:
            return None


def _ssh_error_message(stderr):
    """A user-safe explanation of an ssh connection failure (never echoes key material)."""
    e = (stderr or "").lower()
    if "permission denied" in e:
        return ("SSH authentication failed: the key was rejected (wrong key, key not authorised for this "
                "account, account does not exist, or the key is passphrase-protected, which is not supported).")
    if "host key verification failed" in e or "remote host identification has changed" in e:
        return "SSH host key verification failed: the server's key does not match the fingerprint you supplied."
    if "connection refused" in e:
        return "SSH connection refused: nothing is accepting SSH connections on that host/port."
    if "timed out" in e or "no route to host" in e or "network is unreachable" in e:
        return "SSH connection timed out or the host is unreachable."
    if "could not resolve hostname" in e or "name or service not known" in e:
        return "SSH host name could not be resolved."
    if "connection closed" in e or "connection reset" in e:
        return "SSH connection was closed by the server."
    return "SSH connection failed (see the server log for details)."


# ---------------------------------------------------------------------------
# SSH credential handling
# ---------------------------------------------------------------------------
_KEY_BEGIN = re.compile(r"^-----BEGIN ((?:OPENSSH|RSA|EC|DSA) )?PRIVATE KEY-----\s*$", re.M)
_KEY_END = re.compile(r"^-----END ((?:OPENSSH|RSA|EC|DSA) )?PRIVATE KEY-----\s*$", re.M)
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
MAX_KEY_BYTES = 16_384


def validate_key_format(text):
    """Cheap structural check of a pasted private key. Returns a normalised
    key text (LF endings, trailing newline) or raises SystemScanError."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        raise SystemScanError("An SSH private key is required for remote system scans.")
    if len(text.encode()) > MAX_KEY_BYTES:
        raise SystemScanError("The SSH private key is too large.")
    if not _KEY_BEGIN.search(text) or not _KEY_END.search(text):
        raise SystemScanError("That does not look like an unencrypted PEM/OpenSSH private key "
                              "(expected -----BEGIN ... PRIVATE KEY----- ... -----END ... PRIVATE KEY-----).")
    if "ENCRYPTED" in text.split("\n", 3)[0] or "Proc-Type: 4,ENCRYPTED" in text:
        raise SystemScanError("Passphrase-protected keys are not supported: use a dedicated, "
                              "unencrypted key for the scan account.")
    return text + "\n"


def normalize_fingerprint(text):
    fp = (text or "").strip()
    if not fp:
        return None
    if not fp.startswith("SHA256:"):
        fp = "SHA256:" + fp
    fp = fp.rstrip("=")
    if not FINGERPRINT_RE.match(fp):
        raise SystemScanError("Host key fingerprint must look like SHA256:xxxxxxxx... (as printed by "
                              "`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`).")
    return fp


def _need(binary):
    if not shutil.which(binary):
        raise SystemScanError(f"The '{binary}' program is required for remote system scans but is not installed "
                              "on the SentriX server (install the OpenSSH client).")


def _shred(path):
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


@contextlib.contextmanager
def private_key_file(key_text):
    """Write the key to a 0600 file inside a private 0700 temp dir; shred and
    remove it on exit no matter what."""
    workdir = tempfile.mkdtemp(prefix="sentrix-ssh-")
    os.chmod(workdir, 0o700)
    path = os.path.join(workdir, "id")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key_text)
        yield path, workdir
    finally:
        _shred(path)
        shutil.rmtree(workdir, ignore_errors=True)


def check_key_usable(key_path):
    """True if the key parses and has no passphrase (ssh-keygen -y -P '')."""
    _need("ssh-keygen")
    r = subprocess.run(["ssh-keygen", "-y", "-P", "", "-f", key_path], capture_output=True, text=True, timeout=20)
    return r.returncode == 0


def scan_host_keys(host, port):
    """[(key_line, fingerprint, key_type), ...] presented by the server."""
    _need("ssh-keyscan")
    _need("ssh-keygen")
    r = subprocess.run(["ssh-keyscan", "-T", "10", "-p", str(port), "-t", "ed25519,ecdsa,rsa", host],
                       capture_output=True, text=True, timeout=40)
    keys = []
    for line in r.stdout.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        with tempfile.TemporaryDirectory(prefix="sentrix-kh-") as d:
            kh = os.path.join(d, "kh")
            with open(kh, "w") as f:
                f.write(line + "\n")
            fp = subprocess.run(["ssh-keygen", "-lf", kh, "-E", "sha256"], capture_output=True, text=True, timeout=15)
        m = re.search(r"(SHA256:\S+)", fp.stdout)
        if m:
            keys.append((line, m.group(1), line.split()[1] if len(line.split()) > 1 else "?"))
    return keys


@contextlib.contextmanager
def open_ssh_transport(host, port, user, key_text, fingerprint=None, accept_unverified=False, use_sudo=False):
    """Yield a connected SSHTransport. Verifies the server's host key against
    `fingerprint` (strict pinning) unless accept_unverified is set. Raises
    SystemScanError with a user-safe message on any failure."""
    _need("ssh")
    fingerprint = normalize_fingerprint(fingerprint)
    if not fingerprint and not accept_unverified:
        raise SystemScanError("Provide the server's host key fingerprint (SHA256:...) or explicitly accept an "
                              "unverified host key.")
    key_text = validate_key_format(key_text)
    with private_key_file(key_text) as (key_path, workdir):
        if not check_key_usable(key_path):
            raise SystemScanError("The SSH private key is invalid or passphrase-protected (not supported).")
        known_hosts, verified = None, False
        if fingerprint:
            presented = scan_host_keys(host, port)
            if not presented:
                raise SystemScanError("Could not read the server's SSH host keys (is SSH reachable on that host/port?).")
            match = next((k for k in presented if k[1] == fingerprint), None)
            if not match:
                raise SystemScanError(
                    "The server's host key does not match the fingerprint you supplied (possible impersonation, "
                    "or the wrong fingerprint). Keys presented: " + ", ".join(f"{k[2]} {k[1]}" for k in presented))
            known_hosts = os.path.join(workdir, "known_hosts")
            with open(known_hosts, "w") as f:
                f.write(match[0] + "\n")
            verified = True
        t = SSHTransport(host, port, user, key_path, known_hosts, verified, sudo_enabled=use_sudo)
        t._run(["true"], 20)                          # connection + authentication check (raises SystemScanError)
        yield t


# ---------------------------------------------------------------------------
# Result helper
# ---------------------------------------------------------------------------
def check(check_id, category, title, status, severity=None, evidence="", remediation="", requires=None):
    assert status in ("pass", "fail", "unknown", "info", "not_applicable")
    return {"check_id": check_id, "category": category, "title": title, "status": status,
            "severity": severity if status == "fail" else None, "evidence": evidence,
            "remediation": remediation, "requires": requires}


def _needs_root(check_id, category, title, what):
    return check(check_id, category, title, "unknown", evidence=f"Not assessed: {what} requires root. "
                 "Run the scan as root, or enable 'use sudo' with a passwordless-sudo account.", requires="root")


# ---------------------------------------------------------------------------
# Collectors
# ---------------------------------------------------------------------------
def parse_os_release(text):
    info = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"').strip("'")
    return info


# End of STANDARD vendor support dates, from the vendors' published lifecycle
# schedules. Extended programmes (Ubuntu ESM, Debian ELTS, CentOS none) may
# still supply patches, which the check text says explicitly.
OS_EOL = {
    ("ubuntu", "14.04"): "2019-04-30", ("ubuntu", "16.04"): "2021-04-30",
    ("ubuntu", "18.04"): "2023-05-31", ("ubuntu", "20.04"): "2025-05-31",
    ("ubuntu", "22.04"): "2027-06-01", ("ubuntu", "24.04"): "2029-05-31",
    ("debian", "8"): "2020-06-30", ("debian", "9"): "2022-06-30", ("debian", "10"): "2024-06-30",
    ("centos", "6"): "2020-11-30", ("centos", "7"): "2024-06-30", ("centos", "8"): "2021-12-31",
}


def collect_os_info(t):
    r = t.run(["uname", "-snrm"])
    parts = r.out.split() if r.rc == 0 else []
    if len(parts) < 4:
        raise SystemScanError("Could not identify the operating system (uname failed). System Scan supports Linux only.")
    sysname, node, release, arch = parts[0], parts[1], parts[2], parts[3]
    if sysname != "Linux":
        raise UnsupportedPlatform(
            f"System Scan supports Linux only; this target reports '{sysname}'. No checks were performed.")
    osr = parse_os_release(t.read_file("/etc/os-release").content or "")
    up = t.read_file("/proc/uptime").content or ""
    try:
        uptime_days = round(float(up.split()[0]) / 86400, 1)
    except (ValueError, IndexError):
        uptime_days = None
    return {
        "platform": sysname, "hostname": node, "kernel": release, "arch": arch,
        "os_id": (osr.get("ID") or "").lower(), "os_version_id": osr.get("VERSION_ID") or "",
        "os_name": osr.get("NAME") or "Linux", "os_pretty": osr.get("PRETTY_NAME") or f"Linux {release}",
        "uptime_days": uptime_days,
    }


def collect_packages(t):
    """(manager, [{name, version, upstream_source_version, arch}], error)."""
    r = t.run(["dpkg-query", "-W", "-f", r"${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"], timeout=60)
    if r.rc == 0:
        pkgs = []
        for line in r.out.splitlines():
            f = line.split("\t")
            if len(f) >= 4 and f[3].strip().startswith("ii"):
                pkgs.append({"name": f[0], "version": f[1], "arch": f[2], "source": "dpkg"})
        return "dpkg", pkgs, None
    r2 = t.run(["rpm", "-qa", "--qf", r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VERSION}\n"], timeout=60)
    if r2.rc == 0:
        pkgs = []
        for line in r2.out.splitlines():
            f = line.split("\t")
            if len(f) >= 4:
                pkgs.append({"name": f[0], "version": f[1], "arch": f[2], "source": "rpm", "upstream": f[3]})
        return "rpm", pkgs, None
    return None, [], "no supported package manager found (dpkg and rpm are supported)"


def _split_addr(local):
    local = local.strip()
    if local.startswith("["):
        host, _, port = local[1:].partition("]:")
    else:
        host, _, port = local.rpartition(":")
    host = host.split("%")[0]
    return host, port


def _scope(host):
    h = host.strip()
    if h in ("0.0.0.0", "::", "*", ""):
        return "all"
    if h.startswith("127.") or h == "::1":
        return "loopback"
    return "specific"


def parse_ss(text):
    out = []
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) < 5 or f[0] in ("Netid", "State"):
            continue
        proto = f[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        host, port = _split_addr(f[4])
        if not port.isdigit():
            continue
        m = re.search(r'\("([^"]+)"', " ".join(f[6:]))
        out.append({"proto": proto, "address": host or "*", "port": int(port), "scope": _scope(host),
                    "process": m.group(1) if m else None})
    return out


def parse_proc_net(text, proto):
    """Fallback when `ss` is unavailable: /proc/net/{tcp,tcp6,udp,udp6}."""
    out = []
    for line in (text or "").splitlines()[1:]:
        f = line.split()
        if len(f) < 4:
            continue
        addr_hex, port_hex = f[1].split(":")
        state = f[3]
        if proto.startswith("tcp") and state != "0A":      # LISTEN
            continue
        if proto.startswith("udp") and state != "07":      # bound, unconnected
            continue
        if len(addr_hex) == 8:
            ip = ".".join(str(int(addr_hex[i:i + 2], 16)) for i in (6, 4, 2, 0))
        else:
            ip = "::" if set(addr_hex) == {"0"} else ("::1" if addr_hex == "0" * 31 + "1" or
                                                     addr_hex == "00000000000000000000000001000000" else addr_hex)
        out.append({"proto": proto[:3], "address": ip, "port": int(port_hex, 16), "scope": _scope(ip), "process": None})
    return out


def collect_listeners(t):
    """(listeners, source_note). Never raises on a missing tool - returns None
    when listening sockets could not be determined at all."""
    r = t.run(["ss", "-tulnp"], sudo=True)
    if r.rc == 0:
        seen, uniq = set(), []
        for item in parse_ss(r.out):
            k = (item["proto"], item["address"], item["port"])
            if k not in seen:
                seen.add(k)
                uniq.append(item)
        note = "ss -tulnp" + ("" if t.can_elevate else " (process names are only visible for the scan user's own sockets)")
        return uniq, note
    items = []
    for name in ("tcp", "tcp6", "udp", "udp6"):
        fr = t.read_file(f"/proc/net/{name}")
        if fr.content is None:
            return None, "neither ss nor /proc/net could be read"
        items += parse_proc_net(fr.content, name)
    return items, "/proc/net (process names unavailable)"


def collect_running_services(t):
    r = t.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager", "--plain"])
    if r.rc != 0:
        return None
    return sorted({line.split()[0] for line in r.out.splitlines() if line.split()})


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def check_os_support(info, today=None):
    today = today or dt.date.today()
    key = (info["os_id"], info["os_version_id"])
    eol = OS_EOL.get(key)
    title = "Operating system release is within vendor support"
    if not eol:
        return check("os.supported", "os", title, "unknown",
                     evidence=f"{info['os_pretty']}: no lifecycle date for this release in SentriX's table, so its support status was not determined.")
    end = dt.date.fromisoformat(eol)
    if end < today:
        return check("os.supported", "os", title, "fail", "HIGH",
                     evidence=(f"{info['os_pretty']} reached the end of standard vendor support on {eol}. "
                               "Extended-support programmes (e.g. Ubuntu ESM, Debian ELTS) may still provide some patches."),
                     remediation="Upgrade to a supported release, or enrol in the vendor's extended security maintenance.")
    return check("os.supported", "os", title, "pass",
                 evidence=f"{info['os_pretty']}: standard vendor support runs until {eol}.")


def _sshd_config_from_file(t):
    """({directive: value}, source) from sshd_config (+ sshd_config.d), first
    occurrence wins, Match blocks ignored. (None, reason) if unreadable."""
    main = t.read_file("/etc/ssh/sshd_config", sudo=True)
    if main.error == "missing":
        return None, "missing"
    if main.content is None:
        return None, "denied" if main.error == "denied" else "error"
    values = {}

    def parse(text):
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            if key == "match":
                return
            if key == "include":
                if len(parts) > 1 and parts[1].strip().startswith("/etc/ssh/sshd_config.d/"):
                    ls = t.run(["ls", "-1", "--", "/etc/ssh/sshd_config.d"])
                    for name in sorted(ls.out.split()) if ls.rc == 0 else []:
                        if name.endswith(".conf"):
                            sub = t.read_file(f"/etc/ssh/sshd_config.d/{name}", sudo=True)
                            if sub.content:
                                parse(sub.content)
                continue
            if len(parts) > 1 and key not in values:
                values[key] = parts[1].strip().strip('"').lower()
    parse(main.content)
    return values, "/etc/ssh/sshd_config"


def check_ssh(t):
    cat = "ssh"
    ids = [("ssh.permit_root_login", "SSH root login is not permitted with a password"),
           ("ssh.password_authentication", "SSH password authentication is disabled"),
           ("ssh.permit_empty_passwords", "SSH does not permit empty passwords"),
           ("ssh.max_auth_tries", "SSH limits authentication attempts"),
           ("ssh.x11_forwarding", "SSH X11 forwarding is disabled")]
    values, source, effective = None, None, False
    eff_failure = None
    if t.can_elevate:
        r = t.run(["/usr/sbin/sshd", "-T"], sudo=True)
        if r.rc != 0 or not r.out.strip():
            eff_failure = (r.err or r.out or "no output").strip().splitlines()[0][:100]
        if r.rc == 0 and r.out.strip():
            values = {}
            for line in r.out.splitlines():
                p = line.split(None, 1)
                if len(p) == 2:
                    values.setdefault(p[0].lower(), p[1].strip().lower())
            source, effective = "the effective configuration (sshd -T)", True
    if values is None:
        values, why = _sshd_config_from_file(t)
        if values is None:
            if why == "missing":
                return [check(i, cat, title, "not_applicable",
                              evidence="/etc/ssh/sshd_config does not exist: no SSH server is configured on this machine.")
                        for i, title in ids]
            return [check(i, cat, title, "unknown", evidence="/etc/ssh/sshd_config could not be read.",
                          requires="root" if why == "denied" else None) for i, title in ids]
        source = f"{why} (as written; the effective value could also depend on Match blocks and compiled-in defaults)"

    out = []
    pr = values.get("permitrootlogin")
    title = ids[0][1]
    if pr is None and eff_failure is not None:
        # We HAD the privilege; sshd -T itself failed. Say so - don't blame missing root.
        out.append(check(ids[0][0], cat, title, "unknown",
                         evidence="PermitRootLogin is not set in the file and its compiled-in default depends on the OpenSSH "
                                  f"version; `sshd -T` was attempted with sufficient privilege but failed ({eff_failure}), "
                                  "so the effective value could not be read."))
    elif pr is None:
        out.append(check(ids[0][0], cat, title, "unknown",
                         evidence="PermitRootLogin is not set in the file; its compiled-in default depends on the OpenSSH "
                                  "version. Run as root (or with sudo) so the effective value can be read with sshd -T.",
                         requires="root"))
    elif pr == "yes":
        out.append(check(ids[0][0], cat, title, "fail", "HIGH", evidence=f"PermitRootLogin yes - from {source}.",
                         remediation="Set 'PermitRootLogin no' (or prohibit-password) in sshd_config and reload sshd."))
    else:
        out.append(check(ids[0][0], cat, title, "pass", evidence=f"PermitRootLogin {pr} - from {source}."))

    pa = values.get("passwordauthentication")
    default_note = ""
    if pa is None:
        pa, default_note = "yes", " (not set: the OpenSSH default 'yes' applies)"
    out.append(check(ids[1][0], cat, ids[1][1], "fail" if pa == "yes" else "pass", "MEDIUM",
                     evidence=f"PasswordAuthentication {pa}{default_note} - from {source}.",
                     remediation="Use key-based authentication: set 'PasswordAuthentication no' and reload sshd."))

    pe = values.get("permitemptypasswords")
    default_note = ""
    if pe is None:
        pe, default_note = "no", " (not set: the OpenSSH default 'no' applies)"
    out.append(check(ids[2][0], cat, ids[2][1], "fail" if pe == "yes" else "pass", "HIGH",
                     evidence=f"PermitEmptyPasswords {pe}{default_note} - from {source}.",
                     remediation="Set 'PermitEmptyPasswords no' in sshd_config and reload sshd."))

    mt = values.get("maxauthtries")
    default_note = ""
    if mt is None:
        mt, default_note = "6", " (not set: the OpenSSH default 6 applies)"
    try:
        too_many = int(mt) > 6
    except ValueError:
        too_many = False
    out.append(check(ids[3][0], cat, ids[3][1], "fail" if too_many else "pass", "LOW",
                     evidence=f"MaxAuthTries {mt}{default_note} - from {source}.",
                     remediation="Set 'MaxAuthTries 4' (or lower) in sshd_config."))

    x11 = values.get("x11forwarding")
    default_note = ""
    if x11 is None:
        x11, default_note = "no", " (not set: the OpenSSH default 'no' applies)"
    out.append(check(ids[4][0], cat, ids[4][1], "fail" if x11 == "yes" else "pass", "LOW",
                     evidence=f"X11Forwarding {x11}{default_note} - from {source}.",
                     remediation="Set 'X11Forwarding no' unless graphical forwarding is required."))
    return out


def check_firewall(t):
    cid, cat, title = "firewall.active", "firewall", "A host firewall is active"
    r = t.run(["ufw", "status"], sudo=True)
    if r.rc == 0 and "status: active" in r.out.lower():
        return check(cid, cat, title, "pass", evidence="ufw reports: Status: active.")
    r = t.run(["systemctl", "is-active", "firewalld"])
    if r.rc == 0 and r.out.strip() == "active":
        return check(cid, cat, title, "pass", evidence="firewalld service is active.")
    if not t.can_elevate:
        return _needs_root(cid, cat, title, "reading the firewall ruleset (iptables/nftables)")
    r = t.run(["iptables", "-S"], sudo=True)
    if r.rc == 0:
        lines = r.out.splitlines()
        policy = next((l.split()[2] for l in lines if l.startswith("-P INPUT")), "ACCEPT")
        rules = [l for l in lines if l.startswith("-A INPUT")]
        if policy in ("DROP", "REJECT") or rules:
            return check(cid, cat, title, "pass", evidence=f"iptables INPUT policy {policy} with {len(rules)} rule(s).")
        return check(cid, cat, title, "fail", "MEDIUM",
                     evidence="iptables INPUT chain has policy ACCEPT and no rules: no packet filtering is configured.",
                     remediation="Enable a host firewall (ufw/firewalld/nftables) with a default-deny inbound policy.")
    r = t.run(["nft", "list", "ruleset"], sudo=True)
    if r.rc == 0:
        if "policy drop" in r.out or "drop" in r.out or "reject" in r.out:
            return check(cid, cat, title, "pass", evidence="nftables ruleset contains filtering rules.")
        return check(cid, cat, title, "fail", "MEDIUM", evidence="nftables has no filtering rules.",
                     remediation="Enable a host firewall with a default-deny inbound policy.")
    return check(cid, cat, title, "unknown",
                 evidence="No firewall tooling (ufw, firewalld, iptables, nft) could be queried on this machine.")


_SYSCTLS = [
    ("kernel.aslr", "kernel.randomize_va_space", "Address-space layout randomisation is fully enabled",
     lambda v: v == "2", "MEDIUM", "Set kernel.randomize_va_space = 2 in /etc/sysctl.d/."),
    ("kernel.syncookies", "net.ipv4.tcp_syncookies", "TCP SYN cookies are enabled",
     lambda v: v == "1", "LOW", "Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.d/."),
    ("kernel.source_routing", "net.ipv4.conf.all.accept_source_route", "IP source routing is disabled",
     lambda v: v == "0", "MEDIUM", "Set net.ipv4.conf.all.accept_source_route = 0 in /etc/sysctl.d/."),
    ("kernel.icmp_redirects", "net.ipv4.conf.all.accept_redirects", "ICMP redirects are not accepted",
     lambda v: v == "0", "LOW", "Set net.ipv4.conf.all.accept_redirects = 0 in /etc/sysctl.d/."),
    ("kernel.suid_dumpable", "fs.suid_dumpable", "Core dumps of setuid programs are disabled",
     lambda v: v == "0", "LOW", "Set fs.suid_dumpable = 0 in /etc/sysctl.d/."),
    ("kernel.kptr_restrict", "kernel.kptr_restrict", "Kernel pointer exposure is restricted",
     lambda v: v.isdigit() and int(v) >= 1, "LOW", "Set kernel.kptr_restrict = 1 (or 2) in /etc/sysctl.d/."),
]


def check_sysctl(t):
    out = []
    for cid, key, title, ok, sev, fix in _SYSCTLS:
        fr = t.read_file("/proc/sys/" + key.replace(".", "/"))
        if fr.content is None:
            out.append(check(cid, "kernel", title, "unknown",
                             evidence=f"/proc/sys/{key.replace('.', '/')} could not be read ({fr.error}).",
                             requires="root" if fr.error == "denied" else None))
            continue
        val = fr.content.strip()
        out.append(check(cid, "kernel", title, "pass" if ok(val) else "fail", sev,
                         evidence=f"{key} = {val} (read from /proc/sys).", remediation=fix))
    fr = t.read_file("/proc/sys/net/ipv4/ip_forward")
    if fr.content is not None:
        v = fr.content.strip()
        out.append(check("kernel.ip_forward", "kernel", "IP forwarding state", "info",
                         evidence=f"net.ipv4.ip_forward = {v}" + (" - forwarding is ON, which is only expected on routers, "
                                                                 "VPN gateways and container hosts." if v == "1" else ".")))
    return out


def check_file_permissions(t):
    out = []

    def one(cid, path, title, bad, sev, fix, optional=False):
        st = t.stat(path)
        if st is None:
            out.append(check(cid, "files", title, "not_applicable" if optional else "unknown",
                             evidence=f"{path} does not exist or could not be inspected."))
            return
        problems = bad(st)
        ev = f"{path}: mode {st.mode:04o}, owner {st.owner or st.uid}."
        out.append(check(cid, "files", title, "fail" if problems else "pass", sev,
                         evidence=ev + (f" Problem: {problems}." if problems else ""), remediation=fix))

    one("files.passwd", "/etc/passwd", "/etc/passwd is not writable by group/others",
        lambda s: "writable by group/others" if s.mode & 0o022 else (f"owned by uid {s.uid}, not root" if s.uid != 0 else ""),
        "HIGH", "chown root:root /etc/passwd && chmod 644 /etc/passwd")
    one("files.shadow", "/etc/shadow", "/etc/shadow is not readable by group/others beyond the shadow group",
        lambda s: "accessible to other users" if s.mode & 0o007 else ("writable by group" if s.mode & 0o020 else ""),
        "HIGH", "chmod 640 /etc/shadow (or 000) and chown root:shadow /etc/shadow")
    one("files.sudoers", "/etc/sudoers", "/etc/sudoers is not writable by group/others",
        lambda s: "writable by group/others" if s.mode & 0o022 else "", "HIGH",
        "chmod 440 /etc/sudoers", optional=True)
    one("files.sshd_config", "/etc/ssh/sshd_config", "sshd_config is not writable by group/others",
        lambda s: "writable by group/others" if s.mode & 0o022 else "", "MEDIUM",
        "chmod 600 /etc/ssh/sshd_config", optional=True)
    return out


def check_accounts(t):
    out = []
    pw = t.read_file("/etc/passwd")
    if pw.content is None:
        out.append(check("accounts.uid0", "accounts", "Only root has UID 0", "unknown",
                         evidence="/etc/passwd could not be read."))
    else:
        extra = []
        for line in pw.content.splitlines():
            f = line.split(":")
            if len(f) >= 3 and f[2] == "0" and f[0] != "root":
                extra.append(f[0])
        out.append(check("accounts.uid0", "accounts", "Only root has UID 0", "fail" if extra else "pass", "CRITICAL",
                         evidence=("Additional UID-0 accounts: " + ", ".join(extra)) if extra
                         else "No account other than root has UID 0 (from /etc/passwd).",
                         remediation="Remove or re-number the extra UID-0 accounts; only root should have UID 0."))
    sh = t.read_file("/etc/shadow", sudo=True)
    if sh.content is None:
        out.append(_needs_root("accounts.empty_passwords", "accounts", "No account has an empty password",
                               "reading /etc/shadow") if sh.error == "denied" else
                   check("accounts.empty_passwords", "accounts", "No account has an empty password", "unknown",
                         evidence="/etc/shadow could not be read."))
    else:
        empty = [l.split(":")[0] for l in sh.content.splitlines() if l.count(":") >= 1 and l.split(":")[1] == ""]
        out.append(check("accounts.empty_passwords", "accounts", "No account has an empty password",
                         "fail" if empty else "pass", "CRITICAL",
                         evidence=("Accounts with an empty password: " + ", ".join(empty)) if empty
                         else "No account has an empty password field (from /etc/shadow).",
                         remediation="Set a password or lock each listed account (passwd -l <user>)."))
    return out


def check_updates(t, manager):
    cid, cat, title = "updates.security_pending", "updates", "No security updates are pending"
    if manager != "dpkg":
        return check(cid, cat, title, "unknown",
                     evidence="Pending-update detection is implemented for apt (Debian/Ubuntu) systems only; "
                              "it was not assessed on this machine.")
    r = t.run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=90)
    if r.rc != 0:
        return check(cid, cat, title, "unknown", evidence="apt-get could not simulate an upgrade on this machine.")
    pending = [l for l in r.out.splitlines() if l.startswith("Inst ")]
    security = [l.split()[1] for l in pending if "-security" in l]
    st = t.stat("/var/lib/apt/lists")
    age_note, stale = "", False
    if st:
        age = (dt.datetime.now().timestamp() - st.mtime) / 86400
        age_note = f" The package index was last refreshed {age:.0f} day(s) ago (no network access is used, so an old index under-reports)."
        stale = age > 14
    if security:
        return check(cid, cat, title, "fail", "HIGH",
                     evidence=f"{len(security)} security update(s) pending: {', '.join(security[:15])}"
                              f"{' ...' if len(security) > 15 else ''}.{age_note}",
                     remediation="Apply them: apt-get update && apt-get upgrade (then restart affected services).")
    if stale:
        return check(cid, cat, title, "unknown",
                     evidence=f"No security updates are pending according to the local index, but it is stale.{age_note}")
    return check(cid, cat, title, "pass",
                 evidence=f"No security updates pending per the local apt index ({len(pending)} other update(s)).{age_note}")


RISKY_PORTS = {
    # port: (proto or None=any, name, severity, why)
    23: ("tcp", "Telnet", "HIGH", "sends credentials and sessions in cleartext"),
    21: ("tcp", "FTP", "MEDIUM", "sends credentials in cleartext"),
    69: ("udp", "TFTP", "MEDIUM", "has no authentication"),
    512: ("tcp", "rexec", "HIGH", "legacy remote execution with weak authentication"),
    513: ("tcp", "rlogin", "HIGH", "legacy remote login with weak authentication"),
    514: ("tcp", "rsh", "HIGH", "legacy remote shell with weak authentication"),
    111: (None, "rpcbind", "MEDIUM", "exposes RPC services"),
    139: ("tcp", "NetBIOS/SMB", "MEDIUM", "file-sharing protocol frequently targeted by attackers"),
    445: ("tcp", "SMB", "MEDIUM", "file-sharing protocol frequently targeted by attackers"),
    2049: (None, "NFS", "MEDIUM", "network file system"),
    3389: ("tcp", "RDP", "MEDIUM", "remote desktop"),
    5900: ("tcp", "VNC", "MEDIUM", "remote desktop with weak authentication"),
    161: ("udp", "SNMP", "MEDIUM", "management protocol, often with default community strings"),
    1433: ("tcp", "Microsoft SQL Server", "MEDIUM", "database"),
    3306: ("tcp", "MySQL/MariaDB", "MEDIUM", "database"),
    5432: ("tcp", "PostgreSQL", "MEDIUM", "database"),
    6379: ("tcp", "Redis", "HIGH", "has no authentication by default"),
    11211: (None, "Memcached", "HIGH", "has no authentication and is abused for amplification"),
    27017: ("tcp", "MongoDB", "HIGH", "has historically shipped without authentication"),
    9200: ("tcp", "Elasticsearch", "HIGH", "frequently left without authentication"),
    2375: ("tcp", "Docker API", "CRITICAL", "unauthenticated remote control of the container host"),
}


def check_exposure(listeners, note):
    if listeners is None:
        return [check("exposure.listeners", "exposure", "Listening network services were enumerated", "unknown",
                      evidence="Neither `ss` nor /proc/net could be read, so listening sockets are unknown.")]
    exposed = [l for l in listeners if l["scope"] != "loopback"]
    out = [check("exposure.summary", "exposure", "Listening network services", "info",
                 evidence=f"{len(listeners)} listening socket(s); {len(exposed)} bound to a non-loopback address "
                          f"(source: {note}). Binding to an address is not proof of remote reachability - firewalls and "
                          "network ACLs also apply.")]
    risky = []
    for l in exposed:
        spec = RISKY_PORTS.get(l["port"])
        if spec and (spec[0] is None or spec[0] == l["proto"]):
            risky.append((l, spec))
    for l, (proto, name, sev, why) in risky:
        who = f" (process: {l['process']})" if l["process"] else ""
        bind = "all interfaces" if l["scope"] == "all" else l["address"]
        out.append(check(f"exposure.{l['proto']}_{l['port']}", "exposure", f"{name} is not exposed on a network interface",
                         "fail", sev,
                         evidence=f"{name} ({l['proto']}/{l['port']}) is listening on {l['address']} ({bind}){who}; {why}.",
                         remediation=f"Disable {name} if unused, bind it to 127.0.0.1, or restrict access with a host firewall."))
    if not risky:
        out.append(check("exposure.risky_services", "exposure", "No known-risky service is exposed", "pass",
                         evidence="None of the well-known risky service ports is bound to a non-loopback address."))
    return out


LEGACY_UNITS = ("telnet", "rsh", "rlogin", "rexec", "tftp", "xinetd", "ypserv", "ypbind", "talk", "vsftpd", "proftpd")


def check_legacy_services(running):
    cid, cat, title = "services.legacy_running", "services", "No legacy/insecure service units are running"
    if running is None:
        return check(cid, cat, title, "unknown",
                     evidence="systemd is not available (or cannot be queried) on this machine, so running service units are unknown.")
    bad = [u for u in running if any(u.lower().startswith(p) for p in LEGACY_UNITS)]
    if bad:
        return check(cid, cat, title, "fail", "MEDIUM", evidence="Running legacy units: " + ", ".join(bad) + ".",
                     remediation="Stop and disable them (systemctl disable --now <unit>) or replace with a secure alternative.")
    return check(cid, cat, title, "pass", evidence=f"{len(running)} running service unit(s); none are known legacy/insecure services.")


# ---------------------------------------------------------------------------
# Orchestration of collectors + checks
# ---------------------------------------------------------------------------
def gather(t, today=None):
    """Run every collector and check against a Transport. Raises
    UnsupportedPlatform / SystemScanError for fatal problems; everything else
    degrades to 'unknown' results plus a coverage entry saying why."""
    data = {"coverage": [], "checks": [], "os": None, "packages": [], "package_manager": None,
            "listeners": None, "running_services": None}
    cov = data["coverage"]

    def step(name, fn, requires=None):
        try:
            return fn()
        except UnsupportedPlatform:
            raise
        except SystemScanError:
            raise
        except Exception as e:                         # a collector must never abort the whole scan
            logger.exception("system scan step %s failed", name)
            cov.append({"name": name, "status": "failed", "detail": f"{e.__class__.__name__} (see the server log)",
                        "requires": requires})
            return None

    info = collect_os_info(t)
    data["os"] = info
    cov.append({"name": "os_info", "status": "ran", "detail": info["os_pretty"], "requires": None})
    data["checks"].append(check_os_support(info, today))

    manager, pkgs, err = collect_packages(t)
    data["package_manager"], data["packages"] = manager, pkgs
    cov.append({"name": "software_inventory", "status": "ran" if manager else "skipped",
                "detail": f"{len(pkgs)} packages via {manager}" if manager else err, "requires": None})

    listeners, note = collect_listeners(t)
    data["listeners"] = listeners
    cov.append({"name": "listening_services", "status": "ran" if listeners is not None else "skipped",
                "detail": note, "requires": None if t.can_elevate else "root (for process names)"})

    data["running_services"] = collect_running_services(t)
    cov.append({"name": "running_services", "status": "ran" if data["running_services"] is not None else "skipped",
                "detail": f"{len(data['running_services'])} running units" if data["running_services"] is not None
                else "systemd not available", "requires": None})

    for name, fn, req in (
        ("ssh_configuration", lambda: check_ssh(t), "root"),
        ("firewall", lambda: [check_firewall(t)], "root"),
        ("kernel_hardening", lambda: check_sysctl(t), None),
        ("file_permissions", lambda: check_file_permissions(t), None),
        ("accounts", lambda: check_accounts(t), "root"),
        ("pending_updates", lambda: [check_updates(t, manager)], None),
        ("network_exposure", lambda: check_exposure(listeners, note), None),
        ("legacy_services", lambda: [check_legacy_services(data["running_services"])], None),
    ):
        res = step(name, fn, req)
        if res is None:
            continue
        data["checks"].extend(res)
        unknown_priv = [c for c in res if c["status"] == "unknown" and c.get("requires") == "root"]
        unknown_other = [c for c in res if c["status"] == "unknown" and not c.get("requires")]
        status = "ran" if not (unknown_priv or unknown_other) else "partial"
        detail = f"{len(res)} check(s)"
        if unknown_priv:
            detail += f"; {len(unknown_priv)} need root/sudo"
        if unknown_other:
            detail += f"; {len(unknown_other)} could not be determined"
        cov.append({"name": name, "status": status, "detail": detail,
                    "requires": "root" if unknown_priv else None})
    return data
