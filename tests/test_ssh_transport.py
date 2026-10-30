import os
import shlex
import stat
import pytest
import scanner.system_collectors as sc
from scanner.system_collectors import CommandResult, SystemScanError

FP = "SHA256:" + "B" * 43


def test_private_key_file_is_private_and_always_removed():
    with sc.private_key_file("KEYDATA\n") as (path, workdir):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(workdir).st_mode) == 0o700
        assert open(path).read() == "KEYDATA\n"
    assert not os.path.exists(path) and not os.path.exists(workdir)
    with pytest.raises(RuntimeError):
        with sc.private_key_file("KEYDATA\n") as (path, workdir):
            raise RuntimeError("scan blew up")
    assert not os.path.exists(path) and not os.path.exists(workdir)             # cleaned up on error too


@pytest.mark.parametrize("bad,msg", [
    ("", "required"), ("hello", "does not look like"), ("-----BEGIN PRIVATE KEY-----\nabc", "does not look like"),
    ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n-----END RSA PRIVATE KEY-----", "Passphrase"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * 20000 + "\n-----END OPENSSH PRIVATE KEY-----", "too large"),
])
def test_key_format_rejections(bad, msg):
    with pytest.raises(SystemScanError, match=msg):
        sc.validate_key_format(bad)


def test_key_format_accepts_openssh_and_normalises_newlines():
    k = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nabc\r\n-----END OPENSSH PRIVATE KEY-----"
    out = sc.validate_key_format(k)
    assert "\r" not in out and out.endswith("\n")


@pytest.mark.parametrize("raw,expected", [("", None), ("  ", None), ("SHA256:" + "C" * 43, "SHA256:" + "C" * 43),
                                          ("C" * 43, "SHA256:" + "C" * 43), ("C" * 43 + "=", "SHA256:" + "C" * 43)])
def test_fingerprint_normalisation(raw, expected):
    assert sc.normalize_fingerprint(raw) == expected


@pytest.mark.parametrize("raw", ["SHA256:short", "MD5:aa:bb", "SHA256:" + "!" * 43])
def test_bad_fingerprints_rejected(raw):
    with pytest.raises(SystemScanError):
        sc.normalize_fingerprint(raw)


@pytest.fixture
def ssh_stubs(monkeypatch):
    monkeypatch.setattr(sc, "_need", lambda b: None)
    monkeypatch.setattr(sc, "check_key_usable", lambda p: True)
    monkeypatch.setattr(sc.SSHTransport, "_run", lambda self, argv, timeout: CommandResult(0, "", ""))
    monkeypatch.setattr(sc, "scan_host_keys", lambda h, p: [("[h]:22 ssh-ed25519 AAAAkey", FP, "ssh-ed25519"),
                                                           ("[h]:22 ssh-rsa AAAArsa", "SHA256:" + "D" * 43, "ssh-rsa")])
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
    return key


def _opt(t, name):
    return [t._base[i + 1] for i, a in enumerate(t._base) if a == "-o" and t._base[i + 1].startswith(name + "=")]


def test_matching_fingerprint_pins_the_host_key_strictly(ssh_stubs):
    with sc.open_ssh_transport("h", 22, "audit", ssh_stubs, fingerprint=FP) as t:
        assert t.host_key_verified is True
        assert _opt(t, "StrictHostKeyChecking") == ["StrictHostKeyChecking=yes"]
        kh = _opt(t, "UserKnownHostsFile")[0].split("=", 1)[1]
        assert open(kh).read().strip() == "[h]:22 ssh-ed25519 AAAAkey"            # only the matched key is trusted
    assert not os.path.exists(kh)


def test_mismatched_fingerprint_aborts_and_shows_what_was_presented(ssh_stubs):
    with pytest.raises(SystemScanError) as e:
        with sc.open_ssh_transport("h", 22, "audit", ssh_stubs, fingerprint="SHA256:" + "E" * 43):
            pass
    assert "does not match" in str(e.value) and FP in str(e.value) and "ssh-rsa" in str(e.value)


def test_unverified_host_key_requires_explicit_opt_in(ssh_stubs):
    with pytest.raises(SystemScanError, match="fingerprint"):
        with sc.open_ssh_transport("h", 22, "audit", ssh_stubs):
            pass
    with sc.open_ssh_transport("h", 22, "audit", ssh_stubs, accept_unverified=True) as t:
        assert t.host_key_verified is False and _opt(t, "StrictHostKeyChecking") == ["StrictHostKeyChecking=no"]


def test_unusable_key_is_rejected(ssh_stubs, monkeypatch):
    monkeypatch.setattr(sc, "check_key_usable", lambda p: False)
    with pytest.raises(SystemScanError, match="passphrase-protected"):
        with sc.open_ssh_transport("h", 22, "audit", ssh_stubs, fingerprint=FP):
            pass


def test_ssh_command_is_hardened_and_arguments_cannot_inject(monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        class P: returncode, stdout, stderr = 0, "ok", ""
        return P()
    monkeypatch.setattr(sc.subprocess, "run", fake_run)
    t = sc.SSHTransport("10.0.0.5", 2200, "audit", "/tmp/k", "/tmp/kh", True)
    t._run(["cat", "--", "/etc/x; rm -rf / $(id)"], 10)
    cmd = captured["cmd"]
    for needed in ("-F", "/dev/null", "BatchMode=yes", "IdentitiesOnly=yes", "PasswordAuthentication=no",
                   "ForwardAgent=no", "ClearAllForwardings=yes", "StrictHostKeyChecking=yes", "audit@10.0.0.5"):
        assert needed in cmd, needed
    assert cmd[cmd.index("-p") + 1] == "2200"
    assert cmd[-1] == shlex.join(["cat", "--", "/etc/x; rm -rf / $(id)"])          # one safely quoted remote command
    assert "'/etc/x; rm -rf / $(id)'" in cmd[-1]


@pytest.mark.parametrize("stderr,fragment", [
    ("audit@h: Permission denied (publickey).", "authentication failed"),
    ("Host key verification failed.", "host key verification failed"),
    ("ssh: connect to host h port 22: Connection refused", "refused"),
    ("ssh: connect to host h port 22: Connection timed out", "timed out"),
    ("ssh: Could not resolve hostname nope: Name or service not known", "could not be resolved"),
    ("something unexpected with secret path /tmp/key", "see the server log"),
])
def test_ssh_failures_map_to_safe_messages(monkeypatch, stderr, fragment):
    class P: returncode, stdout = 255, ""
    P.stderr = stderr
    monkeypatch.setattr(sc.subprocess, "run", lambda cmd, **kw: P())
    t = sc.SSHTransport("h", 22, "u", "/tmp/k", None, False)
    with pytest.raises(SystemScanError) as e:
        t._run(["true"], 5)
    assert fragment in str(e.value) and "/tmp/key" not in str(e.value)
