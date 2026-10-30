import datetime as dt
import pytest
import scanner.system_collectors as sc
from scanner.system_collectors import CommandResult
from tests.fake_transport import (FakeTransport, as_root, st, OS_RELEASE_1804, SS_OUT, SSHD_CONFIG, APT_SIM)

STATUS = lambda checks: {c["check_id"]: c for c in checks}


# ---------------------------------------------------------------- parsers
def test_parse_ss_addresses_scopes_and_processes():
    rows = sc.parse_ss(SS_OUT)
    by = {(r["proto"], r["port"], r["address"]): r for r in rows}
    assert by[("tcp", 22, "0.0.0.0")]["scope"] == "all" and by[("tcp", 22, "0.0.0.0")]["process"] == "sshd"
    assert by[("tcp", 22, "::")]["scope"] == "all"
    assert by[("tcp", 6379, "0.0.0.0")]["process"] == "redis-server"
    assert by[("tcp", 53, "127.0.0.53")]["scope"] == "loopback"            # %lo suffix stripped
    assert by[("tcp", 5432, "127.0.0.1")]["scope"] == "loopback"
    assert by[("udp", 68, "0.0.0.0")]["process"] is None
    assert len(rows) == 6                                                     # header skipped


def test_parse_proc_net_fallback():
    tcp = ("  sl  local_address rem_address   st\n"
           "   0: 00000000:0016 00000000:0000 0A 0\n"          # 0.0.0.0:22 LISTEN
           "   1: 0100007F:1538 00000000:0000 0A 0\n"          # 127.0.0.1:5432 LISTEN
           "   2: 0100007F:9999 0100007F:0050 01 0\n")         # established -> ignored
    rows = sc.parse_proc_net(tcp, "tcp")
    assert [(r["address"], r["port"], r["scope"]) for r in rows] == [("0.0.0.0", 22, "all"), ("127.0.0.1", 5432, "loopback")]
    z = "0" * 32
    tcp6 = ("  sl local\n"
            f"   0: {z}:0016 {z}:0000 0A 0\n"
            f"   1: 00000000000000000000000001000000:0019 {z}:0000 0A 0\n")
    rows = sc.parse_proc_net(tcp6, "tcp6")
    assert [(r["address"], r["scope"]) for r in rows] == [("::", "all"), ("::1", "loopback")]


def test_collect_packages_dpkg_only_installed_and_rpm_fallback():
    t = FakeTransport()
    mgr, pkgs, err = sc.collect_packages(t)
    assert mgr == "dpkg" and err is None
    assert {p["name"] for p in pkgs} == {"libssl3", "openssl", "openssh-server", "coreutils", "postgresql", "postgresql-14"}   # 'rc' row excluded
    t2 = FakeTransport()
    t2.commands.pop(next(k for k in t2.commands if k[0] == "dpkg-query"))
    t2.commands[("rpm", "-qa", "--qf", r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VERSION}\n")] = \
        CommandResult(0, "openssl\t3.0.7-24.el9\tx86_64\t3.0.7\n", "")
    mgr, pkgs, _ = sc.collect_packages(t2)
    assert mgr == "rpm" and pkgs[0]["upstream"] == "3.0.7"
    t3 = FakeTransport(); [t3.commands.pop(k) for k in [k for k in t3.commands if k[0] == "dpkg-query"]]
    assert sc.collect_packages(t3) == (None, [], "no supported package manager found (dpkg and rpm are supported)")


# ---------------------------------------------------------------- OS
def test_os_info_and_platform_gate():
    info = sc.collect_os_info(FakeTransport())
    assert info["os_pretty"] == "Ubuntu 22.04.4 LTS" and info["kernel"] == "5.15.0-91-generic" and info["uptime_days"] == 10.0
    with pytest.raises(sc.UnsupportedPlatform, match="Linux only"):
        sc.collect_os_info(FakeTransport(uname="Darwin mac 23.1.0 arm64"))
    t = FakeTransport(); t.commands[("uname", "-snrm")] = CommandResult(127, "", "not found")
    with pytest.raises(sc.SystemScanError):
        sc.collect_os_info(t)


def test_os_support_status():
    today = dt.date(2026, 10, 20)
    old = sc.collect_os_info(FakeTransport(os_release=OS_RELEASE_1804))
    c = sc.check_os_support(old, today)
    assert c["status"] == "fail" and c["severity"] == "HIGH" and "2023-05-31" in c["evidence"] and "ESM" in c["evidence"]
    assert sc.check_os_support(sc.collect_os_info(FakeTransport()), today)["status"] == "pass"
    unknown = dict(old, os_id="gentoo", os_version_id="1", os_pretty="Gentoo")
    assert sc.check_os_support(unknown, today)["status"] == "unknown"


# ---------------------------------------------------------------- SSH daemon config
def test_ssh_file_mode_flags_dangerous_settings():
    r = STATUS(sc.check_ssh(FakeTransport()))
    assert r["ssh.permit_root_login"]["status"] == "fail" and r["ssh.permit_root_login"]["severity"] == "HIGH"
    assert r["ssh.password_authentication"]["status"] == "pass"             # explicitly 'no'
    assert r["ssh.max_auth_tries"]["status"] == "fail" and "10" in r["ssh.max_auth_tries"]["evidence"]
    assert r["ssh.x11_forwarding"]["status"] == "fail"
    assert "default" in r["ssh.permit_empty_passwords"]["evidence"]         # not set -> documented default is stated


def test_ssh_unprivileged_unset_directive_needs_root_not_pass():
    t = FakeTransport(); t.files["/etc/ssh/sshd_config"] = "Port 22\n"
    c = STATUS(sc.check_ssh(t))["ssh.permit_root_login"]
    assert c["status"] == "unknown" and c["requires"] == "root"
    # an unset PasswordAuthentication uses the documented OpenSSH default (yes) -> flagged, evidence says so
    p = STATUS(sc.check_ssh(t))["ssh.password_authentication"]
    assert p["status"] == "fail" and "default" in p["evidence"]


def test_ssh_root_whose_sshd_T_fails_does_not_blame_missing_root():
    t = as_root(FakeTransport()); t.files["/etc/ssh/sshd_config"] = "Port 22\n"
    c = STATUS(sc.check_ssh(t))["ssh.permit_root_login"]
    assert c["status"] == "unknown" and c["requires"] is None and "sshd -T" in c["evidence"] and "failed" in c["evidence"]


def test_ssh_effective_config_wins_when_available():
    t = as_root(FakeTransport())
    t.commands[("/usr/sbin/sshd", "-T")] = CommandResult(0, "permitrootlogin no\npasswordauthentication no\n"
                                                           "permitemptypasswords no\nmaxauthtries 3\nx11forwarding no\n", "")
    r = STATUS(sc.check_ssh(t))
    assert all(r[k]["status"] == "pass" for k in r) and "sshd -T" in r["ssh.permit_root_login"]["evidence"]


def test_ssh_not_installed_is_not_applicable_and_include_dir_and_match_blocks():
    t = FakeTransport(); t.files.pop("/etc/ssh/sshd_config")
    assert {c["status"] for c in sc.check_ssh(t)} == {"not_applicable"}
    t = FakeTransport()
    t.files["/etc/ssh/sshd_config"] = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nMatch User bob\n  PermitRootLogin yes\n"
    t.commands[("ls", "-1", "--", "/etc/ssh/sshd_config.d")] = CommandResult(0, "50-hardening.conf\n", "")
    t.files["/etc/ssh/sshd_config.d/50-hardening.conf"] = "PermitRootLogin no\nPasswordAuthentication no\n"
    r = STATUS(sc.check_ssh(t))
    assert r["ssh.permit_root_login"]["status"] == "pass"                    # included file wins (first occurrence); Match block ignored
    assert r["ssh.password_authentication"]["status"] == "pass"


# ---------------------------------------------------------------- privilege handling (the core honesty rule)
def test_firewall_and_shadow_checks_are_not_assessed_without_root():
    t = FakeTransport()
    fw = sc.check_firewall(t)
    assert fw["status"] == "unknown" and fw["requires"] == "root" and "Not assessed" in fw["evidence"]
    ep = STATUS(sc.check_accounts(t))["accounts.empty_passwords"]
    assert ep["status"] == "unknown" and ep["requires"] == "root"


def test_sudo_enables_privileged_checks_only_when_it_actually_works():
    t = FakeTransport(sudo_enabled=True, sudo_works=True)
    t.commands[("ufw", "status")] = CommandResult(0, "Status: active\n", "")
    assert sc.check_firewall(t)["status"] == "pass"
    assert ("sudo", "-n", "--", "ufw", "status") in t.ran                    # elevated explicitly, via sudo -n
    ep = STATUS(sc.check_accounts(t))["accounts.empty_passwords"]
    assert ep["status"] == "pass"                                            # shadow read through `sudo -n cat`
    t2 = FakeTransport(sudo_enabled=True, sudo_works=False)                  # sudo requested but not permitted
    assert t2.can_elevate is False and sc.check_firewall(t2)["status"] == "unknown"


def test_empty_password_and_extra_uid0_are_detected():
    t = as_root(FakeTransport())
    t.files["/etc/shadow"] = "root:$6$x:1::::::\nbad::19000:0:99999:7:::\nlocked:!:1::::::\n"
    t.files["/etc/passwd"] += "toor:x:0:0::/root:/bin/sh\n"
    r = STATUS(sc.check_accounts(t))
    assert r["accounts.empty_passwords"]["status"] == "fail" and "bad" in r["accounts.empty_passwords"]["evidence"]
    assert "locked" not in r["accounts.empty_passwords"]["evidence"]
    assert r["accounts.uid0"]["status"] == "fail" and "toor" in r["accounts.uid0"]["evidence"]


def test_firewall_iptables_open_policy_fails_when_root():
    t = as_root(FakeTransport())
    t.commands[("iptables", "-S")] = CommandResult(0, "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", "")
    c = sc.check_firewall(t)
    assert c["status"] == "fail" and c["severity"] == "MEDIUM"
    t.commands[("iptables", "-S")] = CommandResult(0, "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n", "")
    assert sc.check_firewall(t)["status"] == "pass"


# ---------------------------------------------------------------- kernel / files / updates / exposure / services
def test_sysctl_pass_fail_and_unreadable():
    t = FakeTransport()
    assert all(c["status"] == "pass" for c in sc.check_sysctl(t) if c["check_id"] != "kernel.ip_forward")
    t.files["/proc/sys/kernel/randomize_va_space"] = "0\n"
    t.files.pop("/proc/sys/kernel/kptr_restrict")
    r = STATUS(sc.check_sysctl(t))
    assert r["kernel.aslr"]["status"] == "fail" and "= 0" in r["kernel.aslr"]["evidence"]
    assert r["kernel.kptr_restrict"]["status"] == "unknown"                  # unreadable is NOT a pass
    t.files["/proc/sys/net/ipv4/ip_forward"] = "1\n"
    assert STATUS(sc.check_sysctl(t))["kernel.ip_forward"]["status"] == "info"


def test_file_permissions():
    t = FakeTransport()
    assert STATUS(sc.check_file_permissions(t))["files.shadow"]["status"] == "pass"
    t.stats["/etc/shadow"] = st(0o644)
    t.stats["/etc/passwd"] = st(0o666)
    del t.stats["/etc/sudoers"]
    r = STATUS(sc.check_file_permissions(t))
    assert r["files.shadow"]["status"] == "fail" and "other users" in r["files.shadow"]["evidence"]
    assert r["files.passwd"]["status"] == "fail" and r["files.sudoers"]["status"] == "not_applicable"


def test_pending_security_updates():
    t = FakeTransport()
    c = sc.check_updates(t, "dpkg")
    assert c["status"] == "fail" and "libssl3" in c["evidence"] and "vim" not in c["evidence"].split("pending:")[1].split(".")[0]
    t.commands[("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")] = CommandResult(0, "Inst vim [1] (2 Ubuntu:22.04/jammy-updates [amd64])\n", "")
    assert sc.check_updates(t, "dpkg")["status"] == "pass"
    t.stats["/var/lib/apt/lists"] = st(0o755, mtime=int(dt.datetime.now().timestamp()) - 40 * 86400)
    stale = sc.check_updates(t, "dpkg")
    assert stale["status"] == "unknown" and "stale" in stale["evidence"]       # a stale index can't prove "nothing pending"
    assert sc.check_updates(t, "rpm")["status"] == "unknown"


def test_exposure_flags_only_risky_services_on_non_loopback():
    listeners, note = sc.collect_listeners(FakeTransport())
    r = STATUS(sc.check_exposure(listeners, note))
    assert r["exposure.tcp_6379"]["status"] == "fail" and r["exposure.tcp_6379"]["severity"] == "HIGH"
    assert "redis-server" in r["exposure.tcp_6379"]["evidence"] and "firewall" in r["exposure.summary"]["evidence"]
    assert "exposure.tcp_5432" not in r                                       # postgres on 127.0.0.1 is not exposed
    assert "exposure.risky_services" not in r
    clean = [l for l in listeners if l["port"] != 6379]
    assert STATUS(sc.check_exposure(clean, note))["exposure.risky_services"]["status"] == "pass"
    assert sc.check_exposure(None, "x")[0]["status"] == "unknown"
    telnet = clean + [{"proto": "tcp", "address": "0.0.0.0", "port": 23, "scope": "all", "process": None}]
    assert STATUS(sc.check_exposure(telnet, note))["exposure.tcp_23"]["severity"] == "HIGH"


def test_legacy_services():
    assert sc.check_legacy_services(None)["status"] == "unknown"
    assert sc.check_legacy_services(["ssh.service", "cron.service"])["status"] == "pass"
    bad = sc.check_legacy_services(["ssh.service", "telnetd.service"])
    assert bad["status"] == "fail" and "telnetd.service" in bad["evidence"]


# ---------------------------------------------------------------- whole-machine gather()
def test_gather_unprivileged_never_reports_privileged_checks_as_passed():
    data = sc.gather(FakeTransport(), today=dt.date(2026, 10, 20))
    r = STATUS(data["checks"])
    assert r["firewall.active"]["status"] == "unknown" and r["accounts.empty_passwords"]["status"] == "unknown"
    assert r["ssh.permit_root_login"]["status"] == "fail"
    cov = {c["name"]: c for c in data["coverage"]}
    assert cov["firewall"]["status"] == "partial" and cov["firewall"]["requires"] == "root"
    assert cov["os_info"]["status"] == "ran" and "software_inventory" in cov and "listening_services" in cov
    assert data["package_manager"] == "dpkg" and len(data["packages"]) == 6


def test_a_crashing_check_degrades_to_coverage_failure_not_a_dead_scan(monkeypatch):
    monkeypatch.setattr(sc, "check_sysctl", lambda t: (_ for _ in ()).throw(ValueError("boom")))
    data = sc.gather(FakeTransport())
    cov = {c["name"]: c for c in data["coverage"]}
    assert cov["kernel_hardening"]["status"] == "failed" and "boom" not in cov["kernel_hardening"]["detail"]
    assert any(c["check_id"].startswith("ssh.") for c in data["checks"])      # the rest still ran


# ---------------------------------------------------------------- regression: real unprivileged run lost the firewall check
def test_exec_failures_are_failed_commands_not_crashes(monkeypatch):
    """As an unprivileged user, exec can raise PermissionError (inaccessible PATH entry). That used to abort the
    whole firewall assessment; it must degrade to 'not assessed (needs root)'."""
    class Unprivileged(sc.LocalTransport):
        def _uid(self):
            return 1000
    t = Unprivileged()
    monkeypatch.setattr(sc.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(PermissionError("denied")))
    r = t._run(["ufw", "status"], 5)
    assert r.rc == 126 and "cannot execute" in r.err
    fw = sc.check_firewall(t)
    assert fw["status"] == "unknown" and fw["requires"] == "root"


def test_crashed_assessment_areas_are_called_out_in_the_scan_warnings(db_module, monkeypatch):
    import contextlib
    import scanner.system_scan as ss
    from scanner.jobs import submit_system_scan
    from tests import nvd_fixtures as nvd
    nvd.FakeNVD(monkeypatch, by_cpe={})
    monkeypatch.setattr(sc, "check_sysctl", lambda t: (_ for _ in ()).throw(ValueError("boom")))
    monkeypatch.setattr(ss, "_open", lambda m, s, u: contextlib.nullcontext(FakeTransport()))
    sid = submit_system_scan("local", allow_local=True, wait=True)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed"
    assert "failed to run and produced NO results: kernel hardening" in s["status_detail"]
