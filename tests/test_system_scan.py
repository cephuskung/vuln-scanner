import contextlib
import logging
import subprocess
import pytest
import scanner.system_scan as ss
import scanner.system_collectors as sc
from scanner.jobs import submit_system_scan, validate_system_request, ScanRejected
from scanner.system_collectors import CommandResult, SystemScanError
from tests import nvd_fixtures as nvd
from tests.fake_transport import FakeTransport, as_root

FP = "SHA256:" + "A" * 43


@pytest.fixture
def patched(monkeypatch):
    """Route the scan through a scripted machine instead of a real one."""
    box = {"transport": FakeTransport(), "ssh": None, "boom": None}

    def fake_open(mode, ssh, use_sudo):
        box["ssh"] = ssh
        if box["boom"]:
            raise box["boom"]
        return contextlib.nullcontext(box["transport"])
    monkeypatch.setattr(ss, "_open", fake_open)
    return box


@pytest.fixture
def engine(monkeypatch):
    return nvd.FakeNVD(monkeypatch, by_cpe={"openssl:openssl": [nvd.CVE_3786, nvd.CVE_3602, nvd.CVE_OUT_OF_RANGE],
                                             "openbsd:openssh": [], "postgresql:postgresql": []})


def _local(**kw):
    return submit_system_scan("local", allow_local=True, wait=True, **kw)


# ---------------------------------------------------------------- end-to-end (unprivileged local scan)
def test_system_scan_persists_checks_inventory_findings_and_info(db_module, patched, engine):
    sid = _local()
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and s["scan_type"] == "system-local" and s["finished_at"] and float(s["total_risk"]) > 0
    info = s["scan_info"]
    assert info["mode"] == "local" and info["elevation"] == "none" and info["os"] == "Ubuntu 22.04.4 LTS"
    assert info["counts"]["packages"] == 6 and info["package_manager"] == "dpkg"
    assert {c["name"] for c in info["coverage"]} >= {"os_info", "software_inventory", "listening_services", "ssh_configuration",
                                                      "firewall", "kernel_hardening", "file_permissions", "accounts",
                                                      "pending_updates", "network_exposure", "legacy_services"}
    checks = {c["check_id"]: c for c in db_module.get_system_checks(sid)}
    assert checks["ssh.permit_root_login"]["status"] == "fail" and checks["ssh.permit_root_login"]["priority_label"]
    assert checks["firewall.active"]["status"] == "unknown" and checks["firewall.active"]["requires"] == "root"
    assert checks["accounts.empty_passwords"]["status"] == "unknown"
    assert checks["exposure.tcp_6379"]["status"] == "fail" and "redis-server" in checks["exposure.tcp_6379"]["evidence"]
    assert checks["updates.security_pending"]["status"] == "fail"
    # honest, explicit about what could not be done
    assert "require root and were NOT assessed" in s["status_detail"]
    assert "POTENTIAL at most" in s["status_detail"]
    # asset got the OS
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT os FROM assets"); assert cur.fetchone()[0] == "Ubuntu 22.04.4 LTS"; conn.close()


def test_distro_package_cves_are_potential_with_backport_caveat_and_no_port(db_module, patched, engine):
    sid = _local()
    f = {v["cve_id"]: v for v in db_module.get_vulnerabilities(sid)}
    assert set(f) == {"CVE-2022-3786", "CVE-2022-3602"}                          # real engine: range enforced, out-of-range dropped
    v = f["CVE-2022-3786"]
    assert v["applicability_status"] == "POTENTIAL"                              # never PROBABLE for an OS package
    assert "backported" in v["applicability_reason"] and "CVE tracker" in v["remediation"]
    assert v["port_number"] is None and "package" in v["service"]
    assert v["match_evidence"]["distro_packaged"] is True and v["match_evidence"]["input_version"] == "3.0.2"


def test_inventory_marks_what_was_and_was_not_assessed(db_module, patched, engine):
    sid = _local()
    inv = {r["product"]: r for r in db_module.get_software_inventory(sid)}
    assert set(inv) == {"libssl3", "openssl", "openssh-server", "coreutils", "postgresql", "postgresql-14"}   # 'rc' row absent
    assert inv["libssl3"]["assessment"] == "assessed" and inv["libssl3"]["findings_count"] == 2
    assert inv["openssh-server"]["assessment"] == "assessed" and inv["openssh-server"]["upstream_version"] == "8.9p1"
    assert inv["postgresql-14"]["upstream_version"] == "14.11"
    assert inv["coreutils"]["assessment"] == "not_assessed" and "no NVD identity" in inv["coreutils"]["note"]
    assert inv["postgresql"]["assessment"] == "not_assessed"                      # meta-package is not mistaken for the server
    assert db_module.count_software_inventory(sid) == {"total": 6, "assessed": 4}


def test_root_scan_runs_privileged_checks_and_drops_the_warning(db_module, patched, engine):
    t = as_root(FakeTransport())
    from scanner.system_collectors import CommandResult as CR
    t.commands[("/usr/sbin/sshd", "-T")] = CR(0, "permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 3\nx11forwarding no\n", "")
    t.commands[("ufw", "status")] = CR(0, "Status: active\n", "")
    patched["transport"] = t
    sid = _local()
    s = db_module.get_scan(sid)
    checks = {c["check_id"]: c for c in db_module.get_system_checks(sid)}
    assert s["scan_info"]["elevation"] == "root"
    assert checks["firewall.active"]["status"] == "pass" and checks["ssh.permit_root_login"]["status"] == "pass"
    assert checks["accounts.empty_passwords"]["status"] == "pass"
    assert "require root" not in (s["status_detail"] or "")


def test_nvd_outage_marks_packages_not_assessed_not_clean(db_module, patched, monkeypatch):
    nvd.FakeNVD(monkeypatch, fail=True)
    sid = _local()
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and "NOT assessed" in s["status_detail"]
    inv = {r["product"]: r for r in db_module.get_software_inventory(sid)}
    assert inv["libssl3"]["assessment"] == "lookup_failed"
    assert db_module.get_vulnerabilities(sid) == []


# ---------------------------------------------------------------- failure paths
def test_non_linux_target_fails_clearly_without_partial_results(db_module, patched):
    patched["transport"] = FakeTransport(uname="Darwin mac 23.1.0 arm64")
    sid = _local()
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and "Linux only" in s["status_detail"]
    assert db_module.get_system_checks(sid) == [] and db_module.get_software_inventory(sid) == []


def test_ssh_failure_message_is_stored_on_the_scan(db_module, patched):
    patched["boom"] = SystemScanError("SSH authentication failed: the key was rejected")
    sid = _local()
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and "authentication failed" in s["status_detail"]


def test_unexpected_error_does_not_leak(db_module, patched, monkeypatch):
    monkeypatch.setattr(ss, "gather", lambda t: {}["secret_detail"])
    sid = _local()
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and "secret_detail" not in s["status_detail"] and "server log" in s["status_detail"]


# ---------------------------------------------------------------- local scans are admin-only; request validation
def test_local_scan_requires_admin():
    with pytest.raises(ScanRejected, match="administrator"):
        submit_system_scan("local", allow_local=False)


def _keygen(tmp_path, name="k", passphrase=""):
    path = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", passphrase, "-f", str(path), "-C", "t"], check=True)
    return path.read_text()


def test_remote_request_validation(tmp_path):
    key = _keygen(tmp_path)
    ok = dict(host="10.0.0.5", port=22, username="audit", private_key=key, fingerprint=FP)
    req = validate_system_request("remote", **ok)
    assert req["host"] == "10.0.0.5" and req["fingerprint"] == FP and req["accept_unverified"] is False
    bad = [
        (dict(ok, host="10.0.0.0/24"), "single machine"), (dict(ok, host=""), "Invalid host"), (dict(ok, host="a b"), "Invalid host"),
        (dict(ok, port="0"), "between 1 and 65535"), (dict(ok, port="70000"), "between 1 and 65535"), (dict(ok, port="abc"), "number"),
        (dict(ok, username=""), "username"), (dict(ok, username="a b;c"), "username"),
        (dict(ok, private_key=""), "required"), (dict(ok, private_key="not a key"), "does not look like"),
        (dict(ok, fingerprint=""), "fingerprint"), (dict(ok, fingerprint="SHA256:short"), "Fingerprint|fingerprint"),
    ]
    for kw, msg in bad:
        with pytest.raises(ScanRejected, match=msg):
            validate_system_request("remote", **kw)
    # explicitly accepting an unverified key lifts the fingerprint requirement (and is recorded)
    assert validate_system_request("remote", **dict(ok, fingerprint="", accept_unverified=True))["accept_unverified"] is True
    with pytest.raises(ScanRejected):
        validate_system_request("sideways")


def test_passphrase_protected_key_rejected_up_front(tmp_path):
    enc = _keygen(tmp_path, "enc", passphrase="hunter22")
    with pytest.raises(ScanRejected, match="passphrase"):
        validate_system_request("remote", host="10.0.0.5", port=22, username="audit", private_key=enc, fingerprint=FP)


# ---------------------------------------------------------------- credentials are never persisted or logged
def test_ssh_key_never_stored_or_logged_and_is_wiped(db_module, patched, engine, tmp_path, caplog):
    key = _keygen(tmp_path)
    marker = [l for l in key.splitlines() if l and not l.startswith("-----")][0][:40]
    caplog.set_level(logging.DEBUG)
    sid = submit_system_scan("remote", created_by=None, wait=True, host="10.9.9.9", port=2222, username="audit",
                             private_key=key, fingerprint=FP)
    s = db_module.get_scan(sid)
    assert s["scan_type"] == "system-remote" and s["target"] == "system:ssh://audit@10.9.9.9:2222" and s["status"] == "completed"
    assert patched["ssh"]["key_text"] is None                                     # dropped from memory after use
    assert marker not in caplog.text
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")
    for (table,) in cur.fetchall():
        cur.execute(f'SELECT COUNT(*) FROM "{table}" t WHERE t::text LIKE %s', (f"%{marker}%",))
        assert cur.fetchone()[0] == 0, f"SSH key material found in table {table}"
    conn.close()


def test_remote_scan_attaches_to_the_remote_host_asset(db_module, patched, engine, tmp_path):
    sid = submit_system_scan("remote", wait=True, host="10.9.9.9", port=22, username="audit",
                             private_key=_keygen(tmp_path), fingerprint=FP)
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT ip_address, os FROM assets"); assert cur.fetchall() == [("10.9.9.9", "Ubuntu 22.04.4 LTS")]; conn.close()


def test_duplicate_system_scan_rejected(db_module, monkeypatch):
    import scanner.jobs as jobs
    monkeypatch.setattr(jobs, "run_system_scan", lambda *a, **k: None)
    submit_system_scan("local", allow_local=True, wait=True)
    with pytest.raises(ScanRejected, match="already"):
        submit_system_scan("local", allow_local=True)
