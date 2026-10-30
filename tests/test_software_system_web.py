import contextlib
import subprocess
import pytest
import scanner.jobs as jobs
import scanner.system_scan as ss
from scanner.jobs import submit_software_scan, submit_system_scan
from tests import nvd_fixtures as nvd
from tests.fake_transport import FakeTransport
from vulnerability.software_catalog import normalize_software

FP = "SHA256:" + "A" * 43


@pytest.fixture
def users(make_user):
    return {"admin": make_user("admin1", "admin"), "alice": make_user("alice", "analyst"), "bob": make_user("bob", "analyst")}


@pytest.fixture
def no_run(monkeypatch):
    """Accept submissions but leave scans queued (we are testing the web layer)."""
    monkeypatch.setattr(jobs, "run_software_scan", lambda *a, **k: None)
    monkeypatch.setattr(jobs, "run_system_scan", lambda *a, **k: None)


def _scans(db):
    conn = db.get_connection(); cur = conn.cursor()
    cur.execute("SELECT scan_type, status, created_by, target FROM scans ORDER BY id")
    rows = cur.fetchall(); conn.close()
    return rows


def _key(tmp_path):
    p = tmp_path / "k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(p), "-C", "t"], check=True)
    return p.read_text()


# ------------------------------------------------------------ scan-selection page
def test_scan_page_offers_all_three_scan_types(client, login, users):
    login("admin1")
    html = client.get("/scan-page?tab=software").data.decode()
    for needle in ('data-tab="network"', 'data-tab="software"', 'data-tab="system"', 'name="vendor"', 'name="product"',
                   'name="version"', 'name="cpe"', 'name="bulk"', 'name="private_key"', 'name="fingerprint"',
                   'name="mode" value="local"', "Apache HTTP Server"):
        assert needle in html, needle
    assert 'name="mode" value="local" disabled' not in html                 # admin may choose local


def test_local_mode_is_disabled_for_non_admins(client, login, users):
    login("alice")
    assert 'value="local" disabled' in client.get("/scan-page?tab=system").data.decode()


def test_network_scan_form_is_untouched(client, login, users):
    login("admin1")
    html = client.get("/scan-page").data.decode()
    assert 'action="/scan"' in html and 'name="target"' in html and "/schedule" in html


# ------------------------------------------------------------ software form
def test_software_form_queues_and_redirects_to_the_scan_page(client, login, users, db_module, no_run):
    login("alice")
    r = client.post("/software-scan", data={"vendor": "", "product": "OpenSSL", "version": "3.0.2"})
    assert r.status_code == 302 and "/scan/" in r.headers["Location"]
    rows = _scans(db_module)
    assert rows == [("software", "queued", users["alice"], "software: OpenSSL 3.0.2")]
    assert client.get(r.headers["Location"]).status_code == 200


@pytest.mark.parametrize("data,msg", [
    ({"product": ""}, "Enter at least one"), ({"product": "x;rm -rf /"}, "Invalid product"),
    ({"product": "ok", "version": "1.0;x"}, "Invalid version"), ({"cpe": "cpe:/o:linux:linux_kernel:5"}, "application CPEs"),
    ({"bulk": "a,b"}, "Line 1"), ({"product": "ok", "asset_id": "abc"}, "Invalid asset"),
    ({"product": "ok", "asset_id": "99999"}, "does not exist"),
])
def test_software_form_validation(client, login, users, db_module, no_run, data, msg):
    login("alice")
    r = client.post("/software-scan", data=data, follow_redirects=True)
    assert msg in r.data.decode() and _scans(db_module) == []


def test_software_scan_cannot_attach_to_someone_elses_asset(client, login, users, db_module, no_run):
    other = db_module.upsert_asset("10.77.0.1")
    s = db_module.create_scan("10.77.0.1", asset_id=other, created_by=users["bob"])
    login("alice")
    r = client.post("/software-scan", data={"product": "curl", "version": "8.0.1", "asset_id": str(other)}, follow_redirects=True)
    assert "does not exist" in r.data.decode()                                # not disclosed, not accepted
    assert "10.77.0.1" not in client.get("/scan-page?tab=software").data.decode()
    client.get("/logout"); login("bob")
    assert "10.77.0.1" in client.get("/scan-page?tab=software").data.decode()


def test_software_duplicate_is_rejected(client, login, users, db_module, no_run):
    login("alice")
    client.post("/software-scan", data={"product": "OpenSSL", "version": "3.0.2"})
    r = client.post("/software-scan", data={"product": "OpenSSL", "version": "3.0.2"}, follow_redirects=True)
    assert "identical software scan is already" in r.data.decode() and len(_scans(db_module)) == 1


# ------------------------------------------------------------ system form
def test_local_system_scan_is_admin_only(client, login, users, db_module, no_run):
    login("alice")
    r = client.post("/system-scan", data={"mode": "local"}, follow_redirects=True)
    assert "administrator" in r.data.decode() and _scans(db_module) == []
    client.get("/logout"); login("admin1")
    r = client.post("/system-scan", data={"mode": "local"})
    assert r.status_code == 302 and _scans(db_module)[0][:2] == ("system-local", "queued")


def test_remote_form_validation_never_echoes_the_private_key(client, login, users, db_module, no_run, tmp_path):
    key = _key(tmp_path)
    marker = [l for l in key.splitlines() if not l.startswith("-----")][0][:40]
    login("alice")
    r = client.post("/system-scan", data={"mode": "remote", "host": "10.0.0.5", "port": "99999", "username": "audit",
                                          "private_key": key, "fingerprint": FP}, follow_redirects=True)
    body = r.data.decode()
    assert "between 1 and 65535" in body and marker not in body and _scans(db_module) == []
    r = client.post("/system-scan", data={"mode": "remote", "host": "10.0.0.5", "port": "22", "username": "audit",
                                          "private_key": key, "fingerprint": ""}, follow_redirects=True)
    assert "fingerprint" in r.data.decode() and marker not in r.data.decode()


def test_remote_form_queues_with_valid_input_and_stores_no_credentials(client, login, users, db_module, no_run, tmp_path):
    key = _key(tmp_path)
    login("alice")
    r = client.post("/system-scan", data={"mode": "remote", "host": "10.0.0.5", "port": "22", "username": "audit",
                                          "private_key": key, "fingerprint": FP, "use_sudo": "1"})
    assert r.status_code == 302
    assert _scans(db_module) == [("system-remote", "queued", users["alice"], "system:ssh://audit@10.0.0.5:22")]
    marker = [l for l in key.splitlines() if not l.startswith("-----")][0][:40]
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scans s WHERE s::text LIKE %s", (f"%{marker}%",)); assert cur.fetchone()[0] == 0
    conn.close()


# ------------------------------------------------------------ results pages, reports, history, ownership
@pytest.fixture
def finished(db_module, users, monkeypatch):
    nvd.FakeNVD(monkeypatch, by_cpe={"openssl:openssl": [nvd.CVE_3786, nvd.CVE_3602, nvd.CVE_UNCONSTRAINED],
                                     "openbsd:openssh": [], "postgresql:postgresql": []})
    monkeypatch.setattr(ss, "_open", lambda m, s, u: contextlib.nullcontext(FakeTransport()))
    sw = submit_software_scan([normalize_software("", "OpenSSL", "3.0.2"), normalize_software("", "OpenSSL", "")],
                              created_by=users["alice"], wait=True)
    sy = submit_system_scan("local", created_by=users["alice"], allow_local=True, wait=True)
    return {"software": sw, "system": sy}


def test_software_scan_page_shows_tiers_evidence_and_what_was_assessed(client, login, users, finished):
    login("alice")
    html = client.get(f"/scan/{finished['software']}").data.decode()
    assert "software scan" in html and "Software assessed" in html
    assert "applic-PROBABLE" in html and "applic-INDETERMINATE" in html
    assert "Matched: openssl (openssl) 3.0.2" in html and "CVE-2022-3786" in html
    assert "no version" in html and "unknown" in html                          # honest about the version-less item
    assert "Factors" in html and ">—<" in html                                 # no port shown for software findings


def test_system_scan_page_shows_info_coverage_checks_and_inventory(client, login, users, finished):
    login("alice")
    html = client.get(f"/scan/{finished['system']}").data.decode()
    for needle in ("System information", "Ubuntu 22.04.4 LTS", "Assessment coverage", "Security configuration checks",
                   "ssh.permit_root_login", "chk-fail", "chk-unknown", "needs root", "Listening services",
                   "redis-server", "Installed software assessed against NVD", "libssl3", "CVE findings for installed software",
                   "applic-POTENTIAL", "Results may be incomplete or limited", "passing every check performed does not prove"):
        assert needle in html, needle
    assert "6 packages" in html and "4 of 6" in html


def test_pdf_reports_render_for_both_scan_types(client, login, users, finished):
    login("alice")
    for kind in ("software", "system"):
        r = client.get(f"/scan/{finished[kind]}/pdf")
        assert r.status_code == 200 and r.data[:4] == b"%PDF" and len(r.data) > 3000


def test_pdf_survives_hostile_text_in_system_evidence(client, login, users, db_module, finished):
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("UPDATE system_checks SET evidence = %s, title = %s WHERE scan_id = %s",
                ("<b>unclosed & <para></font>", "a < b </para>", finished["system"]))
    cur.execute("UPDATE software_inventory SET product = %s WHERE scan_id = %s", ("<i>x&y", finished["system"]))
    conn.commit(); conn.close()
    login("alice")
    r = client.get(f"/scan/{finished['system']}/pdf")
    assert r.status_code == 200 and r.data[:4] == b"%PDF"
    assert client.get(f"/scan/{finished['system']}").status_code == 200       # and HTML autoescapes it


def test_new_scan_types_appear_in_history_and_are_owner_scoped(client, login, users, finished):
    login("alice")
    types = {s["scan_type"] for s in client.get("/api/scans").get_json()}
    assert {"software", "system-local"} <= types
    client.get("/logout"); login("bob")
    assert client.get("/api/scans").get_json() == []
    for kind in ("software", "system"):
        for suffix in ("", "/pdf", "/status"):
            assert client.get(f"/scan/{finished[kind]}{suffix}").status_code == 404
    client.get("/logout"); login("admin1")
    assert client.get(f"/scan/{finished['system']}").status_code == 200


# ------------------------------------------------------------ KPIs across scan kinds
def test_current_picture_combines_scan_kinds_and_counts_each_cve_once_per_asset(db_module, users):
    asset = db_module.upsert_asset("10.5.5.5")
    def finding(sid, cve, sev="CRITICAL"):
        conn = db_module.get_connection(); cur = conn.cursor()
        cur.execute("INSERT INTO vulnerabilities (scan_id, service, cve_id, severity, cvss_score) VALUES (%s,'x',%s,%s,9.0)", (sid, cve, sev))
        conn.commit(); conn.close()
    net = db_module.create_scan("10.5.5.5", asset_id=asset, created_by=users["alice"], scan_type="manual")
    finding(net, "CVE-2099-1"); finding(net, "CVE-2099-2")
    db_module.update_scan_status(net, "completed", total_risk=5)
    sysc = db_module.create_scan("system:local (x)", asset_id=asset, created_by=users["alice"], scan_type="system-local")
    finding(sysc, "CVE-2099-2"); finding(sysc, "CVE-2099-3")                    # CVE-2099-2 overlaps with the network scan
    db_module.update_scan_status(sysc, "completed", total_risk=5)
    kpis = db_module.get_kpis()
    assert kpis["critical_vulns"] == 3                                           # {1,2,3}: overlap counted once, system scan didn't hide the network one
    assert db_module.get_severity_stats()["CRITICAL"] == 3
    rescan = db_module.create_scan("10.5.5.5", asset_id=asset, created_by=users["alice"], scan_type="manual")
    db_module.update_scan_status(rescan, "completed", total_risk=0)               # the host was fixed: clean network rescan
    assert db_module.get_kpis()["critical_vulns"] == 2                           # only the system scan's CVE-2099-2/-3 remain
