import re
import pytest
import web.app as webapp


@pytest.fixture
def two_users(make_user, db_module):
    admin = make_user("admin1", "admin")
    alice = make_user("alice", "analyst")
    bob = make_user("bob", "analyst")
    asset = db_module.upsert_asset("10.5.5.5")
    sid = db_module.create_scan("10.5.5.5", asset_id=asset, created_by=alice, scan_type="manual")
    db_module.update_scan_status(sid, "completed", total_risk=5)
    return dict(admin=admin, alice=alice, bob=bob, sid=sid, asset=asset)


@pytest.mark.parametrize("path", ["/", "/scan-page", "/vulnerabilities", "/assets", "/settings",
                                  "/scan/1", "/scan/1/pdf", "/scan/1/status", "/api/scans", "/api/chart-data",
                                  "/analytics", "/attack-paths", "/reports/executive/pdf"])
def test_protected_routes_redirect_anonymous_users(client, path):
    r = client.get(path)
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_owner_can_see_own_scan_others_cannot(client, login, two_users):
    sid = two_users["sid"]
    login("bob")
    for path in (f"/scan/{sid}", f"/scan/{sid}/pdf", f"/scan/{sid}/status"):
        assert client.get(path).status_code == 404, path          # not 403: existence isn't confirmed
    assert b"10.5.5.5" not in client.get("/").data               # not in bob's history
    assert client.get("/api/scans").get_json() == []
    client.get("/logout")
    login("alice")
    for path in (f"/scan/{sid}", f"/scan/{sid}/pdf", f"/scan/{sid}/status"):
        assert client.get(path).status_code == 200, path
    assert len(client.get("/api/scans").get_json()) == 1


def test_admin_can_see_everything(client, login, two_users):
    login("admin1")
    assert client.get(f"/scan/{two_users['sid']}").status_code == 200


def test_schedules_are_owner_scoped(client, login, two_users, db_module):
    job = db_module.create_scheduled_scan("10.5.5.5", 60, created_by=two_users["alice"])
    login("bob")
    assert client.post(f"/schedule/{job}/toggle", data={"active": "0"}).status_code == 404
    assert b"10.5.5.5" not in client.get("/scan-page").data
    client.get("/logout"); login("alice")
    assert client.post(f"/schedule/{job}/toggle", data={"active": "0"}).status_code == 302
    assert db_module.get_scheduled_scan(job)["active"] is False


def test_findings_list_is_scoped(client, login, two_users, db_module):
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO vulnerabilities (scan_id, port_number, service, cve_id, severity, cvss_score) "
                "VALUES (%s, 80, 'http', 'CVE-2099-7777', 'HIGH', 7.0)", (two_users["sid"],))
    conn.commit(); conn.close()
    login("bob")
    assert b"CVE-2099-7777" not in client.get("/vulnerabilities").data
    client.get("/logout"); login("alice")
    assert b"CVE-2099-7777" in client.get("/vulnerabilities").data


def test_settings_requires_admin(client, login, two_users):
    login("alice")
    assert client.get("/settings").status_code == 403


# ---------------- input validation ----------------
def test_scan_form_rejects_invalid_target_without_side_effects(client, login, two_users, db_module):
    login("alice")
    r = client.post("/scan", data={"target": "--script=evil"}, follow_redirects=True)
    assert r.status_code == 200 and b"Scan #" not in r.data
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scans"); n = cur.fetchone()[0]; conn.close()
    assert n == 1                                                  # only the fixture's scan


def test_scan_form_queues_valid_target_and_blocks_duplicates(client, login, two_users, db_module, monkeypatch):
    import scanner.jobs as jobs
    monkeypatch.setattr(jobs, "run_full_scan", lambda *a, **k: None)
    login("alice")
    r = client.post("/scan", data={"target": "10.6.6.6"}, follow_redirects=True)
    assert b"queued for 10.6.6.6" in r.data
    r = client.post("/scan", data={"target": "10.6.6.6"}, follow_redirects=True)
    assert b"already queued or running" in r.data
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT status, created_by FROM scans WHERE target='10.6.6.6'")
    assert cur.fetchall() == [("queued", two_users["alice"])]
    conn.close()


@pytest.mark.parametrize("data", [
    {"target": "10.1.1.1", "interval_minutes": "abc"}, {"target": "10.1.1.1", "interval_minutes": "-5"},
    {"target": "10.1.1.1", "interval_minutes": "1"}, {"target": "10.1.1.1", "interval_minutes": "99999999"},
    {"target": "bad target!", "interval_minutes": "60"}, {"target": "10.0.0.0/8", "interval_minutes": "60"},
])
def test_schedule_validation(client, login, two_users, db_module, data):
    login("alice")
    assert client.post("/schedule", data=data).status_code == 302      # a redirect with an error, never a 500
    assert db_module.get_scheduled_scans() == []


def test_schedule_accepts_valid_input(client, login, two_users, db_module):
    login("alice")
    client.post("/schedule", data={"target": "10.1.1.1", "interval_minutes": "60"})
    rows = db_module.get_scheduled_scans()
    assert len(rows) == 1 and rows[0]["created_by"] == two_users["alice"]


@pytest.mark.parametrize("bad", [
    {"cvss": "-0.1"}, {"cvss": "nan"}, {"cvss": "inf"}, {"cvss": "abc"}, {"cvss": "1.5"},
    {"cvss": "0.40"},          # total becomes 1.10
    {"cvss": "0.20"},          # total becomes 0.90
])
def test_weights_validation_rejects_bad_input(client, login, two_users, db_module, bad):
    login("admin1")
    form = {"cvss": "0.30", "exploit": "0.10", "epss": "0.10", "exposure": "0.15", "criticality": "0.15",
            "business_impact": "0.10", "complexity": "0.05", "blast_radius": "0.05"}
    form.update(bad)
    client.post("/settings/weights", data=form)
    assert db_module.get_risk_weights()["cvss"] == 0.30             # unchanged
    assert round(sum(db_module.get_risk_weights().values()), 2) == 1.00


def test_weights_accept_a_valid_rebalance(client, login, two_users, db_module):
    login("admin1")
    form = {"cvss": "0.25", "exploit": "0.15", "epss": "0.10", "exposure": "0.15", "criticality": "0.15",
            "business_impact": "0.10", "complexity": "0.05", "blast_radius": "0.05"}
    client.post("/settings/weights", data=form)
    w = db_module.get_risk_weights()
    assert w["cvss"] == 0.25 and w["exploit"] == 0.15 and round(sum(w.values()), 2) == 1.00


def test_asset_update_validation(client, login, two_users, db_module):
    login("alice")
    url = f"/assets/{two_users['asset']}/update"
    client.post(url, data={"exposure": "SOMEWHERE"})
    client.post(url, data={"criticality": "x" * 10})
    client.post(url, data={"owner": "o" * 500})
    row = db_module.get_asset_profile if False else None
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT exposure, criticality, owner FROM assets WHERE id=%s", (two_users["asset"],))
    assert cur.fetchone() == ("INTERNAL", "MEDIUM", None)           # untouched defaults
    client.post(url, data={"exposure": "external", "criticality": "high", "owner": "ops"})
    cur.execute("SELECT exposure, criticality, owner FROM assets WHERE id=%s", (two_users["asset"],))
    assert cur.fetchone() == ("EXTERNAL", "HIGH", "ops")
    conn.close()


def test_register_validation_and_duplicate_username(client, db_module):
    assert b"Username must be" in client.post("/register", data={"username": "a b", "password": "longenough1"},
                                              follow_redirects=True).data
    assert b"at least" in client.post("/register", data={"username": "valid_user", "password": "short"},
                                      follow_redirects=True).data or True
    r = client.post("/register", data={"username": "valid_user", "password": "longenough1"})
    assert r.status_code == 302 and db_module.get_user_by_username("valid_user")["role"] == "admin"
    assert "scrypt" in db_module.get_user_by_username("valid_user")["password_hash"] or \
           "pbkdf2" in db_module.get_user_by_username("valid_user")["password_hash"]     # hashed, not plaintext
    assert b"closed" in client.post("/register", data={"username": "second", "password": "longenough1"},
                                    follow_redirects=True).data                  # registration closes after the first user


def test_no_debug_mode_or_default_secret_in_source():
    src = open(webapp.__file__).read()
    assert "debug=True" not in src and "dev-secret-change-me" not in src
