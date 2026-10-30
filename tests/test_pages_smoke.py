"""Every page renders (HTTP 200) for both roles, with and without data."""
import pytest

ADMIN_PAGES = ["/", "/scan-page", "/vulnerabilities", "/assets", "/settings", "/analytics", "/attack-paths",
               "/api/scans", "/api/chart-data", "/reports/executive/pdf"]
ANALYST_PAGES = ["/", "/scan-page", "/vulnerabilities", "/api/scans", "/api/chart-data"]


@pytest.fixture
def populated(db_module, make_user):
    admin, analyst = make_user("admin1", "admin"), make_user("alice", "analyst")
    asset = db_module.upsert_asset("10.7.7.7")
    sid = db_module.create_scan("10.7.7.7", asset_id=asset, created_by=analyst)
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO vulnerabilities (scan_id, port_number, service, cve_id, severity, cvss_score,"
                " contextual_priority, priority_label) VALUES (%s,22,'ssh','CVE-2099-1','HIGH',7.5,50,'HIGH')", (sid,))
    conn.commit(); conn.close()
    db_module.update_scan_status(sid, "completed", total_risk=7.5)
    return dict(asset=asset, sid=sid)


@pytest.mark.parametrize("with_data", [False, True])
def test_admin_pages_render(client, login, make_user, db_module, with_data, request):
    if with_data:
        ids = request.getfixturevalue("populated")
    else:
        make_user("admin1", "admin")
    login("admin1")
    pages = list(ADMIN_PAGES)
    if with_data:
        pages += [f"/assets/{ids['asset']}", f"/scan/{ids['sid']}", f"/scan/{ids['sid']}/pdf", f"/scan/{ids['sid']}/status"]
    for path in pages:
        assert client.get(path).status_code == 200, path


def test_analyst_pages_render_including_dashboard_without_org_wide_data(client, login, populated):
    login("alice")
    for path in ANALYST_PAGES + [f"/scan/{populated['sid']}", f"/scan/{populated['sid']}/pdf"]:
        assert client.get(path).status_code == 200, path


def test_login_logout_and_bad_credentials(client, make_user):
    make_user("admin1", "admin")
    assert client.post("/login", data={"username": "admin1", "password": "wrong"}).status_code in (200, 401)
    assert client.get("/").status_code == 302                      # still anonymous
    assert client.post("/login", data={"username": "admin1", "password": "password123"}).status_code == 302
    assert client.get("/").status_code == 200
    client.get("/logout")
    assert client.get("/").status_code == 302                      # logged out
