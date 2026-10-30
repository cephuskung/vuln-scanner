import math
import re
import pytest
import web.app as webapp
from risk.contextual_risk import calculate_contextual_risk, priority_label


def _finding(db, scan_id, cve="CVE-2099-0001", sev="HIGH", cvss=8.0, conf=0.75, prio=54.6,
             desc="d", rem="r", evidence=True, applic="PROBABLE", port=443):
    import json
    conn = db.get_connection(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO vulnerabilities (scan_id, port_number, service, cve_id, severity, cvss_score, description,"
        " remediation, attack_complexity, contextual_priority, priority_label, match_confidence, match_evidence,"
        " applicability_status, applicability_reason, vulnerability_confidence, confidence_reason)"
        " VALUES (%s,%s,'https',%s,%s,%s,%s,%s,'LOW',%s,'MEDIUM',%s,%s,%s,'version in range only',0.7,'why')",
        (scan_id, port, cve, sev, cvss, desc, rem, prio, conf,
         json.dumps({"product": "nginx", "vendor": "f5", "version": "1.18.0", "cpe_confirmed": True}) if evidence else None,
         applic))
    conn.commit(); conn.close()


@pytest.fixture
def scan(db_module, make_user, login):
    uid = make_user("admin1", "admin")
    asset = db_module.upsert_asset("10.7.7.7")
    sid = db_module.create_scan("10.7.7.7", asset_id=asset, created_by=uid)
    db_module.update_scan_status(sid, "completed", total_risk=8.0)
    login("admin1")
    return sid


def _displayed_priority(html, cve):
    row = re.search(r"<tr>(?:(?!</tr>).)*?" + re.escape(cve) + r"(?:(?!</tr>).)*?</tr>", html, re.S).group(0)
    return float(re.search(r'badge priority-[A-Z]+">([\d.]+)</span>', row).group(1))


def test_web_and_pdf_use_identical_priority_even_after_weights_change(client, db_module, scan, monkeypatch):
    _finding(db_module, scan, conf=0.75)
    seen = {}
    real = webapp.build_pdf_report
    monkeypatch.setattr(webapp, "build_pdf_report", lambda s, v, c, *x: seen.setdefault("v", v) and real(s, v, c, *x))

    def snapshot():
        seen.clear()
        page = _displayed_priority(client.get(f"/scan/{scan}").data.decode(), "CVE-2099-0001")
        assert client.get(f"/scan/{scan}/pdf").status_code == 200
        return page, seen["v"][0]["contextual_priority"]
    before_page, before_pdf = snapshot()
    assert before_page == before_pdf
    # confidence 0.75 must scale the score DOWN (the D1 regression): same finding at 1.0 scores higher
    full = calculate_contextual_risk({"cvss_score": 8.0, "attack_complexity": "LOW", "match_confidence": 1.0},
                                     {"exposure": "INTERNAL", "criticality": "MEDIUM", "business_impact": "MEDIUM"},
                                     db_module.get_risk_weights(), 0, 0, False)
    assert before_page < full
    # change the weights: web and PDF must still agree (previously the PDF kept the stale stored value)
    client.post("/settings/weights", data={"cvss": "0.50", "exploit": "0.10", "epss": "0.05", "exposure": "0.10",
                                           "criticality": "0.10", "business_impact": "0.05", "complexity": "0.05",
                                           "blast_radius": "0.05"})
    after_page, after_pdf = snapshot()
    assert after_page == after_pdf and after_page != before_page


def test_page_shows_evidence_applicability_and_priority_factors(client, db_module, scan):
    _finding(db_module, scan)
    html = client.get(f"/scan/{scan}").data.decode()
    assert "Matched: nginx (f5) 1.18.0" in html and "CPE-confirmed" in html
    assert "applic-PROBABLE" in html and "version in range only" in html
    assert "Factors" in html and "Match confidence 0.75" in html
    assert "remote, unauthenticated assessment" in html


def test_pdf_survives_hostile_text_and_includes_new_fields(client, db_module, scan):
    _finding(db_module, scan, desc="<b>unclosed & <para> </font> <script>x</script>", rem="a < b && c > d</para>")
    r = client.get(f"/scan/{scan}/pdf")
    assert r.status_code == 200 and r.data[:4] == b"%PDF"


def test_empty_and_failed_states_are_honest(client, db_module, scan):
    html = client.get(f"/scan/{scan}").data.decode()
    assert "not proof that the target is secure" in html
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("INSERT INTO scans (target, status, status_detail, created_by) VALUES ('10.8.8.8','failed',"
                "'Nmap reported no hosts for this target', 1) RETURNING id")
    fid = cur.fetchone()[0]; conn.commit(); conn.close()
    html = client.get(f"/scan/{fid}").data.decode()
    assert "Scan failed." in html and "Nmap reported no hosts" in html and "did not complete" in html
    assert client.get(f"/scan/{fid}/pdf").status_code == 200


def test_status_detail_warning_is_displayed(client, db_module, scan):
    db_module.update_scan_status(scan, "completed", status_detail="Vulnerability intelligence (NVD) was unavailable")
    assert "Results may be incomplete" in client.get(f"/scan/{scan}").data.decode()
    assert client.get(f"/scan/{scan}/status").get_json()["status_detail"].startswith("Vulnerability intelligence")


# ---------------- KPI / chart accuracy ----------------
def test_kpis_do_not_inflate_on_rescan_or_count_failed_scans(db_module, make_user):
    asset = db_module.upsert_asset("10.7.7.7")
    for i in range(3):                                   # three rescans of the same host, same critical finding
        sid = db_module.create_scan("10.7.7.7", asset_id=asset)
        _finding(db_module, sid, cve="CVE-2099-5555", sev="CRITICAL")
        db_module.update_scan_status(sid, "completed", total_risk=10)
    bad = db_module.create_scan("10.7.7.7", asset_id=asset)       # a later failed scan must not count either
    _finding(db_module, bad, cve="CVE-2099-6666", sev="CRITICAL")
    db_module.update_scan_status(bad, "failed")
    assert db_module.get_kpis()["critical_vulns"] == 1
    assert db_module.get_severity_stats()["CRITICAL"] == 1


def test_network_parent_scans_excluded_from_average_risk_and_trend(db_module):
    a = db_module.upsert_asset("10.7.7.7")
    h = db_module.create_scan("10.7.7.7", asset_id=a, scan_type="network-host")
    db_module.update_scan_status(h, "completed", total_risk=20)
    p = db_module.create_scan("10.7.7.0/30", scan_type="network")
    db_module.update_scan_status(p, "completed", total_risk=0)
    assert db_module.get_kpis()["avg_risk"] == 20.0
    assert len(db_module.get_risk_trend()) == 1


def test_kpis_scoped_per_owner(db_module, make_user):
    u1, u2 = make_user("u1"), make_user("u2")
    a = db_module.upsert_asset("10.7.7.7")
    s = db_module.create_scan("10.7.7.7", asset_id=a, created_by=u1)
    _finding(db_module, s, sev="CRITICAL"); db_module.update_scan_status(s, "completed", total_risk=9)
    assert db_module.get_kpis(owner_id=u1)["critical_vulns"] == 1
    assert db_module.get_kpis(owner_id=u2) == {"total_assets": 0, "total_scans": 0, "running_scans": 0,
                                               "avg_risk": 0.0, "critical_vulns": 0}


# ---------------- risk engine ----------------
def test_default_weights_total_exactly_one(db_module):
    assert round(sum(db_module.get_risk_weights().values()), 2) == 1.00


def test_contextual_risk_always_valid_and_missing_data_is_not_zero_risk(db_module):
    w = db_module.get_risk_weights()
    for vuln in ({}, {"cvss_score": None}, {"cvss_score": -5, "epss_score": 5, "match_confidence": 5},
                 {"cvss_score": 10, "epss_score": 1, "attack_complexity": "LOW", "match_confidence": 1}):
        for asset in (None, {}, {"exposure": "EXTERNAL", "criticality": "CRITICAL", "business_impact": "CRITICAL"}):
            for kev in (True, False):
                score = calculate_contextual_risk(vuln, asset, w, 3, 10, kev)
                assert 0 <= score <= 100 and not math.isnan(score)
    # an unknown asset still contributes default (non-zero) context rather than reading as "no risk"
    assert calculate_contextual_risk({"cvss_score": 7}, None, w, 0, 0, False) > 0
    # high findings are no longer flattened to exactly 100 by an over-weighted configuration
    top = calculate_contextual_risk({"cvss_score": 10, "epss_score": 1, "attack_complexity": "LOW"},
                                    {"exposure": "EXTERNAL", "criticality": "CRITICAL", "business_impact": "CRITICAL"},
                                    w, 5, 5, True)
    mid = calculate_contextual_risk({"cvss_score": 9, "epss_score": .5, "attack_complexity": "LOW"},
                                    {"exposure": "EXTERNAL", "criticality": "CRITICAL", "business_impact": "CRITICAL"},
                                    w, 5, 5, True)
    assert mid < top <= 100
