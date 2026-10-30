import pytest
from scanner.jobs import submit_software_scan, ScanRejected
from scanner.software_scan import classify
from vulnerability.software_catalog import normalize_software, parse_bulk, SoftwareInputError, upstream_version, map_package
from tests import nvd_fixtures as nvd


def _run(items, **kw):
    return submit_software_scan(items, wait=True, **kw)


def _findings(db, sid):
    return {v["cve_id"]: v for v in db.get_vulnerabilities(sid)}


@pytest.fixture
def openssl_nvd(monkeypatch):
    return nvd.FakeNVD(monkeypatch, by_cpe={"openssl:openssl": [
        nvd.CVE_3786, nvd.CVE_3602, nvd.CVE_OUT_OF_RANGE, nvd.CVE_UNCONSTRAINED, nvd.CVE_OTHER_PRODUCT,
        nvd.CVE_EXACT_302]})


# ----------------------------------------------------------------- engine integration
def test_exact_version_in_range_is_probable_and_range_is_enforced(db_module, openssl_nvd):
    sid = _run([normalize_software("", "OpenSSL", "3.0.2")])
    f = _findings(db_module, sid)
    assert set(f) == {"CVE-2022-3786", "CVE-2022-3602", "CVE-2099-0001", "CVE-2099-0003"}   # range + product enforced by the real engine
    assert "CVE-2023-0286" not in f                                           # 3.0.2 is outside 3.0.7-3.0.8
    assert "CVE-2099-0002" not in f                                           # different product never matches
    v = f["CVE-2022-3786"]
    assert v["applicability_status"] == "PROBABLE" and "inside the CVE's affected range" in v["applicability_reason"]
    assert v["severity"] == "HIGH" and float(v["cvss_score"]) == 7.5 and v["remediation"]
    assert v["contextual_priority"] is not None and v["priority_label"] and v["vulnerability_confidence"] is not None
    assert v["match_evidence"]["product"] == "openssl" and v["match_evidence"]["vendor"] == "openssl"
    assert v["match_evidence"]["identity_source"] == "catalog" and v["match_evidence"]["input_version"] == "3.0.2"
    assert v["port_number"] is None


def test_scan_record_inventory_and_history(db_module, openssl_nvd):
    sid = _run([normalize_software("", "OpenSSL", "3.0.2")])
    s = db_module.get_scan(sid)
    assert s["scan_type"] == "software" and s["status"] == "completed" and s["finished_at"] and float(s["total_risk"]) > 0
    inv = db_module.get_software_inventory(sid)
    assert len(inv) == 1 and inv[0]["assessment"] == "assessed" and inv[0]["findings_count"] == 4
    assert inv[0]["cpe_vendor"] == "openssl" and inv[0]["source"] == "user"
    assert any(r["id"] == sid for r in db_module.get_scans())                 # appears in scan history


def test_unknown_version_is_indeterminate_and_never_lists_version_constrained_cves(db_module, openssl_nvd):
    sid = _run([normalize_software("", "OpenSSL", "unknown")])
    f = _findings(db_module, sid)
    assert set(f) == {"CVE-2099-0001"}                                        # only the unrestricted CVE can be listed
    assert "CVE-2099-0003" not in f
    assert f["CVE-2099-0001"]["applicability_status"] == "INDETERMINATE"
    assert "cannot be evaluated" in f["CVE-2099-0001"]["applicability_reason"]
    s = db_module.get_scan(sid)
    assert "no version" in s["status_detail"] and "INDETERMINATE" in s["status_detail"]


def test_partial_version_is_potential_not_probable_and_warns_about_missed_ranges(db_module, openssl_nvd):
    sid = _run([normalize_software("", "OpenSSL", "3.0")])
    f = _findings(db_module, sid)
    assert f["CVE-2099-0003"]["applicability_status"] == "POTENTIAL"        # exact-version record, partial version
    assert "partial version" in f["CVE-2099-0003"]["applicability_reason"]
    assert "CVE-2022-3786" not in f                                           # range CVEs can't be evaluated from "3.0"
    assert "Partial version" in db_module.get_scan(sid)["status_detail"]      # ...and the scan says so


def test_confidence_orders_the_tiers(db_module, openssl_nvd):
    probable = _findings(db_module, _run([normalize_software("", "OpenSSL", "3.0.2")]))["CVE-2099-0003"]
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("TRUNCATE scans, vulnerabilities, cve_cache RESTART IDENTITY CASCADE"); conn.commit(); conn.close()
    potential = _findings(db_module, _run([normalize_software("", "OpenSSL", "3.0")]))["CVE-2099-0003"]
    assert probable["applicability_status"] == "PROBABLE" and potential["applicability_status"] == "POTENTIAL"
    assert float(probable["vulnerability_confidence"]) > float(potential["vulnerability_confidence"])


def test_unrecognised_names_fall_back_to_keyword_search_and_are_potential(db_module, monkeypatch):
    fake = nvd.FakeNVD(monkeypatch, by_cpe={}, by_keyword={"widget": [nvd.CVE_ACME]})
    sid = _run([normalize_software("Acme", "Widget Pro", "2.1.0")])          # vendor+product typed, not in catalogue
    assert fake.queries("virtualMatchString") and fake.queries("keywordSearch")   # tried the guessed CPE, then keyword
    f = _findings(db_module, sid)
    assert set(f) == {"CVE-2099-1111"}
    assert f["CVE-2099-1111"]["applicability_status"] == "POTENTIAL"
    assert "name only" in f["CVE-2099-1111"]["applicability_reason"]
    assert f["CVE-2099-1111"]["match_evidence"]["retrieval"] == "keyword"


def test_catalogue_alias_resolves_to_nvd_names(db_module, openssl_nvd):
    it = normalize_software("", "Apache HTTP Server", "2.4.58")
    assert (it["cpe_vendor"], it["cpe_product"], it["identity_source"]) == ("apache", "http_server", "catalog")


def test_no_match_is_reported_as_no_match_not_as_safe(db_module, monkeypatch):
    nvd.FakeNVD(monkeypatch, by_cpe={"openssl:openssl": []})
    sid = _run([normalize_software("", "OpenSSL", "9.9.9")])
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and "not proof" in s["status_detail"]
    assert db_module.get_software_inventory(sid)[0]["assessment"] == "assessed"


def test_nvd_outage_is_never_reported_as_a_clean_result(db_module, monkeypatch):
    nvd.FakeNVD(monkeypatch, fail=True)
    sid = _run([normalize_software("", "OpenSSL", "3.0.2")])
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and "NOT assessed" in s["status_detail"] and "not a clean result" in s["status_detail"]
    inv = db_module.get_software_inventory(sid)[0]
    assert inv["assessment"] == "lookup_failed" and "NOT assessed" in inv["note"]
    conn = db_module.get_connection(); cur = conn.cursor(); cur.execute("SELECT COUNT(*) FROM cve_cache")
    assert cur.fetchone()[0] == 0; conn.close()                              # the failure was not cached either


def test_bulk_scan_assesses_each_item_and_labels_mixed_results(db_module, openssl_nvd):
    items = parse_bulk("openssl, OpenSSL, 3.0.2\n, openssl, \n")
    sid = _run(items)
    inv = {(r["product"], r["version"]): r for r in db_module.get_software_inventory(sid)}
    assert len(inv) == 2 and inv[("OpenSSL", "3.0.2")]["findings_count"] == 4 and inv[("OpenSSL", None)]["findings_count"] == 1
    assert "software: 2 items" in db_module.get_scan(sid)["target"]


def test_attaching_an_asset_feeds_contextual_risk(db_module, openssl_nvd):
    plain = _findings(db_module, _run([normalize_software("", "OpenSSL", "3.0.2")]))["CVE-2022-3786"]
    asset = db_module.upsert_asset("10.0.0.9")
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("UPDATE assets SET exposure='EXTERNAL', criticality='CRITICAL', business_impact='CRITICAL' WHERE id=%s", (asset,))
    cur.execute("TRUNCATE scans, vulnerabilities RESTART IDENTITY CASCADE"); conn.commit(); conn.close()
    ctx = _findings(db_module, _run([normalize_software("", "OpenSSL", "3.0.2")], asset_id=asset))["CVE-2022-3786"]
    assert float(ctx["contextual_priority"]) > float(plain["contextual_priority"])


def test_duplicate_and_invalid_submissions(db_module, monkeypatch):
    import scanner.jobs as jobs
    monkeypatch.setattr(jobs, "run_software_scan", lambda *a, **k: None)     # leave the first one queued
    item = normalize_software("", "OpenSSL", "3.0.2")
    submit_software_scan([item], wait=True)
    with pytest.raises(ScanRejected, match="identical"):
        submit_software_scan([item])
    with pytest.raises(ScanRejected):
        submit_software_scan([])
    with pytest.raises(ScanRejected, match="asset"):
        submit_software_scan([normalize_software("", "curl", "8.0.1")], asset_id=99999)


# ----------------------------------------------------------------- classification rules (unit)
BASE_PROB = {"applicability_status": "PROBABLE", "applicability_reason": "engine says probable"}
CTX = {"version": "3.0.2", "identity_source": "catalog", "retrieval": "cpe", "distro_packaged": False}


def test_classification_rules():
    assert classify({}, BASE_PROB, CTX)["applicability_status"] == "PROBABLE"
    assert classify({}, {"applicability_status": "CONFIRMED", "applicability_reason": "x"}, CTX)["applicability_status"] == "CONFIRMED"
    assert classify({}, BASE_PROB, {**CTX, "version": None})["applicability_status"] == "INDETERMINATE"
    assert classify({}, BASE_PROB, {**CTX, "distro_packaged": True})["applicability_status"] == "POTENTIAL"
    assert "backported" in classify({}, BASE_PROB, {**CTX, "distro_packaged": True})["applicability_reason"]
    assert classify({}, BASE_PROB, {**CTX, "identity_source": "name_only"})["applicability_status"] == "POTENTIAL"
    assert classify({}, BASE_PROB, {**CTX, "retrieval": "keyword"})["applicability_status"] == "POTENTIAL"
    unconfirmed = {"applicability_status": "UNCONFIRMED", "applicability_reason": "no CPE confirmation"}
    assert classify({}, unconfirmed, CTX)["applicability_status"] == "POTENTIAL"
    # missing version beats every other rule, including CONFIRMED-by-engine only when evidence is direct
    assert classify({}, unconfirmed, {**CTX, "version": None})["applicability_status"] == "INDETERMINATE"


# ----------------------------------------------------------------- input validation
@pytest.mark.parametrize("kw", [
    dict(product=""), dict(product="x;rm -rf"), dict(product="ok", vendor="bad;vendor"), dict(product="ok", version="1.0;x"),
    dict(product="ok", version="no-digits"), dict(product="a" * 200), dict(cpe="cpe:/o:linux:linux_kernel:5.4"),
    dict(cpe="not a cpe"), dict(cpe="cpe:/a:v:p:1.0", version="2.0"),
])
def test_invalid_software_input_rejected(kw):
    with pytest.raises(SoftwareInputError):
        normalize_software(**kw)


def test_bulk_errors_name_the_line():
    with pytest.raises(SoftwareInputError, match="Line 2"):
        parse_bulk("a, b, 1.0\nonly,two\n")


@pytest.mark.parametrize("raw", ["", "unknown", "N/A", "-", "*", "latest"])
def test_placeholder_versions_mean_unknown(raw):
    assert normalize_software("", "OpenSSL", raw)["version"] is None


def test_package_version_extraction_and_mapping():
    cases = [("1:9.6p1-3ubuntu13.5", "dpkg", "9.6p1"), ("3.0.13-0ubuntu3.4", "dpkg", "3.0.13"),
             ("1:1.3.dfsg-3.1ubuntu2.1", "dpkg", "1.3"), ("1.9.15p5-3ubuntu5", "dpkg", "1.9.15p5"),
             ("3.0.7", "rpm", "3.0.7"), ("garbage", "dpkg", None)]
    for raw, src, want in cases:
        assert upstream_version(raw, src) == want, raw
    assert map_package("libssl3") == ("openssl", "openssl") and map_package("apache2") == ("apache", "http_server")
    assert map_package("postgresql") is None and map_package("php") is None and map_package("coreutils") is None


# ----------------------------------------------------------------- engine regression: product named only by its vendor
@pytest.mark.parametrize("a,b,vendor,expected", [
    ("openssl", "openssl", "openssl", True),            # was False: vendor tokens stripped to the empty set
    ("postgresql", "postgresql", "postgresql", True),
    ("redis", "redis", "redis", True),
    ("libressl", "openssl", "openssl", False),          # a different product must still not match
    ("Apache httpd", "http_server", "apache", True),    # pre-existing behaviour preserved
    ("F5 BIG-IP HTTP proxy", "http_server", "apache", False),
    ("apache_http_server", "http_server", "apache", True),
])
def test_product_identity_matching(a, b, vendor, expected):
    from vulnerability.cve_lookup import _product_identity_match
    assert _product_identity_match(a, b, vendor) is expected
