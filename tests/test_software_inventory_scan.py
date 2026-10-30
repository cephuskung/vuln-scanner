"""'Scan this computer': installed applications -> the EXISTING vulnerability engine -> history, findings, reports.
The registry is faked; NVD is faked at the HTTP layer so the real search_cves()/applicability/confidence code runs."""
import pytest

import scanner.jobs as jobs
import scanner.software_inventory_scan as sis
from scanner.inventory import InventoryEntry, InventoryResult, LocationStatus
from scanner.jobs import submit_local_software_scan, ScanRejected
from tests import nvd_fixtures as nvd


class FakeProvider:
    name = "fake-provider"

    def __init__(self, entries, status="complete", error=None, locations=None):
        self.result = InventoryResult(
            provider="windows-registry", status=status, error=error,
            host={"computer_name": "WS-01", "os": "Windows 11 Pro 23H2 (build 22631)", "scope": "server-local", "supported": True},
            entries=entries, locations=locations or [LocationStatus("HKLM 64-bit", "ok", len(entries))],
            skipped={"updates": 0, "nameless": 0, "invalid_values": 0, "duplicates_merged": 0}, notes=["registry note"])
        self.calls = 0

    def collect(self):
        self.calls += 1
        return self.result


def E(name, version="1.0", publisher="Acme", sources=("HKLM 64-bit",), date="2024-01-01"):
    return InventoryEntry(name=name, publisher=publisher, version=version, install_date=date, sources=list(sources),
                          missing=[] if version and publisher else ["version"] if not version else ["publisher"])


@pytest.fixture(autouse=True)
def windows_server(monkeypatch):
    monkeypatch.setattr(jobs, "local_host_os", lambda: "Windows")


@pytest.fixture
def engine(monkeypatch):
    return nvd.FakeNVD(monkeypatch,
                       by_cpe={"openssl:openssl": [nvd.CVE_3786, nvd.CVE_3602, nvd.CVE_OUT_OF_RANGE, nvd.CVE_OTHER_PRODUCT]},
                       by_keyword={"widget pro": [nvd.CVE_ACME]})


def scan(entries, **kw):
    provider = kw.pop("provider", None) or FakeProvider(entries)
    sid = submit_local_software_scan(created_by=None, allow_local=True, wait=True, provider=provider)
    return sid, provider


def rows(db, sid):
    return {(r["product"], r["version"]): r for r in db.get_software_inventory(sid)}


# ---------------------------------------------------------------- end to end
def test_inventory_is_assessed_through_the_existing_engine_and_saved(db_module, engine):
    sid, _ = scan([E("OpenSSL 3.0.2 (64-bit)", "3.0.2", "OpenSSL Software Foundation"),
                   E("Acme Widget Pro", "2.1.0"),
                   E("Mystery Tool", None, None)])
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and s["scan_type"] == "software" and s["finished_at"] and float(s["total_risk"]) > 0
    assert s["scan_info"]["mode"] == "windows-inventory" and s["scan_info"]["host"]["computer_name"] == "WS-01"
    assert "progress" not in s["scan_info"]
    inv = rows(db_module, sid)

    ssl = inv[("OpenSSL 3.0.2 (64-bit)", "3.0.2")]                       # recognised product: CPE path, version range enforced
    assert ssl["assessment"] == "assessed" and ssl["findings_count"] == 2 and ssl["identity_source"] == "catalog"
    assert ssl["vendor"] == "OpenSSL Software Foundation" and ssl["install_date"] == "2024-01-01"
    assert ssl["inventory_source"] == "HKLM 64-bit" and ssl["collection_status"] == "complete" and ssl["source"] == "windows-registry"

    widget = inv[("Acme Widget Pro", "2.1.0")]                            # unrecognised: matched by name only
    assert widget["assessment"] == "assessed" and widget["findings_count"] == 1 and widget["identity_source"] == "name_only"

    mystery = inv[("Mystery Tool", None)]                                  # no version: UNKNOWN applicability, not sent to NVD
    assert mystery["assessment"] == "not_assessed" and mystery["assessment_reason"] == "no_version"
    assert mystery["collection_status"] == "partial" and "applicability is UNKNOWN" in mystery["note"]
    assert not any("mystery" in c.lower() for c in engine.calls)

    findings = {v["cve_id"]: v for v in db_module.get_vulnerabilities(sid)}
    assert set(findings) == {"CVE-2022-3786", "CVE-2022-3602", "CVE-2099-1111"}        # range + product enforced
    probable = findings["CVE-2022-3786"]
    assert probable["applicability_status"] == "PROBABLE" and probable["vulnerability_confidence"] is not None
    assert probable["contextual_priority"] is not None and probable["remediation"]
    assert probable["match_evidence"]["inventory"]["publisher"] == "OpenSSL Software Foundation"
    assert probable["match_evidence"]["source"] == "windows-registry" and probable["port_number"] is None
    potential = findings["CVE-2099-1111"]                                   # name-only match can never be better than POTENTIAL
    assert potential["applicability_status"] == "POTENTIAL" and "name only" in potential["applicability_reason"]
    assert all(v["applicability_status"] != "CONFIRMED" for v in findings.values())
    assert s["scan_info"]["tiers"] == {"PROBABLE": 2, "POTENTIAL": 1}


def test_scan_is_attached_to_the_computer_asset_and_shows_in_history(db_module, engine):
    sid, _ = scan([E("OpenSSL", "3.0.2")])
    s = db_module.get_scan(sid)
    assert s["asset_id"] is not None and s["target"].startswith("software:local (")
    assert sid in [x["id"] for x in db_module.get_scans()]


def test_no_cve_match_is_not_reported_as_secure(db_module, monkeypatch):
    nvd.FakeNVD(monkeypatch, by_cpe={"openssl:openssl": []})
    sid, _ = scan([E("OpenSSL", "3.0.2")])
    detail = db_module.get_scan(sid)["status_detail"]
    assert "not proof that the computer is secure" in detail and "portable applications" in detail


def test_unrecognised_names_carry_the_name_only_caveat(db_module, engine):
    sid, _ = scan([E("Acme Widget Pro", "2.1.0")])
    assert "NAME ONLY" in db_module.get_scan(sid)["status_detail"]


# ---------------------------------------------------------------- bounded NVD usage
def test_duplicate_products_are_assessed_once(db_module, engine):
    sid, _ = scan([E("OpenSSL 3.0.2 (x64)", "3.0.2", sources=("HKLM 64-bit",)), E("OpenSSL 3.0.2 (x86)", "3.0.2", sources=("HKLM 32-bit",))])
    assert len(engine.queries("virtualMatchString")) == 1                   # one NVD request for two entries
    inv = list(rows(db_module, sid).values())
    assert len(inv) == 2 and all(r["findings_count"] == 2 for r in inv)
    assert len(db_module.get_vulnerabilities(sid)) == 2                      # findings stored once


def test_not_assessable_entries_never_reach_nvd(db_module, engine):
    sid, _ = scan([E("Windows Driver Package - Intel (x) System 01/01/2020 1.2", "1.2"), E("Office Language Pack", "16.0"),
                   E("!!!", "1.0"), E("No Version App", None)])
    assert engine.calls == []
    reasons = {r["assessment_reason"] for r in db_module.get_software_inventory(sid)}
    assert reasons == {"driver_package", "language_pack", "unidentifiable_name", "no_version"}
    assert all(r["assessment"] == "not_assessed" for r in db_module.get_software_inventory(sid))


def test_assessment_count_is_capped_and_the_rest_are_listed_as_not_assessed(db_module, engine, monkeypatch):
    monkeypatch.setenv("SENTRIX_MAX_INVENTORY_ASSESSMENTS", "3")
    entries = [E(f"Tool Number {c}", "1.0") for c in "ABCDEF"]
    sid, _ = scan(entries)
    inv = db_module.get_software_inventory(sid)
    assert sum(1 for r in inv if r["assessment"] == "assessed") == 3
    over = [r for r in inv if r["assessment_reason"] == "over_limit"]
    assert len(over) == 3 and all("limit" in r["note"] for r in over)
    assert len(engine.calls) <= 3 * 2                                        # bounded: at most 3 identities x (cpe + keyword)
    assert "Only the first 3 distinct products" in db_module.get_scan(sid)["status_detail"]


def test_recognised_products_are_assessed_before_name_only_ones(db_module, engine, monkeypatch):
    monkeypatch.setenv("SENTRIX_MAX_INVENTORY_ASSESSMENTS", "1")
    sid, _ = scan([E("Aardvark Tool", "1.0"), E("OpenSSL", "3.0.2")])
    inv = rows(db_module, sid)
    assert inv[("OpenSSL", "3.0.2")]["assessment"] == "assessed"
    assert inv[("Aardvark Tool", "1.0")]["assessment_reason"] == "over_limit"


def test_time_budget_stops_assessment_and_says_so(db_module, engine, monkeypatch):
    ticks = iter(range(0, 10000, 100))                                       # each clock() call advances 100 s
    monkeypatch.setenv("SENTRIX_INVENTORY_TIME_BUDGET_SECONDS", "250")
    provider = FakeProvider([E(f"Tool Number {c}", "1.0") for c in "ABCDE"])
    sid = jobs.db.create_scan_if_idle("software:local (WS-01)", None, None, "software", "queued")
    result = sis.run_inventory_scan(sid, None, None, provider=provider, clock=lambda: next(ticks))
    inv = db_module.get_software_inventory(sid)
    budget = [r for r in inv if r["assessment_reason"] == "time_budget"]
    assert budget and len(budget) < len(inv) and result["status"] == "completed"
    assert "time budget ran out" in db_module.get_scan(sid)["status_detail"]
    assert db_module.get_scan(sid)["scan_info"]["limits"]["time_budget_exhausted"] is True


# ---------------------------------------------------------------- partial / failed assessment
def test_nvd_outage_marks_items_as_not_assessed_never_clean(db_module, monkeypatch):
    nvd.FakeNVD(monkeypatch, fail=True)
    sid, _ = scan([E("OpenSSL", "3.0.2"), E("Acme Widget Pro", "2.1.0")])
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and "NOT assessed" in s["status_detail"] and "not a clean result" in s["status_detail"]
    inv = db_module.get_software_inventory(sid)
    assert {r["assessment"] for r in inv} == {"lookup_failed"} and {r["assessment_reason"] for r in inv} == {"nvd_unavailable"}
    assert "not proof that the computer is secure" not in s["status_detail"]   # that sentence only applies to a real "no match"


def test_partial_registry_inventory_is_flagged(db_module, engine):
    provider = FakeProvider([E("OpenSSL", "3.0.2")], status="partial",
                            locations=[LocationStatus("HKLM 64-bit", "ok", 1), LocationStatus("HKLM 32-bit", "access_denied", 0, 0, "denied")])
    sid, _ = scan(None, provider=provider)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and "PARTIAL" in s["status_detail"]
    assert s["scan_info"]["inventory_status"] == "partial"
    assert [l["status"] for l in s["scan_info"]["locations"]] == ["ok", "access_denied"]


@pytest.mark.parametrize("status,error", [("failed", "No installed-software registry location could be read."),
                                          ("unsupported", "only works on Windows")])
def test_failed_or_unsupported_collection_fails_the_scan_with_the_reason(db_module, status, error):
    sid, _ = scan(None, provider=FakeProvider([], status=status, error=error))
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and error in s["status_detail"] and s["finished_at"]
    assert db_module.get_software_inventory(sid) == []


def test_unexpected_crash_marks_the_scan_failed_without_leaking_internals(db_module):
    class Boom(FakeProvider):
        def collect(self):
            raise KeyError("secret internal detail")
    sid, _ = scan(None, provider=Boom([]))
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and "secret internal detail" not in s["status_detail"]


def test_lifecycle_is_queued_then_running_then_completed(db_module, engine, monkeypatch):
    seen = []
    orig = db_module.update_scan_status
    monkeypatch.setattr(sis.db, "update_scan_status", lambda sid, st, *a, **k: (seen.append(st), orig(sid, st, *a, **k))[1])

    class Slow(FakeProvider):
        def collect(self):
            seen.append("collect")
            return super().collect()
    sid, _ = scan(None, provider=Slow([E("OpenSSL", "3.0.2")]))
    assert seen == ["running", "collect", "completed"]


# ---------------------------------------------------------------- submission rules
def test_only_administrators_may_scan_this_computer(db_module):
    with pytest.raises(ScanRejected, match="administrator"):
        submit_local_software_scan(created_by=None, allow_local=False, wait=True, provider=FakeProvider([]))


def test_non_windows_server_is_rejected_up_front_without_creating_a_scan(db_module, monkeypatch):
    monkeypatch.setattr(jobs, "local_host_os", lambda: "Linux")
    with pytest.raises(ScanRejected, match="runs? on Windows.*Linux.*not the\\s+computer your browser"):
        submit_local_software_scan(created_by=None, allow_local=True, wait=True)
    conn = db_module.get_connection(); cur = conn.cursor(); cur.execute("SELECT COUNT(*) FROM scans")
    assert cur.fetchone()[0] == 0; conn.close()


def test_duplicate_local_scan_is_rejected_while_one_is_active(db_module, engine, monkeypatch):
    monkeypatch.setattr(jobs, "run_inventory_scan", lambda *a, **k: None)      # leave the first scan queued
    submit_local_software_scan(created_by=None, allow_local=True, wait=True, provider=FakeProvider([]))
    with pytest.raises(ScanRejected, match="already queued or running"):
        submit_local_software_scan(created_by=None, allow_local=True, wait=True, provider=FakeProvider([]))


def test_manual_software_scan_still_works_alongside(db_module, engine):
    from vulnerability.software_catalog import normalize_software
    sid = jobs.submit_software_scan([normalize_software("", "OpenSSL", "3.0.2")], wait=True)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and s["scan_type"] == "software" and (s["scan_info"] or {}).get("mode") == "software"


# ---------------------------------------------------------------- reports & pages
def test_scan_page_and_pdf_show_inventory_and_unassessed_apps(db_module, engine, make_user, client, login):
    make_user("admin1", "admin")
    sid, _ = scan([E("OpenSSL 3.0.2 (64-bit)", "3.0.2"), E("Mystery Tool", None, None), E("Acme Widget Pro", "2.1.0")])
    login("admin1")
    html = client.get(f"/scan/{sid}").data.decode()
    for needle in ("WS-01", "Windows 11 Pro 23H2", "computer running the SentriX server", "OpenSSL 3.0.2 (64-bit)", "Mystery Tool",
                   "unknown applicability", "matched by name only", "PROBABLE", "POTENTIAL", "CVE-2022-3786",
                   "Remediation", "Collection details", "no finding here is CONFIRMED", "HKLM 64-bit"):
        assert needle in html, needle
    pdf = client.get(f"/scan/{sid}/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    assert client.get(f"/scan/{sid}/status").get_json()["status"] == "completed"
