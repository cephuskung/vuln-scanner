import pytest
import scanner.pipeline as pipeline
from scanner.jobs import submit_scan, ScanRejected


def _all_scans(db):
    conn = db.get_connection(); cur = conn.cursor()
    cur.execute("SELECT target, scan_type, status FROM scans ORDER BY id")
    rows = cur.fetchall(); conn.close()
    return rows


def test_network_scan_discovers_then_scans_each_host(db_module, stub_scan_backends, monkeypatch):
    monkeypatch.setattr(pipeline, "discover_hosts", lambda t: ["10.9.0.1", "10.9.0.2"])
    sid, network = submit_scan("10.9.0.0/30", created_by=None, wait=True)
    assert network
    rows = _all_scans(db_module)
    assert rows[0] == ("10.9.0.0/30", "network", "completed")
    assert sorted(rows[1:]) == [("10.9.0.1", "network-host", "completed"), ("10.9.0.2", "network-host", "completed")]
    parent = db_module.get_scan(sid)
    assert "2 live host(s)" in parent["status_detail"] and float(parent["total_risk"]) > 0
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT ip_address FROM assets ORDER BY ip_address"); ips = [r[0] for r in cur.fetchall()]; conn.close()
    assert ips == ["10.9.0.1", "10.9.0.2"]        # one asset per host - never an asset called '10.9.0.0/30'


def test_one_failing_host_does_not_stop_the_rest(db_module, stub_scan_backends, monkeypatch):
    monkeypatch.setattr(pipeline, "discover_hosts", lambda t: ["10.9.0.1", "10.9.0.2"])
    stub_scan_backends.hook = lambda t: (_ for _ in ()).throw(RuntimeError("boom")) if t == "10.9.0.1" else None
    sid, _ = submit_scan("10.9.0.0/30", wait=True)
    by_target = {t: s for t, _, s in _all_scans(db_module)}
    assert by_target["10.9.0.1"] == "failed" and by_target["10.9.0.2"] == "completed"
    parent = db_module.get_scan(sid)
    assert parent["status"] == "completed" and "1 failed" in parent["status_detail"]


def test_all_hosts_failing_fails_the_network_scan(db_module, stub_scan_backends, monkeypatch):
    monkeypatch.setattr(pipeline, "discover_hosts", lambda t: ["10.9.0.1"])
    stub_scan_backends.nmap_error = "nmap exploded"
    sid, _ = submit_scan("10.9.0.0/30", wait=True)
    assert db_module.get_scan(sid)["status"] == "failed"


def test_host_with_active_scan_is_skipped_not_duplicated(db_module, stub_scan_backends, monkeypatch):
    monkeypatch.setattr(pipeline, "discover_hosts", lambda t: ["10.9.0.1", "10.9.0.2"])
    a = db_module.upsert_asset("10.9.0.1")
    db_module.create_scan_if_idle("10.9.0.1", a, None, "manual", "running")
    sid, _ = submit_scan("10.9.0.0/30", wait=True)
    assert [t for t, ty, _ in _all_scans(db_module) if t == "10.9.0.1"] == ["10.9.0.1"]   # still just the original
    assert "skipped" in db_module.get_scan(sid)["status_detail"]


def test_no_live_hosts_is_reported_as_inconclusive(db_module, stub_scan_backends, monkeypatch):
    monkeypatch.setattr(pipeline, "discover_hosts", lambda t: [])
    sid, _ = submit_scan("10.9.0.0/30", wait=True)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and "does not prove" in s["status_detail"]


def test_discovery_failure_fails_the_network_scan(db_module, stub_scan_backends, monkeypatch):
    def bad(t):
        raise RuntimeError("Nmap host discovery timed out after 5 minutes")
    monkeypatch.setattr(pipeline, "discover_hosts", bad)
    sid, _ = submit_scan("10.9.0.0/30", wait=True)
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and "timed out" in s["status_detail"]


def test_oversized_range_rejected(db_module):
    with pytest.raises(ScanRejected):
        submit_scan("10.0.0.0/8")
    assert _all_scans(db_module) == []
