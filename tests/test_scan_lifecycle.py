import os
import threading
import time
import pytest
import scanner.pipeline as pipeline
from scanner.jobs import submit_scan, ScanRejected
from tests.conftest import XML_NO_PORTS, XML_NO_HOSTS


def _scan(db, sid):
    return db.get_scan(sid)


def test_success_path_persists_everything_and_cleans_temp_files(db_module, stub_scan_backends):
    sid, network = submit_scan("10.1.1.1", created_by=None, wait=True)
    s = _scan(db_module, sid)
    assert not network and s["status"] == "completed" and s["finished_at"] is not None
    assert s["status_detail"] is None and float(s["total_risk"]) > 0
    assert len(db_module.get_vulnerabilities(sid)) == 1
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT port_number FROM asset_services WHERE scan_id=%s", (sid,))
    assert cur.fetchall() == [(8080,)]
    conn.close()
    assert stub_scan_backends.written and not os.path.exists(stub_scan_backends.written[0])   # temp XML removed


def test_scan_is_queued_before_it_runs(db_module):
    asset = db_module.upsert_asset("10.1.1.1")
    sid = db_module.create_scan_if_idle("10.1.1.1", asset, None, "manual", "queued")
    assert _scan(db_module, sid)["status"] == "queued"


def test_nmap_failure_marks_failed_with_reason(db_module, stub_scan_backends):
    stub_scan_backends.nmap_error = "Nmap scan failed: host unreachable"
    sid, _ = submit_scan("10.1.1.1", wait=True)
    s = _scan(db_module, sid)
    assert s["status"] == "failed" and "host unreachable" in s["status_detail"] and s["finished_at"]


def test_unresolvable_target_fails_instead_of_completing(db_module, stub_scan_backends):
    stub_scan_backends.xml = XML_NO_HOSTS
    sid, _ = submit_scan("no-such-host.invalid", wait=True)
    s = _scan(db_module, sid)
    assert s["status"] == "failed" and "no hosts" in s["status_detail"].lower()


def test_no_open_ports_completes_with_inconclusive_warning(db_module, stub_scan_backends):
    stub_scan_backends.xml = XML_NO_PORTS
    sid, _ = submit_scan("10.1.1.1", wait=True)
    s = _scan(db_module, sid)
    assert s["status"] == "completed" and "inconclusive" in s["status_detail"]


def test_nvd_outage_is_reported_not_silent(db_module, stub_scan_backends):
    stub_scan_backends.nvd_fails = True
    sid, _ = submit_scan("10.1.1.1", wait=True)
    s = _scan(db_module, sid)
    assert s["status"] == "completed" and "NVD" in s["status_detail"] and "incomplete" in s["status_detail"]


def test_unexpected_error_does_not_leak_internals(db_module, stub_scan_backends, monkeypatch):
    monkeypatch.setattr(pipeline, "parse_nmap_xml", lambda p: {}["secret_internal_key"])
    sid, _ = submit_scan("10.1.1.1", wait=True)
    s = _scan(db_module, sid)
    assert s["status"] == "failed"
    assert "secret_internal_key" not in s["status_detail"] and "server log" in s["status_detail"]


def test_invalid_target_rejected_before_any_row_is_created(db_module):
    with pytest.raises(ScanRejected):
        submit_scan("--script=evil")
    conn = db_module.get_connection(); cur = conn.cursor()
    cur.execute("SELECT (SELECT COUNT(*) FROM scans), (SELECT COUNT(*) FROM assets)")
    assert cur.fetchone() == (0, 0)
    conn.close()


def test_duplicate_submission_rejected(db_module, monkeypatch):
    import scanner.jobs as jobs
    monkeypatch.setattr(jobs, "run_full_scan", lambda *a, **k: None)   # leaves the first scan 'queued'
    sid, _ = submit_scan("10.1.1.1", wait=True)
    assert _scan(db_module, sid)["status"] == "queued"
    with pytest.raises(ScanRejected, match="already"):
        submit_scan("10.1.1.1")
    submit_scan("10.1.1.2")      # a different target is fine


def test_concurrent_submissions_create_exactly_one_scan(db_module, monkeypatch):
    import scanner.jobs as jobs
    monkeypatch.setattr(jobs, "run_full_scan", lambda *a, **k: None)
    results = []

    def go():
        try:
            results.append(submit_scan("10.2.2.2", wait=True)[0])
        except ScanRejected:
            results.append(None)
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert len([r for r in results if r]) == 1


def test_interrupted_scans_recovered_on_startup(db_module):
    a = db_module.upsert_asset("10.3.3.3")
    running = db_module.create_scan("10.3.3.3", asset_id=a, status="running")
    queued = db_module.create_scan("10.3.3.4", asset_id=a, status="queued")
    done = db_module.create_scan("10.3.3.5", asset_id=a)
    db_module.update_scan_status(done, "completed", total_risk=1)
    assert db_module.fail_interrupted_scans() == 2
    assert _scan(db_module, running)["status"] == "failed" and "Interrupted" in _scan(db_module, running)["status_detail"]
    assert _scan(db_module, queued)["status"] == "failed"
    assert _scan(db_module, done)["status"] == "completed"


def test_concurrency_cap_keeps_extra_scans_queued(db_module, stub_scan_backends, monkeypatch):
    monkeypatch.setattr(pipeline, "_SCAN_SLOTS", threading.BoundedSemaphore(1))
    gate, started = threading.Event(), threading.Event()

    def hook(target):
        if target == "10.4.4.1":
            started.set()
            gate.wait(10)
    stub_scan_backends.hook = hook
    first, _ = submit_scan("10.4.4.1")
    assert started.wait(10)
    second, _ = submit_scan("10.4.4.2")
    time.sleep(0.5)
    assert _scan(db_module, first)["status"] == "running"
    assert _scan(db_module, second)["status"] == "queued"        # waiting for a free slot
    gate.set()
    for _ in range(100):
        if all(_scan(db_module, i)["status"] == "completed" for i in (first, second)):
            break
        time.sleep(0.1)
    assert all(_scan(db_module, i)["status"] == "completed" for i in (first, second))
