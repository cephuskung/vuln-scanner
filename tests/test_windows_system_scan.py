"""Windows System Scan (Microsoft Defender): lifecycle, honest outcomes, persistence, backend selection, pages & PDF.
Defender/PowerShell are simulated; nothing here was run against a real Windows Defender."""
import json
import threading
import time
from datetime import timedelta

import pytest

import scanner.jobs as jobs
import scanner.windows_system_scan as wss
from scanner.jobs import submit_windows_system_scan, submit_system_scan, ScanRejected
from scanner.windows_defender import DefenderClient, RunResult
from tests.test_windows_defender import (
    T0, iso, out, err_payload, status_payload, detection, THREATS, STATUS_FIELDS, FakeRunner,
)

EICAR = "2147519003"
WACATAC = "2147735503"


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def build(status=None, scan=None, verify="finished", before=(), after=None, kind="quick", detections_error=False, scan_hook=None):
    """A DefenderClient over a scripted Windows box. ``after`` are the detection records visible once the scan ran."""
    clock, state = Clock(), {"scanned": False}
    after = list(before) if after is None else list(after)

    def run_scan(env, timeout):
        if scan_hook:
            scan_hook()
        state["scanned"] = True
        clock.t = clock.t + timedelta(minutes=10)                   # the scan "took" ten minutes
        return scan if scan is not None else out({"ok": True})

    def detections(env, timeout):
        if detections_error and state["scanned"]:
            return out(err_payload("System.UnauthorizedAccessException", "Access is denied.", "x"), rc=2)
        return out({"ok": True, "detections": after if state["scanned"] else list(before), "threats": THREATS,
                    "detection_total": len(after if state["scanned"] else before)})

    def verify_h(env, timeout):
        label = "Quick" if kind == "quick" else "Full"
        if verify == "finished":
            return out({"ok": True, "status": {f"{label}ScanStartTime": iso(T0 + timedelta(seconds=1)), f"{label}ScanEndTime": iso(T0 + timedelta(minutes=9))},
                        "events": [{"id": 1001, "time": iso(T0 + timedelta(minutes=9))}]})
        if verify == "stopped":
            return out({"ok": True, "status": {}, "events": [{"id": 1002, "time": iso(T0 + timedelta(minutes=3))}]})
        if verify == "custom_finished":
            return out({"ok": True, "status": {}, "events": [{"id": 1001, "time": iso(T0 + timedelta(minutes=9))}]})
        return out({"ok": True, "status": {f"{label}ScanEndTime": iso(T0 - timedelta(days=2))}, "events": []})   # nothing proves completion

    runner = FakeRunner(status=status or out(status_payload()), detections=detections, scan_quick=run_scan, scan_full=run_scan,
                        scan_custom=run_scan, verify=verify_h)
    return DefenderClient(runner=runner, clock=clock, platform_system="Windows"), runner


@pytest.fixture(autouse=True)
def windows_server(monkeypatch):
    monkeypatch.setattr(jobs, "local_host_os", lambda: "Windows")


def run(action="quick", path=None, client=None, **kw):
    client = client or build()[0]
    sid = submit_windows_system_scan(action, path, confirmed=kw.pop("confirmed", True), allow_local=True, wait=True, client=client, **kw)
    return sid


def info(db, sid):
    return db.get_scan(sid)["scan_info"]


# =============================================================== successful scan
def test_successful_quick_scan_with_current_and_historical_detections(db_module):
    old = detection(1, EICAR, T0 - timedelta(days=30), status=3)
    new = detection(2, WACATAC, T0 + timedelta(minutes=4), status=1)
    client, runner = build(before=[old], after=[old, new])
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and s["scan_type"] == "system-windows" and s["finished_at"]
    i = s["scan_info"]
    assert i["mode"] == "windows-defender" and i["action"] == "quick" and "progress" not in i
    assert i["scan"]["outcome"] == "scan_finished" and i["scan"]["completion"]["established"] is True
    assert i["protection"]["state"] == "active" and i["host"]["scope"] == "server-local"
    assert i["detections"]["current_scan"] == 1 and i["detections"]["historical"] == 1 and i["detections"]["needs_attention"] == 1
    assert [c[0] for c in runner.calls if c[0].startswith("scan_")] == ["scan_quick"]

    threats = {t["detection_id"]: t for t in db_module.get_threat_findings(sid)}
    cur, hist = threats["{D2}"], threats["{D1}"]
    assert cur["attribution"] == "current_scan" and cur["threat_name"].startswith("Trojan:Win32/Wacatac") and cur["severity"] == "HIGH"
    assert cur["needs_attention"] and cur["status"] == "Detected" and cur["resources"][0]["type"] == "file"
    assert cur["evidence"]["DetectionID"] == "{D2}" and "Protection history" in cur["remediation"]
    assert hist["attribution"] == "historical" and not hist["needs_attention"] and hist["severity"] == "CRITICAL"
    assert [t["detection_id"] for t in db_module.get_threat_findings(sid)][0] == "{D2}"        # current-scan findings first
    assert float(s["total_risk"]) >= 7.5                                                         # the unresolved HIGH counts; the handled historical does not
    checks = {c["check_id"] for c in db_module.get_system_checks(sid)}
    assert {"windows.defender.service", "windows.defender.realtime", "windows.defender.signatures"} <= checks
    assert db_module.get_scan(sid)["asset_id"] is not None


def test_handled_historical_detections_do_not_raise_the_risk_score(db_module):
    client, _ = build(before=[detection(1, EICAR, T0 - timedelta(days=30), status=3)])
    sid = run(client=client)
    assert float(db_module.get_scan(sid)["total_risk"]) == 0.0 and info(db_module, sid)["detections"]["current_scan"] == 0


def test_finished_scan_with_no_detections_is_not_claimed_to_prove_anything(db_module, make_user, client, login):
    make_user("admin1", "admin")
    sid = run()
    assert db_module.get_scan(sid)["status_detail"] is None
    login("admin1")
    html = client.get(f"/scan/{sid}").data.decode()
    assert "Defender reports the scan finished" in html and "not proof the computer is free of malware" in html
    assert "No scan was performed" not in html


def test_history_and_dashboard_list_the_scan(db_module):
    sid = run()
    assert sid in [s["id"] for s in db_module.get_scans()]
    assert db_module.get_kpis()["total_scans"] == 1


# =============================================================== failed / incomplete / unverified
def test_permission_denied_scan_fails_and_explains_the_required_permission(db_module):
    client, runner = build(scan=out(err_payload("System.UnauthorizedAccessException", "Access is denied.", "UnauthorizedAccess"), rc=2))
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and s["scan_info"]["scan"]["outcome"] == "scan_failed"
    assert "Administrators" in s["status_detail"] and "never tries to elevate" in s["status_detail"]
    assert s["scan_info"]["scan"]["error"]["kind"] == "permission_denied"


def test_timed_out_scan_is_incomplete_and_never_clean(db_module):
    client, _ = build(scan=RunResult(timed_out=True))
    sid = run("full", client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and s["scan_info"]["scan"]["outcome"] == "scan_incomplete"
    assert "INCOMPLETE" in s["status_detail"] and "may still be scanning" in s["status_detail"]
    assert s["scan_info"]["scan"]["completion"] is None                  # no completion claim at all


def test_scan_that_returned_but_cannot_be_shown_to_have_finished_is_reported_as_unverified(db_module, make_user, client, login):
    make_user("admin1", "admin")
    cl, _ = build(verify="nothing")
    sid = run(client=cl)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and s["scan_info"]["scan"]["outcome"] == "completion_unverified"
    assert "could not establish that the scan finished" in s["status_detail"] and "clean result" in s["status_detail"]
    login("admin1")
    html = client.get(f"/scan/{sid}").data.decode()
    assert "Completion NOT established" in html and "Defender reports the scan finished" not in html
    assert "Detection records unavailable" not in html


def test_scan_recorded_as_stopped_by_defender_is_incomplete(db_module):
    client, _ = build(verify="stopped")
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and s["scan_info"]["scan"]["outcome"] == "scan_incomplete" and "INCOMPLETE" in s["status_detail"]


def test_completion_verification_failing_outright_is_unverified_not_clean(db_module):
    client, runner = build()
    runner.handlers["verify"] = RunResult(timed_out=True)
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["scan_info"]["scan"]["outcome"] == "completion_unverified" and s["status"] == "completed"
    assert "could not be verified" in " ".join(s["scan_info"]["scan"]["completion"]["caveats"])


def test_unreadable_detection_records_are_flagged_so_no_result_looks_clean(db_module, make_user, client, login):
    make_user("admin1", "admin")
    cl, _ = build(detections_error=True)
    sid = run(client=cl)
    s = db_module.get_scan(sid)
    assert s["scan_info"]["detections"]["available"] is False and "could not be read" in s["status_detail"] and "incomplete" in s["status_detail"]
    login("admin1")
    assert "Detection records unavailable" in client.get(f"/scan/{sid}").data.decode()


def test_defender_disabled_means_no_scan_is_started(db_module):
    client, runner = build(status=out(status_payload(AMServiceEnabled=False, AntivirusEnabled=False)))
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and s["scan_info"]["scan"]["outcome"] == "not_scanned" and "No scan was started" in s["status_detail"]
    assert not [c for c in runner.calls if c[0].startswith("scan_")]
    assert {c["check_id"]: c["status"] for c in db_module.get_system_checks(sid)}["windows.defender.service"] == "fail"


@pytest.mark.parametrize("status,state", [
    (out(err_payload("System.Management.Automation.CommandNotFoundException", "not recognized as the name of a cmdlet", "CommandNotFoundException"), rc=2), "unavailable"),
    (out(err_payload("System.UnauthorizedAccessException", "Access is denied", "x"), rc=2), "inaccessible"),
    (RunResult(timed_out=True), "inaccessible"),
])
def test_unavailable_or_inaccessible_protection_blocks_scanning(db_module, status, state):
    client, runner = build(status=status)
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and s["scan_info"]["protection"]["state"] == state
    assert not [c for c in runner.calls if c[0].startswith("scan_")]
    assert [c["status"] for c in db_module.get_system_checks(sid)] == ["unknown"]               # never 'pass'


def test_passive_defender_scan_is_attempted_with_a_warning(db_module):
    client, runner = build(status=out(status_payload(AMRunningMode="Passive mode", registered_av=("Windows Defender", "Contoso AV"))))
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and "passive mode" in s["status_detail"] and [c[0] for c in runner.calls].count("scan_quick") == 1


def test_scan_command_failure_other_than_permissions_is_reported(db_module):
    client, _ = build(scan=out(err_payload("System.Exception", "Unexpected failure 0x80004005", "x"), rc=2))
    sid = run(client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and "The scan did not run" in s["status_detail"] and s["scan_info"]["scan"]["error"]["kind"] == "command_failed"


def test_unexpected_crash_does_not_leak_internals(db_module):
    class Boom(DefenderClient):
        def get_protection_status(self):
            raise KeyError("internal secret detail")
    sid = run(client=Boom(runner=FakeRunner(), platform_system="Windows"))
    s = db_module.get_scan(sid)
    assert s["status"] == "failed" and "internal secret detail" not in s["status_detail"]


# =============================================================== status-only
def test_status_only_reads_protection_and_existing_records_without_scanning(db_module):
    client, runner = build(before=[detection(1, EICAR, T0 - timedelta(days=3), status=3)])
    sid = run("status", client=client, confirmed=False)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and s["scan_info"]["scan"]["outcome"] == "not_scanned"
    assert not [c for c in runner.calls if c[0].startswith("scan_")] and "verify" not in [c[0] for c in runner.calls]
    assert [t["attribution"] for t in db_module.get_threat_findings(sid)] == ["historical"]


def test_status_only_when_defender_unavailable_completes_with_the_finding_but_inaccessible_fails(db_module):
    c1, _ = build(status=out(err_payload("X", "The term is not recognized as the name of a cmdlet", "CommandNotFoundException"), rc=2))
    assert db_module.get_scan(run("status", client=c1, confirmed=False))["status"] == "completed"
    db_module_ = db_module
    conn = db_module_.get_connection(); cur = conn.cursor(); cur.execute("UPDATE scans SET status='completed'"); conn.commit(); conn.close()
    c2, _ = build(status=out(err_payload("System.UnauthorizedAccessException", "Access is denied", "x"), rc=2))
    s = db_module.get_scan(run("status", client=c2, confirmed=False))
    assert s["status"] == "failed" and "Protection status could not be established" in s["status_detail"]


# =============================================================== custom scan
def test_custom_scan_passes_the_validated_path_and_scopes_attribution(db_module):
    inside = detection(1, WACATAC, T0 + timedelta(minutes=2), status=1, resources=["file:_C:\\Users\\Public\\Downloads\\x.exe"])
    outside = detection(2, WACATAC, T0 + timedelta(minutes=3), status=1, resources=["file:_C:\\Windows\\Temp\\y.exe"])
    client, runner = build(after=[inside, outside], kind="custom", verify="custom_finished")
    sid = run("custom", "C:/Users/Public/Downloads/", client=client)
    s = db_module.get_scan(sid)
    assert s["status"] == "completed" and s["scan_info"]["path"] == "C:\\Users\\Public\\Downloads"
    assert [c for c in runner.calls if c[0] == "scan_custom"][0][1] == {"SENTRIX_SCAN_PATH": "C:\\Users\\Public\\Downloads"}
    t = {x["detection_id"]: x for x in db_module.get_threat_findings(sid)}
    assert t["{D1}"]["attribution"] == "current_scan" and t["{D1}"]["in_scan_scope"] is True
    assert t["{D2}"]["attribution"] == "unattributed" and t["{D2}"]["in_scan_scope"] is False
    assert s["scan_info"]["scan"]["completion"]["method"] == "event_log"
    assert "event log" in " ".join(s["scan_info"]["scan"]["completion"]["caveats"])


def test_custom_scan_of_a_missing_path_fails_with_a_clear_reason(db_module):
    client, _ = build(scan=out({"ok": False, "error": {"type": "PathNotFound", "message": "x", "id": "PathNotFound"}}, rc=2))
    s = db_module.get_scan(run("custom", "C:\\does\\not\\exist", client=client))
    assert s["status"] == "failed" and "does not exist or is not visible" in s["status_detail"]


@pytest.mark.parametrize("bad", ["", "\\\\evil\\share", "C:\\a\\..\\b", "relative", "C:\\*", "C:\\x\ncalc", "C:\\a'; Remove-MpPreference -ExclusionPath 'C:\\'"])
def test_invalid_custom_paths_are_rejected_before_anything_is_queued(db_module, bad):
    with pytest.raises(ScanRejected):
        submit_windows_system_scan("custom", bad, confirmed=True, allow_local=True, wait=True, client=build()[0])
    conn = db_module.get_connection(); cur = conn.cursor(); cur.execute("SELECT COUNT(*) FROM scans")
    assert cur.fetchone()[0] == 0; conn.close()


def test_a_path_that_looks_like_an_injection_is_data_and_scans_only_that_path(db_module):
    nasty = "C:\\Users\\Public\\a'; Remove-MpPreference -ExclusionPath 'X'; $(calc) #"
    client, runner = build(kind="custom", verify="custom_finished")
    sid = run("custom", nasty, client=client)
    assert db_module.get_scan(sid)["status"] == "completed"
    assert [c[0] for c in runner.calls if c[0].startswith("scan_")] == ["scan_custom"]
    assert runner.calls[[c[0] for c in runner.calls].index("scan_custom")][1]["SENTRIX_SCAN_PATH"] == nasty
    assert "Remove-MpPreference" not in "".join(wss_script for wss_script in __import__("scanner.windows_defender", fromlist=["SCRIPTS"]).SCRIPTS.values())


# =============================================================== submission rules
@pytest.mark.parametrize("action", ["quick", "full", "custom"])
def test_scans_require_explicit_confirmation_but_status_does_not(db_module, action):
    with pytest.raises(ScanRejected, match="Confirm that you understand"):
        submit_windows_system_scan(action, "C:\\Users\\Public", confirmed=False, allow_local=True, wait=True, client=build()[0])
    conn = db_module.get_connection(); cur = conn.cursor(); cur.execute("SELECT COUNT(*) FROM scans")
    assert cur.fetchone()[0] == 0; conn.close()


def test_unknown_action_is_rejected():
    with pytest.raises(ScanRejected, match="Choose"):
        submit_windows_system_scan("format-c", None, confirmed=True, allow_local=True, wait=True, client=build()[0])


def test_only_administrators_and_only_windows_servers(db_module, monkeypatch):
    with pytest.raises(ScanRejected, match="administrator"):
        submit_windows_system_scan("status", allow_local=False, wait=True, client=build()[0])
    monkeypatch.setattr(jobs, "local_host_os", lambda: "Linux")
    with pytest.raises(ScanRejected, match="runs? on Windows.*Linux"):
        submit_windows_system_scan("status", allow_local=True, wait=True, client=build()[0])


def test_second_scan_while_one_is_active_is_rejected(db_module, monkeypatch):
    monkeypatch.setattr(jobs, "run_windows_system_scan", lambda *a, **k: None)
    submit_windows_system_scan("status", allow_local=True, wait=True, client=build()[0])
    with pytest.raises(ScanRejected, match="already queued or running"):
        submit_windows_system_scan("quick", confirmed=True, allow_local=True, wait=True, client=build()[0])


def test_long_running_scan_stays_running_with_progress_then_completes_without_blocking_the_caller(db_module):
    gate, started = threading.Event(), threading.Event()
    client, _ = build(scan_hook=lambda: (started.set(), gate.wait(15)))
    t0 = time.monotonic()
    sid = submit_windows_system_scan("full", confirmed=True, allow_local=True, wait=False, client=client)
    assert time.monotonic() - t0 < 5                                                 # the submit call returned immediately
    assert started.wait(10)
    s = db_module.get_scan(sid)
    assert s["status"] == "running" and "Full Scan running in Microsoft Defender" in s["scan_info"]["progress"]
    assert "one to several hours" in s["scan_info"]["progress"] and db_module.get_scan_status(sid)["progress"].startswith("Full Scan running")
    gate.set()
    for _ in range(100):
        if db_module.get_scan(sid)["status"] != "running":
            break
        time.sleep(0.1)
    final = db_module.get_scan(sid)
    assert final["status"] == "completed" and "progress" not in final["scan_info"] and final["scan_info"]["scan"]["outcome"] == "scan_finished"


def test_interrupted_scan_is_failed_on_restart_not_left_running(db_module):
    sid = db_module.create_scan_if_idle("system:windows-defender (X)", None, None, "system-windows", "running")
    assert db_module.fail_interrupted_scans() == 1 and db_module.get_scan(sid)["status"] == "failed"


# =============================================================== backend selection
def test_local_system_scan_uses_defender_on_windows_and_the_linux_checks_elsewhere(db_module, monkeypatch):
    calls = []
    monkeypatch.setattr(jobs, "run_windows_system_scan", lambda *a, **k: calls.append(("windows", a[-1] if a else None)))
    monkeypatch.setattr(jobs, "run_system_scan", lambda *a, **k: calls.append(("linux", None)))
    submit_system_scan("local", allow_local=True, wait=True, windows_action="status")
    assert calls[-1][0] == "windows" and calls[-1][1] == {"action": "status", "path": None}
    conn = db_module.get_connection(); cur = conn.cursor(); cur.execute("SELECT scan_type FROM scans ORDER BY id DESC LIMIT 1")
    assert cur.fetchone()[0] == "system-windows"; cur.execute("UPDATE scans SET status='completed'"); conn.commit(); conn.close()

    monkeypatch.setattr(jobs, "local_host_os", lambda: "Linux")
    submit_system_scan("local", allow_local=True, wait=True)
    assert calls[-1][0] == "linux"
    conn = db_module.get_connection(); cur = conn.cursor(); cur.execute("SELECT scan_type FROM scans ORDER BY id DESC LIMIT 1")
    assert cur.fetchone()[0] == "system-local"; conn.close()


def test_remote_system_scan_is_never_routed_to_windows(db_module, monkeypatch):
    monkeypatch.setattr(jobs, "run_windows_system_scan", lambda *a, **k: pytest.fail("remote must not use Defender"))
    with pytest.raises(ScanRejected):                                                # no host given -> normal Linux validation error
        submit_system_scan("remote", allow_local=True, wait=True)


# =============================================================== pages, routes, PDF
@pytest.fixture
def web(monkeypatch, make_user, client, login):
    """Admin + analyst users; threads run inline; the Defender client is the scripted one."""
    class SyncThread:
        def __init__(self, target=None, args=(), kwargs=None, daemon=None):
            self.target, self.args, self.kwargs = target, args, kwargs or {}

        def start(self):
            self.target(*self.args, **self.kwargs)
    monkeypatch.setattr(jobs.threading, "Thread", SyncThread)
    monkeypatch.setattr(wss, "DefenderClient", lambda clock=None: build()[0])
    import web.app as webapp
    monkeypatch.setattr(webapp, "local_host_os", lambda: "Windows")
    make_user("admin1", "admin")
    make_user("alice", "analyst")
    return client, login


def test_scan_page_shows_the_computer_being_inspected_and_the_windows_controls(web):
    client, login = web
    login("admin1")
    html = client.get("/scan-page?tab=system").data.decode()
    for needle in ("This computer (Microsoft Defender)", "Computer inspected", 'name="action" value="quick"', 'name="action" value="full"',
                   'name="action" value="custom"', 'name="scan_path"', 'name="confirm_scan"', "Check protection now",
                   "SentriX server computer only", "remote Windows endpoints are not supported", "Linux System Scan"):
        assert needle in html, needle
    assert 'name="mode" value="local"' not in html                                  # Windows server: local = the Defender panel
    sw = client.get("/scan-page?tab=software").data.decode()
    for needle in ("Scan this computer", "Computer inspected", "not the computer your browser is running on", "Manual software lookup", 'name="vendor"'):
        assert needle in sw, needle


def test_non_admin_sees_the_windows_controls_disabled(web):
    client, login = web
    login("alice")
    html = client.get("/scan-page?tab=system").data.decode()
    assert "Only administrators can inspect the SentriX server computer." in html and "disabled" in html


def test_windows_scan_post_requires_confirmation_and_runs_end_to_end(web, db_module):
    client, login = web
    login("admin1")
    r = client.post("/system-scan/windows", data={"action": "quick"}, follow_redirects=True)
    assert "Confirm that you understand" in r.data.decode()
    r = client.post("/system-scan/windows", data={"action": "custom", "scan_path": "\\\\evil\\share", "confirm_scan": "1"}, follow_redirects=True)
    assert "Network (UNC)" in r.data.decode()
    r = client.post("/system-scan/windows", data={"action": "quick", "confirm_scan": "1"})
    assert r.status_code == 302 and "/scan/" in r.headers["Location"]
    sid = int(r.headers["Location"].rsplit("/", 1)[1])
    page = client.get(f"/scan/{sid}").data.decode()
    for needle in ("Windows threat assessment", "Protection status", "Scan result", "Protection checks", "Threat detections",
                   "Microsoft Defender", "Real-time protection is on", "SentriX has no antivirus engine"):
        assert needle in page, needle
    pdf = client.get(f"/scan/{sid}/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")


def test_non_admin_cannot_start_windows_scan_or_read_status_api(web):
    client, login = web
    login("alice")
    r = client.post("/system-scan/windows", data={"action": "status"}, follow_redirects=True)
    assert "administrator" in r.data.decode()
    assert client.get("/api/windows-defender/status").status_code == 403


def test_status_api_returns_state_for_admins(web, monkeypatch):
    client, login = web
    monkeypatch.setattr("web.app.defender_status", lambda: build()[0].get_protection_status())
    login("admin1")
    d = client.get("/api/windows-defender/status").get_json()
    assert d["state"] == "active" and d["realtime"] is True and d["signature_version"] == "1.411.200.0"


def test_status_api_on_a_non_windows_server_says_so(client, login, make_user):
    make_user("admin1", "admin")
    login("admin1")
    d = client.get("/api/windows-defender/status").get_json()
    assert d["state"] == "unavailable" and "Windows" in d["summary"]


def test_scan_detail_page_shows_historical_and_current_threats_with_evidence(web, db_module):
    client, login = web
    old = detection(1, EICAR, T0 - timedelta(days=30), status=3)
    new = detection(2, WACATAC, T0 + timedelta(minutes=4), status=1)
    sid = run(client=build(before=[old], after=[old, new])[0])
    login("admin1")
    html = client.get(f"/scan/{sid}").data.decode()
    for needle in ("during this scan", "historical", "Trojan:Win32/Wacatac.B!ml", "Virus:DOS/EICAR_Test_File", "unresolved",
                   "Defender fields", "Protection history", "Quarantined", "file: C:\\Users\\bob\\Downloads\\bad2.exe"):
        assert needle in html, needle
    pdf = client.get(f"/scan/{sid}/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
