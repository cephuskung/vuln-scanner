"""Microsoft Defender integration: protection states, safe execution, path validation / command-injection
resistance, failure classification, detection parsing, completion evidence and historical-vs-current attribution.

Defender and PowerShell are simulated (a fake runner, plus a stub executable for the real subprocess layer), so none of
this proves behaviour against a real Windows Defender - see the README's verification section."""
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

import scanner.windows_defender as wd
from scanner.windows_defender import (
    DefenderClient, DefenderInputError, PowerShellRunner, RunResult, SCRIPTS, validate_scan_path, parse_json_output,
    classify_failure, protection_checks, parse_detections, attribute_detections, decide_completion, ProtectionStatus,
)

T0 = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


STATUS_FIELDS = {
    "AMServiceEnabled": True, "AMRunningMode": "Normal", "AntivirusEnabled": True, "AntispywareEnabled": True,
    "RealTimeProtectionEnabled": True, "OnAccessProtectionEnabled": True, "IoavProtectionEnabled": True,
    "BehaviorMonitorEnabled": True, "IsTamperProtected": True, "AntivirusSignatureVersion": "1.411.200.0",
    "AntivirusSignatureLastUpdated": iso(T0 - timedelta(hours=5)), "AntivirusSignatureAge": 0,
    "DefenderSignaturesOutOfDate": False, "QuickScanEndTime": iso(T0 - timedelta(days=1)), "QuickScanAge": 1,
    "FullScanEndTime": None, "FullScanAge": None,
}


def status_payload(registered_av=("Windows Defender",), **over):
    f = dict(STATUS_FIELDS, **over)
    return {"ok": True, "status": f, "registered_av": list(registered_av)}


def err_payload(type_="System.Exception", message="boom", id_="X"):
    return {"ok": False, "error": {"type": type_, "message": message, "id": id_}}


def out(payload, rc=0, stderr=""):
    return RunResult(returncode=rc, stdout=json.dumps(payload), stderr=stderr)


class FakeRunner:
    """script_id -> RunResult | callable(env_extra, timeout) -> RunResult"""

    def __init__(self, **handlers):
        self.handlers, self.calls = handlers, []

    def run(self, script_id, env_extra=None, timeout=60):
        self.calls.append((script_id, dict(env_extra or {}), timeout))
        h = self.handlers[script_id]
        return h(env_extra, timeout) if callable(h) else h


def client(runner, system="Windows"):
    return DefenderClient(runner=runner, clock=lambda: T0, platform_system=system)


# =============================================================== protection status
def test_active_state_and_checks():
    st = client(FakeRunner(status=out(status_payload()))).get_protection_status()
    assert st.state == "active" and "active antivirus provider" in st.summary and st.error_kind is None
    checks = {c["check_id"]: c for c in protection_checks(st)}
    assert checks["windows.defender.service"]["status"] == "pass"
    assert checks["windows.defender.realtime"]["status"] == "pass"
    assert "1.411.200.0" in checks["windows.defender.signatures"]["evidence"]
    assert checks["windows.defender.signatures"]["status"] == "pass"
    assert checks["windows.defender.last_full_scan"]["status"] == "unknown"       # never run / not readable is NOT a pass


def test_realtime_off_is_a_high_severity_failure_with_remediation():
    st = client(FakeRunner(status=out(status_payload(RealTimeProtectionEnabled=False)))).get_protection_status()
    c = {x["check_id"]: x for x in protection_checks(st)}["windows.defender.realtime"]
    assert st.state == "active" and c["status"] == "fail" and c["severity"] == "HIGH" and "Windows Security" in c["remediation"]


def test_stale_signatures_fail_and_missing_values_are_unknown_not_pass():
    st = client(FakeRunner(status=out(status_payload(AntivirusSignatureAge=12, DefenderSignaturesOutOfDate=True)))).get_protection_status()
    assert {x["check_id"]: x for x in protection_checks(st)}["windows.defender.signatures"]["status"] == "fail"
    fields = {k: v for k, v in STATUS_FIELDS.items() if k not in ("RealTimeProtectionEnabled", "AntivirusSignatureAge", "DefenderSignaturesOutOfDate")}
    st = client(FakeRunner(status=out({"ok": True, "status": fields}))).get_protection_status()
    c = {x["check_id"]: x for x in protection_checks(st)}
    assert c["windows.defender.realtime"]["status"] == "unknown" and c["windows.defender.signatures"]["status"] == "unknown"


@pytest.mark.parametrize("mode", ["Passive mode", "SxS Passive mode", "EDR Block Mode"])
def test_passive_state_is_not_reported_as_active_protection(mode):
    st = client(FakeRunner(status=out(status_payload(registered_av=("Windows Defender", "Contoso AV"), AMRunningMode=mode, RealTimeProtectionEnabled=False)))).get_protection_status()
    assert st.state == "passive" and "NOT the active real-time antivirus" in st.summary and "Contoso AV" in st.summary
    c = {x["check_id"]: x for x in protection_checks(st)}
    assert c["windows.defender.realtime"]["status"] == "info"                       # not a failure: another product provides it


def test_disabled_state_when_service_or_antivirus_is_off():
    st = client(FakeRunner(status=out(status_payload(AMServiceEnabled=False, AntivirusEnabled=False, registered_av=("Contoso AV",))))).get_protection_status()
    assert st.state == "disabled" and "turned off" in st.summary and "Contoso AV" in st.summary
    c = {x["check_id"]: x for x in protection_checks(st)}["windows.defender.service"]
    assert c["status"] == "fail" and c["severity"] == "HIGH"


def test_service_not_running_error_is_reported_as_disabled():
    r = client(FakeRunner(status=out(err_payload("Microsoft.Management.Infrastructure.CimException",
                                                 "Operation failed with the following error: 0x800106ba", "HRESULT 0x800106ba"), rc=2)))
    st = r.get_protection_status()
    assert st.state == "disabled" and st.error_kind == "service_unavailable" and "not running or is disabled" in st.summary


def test_module_missing_is_unavailable():
    st = client(FakeRunner(status=out(err_payload("System.Management.Automation.CommandNotFoundException",
                                                  "The term 'Get-MpComputerStatus' is not recognized as the name of a cmdlet", "CommandNotFoundException"), rc=2))).get_protection_status()
    assert st.state == "unavailable" and st.error_kind == "unavailable" and "not available" in st.summary
    c = protection_checks(st)
    assert len(c) == 1 and c[0]["status"] == "unknown"


def test_powershell_missing_is_unavailable():
    st = client(FakeRunner(status=RunResult(launch_error="Windows PowerShell (powershell.exe) was not found; the Defender integration only works on Windows."))).get_protection_status()
    assert st.state == "unavailable"


def test_permission_denied_is_inaccessible_and_explains_the_required_permission():
    st = client(FakeRunner(status=out(err_payload("System.UnauthorizedAccessException", "Access is denied.", "UnauthorizedAccess"), rc=2))).get_protection_status()
    assert st.state == "inaccessible" and st.error_kind == "permission_denied"
    assert "Administrators" in st.summary and "never tries to elevate" in st.summary
    c = protection_checks(st)[0]
    assert c["status"] == "unknown" and c["requires"] == "administrator"


@pytest.mark.parametrize("run,kind", [
    (RunResult(timed_out=True), "timeout"),
    (RunResult(returncode=0, stdout="not json at all"), "unparseable"),
    (RunResult(returncode=1, stdout="", stderr="something odd happened"), "command_failed"),
])
def test_other_failures_are_inaccessible_not_guessed(run, kind):
    st = client(FakeRunner(status=run)).get_protection_status()
    assert st.state == "inaccessible" and st.error_kind == kind


def test_non_windows_host_never_invokes_powershell():
    runner = FakeRunner(status=out(status_payload()))
    st = client(runner, system="Linux").get_protection_status()
    assert st.state == "unavailable" and "only be checked on Windows" in st.summary and runner.calls == []


def test_single_registered_av_string_and_odd_payload_shapes_are_tolerated():
    p = status_payload()
    p["registered_av"] = "Contoso AV"
    assert client(FakeRunner(status=out(p))).get_protection_status().registered_av == ["Contoso AV"]
    st = client(FakeRunner(status=out({"ok": True, "status": {}}))).get_protection_status()
    assert st.state == "inaccessible"                                                # nothing usable -> not "active"


# =============================================================== fixed scripts / safe execution
def test_scripts_are_fixed_constants_with_no_quote_or_interpolation_hazards():
    assert set(SCRIPTS) == {"status", "detections", "scan_quick", "scan_full", "scan_custom", "verify"}
    for sid, text in SCRIPTS.items():
        assert '"' not in text and "`" not in text and "{0}" not in text and "%s" not in text, sid
        for bad in ("Remove-MpThreat", "Remove-Item", "Add-MpPreference", "Set-MpPreference", "Invoke-Expression", "iex ",
                    "Start-Process", "-EncodedCommand", "Stop-Service", "Set-ExecutionPolicy", "runas", "Remove-", "Disable-",
                    "Update-MpSignature", "Restore-"):
            assert bad.lower() not in text.lower(), (sid, bad)
    assert "Start-MpScan -ScanType QuickScan" in SCRIPTS["scan_quick"] and "Start-MpScan -ScanType FullScan" in SCRIPTS["scan_full"]
    assert "-ScanType CustomScan -ScanPath $p" in SCRIPTS["scan_custom"] and "$env:SENTRIX_SCAN_PATH" in SCRIPTS["scan_custom"]
    assert "Get-MpComputerStatus" in SCRIPTS["status"] and "Get-MpThreatDetection" in SCRIPTS["detections"]


def test_unknown_script_ids_and_disallowed_environment_are_refused():
    r = PowerShellRunner(executable="/bin/true")
    with pytest.raises(ValueError, match="unknown script"):
        r.run("Get-Process; calc")
    with pytest.raises(ValueError, match="not permitted"):
        r.run("status", env_extra={"PATH": "/evil"})
    with pytest.raises(ValueError):
        r.run("scan_custom", env_extra={"SENTRIX_SCAN_PATH": "C:\\x\x00y"})


def test_powershell_is_resolved_by_absolute_path_on_windows_only(monkeypatch, tmp_path):
    assert wd.resolve_powershell("Linux") is None
    exe = tmp_path / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe.parent.mkdir(parents=True)
    exe.write_text("x")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert wd.resolve_powershell("Windows") == str(exe)
    monkeypatch.setenv("SystemRoot", str(tmp_path / "missing"))
    assert wd.resolve_powershell("Windows") is None


def test_runner_reports_missing_powershell_without_raising():
    res = PowerShellRunner(platform_system="Linux").run("status")
    assert res.launch_error and "powershell.exe" in res.launch_error and res.returncode is None


posix_only = pytest.mark.skipif(os.name == "nt", reason="uses a POSIX shell script as a stand-in for powershell.exe")


def make_stub(tmp_path, body):
    exe = tmp_path / "fake-powershell"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return str(exe)


@posix_only
def test_real_subprocess_uses_argument_list_no_shell_and_fixed_script(tmp_path, monkeypatch):
    record = tmp_path / "rec"
    exe = make_stub(tmp_path, f'for a in "$@"; do printf "%s\\n---\\n" "$a" >> {record}; done\necho \'{{"ok": true}}\'\n')
    seen = {}
    real_run = subprocess.run

    def spy(*a, **k):
        seen.update(k, argv=a[0])
        return real_run(*a, **k)
    monkeypatch.setattr(subprocess, "run", spy)
    res = PowerShellRunner(executable=exe).run("status")
    assert res.returncode == 0 and parse_json_output(res.stdout) == {"ok": True}
    assert seen["shell"] is False and isinstance(seen["argv"], list) and seen["stdin"] == subprocess.DEVNULL and seen["timeout"]
    assert seen["argv"] == [exe, *wd.POWERSHELL_FLAGS, SCRIPTS["status"]]
    args = record.read_text().split("\n---\n")
    assert args[:4] == ["-NoProfile", "-NonInteractive", "-NoLogo", "-Command"] and args[4] == SCRIPTS["status"]


@posix_only
@pytest.mark.parametrize("path", [
    "C:\\Users\\O'Brien\\x'; Remove-Item C:\\ -Recurse #",
    "C:\\Users\\a;b&c$(calc.exe)\\`whoami`",
    "C:\\Users\\$env:USERNAME\\$(Get-Process)",
    "C:\\data\\'; Start-Process calc; '",
    "C:\\Users\\Public\\%COMSPEC% & del *.* ",
])
def test_command_injection_attempts_stay_data_and_never_reach_the_command_line(tmp_path, path):
    envdump = tmp_path / "env"
    exe = make_stub(tmp_path, f'printenv SENTRIX_SCAN_PATH > {envdump}\nprintf "%s\\n" "$@" > {tmp_path / "argv"}\n'
                              'echo \'{"ok": true}\'\n')
    try:
        norm = validate_scan_path(path)
    except DefenderInputError:
        norm = None
    if norm is None:
        return                                             # rejected outright: also acceptable
    DefenderClient(runner=PowerShellRunner(executable=exe), platform_system="Windows").start_scan("custom", path)
    argv_text = (tmp_path / "argv").read_text()
    assert envdump.read_text().rstrip("\n") == norm                       # arrived intact, as data, in the environment
    assert argv_text.count("SENTRIX") >= 1 and norm not in argv_text      # ...and appears nowhere on the command line
    for fragment in ("Remove-Item", "calc.exe", "Get-Process)", "whoami", "Start-Process calc"):
        assert fragment not in argv_text.replace(SCRIPTS["scan_custom"], "")


@posix_only
def test_secrets_in_the_parent_environment_are_not_passed_to_powershell(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PASSWORD", "hunter2-db")
    monkeypatch.setenv("SECRET_KEY", "flask-secret-xyz")
    monkeypatch.setenv("SOME_API_TOKEN", "tok-123")
    dump = tmp_path / "all-env"
    exe = make_stub(tmp_path, f'env > {dump}\necho \'{{"ok": true}}\'\n')
    PowerShellRunner(executable=exe).run("scan_custom", env_extra={"SENTRIX_SCAN_PATH": "C:\\Users\\Public"})
    text = dump.read_text()
    assert "hunter2-db" not in text and "flask-secret-xyz" not in text and "tok-123" not in text
    assert "SENTRIX_SCAN_PATH=C:\\Users\\Public" in text and "PATH=" in text


@posix_only
def test_timeout_kills_the_command_and_is_reported(tmp_path):
    exe = make_stub(tmp_path, "sleep 30\n")
    res = PowerShellRunner(executable=exe).run("status", timeout=1)
    assert res.timed_out and res.returncode is None and res.duration < 10


@posix_only
def test_nonzero_exit_stderr_and_garbled_output_are_handled(tmp_path):
    exe = make_stub(tmp_path, 'echo "oops: Access is denied" >&2\necho "garbage {"\nexit 2\n')
    res = PowerShellRunner(executable=exe).run("status")
    assert res.returncode == 2 and "Access is denied" in res.stderr and parse_json_output(res.stdout) is None
    kind, _ = classify_failure(res, None)
    assert kind == "permission_denied"


@posix_only
def test_missing_executable_is_a_launch_error(tmp_path):
    res = PowerShellRunner(executable=str(tmp_path / "nope")).run("status")
    assert res.launch_error and res.returncode is None


def test_parse_json_output_tolerates_bom_and_noise_and_rejects_non_objects():
    assert parse_json_output('\ufeff{"a": 1}') == {"a": 1}
    assert parse_json_output('WARNING: something\n{"a": 2}\n') == {"a": 2}
    for bad in ("", "   ", "[1,2]", "null", "not json", None):
        assert parse_json_output(bad) is None


# =============================================================== custom path validation
@pytest.mark.parametrize("good,expected", [
    ("C:\\Users\\Public\\Downloads", "C:\\Users\\Public\\Downloads"),
    ("d:/data//files/", "d:\\data\\files"),
    ("C:\\", "C:\\"),
    ("C:\\Program Files (x86)\\App", "C:\\Program Files (x86)\\App"),
    ("  C:\\Users\\me\\a.exe  ", "C:\\Users\\me\\a.exe"),
    ("C:\\Users\\O'Brien\\R&D;$x(1)", "C:\\Users\\O'Brien\\R&D;$x(1)"),
])
def test_valid_paths_are_accepted_and_normalised(good, expected):
    assert validate_scan_path(good) == expected


@pytest.mark.parametrize("bad", [
    "", "   ", None, 42, "relative\\path", "\\Windows", "C:foo", "C:", "\\\\server\\share\\x", "//server/share", "\\\\?\\C:\\x",
    "\\\\.\\PhysicalDrive0", "C:\\a\\..\\b", "C:\\..\\Windows", "C:\\a\\.\\b", "C:\\*.exe", "C:\\a?b", "C:\\a|b", "C:\\a<b", 'C:\\a"b',
    "C:\\file.txt:stream", "C:\\a\nb", "C:\\a\rb", "C:\\a\x00b", "C:\\a\tb", "C:\\con", "C:\\x\\NUL.txt", "C:\\COM1", "C:\\trailing.", "C:\\trail \\x", "C:\\trail.\\x",
    "C:\\" + "a" * 1100, "http://evil/x", "file:///C:/x", "ftp://x/y", "/etc/passwd", "~/x",
])
def test_invalid_paths_are_rejected(bad):
    with pytest.raises(DefenderInputError):
        validate_scan_path(bad)


def test_start_scan_validates_again_and_never_runs_on_an_invalid_path():
    runner = FakeRunner(scan_custom=out({"ok": True}))
    with pytest.raises(DefenderInputError):
        client(runner).start_scan("custom", "\\\\attacker\\share")
    with pytest.raises(ValueError):
        client(runner).start_scan("; calc", None)
    assert runner.calls == []


def test_custom_path_travels_in_the_environment_and_scan_kind_selects_a_fixed_script():
    runner = FakeRunner(scan_custom=out({"ok": True}), scan_quick=out({"ok": True}), scan_full=out({"ok": True}))
    c = client(runner)
    c.start_scan("custom", "C:/Users/Public")
    c.start_scan("quick")
    c.start_scan("full")
    assert [x[0] for x in runner.calls] == ["scan_custom", "scan_quick", "scan_full"]
    assert runner.calls[0][1] == {"SENTRIX_SCAN_PATH": "C:\\Users\\Public"} and runner.calls[1][1] == {} == runner.calls[2][1]


def test_scan_timeouts_are_bounded_and_configurable(monkeypatch):
    assert wd.scan_timeout_seconds("quick") < wd.scan_timeout_seconds("custom") < wd.scan_timeout_seconds("full")
    monkeypatch.setenv("SENTRIX_DEFENDER_QUICK_TIMEOUT_MINUTES", "30")
    assert wd.scan_timeout_seconds("quick") == 1800
    monkeypatch.setenv("SENTRIX_DEFENDER_QUICK_TIMEOUT_MINUTES", "-5")
    assert wd.scan_timeout_seconds("quick") == 300
    monkeypatch.setenv("SENTRIX_DEFENDER_QUICK_TIMEOUT_MINUTES", "junk")
    assert wd.scan_timeout_seconds("quick") == 7200


# =============================================================== scan command outcomes
def test_scan_command_outcomes():
    ok = client(FakeRunner(scan_quick=out({"ok": True}))).start_scan("quick")
    assert ok.command == "returned" and ok.error_kind is None
    denied = client(FakeRunner(scan_quick=out(err_payload("System.UnauthorizedAccessException", "Access is denied", "x"), rc=2))).start_scan("quick")
    assert denied.command == "failed" and denied.error_kind == "permission_denied" and "Administrators" in denied.message
    timeout = client(FakeRunner(scan_full=RunResult(timed_out=True))).start_scan("full")
    assert timeout.command == "timed_out" and "may still be scanning" in timeout.message
    nostart = client(FakeRunner(scan_quick=RunResult(launch_error="PowerShell could not be started (OSError)."))).start_scan("quick")
    assert nostart.command == "not_started"
    missing = client(FakeRunner(scan_custom=out({"ok": False, "error": {"type": "PathNotFound", "message": "x", "id": "PathNotFound"}}, rc=2))).start_scan("custom", "C:\\nope")
    assert missing.command == "failed" and missing.error_kind == "path_not_found"
    # rc 0 but no/invalid JSON: the command "returning" is not enough to call it successful
    assert client(FakeRunner(scan_quick=RunResult(returncode=0, stdout=""))).start_scan("quick").command == "failed"


# =============================================================== completion evidence
def ev(i, t):
    return {"id": i, "time": iso(t)}


def test_quick_scan_completion_established_from_defenders_own_timestamps():
    c = decide_completion("quick", T0, {"QuickScanStartTime": iso(T0 + timedelta(seconds=1)), "QuickScanEndTime": iso(T0 + timedelta(minutes=9))}, [ev(1001, T0 + timedelta(minutes=9))], "ok")
    assert c.outcome == "completed" and c.established and c.method == "status_timestamps"


def test_stale_end_time_is_not_completion():
    c = decide_completion("quick", T0, {"QuickScanEndTime": iso(T0 - timedelta(days=1))}, [], "none")
    assert c.outcome == "unknown" and not c.established and any("BEFORE this scan started" in e for e in c.evidence)


def test_custom_scan_needs_the_event_log():
    assert decide_completion("custom", T0, {}, [ev(1000, T0), ev(1001, T0 + timedelta(minutes=1))], "ok").outcome == "completed"
    c = decide_completion("custom", T0, {}, [], "none")
    assert c.outcome == "unknown" and c.caveats
    c = decide_completion("custom", T0, {}, [], "unreadable")
    assert c.outcome == "unknown" and any("could not be read" in x for x in c.caveats)


def test_stopped_or_failed_scan_is_incomplete():
    assert decide_completion("full", T0, {}, [ev(1000, T0), ev(1002, T0 + timedelta(minutes=2))], "ok").outcome == "stopped"
    assert decide_completion("quick", T0, {}, [ev(1005, T0 + timedelta(minutes=2))], "ok").outcome == "stopped"


def test_conflicting_evidence_is_never_called_complete():
    c = decide_completion("quick", T0, {"QuickScanEndTime": iso(T0 + timedelta(minutes=5))}, [ev(1002, T0 + timedelta(minutes=1))], "ok")
    assert c.outcome == "unknown" and any("cannot tell which scan" in x for x in c.caveats)
    c = decide_completion("custom", T0, {}, [ev(1001, T0 + timedelta(minutes=5)), ev(1002, T0 + timedelta(minutes=1))], "ok")
    assert c.outcome == "unknown"


def test_events_from_before_the_scan_are_ignored():
    c = decide_completion("custom", T0, {}, [ev(1001, T0 - timedelta(hours=3))], "ok")
    assert c.outcome == "unknown"


def test_verify_completion_uses_the_since_timestamp_and_handles_event_log_states():
    since_seen = {}
    payload = {"ok": True, "status": {"QuickScanEndTime": iso(T0 + timedelta(minutes=5))}, "events": [ev(1001, T0 + timedelta(minutes=5))]}

    def handler(env, timeout):
        since_seen.update(env)
        return out(payload)
    c = client(FakeRunner(verify=handler)).verify_completion("quick", T0)
    assert c.outcome == "completed" and since_seen["SENTRIX_SINCE"].startswith("2026-10-25T12:00:00")
    no_events = {"ok": True, "status": {}, "events_error": {"type": "System.Exception", "message": "No events were found", "id": "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand"}}
    assert client(FakeRunner(verify=out(no_events))).verify_completion("custom", T0).outcome == "unknown"
    denied = {"ok": True, "status": {}, "events_error": {"type": "System.UnauthorizedAccessException", "message": "Attempted to perform an unauthorized operation.", "id": "x"}}
    assert any("could not be read" in x for x in client(FakeRunner(verify=out(denied))).verify_completion("custom", T0).caveats)
    broken = client(FakeRunner(verify=RunResult(timed_out=True))).verify_completion("quick", T0)
    assert broken.outcome == "unknown" and "could not be verified" in broken.caveats[0]


# =============================================================== detections & attribution
def detection(i, tid, when, status=2, resources=None, **kw):
    d = {"DetectionID": f"{{D{i}}}", "ThreatID": tid, "InitialDetectionTime": iso(when), "LastThreatStatusChangeTime": iso(when),
         "ThreatStatusID": status, "CurrentThreatExecutionStatusID": 1, "ActionSuccess": True, "ProcessName": "Unknown", "DomainUser": "PC\\bob",
         "Resources": resources if resources is not None else [f"file:_C:\\Users\\bob\\Downloads\\bad{i}.exe"]}
    d.update(kw)
    return d


THREATS = [{"ThreatID": "2147519003", "ThreatName": "Virus:DOS/EICAR_Test_File", "SeverityID": 5, "CategoryID": 42, "IsActive": False},
           {"ThreatID": "2147735503", "ThreatName": "Trojan:Win32/Wacatac.B!ml", "SeverityID": 4, "CategoryID": 8, "IsActive": True}]


def parse(dets, threats=THREATS, **extra):
    return parse_detections(dict({"ok": True, "detections": dets, "threats": threats, "detection_total": len(dets)}, **extra))


def test_detection_fields_names_severity_status_and_evidence_are_extracted():
    recs, meta = parse([detection(1, "2147519003", T0, status=3, resources=["file:_C:\\x\\eicar.com", "containerfile:_C:\\x\\a.zip->eicar.com"])])
    r = recs[0]
    assert r.threat_name == "Virus:DOS/EICAR_Test_File" and r.defender_severity == "Severe" and r.severity == "CRITICAL"
    assert r.status == "Quarantined" and not r.needs_attention and r.execution_status == "Blocked" and r.action_success is True
    assert [x["type"] for x in r.resources] == ["file", "containerfile"] and r.resources[0]["value"] == "C:\\x\\eicar.com"
    assert r.initial_detection_time == T0 and r.domain_user == "PC\\bob"
    assert r.evidence["DetectionID"] == "{D1}" and r.evidence["ThreatCatalogue"]["ThreatName"].startswith("Virus:DOS")
    assert meta == {"total": 1, "truncated": False, "threat_names_available": True}
    assert "SentriX does not delete, quarantine or restore" in r.remediation()


def test_unresolved_statuses_need_attention_and_unknown_codes_are_kept():
    recs, _ = parse([detection(1, "2147735503", T0, status=1), detection(2, "2147735503", T0, status=102),
                     detection(3, "2147735503", T0, status=5), detection(4, "2147735503", T0, status=999)])
    assert [r.needs_attention for r in recs] == [True, True, True, True]
    assert recs[3].status == "status code 999" and recs[1].status == "QuarantineFailed"
    assert "NOT resolved" in recs[0].remediation() and "never removes" in recs[0].remediation()


def test_unknown_threat_id_and_missing_catalogue_degrade_gracefully():
    recs, meta = parse([detection(1, "999", T0)], threats=[], threats_error={"type": "x", "message": "m"})
    assert recs[0].threat_name is None and recs[0].defender_severity == "Unknown" and recs[0].severity == "Unknown"
    assert meta["threat_names_available"] is False


def test_truncation_and_single_object_payload_shapes():
    recs, meta = parse(detection(1, "2147519003", T0), threats=THREATS[0], detection_total=900)
    assert len(recs) == 1 and meta["truncated"] is True and meta["total"] == 900


def test_zero_detections_is_an_empty_list_not_an_error():
    recs, meta = parse([])
    assert recs == [] and meta["total"] == 0


def test_historical_records_are_separated_from_current_scan_findings():
    start, end = T0, T0 + timedelta(minutes=10)
    old = detection(1, "2147519003", T0 - timedelta(days=30))
    new = detection(2, "2147735503", T0 + timedelta(minutes=4), status=1)
    changed = detection(3, "2147519003", T0 - timedelta(days=2), LastThreatStatusChangeTime=iso(T0 + timedelta(minutes=6)))
    recs, _ = parse([old, new, changed])
    attribute_detections(recs, baseline_ids={"{D1}", "{D3}"}, window_start=start, window_end=end)
    assert [r.attribution for r in recs] == ["historical", "current_scan", "current_scan"]


def test_status_only_has_no_window_so_everything_is_historical():
    recs, _ = parse([detection(1, "2147519003", T0 + timedelta(minutes=4))])
    attribute_detections(recs, baseline_ids=set(), window_start=None, window_end=None)
    assert recs[0].attribution == "historical"


def test_new_record_outside_the_window_is_unattributed_not_claimed():
    recs, _ = parse([detection(1, "2147519003", T0 + timedelta(hours=3))])
    attribute_detections(recs, baseline_ids=set(), window_start=T0, window_end=T0 + timedelta(minutes=10))
    assert recs[0].attribution == "unattributed"


def test_without_a_baseline_attribution_rests_on_time_alone():
    recs, _ = parse([detection(1, "2147519003", T0 - timedelta(days=9)), detection(2, "2147519003", T0 + timedelta(minutes=1))])
    attribute_detections(recs, baseline_ids=None, window_start=T0, window_end=T0 + timedelta(minutes=10))
    assert [r.attribution for r in recs] == ["historical", "current_scan"]


def test_custom_scan_detection_outside_the_scanned_path_is_unattributed():
    inside = detection(1, "2147519003", T0 + timedelta(minutes=1), resources=["file:_C:\\Users\\bob\\Downloads\\a.exe"])
    outside = detection(2, "2147519003", T0 + timedelta(minutes=2), resources=["file:_D:\\other\\b.exe"])
    nonfile = detection(3, "2147519003", T0 + timedelta(minutes=2), resources=["process:_pid:4,ProcessStart:1"])
    sibling = detection(4, "2147519003", T0 + timedelta(minutes=2), resources=["file:_C:\\Users\\bob\\Downloads2\\c.exe"])
    recs, _ = parse([inside, outside, nonfile, sibling])
    attribute_detections(recs, set(), T0, T0 + timedelta(minutes=10), scan_path="c:\\users\\BOB\\downloads")
    assert [(r.in_scan_scope, r.attribution) for r in recs] == [
        (True, "current_scan"), (False, "unattributed"), (None, "current_scan"), (False, "unattributed")]


def test_timestamp_parsing_handles_dotnet_seven_digit_fractions():
    assert wd.parse_timestamp("2026-10-25T12:00:00.1234567Z") == T0.replace(microsecond=123456)
    assert wd.parse_timestamp("2026-10-25T14:00:00.0000000+02:00") == T0
    for bad in (None, "", "yesterday", 5):
        assert wd.parse_timestamp(bad) is None


def test_get_detections_failure_is_reported_not_swallowed():
    recs, meta, err = client(FakeRunner(detections=out(err_payload("System.UnauthorizedAccessException", "Access is denied", "x"), rc=2))).get_detections()
    assert recs == [] and err["kind"] == "permission_denied" and "Administrators" in err["message"]
    recs, meta, err = client(FakeRunner(detections=out({"ok": True, "detections": [detection(1, "2147519003", T0)], "threats": THREATS, "detection_total": 1}))).get_detections()
    assert len(recs) == 1 and err is None


def test_this_module_never_uses_shell_true_or_other_process_apis():
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(wd))
    dangerous = {("os", "system"), ("os", "popen"), ("subprocess", "Popen"), ("subprocess", "call"),
                 ("subprocess", "check_output"), ("subprocess", "check_call"), ("os", "execv"), ("os", "spawnl")}
    runs = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            assert isinstance(node.value, ast.Constant) and node.value.value is False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            assert (node.func.value.id, node.func.attr) not in dangerous
            runs += (node.func.value.id, node.func.attr) == ("subprocess", "run")
    assert runs == 1                                   # exactly one place in the module starts a process
