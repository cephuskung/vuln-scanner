"""Microsoft Defender Antivirus integration (Windows, local computer only).

SentriX does not implement an antivirus engine. It drives the one that Windows
already has, through Defender's documented PowerShell cmdlets:

  Get-MpComputerStatus   protection / service / signature / scan status
  Start-MpScan           Quick, Full and Custom (file or folder) scans
  Get-MpThreatDetection  threat detection records
  Get-MpThreat           threat names and severities for those records

Scope: the computer running the SentriX server process. Remote Windows endpoints
are NOT supported - that needs a separately designed, authenticated agent.

SAFE EXECUTION - the rules this module enforces
  * Only the fixed scripts in SCRIPTS can run, selected by id. There is no way to
    pass script text, a cmdlet name or a parameter name in from outside.
  * The ONLY dynamic inputs are two values - the custom scan path and a UTC
    timestamp - and they travel in environment variables (ALLOWED_ENV) that the
    fixed script reads as data ($env:SENTRIX_SCAN_PATH). They are never
    concatenated into command text, so quotes, ``;``, ``$( )`` or backticks in a
    path cannot become code. The path is also validated (validate_scan_path).
  * subprocess is called with an argument LIST and shell=False, stdin closed, a
    timeout, and a minimal environment (no database password / secret key is
    passed to the child process).
  * PowerShell is started by absolute path from %SystemRoot%, not from PATH.
  * No script deletes, quarantines, remediates or executes anything, changes any
    Defender setting, adds exclusions, or tries to elevate privileges.

HONEST RESULTS
  * "Start-MpScan returned" is not "the scan finished": completion is verified
    separately (Defender's own scan timestamps and its Operational event log)
    and, if it cannot be established, the result says so.
  * Defender does not say which scan produced a detection record, so records are
    attributed to the current scan only by time window / pre-scan baseline, and
    labelled as such. Historical records are kept separate.
"""
from __future__ import annotations

import json
import logging
import ntpath
import os
import platform
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fixed, reviewed PowerShell operations
# ---------------------------------------------------------------------------
# Each script is a list of complete statements joined with '; '. Rules (checked by tests):
# no double quotes, no backticks, no string interpolation of anything supplied by Python.
_PRELUDE = [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8",
    "function Conv($v){ if($v -is [datetime]){ return $v.ToUniversalTime().ToString('o') }; return $v }",
    "function Err($e){ return [ordered]@{ type=$e.Exception.GetType().FullName; message=[string]$e.Exception.Message; id=[string]$e.FullyQualifiedErrorId } }",
    "$r=[ordered]@{ ok=$false }",
]

STATUS_PROPERTIES = (
    "AMServiceEnabled", "AMRunningMode", "AMEngineVersion", "AMProductVersion", "AMServiceVersion",
    "AntivirusEnabled", "AntispywareEnabled", "RealTimeProtectionEnabled", "OnAccessProtectionEnabled",
    "IoavProtectionEnabled", "BehaviorMonitorEnabled", "NISEnabled", "IsTamperProtected",
    "AntivirusSignatureVersion", "AntivirusSignatureLastUpdated", "AntivirusSignatureAge",
    "AntispywareSignatureVersion", "AntispywareSignatureLastUpdated", "DefenderSignaturesOutOfDate",
    "QuickScanStartTime", "QuickScanEndTime", "QuickScanAge", "FullScanStartTime", "FullScanEndTime", "FullScanAge",
    "ComputerState",
)
DETECTION_PROPERTIES = (
    "DetectionID", "ThreatID", "ProcessName", "DomainUser", "InitialDetectionTime", "LastThreatStatusChangeTime",
    "RemediationTime", "ActionSuccess", "AMProductVersion", "CleaningActionID", "CurrentThreatExecutionStatusID",
    "DetectionSourceTypeID", "ThreatStatusErrorCode", "ThreatStatusID", "AdditionalActionsBitMask",
)
MAX_DETECTIONS = 500
EVENT_IDS = "1000,1001,1002,1005"       # Defender Operational log: scan started / finished / stopped / failed


def _q(names):
    return "@(" + ",".join(f"'{n}'" for n in names) + ")"


def _script(*statements):
    return "; ".join(list(_PRELUDE) + list(statements))


def _scan_script(start_mp_scan):
    return _script(
        "$r.started=(Get-Date).ToUniversalTime().ToString('o')",
        "try { " + start_mp_scan + "; $r.ok=$true } catch { $r.error=Err $_ }",
        "$r.finished=(Get-Date).ToUniversalTime().ToString('o')",
        "$r | ConvertTo-Json -Depth 4 -Compress",
        "if(-not $r.ok){ exit 2 }",
    )


SCRIPTS = {
    # Protection status + any other registered antivirus product (Windows Security Center, client SKUs).
    "status": _script(
        "try { $s=Get-MpComputerStatus; $f=[ordered]@{}; foreach($n in " + _q(STATUS_PROPERTIES) + "){ $f[$n]=Conv($s.$n) }; $r.status=$f; $r.ok=$true } catch { $r.error=Err $_ }",
        "try { $r.registered_av=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { [string]$_.displayName }) } catch { $r.registered_av_error=[string]$_.Exception.GetType().FullName }",
        "$r | ConvertTo-Json -Depth 5 -Compress",
        "if(-not $r.ok){ exit 2 }",
    ),
    # Detection records (newest first, bounded) + the threat catalogue entries they refer to.
    "detections": _script(
        "try { $all=@(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending); $r.detection_total=$all.Count; "
        "$r.detections=@(foreach($d in ($all | Select-Object -First " + str(MAX_DETECTIONS) + ")){ $o=[ordered]@{}; "
        "foreach($n in " + _q(DETECTION_PROPERTIES) + "){ $o[$n]=Conv($d.$n) }; $o['Resources']=@($d.Resources | ForEach-Object { [string]$_ }); $o }); $r.ok=$true } catch { $r.error=Err $_ }",
        "try { $r.threats=@(foreach($t in @(Get-MpThreat)){ [ordered]@{ ThreatID=[string]$t.ThreatID; ThreatName=[string]$t.ThreatName; SeverityID=$t.SeverityID; CategoryID=$t.CategoryID; IsActive=$t.IsActive } }) } catch { $r.threats_error=Err $_ }",
        "$r | ConvertTo-Json -Depth 6 -Compress",
        "if(-not $r.ok){ exit 2 }",
    ),
    # Scans. Start-MpScan blocks until Defender finishes (or fails) - that is why it runs in the background job.
    "scan_quick": _scan_script("Start-MpScan -ScanType QuickScan"),
    "scan_full": _scan_script("Start-MpScan -ScanType FullScan"),
    # The path is data: read from the environment, checked, then bound to -ScanPath as a single string.
    "scan_custom": _script(
        "$r.started=(Get-Date).ToUniversalTime().ToString('o')",
        "try { $p=$env:SENTRIX_SCAN_PATH; if([string]::IsNullOrWhiteSpace($p)){ throw 'no scan path supplied' }; "
        "if(-not (Test-Path -LiteralPath $p)){ $r.error=[ordered]@{ type='PathNotFound'; message='The path does not exist or is not visible to the account running SentriX.'; id='PathNotFound' } } "
        "else { Start-MpScan -ScanType CustomScan -ScanPath $p; $r.ok=$true } } catch { $r.error=Err $_ }",
        "$r.finished=(Get-Date).ToUniversalTime().ToString('o')",
        "$r | ConvertTo-Json -Depth 4 -Compress",
        "if(-not $r.ok){ exit 2 }",
    ),
    # Completion evidence: Defender's own scan timestamps + its Operational log since a given UTC instant.
    "verify": _script(
        "try { $s=Get-MpComputerStatus; $f=[ordered]@{}; foreach($n in "
        + _q(("QuickScanStartTime", "QuickScanEndTime", "FullScanStartTime", "FullScanEndTime", "AntivirusSignatureVersion"))
        + "){ $f[$n]=Conv($s.$n) }; $r.status=$f; $r.ok=$true } catch { $r.error=Err $_ }",
        "try { $since=[datetime]::Parse($env:SENTRIX_SINCE,[System.Globalization.CultureInfo]::InvariantCulture,[System.Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime(); "
        "$r.events=@(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Windows Defender/Operational'; Id=" + EVENT_IDS + "; StartTime=$since } | Sort-Object TimeCreated | "
        "ForEach-Object { [ordered]@{ id=$_.Id; time=Conv($_.TimeCreated) } }) } catch { $r.events_error=Err $_ }",
        "$r | ConvertTo-Json -Depth 5 -Compress",
        "if(-not $r.ok){ exit 2 }",
    ),
}

# The only environment variables a caller may add for the child process.
ALLOWED_ENV = ("SENTRIX_SCAN_PATH", "SENTRIX_SINCE")
# Only these parent variables reach PowerShell - never DB_PASSWORD, SECRET_KEY or anything else.
_INHERITED_ENV = (
    "SystemRoot", "SYSTEMROOT", "SystemDrive", "windir", "PATH", "PATHEXT", "TEMP", "TMP", "ComSpec", "OS",
    "USERPROFILE", "APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
    "ALLUSERSPROFILE", "COMPUTERNAME", "USERNAME", "USERDOMAIN", "PSModulePath", "HOMEDRIVE", "HOMEPATH",
    "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "LANG", "LC_ALL", "HOME",
)
POWERSHELL_FLAGS = ("-NoProfile", "-NonInteractive", "-NoLogo", "-Command")
MAX_OUTPUT_BYTES = 8 * 1024 * 1024

STATUS_TIMEOUT = 60
DETECTIONS_TIMEOUT = 120
VERIFY_TIMEOUT = 120

SCAN_KINDS = ("quick", "full", "custom")
EXPECTED_DURATION = {
    "quick": "A Quick Scan typically takes a few minutes to around half an hour, depending on the computer.",
    "full": "A Full Scan examines every file and typically takes from one to several hours; it uses noticeable disk and CPU while it runs.",
    "custom": "A Custom Scan's duration depends on the size of the file or folder: seconds for a file, much longer for a large folder or a whole drive.",
}


class DefenderInputError(ValueError):
    """Invalid request input; str(exc) is a user-facing message."""


# ---------------------------------------------------------------------------
# Custom scan path validation
# ---------------------------------------------------------------------------
_RESERVED_NAMES = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
MAX_PATH_LENGTH = 1024


def validate_scan_path(raw):
    """A local, absolute Windows file/folder path, normalised - or DefenderInputError.

    Accepted: ``C:\\Users\\me\\Downloads``, ``D:/data/file.exe``.
    Rejected: UNC/network and device paths (scanning ``\\\\host\\share`` would make this server
    authenticate to that host), drive-relative and relative paths, ``..`` segments, wildcard and
    stream (``:``) syntax, control characters, reserved device names, trailing dot/space segments.
    Characters such as ``'`` ``&`` ``;`` ``$`` ``(`` are legal in Windows names and ARE accepted -
    they are safe because the path only ever reaches PowerShell as data (see module docstring)."""
    if not isinstance(raw, str):
        raise DefenderInputError("Enter the file or folder to scan.")
    path = raw.strip()
    if not path:
        raise DefenderInputError("Enter the file or folder to scan.")
    if len(path) > MAX_PATH_LENGTH:
        raise DefenderInputError(f"The path is too long (maximum {MAX_PATH_LENGTH} characters).")
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise DefenderInputError("The path contains control characters.")
    if path.startswith(("\\\\", "//")):
        raise DefenderInputError("Network (UNC) and device paths are not supported. Use a local path such as C:\\Users\\Public.")
    drive, rest = ntpath.splitdrive(path)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not rest.startswith(("\\", "/")):
        raise DefenderInputError("Enter an absolute local path that starts with a drive letter, e.g. C:\\Users\\Public\\Downloads.")
    if re.search(r'[<>"|?*]', path):
        raise DefenderInputError('The path contains characters that Windows does not allow in paths (< > " | ? *). '
                                 "Wildcards are not supported - enter one file or folder.")
    if ":" in path[2:]:
        raise DefenderInputError("Alternate data stream or extra ':' syntax is not supported.")
    for segment in (s for s in re.split(r"[\\/]+", rest) if s):
        if segment in (".", ".."):
            raise DefenderInputError("Relative path components ('.' and '..') are not allowed.")
        if segment != segment.rstrip(" ."):
            raise DefenderInputError("A path segment ends with a space or a dot, which Windows silently rewrites; remove it.")
        if segment.split(".")[0].lower() in _RESERVED_NAMES:
            raise DefenderInputError(f"'{segment}' is a reserved Windows device name.")
    return ntpath.normpath(path)


# ---------------------------------------------------------------------------
# Controlled subprocess interface
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    launch_error: str | None = None
    duration: float = 0.0


def resolve_powershell(system=None):
    """Absolute path to Windows PowerShell 5.1, or None (never searched on non-Windows hosts)."""
    if (system or platform.system()) != "Windows":
        return None
    root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT") or r"C:\Windows"
    candidate = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return candidate if os.path.isfile(candidate) else None


def _child_environment(extra):
    env, seen = {}, set()
    for k in _INHERITED_ENV:
        if k in os.environ and k.casefold() not in seen:           # Windows env names are case-insensitive
            seen.add(k.casefold())
            env[k] = os.environ[k]
    for key, value in (extra or {}).items():
        if key not in ALLOWED_ENV:
            raise ValueError(f"environment variable {key!r} is not permitted")
        if not isinstance(value, str) or "\x00" in value or len(value) > MAX_PATH_LENGTH + 64:
            raise ValueError(f"invalid value for {key}")
        env[key] = value
    return env


class PowerShellRunner:
    """Runs one of the fixed SCRIPTS and returns its output. Nothing else."""

    def __init__(self, executable=None, platform_system=None):
        self._executable = executable
        self._system = platform_system

    def run(self, script_id, env_extra=None, timeout=STATUS_TIMEOUT):
        if script_id not in SCRIPTS:
            raise ValueError(f"unknown script id {script_id!r}: only fixed, reviewed operations can run")
        exe = self._executable or resolve_powershell(self._system)
        if not exe:
            return RunResult(launch_error="Windows PowerShell (powershell.exe) was not found; the Defender integration "
                                          "only works on Windows.")
        argv = [exe, *POWERSHELL_FLAGS, SCRIPTS[script_id]]
        env = _child_environment(env_extra)
        started = time.monotonic()
        logger.info("Running Defender operation %s (timeout %ss)", script_id, timeout)      # never logs env values
        try:
            proc = subprocess.run(
                argv, shell=False, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as e:
            return RunResult(timed_out=True, stdout=_decode(e.stdout), stderr=_decode(e.stderr),
                             duration=time.monotonic() - started)
        except OSError as e:
            return RunResult(launch_error=f"PowerShell could not be started ({e.__class__.__name__}).",
                             duration=time.monotonic() - started)
        return RunResult(returncode=proc.returncode, stdout=_decode(proc.stdout), stderr=_decode(proc.stderr),
                         duration=time.monotonic() - started)


def _decode(data):
    if not data:
        return ""
    if isinstance(data, str):
        return data[:MAX_OUTPUT_BYTES]
    return data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace").lstrip("\ufeff")


def parse_json_output(text):
    """The JSON object a fixed script printed, or None. Tolerates a BOM and stray lines around it."""
    text = (text or "").strip().lstrip("\ufeff")
    if not text:
        return None
    candidates = [text] + [ln.strip() for ln in reversed(text.splitlines()) if ln.strip().startswith("{")]
    for c in candidates:
        try:
            obj = json.loads(c)
        except ValueError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


# ---------------------------------------------------------------------------
# Failure classification
# ---------------------------------------------------------------------------
KIND_PERMISSION = "permission_denied"
KIND_UNAVAILABLE = "unavailable"          # PowerShell / Defender cmdlets not present
KIND_SERVICE = "service_unavailable"      # Defender service not running / disabled
KIND_TIMEOUT = "timeout"
KIND_PATH = "path_not_found"
KIND_UNPARSEABLE = "unparseable"
KIND_FAILED = "command_failed"

_PATTERNS = [
    (KIND_PATH, ("pathnotfound",)),
    (KIND_PERMISSION, ("access is denied", "0x80070005", "unauthorizedaccess", "requires elevation", "run as administrator",
                       "administrator privileges", "insufficient privileges", "permission denied", "not have permission")),
    (KIND_SERVICE, ("0x800106ba", "0x80070422", "service has not been started", "service is not running",
                    "service cannot be started", "antimalware service is not")),
    (KIND_UNAVAILABLE, ("commandnotfoundexception", "is not recognized as the name of a cmdlet", "module could not be loaded",
                        "no such file or directory", "namespace root", "invalid namespace")),
]

_EXPLANATIONS = {
    KIND_PERMISSION: "Windows denied the request. Reading Defender's status and running scans need the SentriX server "
                     "to run as a member of the local Administrators group (SentriX never tries to elevate itself). "
                     "Restart SentriX from an elevated PowerShell/Command Prompt (Run as administrator) or as an "
                     "administrator account/service.",
    KIND_UNAVAILABLE: "Microsoft Defender's PowerShell module is not available on this computer, so protection cannot "
                      "be checked or scanned from SentriX.",
    KIND_SERVICE: "The Microsoft Defender Antivirus service is not running or is disabled (by policy, or because another "
                  "antivirus product is the active provider).",
    KIND_TIMEOUT: "The operation did not finish within SentriX's time limit.",
    KIND_PATH: "The path does not exist or is not visible to the account running SentriX.",
    KIND_UNPARSEABLE: "PowerShell produced output SentriX could not interpret, so the result cannot be relied on.",
    KIND_FAILED: "The PowerShell command failed.",
}


def classify_failure(run, payload=None):
    """(kind, user-facing message) for a failed/timed-out run or an error reported in the payload."""
    if run is not None and run.timed_out:
        return KIND_TIMEOUT, _EXPLANATIONS[KIND_TIMEOUT]
    if run is not None and run.launch_error:
        return KIND_UNAVAILABLE, run.launch_error
    err = (payload or {}).get("error") or {}
    haystack = " ".join(str(x) for x in (err.get("type"), err.get("message"), err.get("id"),
                                         getattr(run, "stderr", ""))).lower()
    for kind, needles in _PATTERNS:
        if any(n in haystack for n in needles):
            return kind, _EXPLANATIONS[kind]
    if payload is None and run is not None and run.returncode == 0:
        return KIND_UNPARSEABLE, _EXPLANATIONS[KIND_UNPARSEABLE]
    return KIND_FAILED, _EXPLANATIONS[KIND_FAILED]


def safe_detail(run, payload=None, limit=300):
    """A short, single-line technical detail for logs/UI (no environment, no script text)."""
    err = (payload or {}).get("error") or {}
    text = err.get("message") or (run.stderr if run else "") or ""
    return re.sub(r"\s+", " ", str(text)).strip()[:limit]


# ---------------------------------------------------------------------------
# Protection status
# ---------------------------------------------------------------------------
STATE_ACTIVE = "active"
STATE_PASSIVE = "passive"
STATE_DISABLED = "disabled"
STATE_UNAVAILABLE = "unavailable"
STATE_INACCESSIBLE = "inaccessible"
SCANNABLE_STATES = (STATE_ACTIVE, STATE_PASSIVE)

SIGNATURE_STALE_DAYS = 7


@dataclass
class ProtectionStatus:
    state: str
    summary: str
    fields: dict = field(default_factory=dict)
    registered_av: list = field(default_factory=list)
    error_kind: str | None = None
    detail: str | None = None
    checked_at: str = ""

    def to_dict(self):
        return dict(self.__dict__)


def _bool(v):
    return v if isinstance(v, bool) else None


def _num(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def classify_protection(fields, registered_av=()):
    """(state, summary) from Get-MpComputerStatus fields."""
    mode = str(fields.get("AMRunningMode") or "")
    service, av = _bool(fields.get("AMServiceEnabled")), _bool(fields.get("AntivirusEnabled"))
    others = [a for a in registered_av if a and "defender" not in a.lower()]
    other_txt = f" Other registered antivirus product(s): {', '.join(others)}." if others else ""
    low = mode.lower()
    if "passive" in low or "edr block" in low:
        return STATE_PASSIVE, (f"Microsoft Defender is running in '{mode}' mode: it is NOT the active real-time antivirus "
                               f"on this computer.{other_txt} On-demand scans can still be run, but real-time protection "
                               "is provided by something else.")
    if service is False or av is False:
        return STATE_DISABLED, ("Microsoft Defender Antivirus is turned off "
                                f"(service enabled: {service}, antivirus enabled: {av}).{other_txt}")
    if service is None and av is None:
        return STATE_INACCESSIBLE, "Defender returned no usable protection fields, so its state cannot be established."
    return STATE_ACTIVE, "Microsoft Defender Antivirus is the active antivirus provider."


def protection_checks(status):
    """Defender protection state as System Scan check rows (same shape/vocabulary as the Linux checks:
    pass | fail | unknown | info). Anything that could not be read is 'unknown', never 'pass'."""
    def row(check_id, title, state, evidence, severity=None, remediation=None, requires=None):
        return {"check_id": check_id, "category": "antimalware", "title": title, "status": state, "severity": severity,
                "evidence": evidence, "remediation": remediation, "requires": requires}

    if status.state in (STATE_UNAVAILABLE, STATE_INACCESSIBLE):
        needs = "administrator" if status.error_kind == KIND_PERMISSION else None
        return [row("windows.defender.available", "Microsoft Defender protection status could be read", "unknown",
                    status.summary + (f" ({status.detail})" if status.detail else ""), requires=needs)]
    f = status.fields
    rows = []
    rem_on = "Open Windows Security > Virus & threat protection > Manage settings and turn the protection on (or use your organisation's endpoint management)."

    if status.state == STATE_DISABLED:
        rows.append(row("windows.defender.service", "Microsoft Defender Antivirus is enabled", "fail", status.summary,
                        severity="HIGH", remediation="Enable Microsoft Defender Antivirus, or confirm another endpoint "
                                                     "protection product is active and healthy."))
    elif status.state == STATE_PASSIVE:
        rows.append(row("windows.defender.running_mode", "Microsoft Defender is the active antivirus", "info", status.summary))
    else:
        rows.append(row("windows.defender.service", "Microsoft Defender Antivirus is enabled and active", "pass",
                        f"AMServiceEnabled={f.get('AMServiceEnabled')}, AntivirusEnabled={f.get('AntivirusEnabled')}, "
                        f"AMRunningMode={f.get('AMRunningMode') or 'not reported'}"))

    for key, check_id, title, sev in (
        ("RealTimeProtectionEnabled", "windows.defender.realtime", "Real-time protection is on", "HIGH"),
        ("BehaviorMonitorEnabled", "windows.defender.behavior_monitor", "Behaviour monitoring is on", "MEDIUM"),
        ("OnAccessProtectionEnabled", "windows.defender.on_access", "On-access file scanning is on", "MEDIUM"),
        ("IoavProtectionEnabled", "windows.defender.ioav", "Downloaded-file and attachment scanning is on", "MEDIUM"),
    ):
        value = _bool(f.get(key))
        if status.state == STATE_PASSIVE:
            rows.append(row(check_id, title, "info", f"{key}={value} (Defender is passive; another product provides real-time protection)"))
        elif value is True:
            rows.append(row(check_id, title, "pass", f"{key}=True"))
        elif value is False:
            rows.append(row(check_id, title, "fail", f"{key}=False", severity=sev, remediation=rem_on))
        else:
            rows.append(row(check_id, title, "unknown", f"{key} was not reported by Defender", requires=None))

    version = f.get("AntivirusSignatureVersion")
    updated, age = f.get("AntivirusSignatureLastUpdated"), _num(f.get("AntivirusSignatureAge"))
    out_of_date = _bool(f.get("DefenderSignaturesOutOfDate"))
    sig_evidence = f"security intelligence {version or 'version not reported'}, last updated {updated or 'unknown'}" + \
                   (f" ({int(age)} day(s) ago)" if age is not None else "")
    if age is None and out_of_date is None:
        rows.append(row("windows.defender.signatures", "Security intelligence (signatures) is current", "unknown", sig_evidence))
    elif out_of_date or (age is not None and age >= SIGNATURE_STALE_DAYS):
        rows.append(row("windows.defender.signatures", "Security intelligence (signatures) is current", "fail", sig_evidence,
                        severity="MEDIUM", remediation="Update Defender security intelligence (Windows Update, or Windows "
                                                       "Security > Virus & threat protection > Protection updates)."))
    else:
        rows.append(row("windows.defender.signatures", "Security intelligence (signatures) is current", "pass", sig_evidence))

    tamper = _bool(f.get("IsTamperProtected"))
    rows.append(row("windows.defender.tamper_protection", "Tamper protection", "info" if tamper is not None else "unknown",
                    f"IsTamperProtected={tamper}" if tamper is not None else "not reported by Defender"))
    for kind, label in (("Quick", "quick"), ("Full", "full")):
        end, scan_age = f.get(f"{kind}ScanEndTime"), _num(f.get(f"{kind}ScanAge"))
        rows.append(row(f"windows.defender.last_{label}_scan", f"Last {kind} Scan", "info" if end else "unknown",
                        f"last finished {end} ({int(scan_age)} day(s) ago)" if end and scan_age is not None else
                        (f"last finished {end}" if end else f"no {kind} Scan time reported (never run, or not readable)")))
    return rows


# ---------------------------------------------------------------------------
# Threat detections
# ---------------------------------------------------------------------------
SEVERITY_LABELS = {0: "Unknown", 1: "Low", 2: "Moderate", 4: "High", 5: "Severe"}
SEVERITY_TO_SENTRIX = {"Severe": "CRITICAL", "High": "HIGH", "Moderate": "MEDIUM", "Low": "LOW", "Unknown": "Unknown"}
THREAT_STATUS = {0: "Unknown", 1: "Detected", 2: "Cleaned", 3: "Quarantined", 4: "Removed", 5: "Allowed", 6: "Blocked",
                 102: "QuarantineFailed", 103: "RemoveFailed", 104: "AllowFailed", 105: "Abandoned", 107: "BlockedFailed"}
RESOLVED_STATUSES = {"Cleaned", "Quarantined", "Removed", "Blocked"}
EXECUTION_STATUS = {0: "Unknown", 1: "Blocked", 2: "Allowed", 3: "Executing", 4: "NotExecuting"}

ATTR_CURRENT, ATTR_HISTORICAL, ATTR_UNATTRIBUTED = "current_scan", "historical", "unattributed"


def parse_timestamp(value):
    """tz-aware UTC datetime from a PowerShell round-trip ('o') timestamp, or None."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)          # .NET writes 7 fractional digits
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_resource(text):
    """Defender resource strings look like 'file:_C:\\x\\a.exe' or 'process:_pid:12,ProcessStart:...'."""
    text = str(text or "")
    m = re.match(r"^([A-Za-z]+):_(.*)$", text, re.DOTALL)
    return {"type": m.group(1).lower(), "value": m.group(2)} if m else {"type": "unknown", "value": text}


def _file_like_paths(resources):
    out = []
    for r in resources:
        if r["type"] in ("file", "containerfile"):
            out.append(r["value"].split("->", 1)[0])
    return out


def path_in_scope(resources, scan_path):
    """True/False when at least one resource is a file path; None when none is (cannot tell)."""
    paths = _file_like_paths(resources)
    if not paths or not scan_path:
        return None
    base = ntpath.normcase(ntpath.normpath(scan_path)).rstrip("\\")
    for p in paths:
        norm = ntpath.normcase(ntpath.normpath(p))
        if norm == base or norm.startswith(base + "\\"):
            return True
    return False


@dataclass
class ThreatRecord:
    detection_id: str | None
    threat_id: str | None
    threat_name: str | None
    defender_severity: str
    status: str
    execution_status: str | None
    action_success: bool | None
    resources: list
    process_name: str | None
    domain_user: str | None
    initial_detection_time: datetime | None
    last_status_change: datetime | None
    evidence: dict
    attribution: str = ATTR_HISTORICAL
    in_scan_scope: bool | None = None

    @property
    def severity(self):
        return SEVERITY_TO_SENTRIX.get(self.defender_severity, "Unknown")

    @property
    def needs_attention(self):
        return self.status not in RESOLVED_STATUSES

    def remediation(self):
        if self.status in RESOLVED_STATUSES:
            return ("Defender recorded this threat as handled. SentriX does not delete, quarantine or restore files; "
                    "review the entry in Windows Security > Virus & threat protection > Protection history.")
        return ("Defender has NOT resolved this threat (status: " + self.status + "). Open Windows Security > Virus & "
                "threat protection > Protection history to review it and choose an action; SentriX never removes, "
                "quarantines or executes files itself. If the file is unexpected, treat the computer as potentially "
                "compromised and follow your incident-response process.")

    def to_row(self):
        return {
            "detection_id": self.detection_id, "threat_id": self.threat_id, "threat_name": self.threat_name,
            "severity": self.severity, "defender_severity": self.defender_severity, "resources": self.resources,
            "process_name": self.process_name, "domain_user": self.domain_user,
            "initial_detection_time": self.initial_detection_time, "last_status_change": self.last_status_change,
            "status": self.status, "action_success": self.action_success, "execution_status": self.execution_status,
            "attribution": self.attribution, "in_scan_scope": self.in_scan_scope, "needs_attention": self.needs_attention,
            "evidence": self.evidence, "remediation": self.remediation(),
        }


def parse_detections(payload):
    """(records, meta) from the 'detections' script payload. Never raises on odd shapes."""
    def as_list(v):
        return v if isinstance(v, list) else ([] if v in (None, "") else [v])
    threats = {}
    for t in as_list(payload.get("threats")):
        if isinstance(t, dict) and t.get("ThreatID") is not None:
            threats[str(t["ThreatID"])] = t
    records = []
    for d in as_list(payload.get("detections")):
        if not isinstance(d, dict):
            continue
        tid = None if d.get("ThreatID") is None else str(d["ThreatID"])
        threat = threats.get(tid, {})
        sev = SEVERITY_LABELS.get(threat.get("SeverityID"), "Unknown")
        sid = d.get("ThreatStatusID")
        status = THREAT_STATUS.get(sid, f"status code {sid}" if sid is not None else "Unknown")
        resources = [parse_resource(r) for r in as_list(d.get("Resources"))]
        evidence = {k: d.get(k) for k in DETECTION_PROPERTIES if d.get(k) is not None}
        evidence["Resources"] = [str(r) for r in as_list(d.get("Resources"))]
        if threat:
            evidence["ThreatCatalogue"] = {k: threat.get(k) for k in ("ThreatName", "SeverityID", "CategoryID", "IsActive")}
        records.append(ThreatRecord(
            detection_id=None if d.get("DetectionID") is None else str(d["DetectionID"]),
            threat_id=tid, threat_name=(threat.get("ThreatName") or None) if threat else None,
            defender_severity=sev, status=status, execution_status=EXECUTION_STATUS.get(d.get("CurrentThreatExecutionStatusID")),
            action_success=_bool(d.get("ActionSuccess")), resources=resources,
            process_name=d.get("ProcessName") or None, domain_user=d.get("DomainUser") or None,
            initial_detection_time=parse_timestamp(d.get("InitialDetectionTime")),
            last_status_change=parse_timestamp(d.get("LastThreatStatusChangeTime")), evidence=evidence,
        ))
    total = payload.get("detection_total")
    meta = {"total": total if isinstance(total, int) else len(records),
            "truncated": isinstance(total, int) and total > len(records),
            "threat_names_available": "threats_error" not in payload}
    return records, meta


def attribute_detections(records, baseline_ids, window_start, window_end, scan_path=None):
    """Label each record current_scan / historical / unattributed IN PLACE.

    Defender's records do not identify the scan that produced them, so this is evidence-based, not proof:
      historical   already present before the scan (in the baseline) and not changed during the scan window
      current_scan new since the baseline (or changed) AND its detection/status-change time lies in the window
      unattributed in the window but outside a custom scan's path (likely a real-time detection), or the
                   baseline/window could not be established
    window_start / window_end: tz-aware datetimes; None means 'no scan window' (status-only: all historical)."""
    for r in records:
        if scan_path:
            r.in_scan_scope = path_in_scope(r.resources, scan_path)
        if window_start is None:
            r.attribution = ATTR_HISTORICAL
            continue
        times = [t for t in (r.initial_detection_time, r.last_status_change) if t]
        in_window = any(window_start <= t <= window_end for t in times)
        is_new = None if baseline_ids is None else (r.detection_id not in baseline_ids)
        if not in_window:
            # new since the baseline but outside the window: cannot be tied to this scan
            r.attribution = ATTR_UNATTRIBUTED if is_new else ATTR_HISTORICAL
        elif r.in_scan_scope is False:
            r.attribution = ATTR_UNATTRIBUTED          # in the window but outside the scanned path: likely real-time protection
        else:
            r.attribution = ATTR_CURRENT
    return records


# ---------------------------------------------------------------------------
# Scan completion evidence
# ---------------------------------------------------------------------------
COMPLETED, STOPPED, UNKNOWN = "completed", "stopped", "unknown"


@dataclass
class Completion:
    outcome: str                                  # COMPLETED | STOPPED | UNKNOWN
    method: str | None = None                     # status_timestamps | event_log
    evidence: list = field(default_factory=list)
    caveats: list = field(default_factory=list)

    @property
    def established(self):
        return self.outcome == COMPLETED

    def to_dict(self):
        return {"outcome": self.outcome, "established": self.established, "method": self.method,
                "evidence": self.evidence, "caveats": self.caveats}


def decide_completion(kind, since, status_fields, events, events_state):
    """Did the scan that started at ``since`` (UTC) really finish?

    status_fields: the 'verify' payload's Get-MpComputerStatus subset (or {}).
    events: [{'id','time'}] from Defender's Operational log since ``since``.
    events_state: 'ok' | 'none' (log readable, no matching events) | 'unreadable'.

    Quick/Full: the scan-end timestamp Defender keeps must be at/after the scan start.
    Custom scans have no such timestamp, so only the event log can show completion.
    Event log entries are matched by time window, not by scan id - stated in the caveats."""
    c = Completion(outcome=UNKNOWN)
    skew = timedelta(seconds=2)
    parsed = [(e.get("id"), parse_timestamp(e.get("time"))) for e in (events or []) if isinstance(e, dict)]
    parsed = [(i, t) for i, t in parsed if t and t >= since - skew]
    stopped = [t for i, t in parsed if i in (1002, 1005)]
    finished = [t for i, t in parsed if i == 1001]

    ts_ok = False
    if kind in ("quick", "full"):
        label = "Quick" if kind == "quick" else "Full"
        end = parse_timestamp((status_fields or {}).get(f"{label}ScanEndTime"))
        start = parse_timestamp((status_fields or {}).get(f"{label}ScanStartTime"))
        if end and end >= since - skew and (start is None or start >= since - skew):
            ts_ok = True
            c.evidence.append(f"Defender reports the last {label} Scan finished at {end.isoformat()}, after this scan started.")
        elif end:
            c.evidence.append(f"Defender's last {label} Scan end time ({end.isoformat()}) is BEFORE this scan started.")
        else:
            c.evidence.append(f"Defender reported no {label} Scan end time.")
    if events_state == "unreadable":
        c.caveats.append("Defender's Operational event log could not be read (it needs Administrator or Event Log Readers "
                         "rights), so scan-stopped/failed events could not be checked.")
    elif finished:
        c.evidence.append(f"Defender's event log records a scan finishing at {max(finished).isoformat()} (event 1001).")
    if stopped:
        c.evidence.append(f"Defender's event log records a scan stopped or failed at {max(stopped).isoformat()} (event 1002/1005).")

    if stopped and (finished or ts_ok):
        # A stop/failure event may belong to a different scan than the finish evidence; never claim a clean finish.
        c.outcome = UNKNOWN
        c.method = "status_timestamps" if ts_ok else "event_log"
        c.caveats.append("Defender logged a scan stopped/failed event in this window as well as evidence of a finish; "
                         "SentriX cannot tell which scan each refers to, so completion is NOT established.")
    elif ts_ok:
        c.outcome, c.method = COMPLETED, "status_timestamps"
    elif stopped:
        c.outcome, c.method = STOPPED, "event_log"
    elif finished:
        c.outcome, c.method = COMPLETED, "event_log"
    else:
        c.outcome = UNKNOWN
        c.caveats.append("Defender gave no usable evidence that this scan finished.")
    if c.outcome == COMPLETED and c.method == "event_log":
        c.caveats.append("Completion rests on the event log, which is matched by time window rather than scan id.")
    return c


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
def _env_minutes(name, default):
    try:
        v = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        v = default
    return max(5, min(10080, v))


def scan_timeout_seconds(kind):
    default = {"quick": 120, "full": 1440, "custom": 480}[kind]
    return _env_minutes(f"SENTRIX_DEFENDER_{kind.upper()}_TIMEOUT_MINUTES", default) * 60


def utcnow():
    return datetime.now(timezone.utc)


@dataclass
class ScanRun:
    """What happened when Start-MpScan was invoked (NOT whether the scan completed)."""
    command: str                    # returned | failed | timed_out | not_started
    started_at: datetime
    ended_at: datetime
    error_kind: str | None = None
    message: str | None = None
    detail: str | None = None


class DefenderClient:
    """High-level, fixed-operation Defender access. ``runner`` is injectable for tests."""

    def __init__(self, runner=None, clock=utcnow, platform_system=None):
        self._system = platform_system or platform.system()
        self.runner = runner or PowerShellRunner(platform_system=self._system)
        self.clock = clock

    # -- status ------------------------------------------------------------
    def get_protection_status(self):
        now = self.clock().isoformat()
        if self._system != "Windows":
            return ProtectionStatus(STATE_UNAVAILABLE, f"Microsoft Defender can only be checked on Windows; this server runs {self._system}.",
                                    error_kind=KIND_UNAVAILABLE, checked_at=now)
        run = self.runner.run("status", timeout=STATUS_TIMEOUT)
        payload = parse_json_output(run.stdout)
        if run.timed_out or run.launch_error or payload is None or not payload.get("ok"):
            kind, message = classify_failure(run, payload)
            state = {KIND_UNAVAILABLE: STATE_UNAVAILABLE, KIND_SERVICE: STATE_DISABLED}.get(kind, STATE_INACCESSIBLE)
            logger.warning("Defender status check failed: %s", kind)
            return ProtectionStatus(state, message, error_kind=kind, detail=safe_detail(run, payload), checked_at=now)
        fields = payload.get("status") if isinstance(payload.get("status"), dict) else {}
        av = payload.get("registered_av")
        registered = [str(a) for a in (av if isinstance(av, list) else [av] if av else [])]
        state, summary = classify_protection(fields, registered)
        return ProtectionStatus(state, summary, fields=fields, registered_av=registered, checked_at=now,
                                error_kind=KIND_UNPARSEABLE if state == STATE_INACCESSIBLE else None)

    # -- detections ----------------------------------------------------------
    def get_detections(self):
        """(records, meta, error). error is None or {'kind','message','detail'}."""
        run = self.runner.run("detections", timeout=DETECTIONS_TIMEOUT)
        payload = parse_json_output(run.stdout)
        if run.timed_out or run.launch_error or payload is None or not payload.get("ok"):
            kind, message = classify_failure(run, payload)
            return [], {"total": 0, "truncated": False, "threat_names_available": False}, \
                {"kind": kind, "message": message, "detail": safe_detail(run, payload)}
        records, meta = parse_detections(payload)
        return records, meta, None

    # -- scanning ------------------------------------------------------------
    def start_scan(self, kind, path=None):
        if kind not in SCAN_KINDS:
            raise ValueError("unknown scan kind")
        env = None
        if kind == "custom":
            env = {"SENTRIX_SCAN_PATH": validate_scan_path(path)}
        started = self.clock()
        run = self.runner.run(f"scan_{kind}", env_extra=env, timeout=scan_timeout_seconds(kind))
        ended = self.clock()
        payload = parse_json_output(run.stdout)
        if run.timed_out:
            return ScanRun("timed_out", started, ended, KIND_TIMEOUT,
                           "SentriX stopped waiting before Defender reported the scan finished. Defender may still be "
                           "scanning in the background; check Windows Security.")
        if run.launch_error:
            return ScanRun("not_started", started, ended, KIND_UNAVAILABLE, run.launch_error)
        if run.returncode == 0 and payload is not None and payload.get("ok"):
            return ScanRun("returned", started, ended)
        kind_, message = classify_failure(run, payload)
        return ScanRun("failed", started, ended, kind_, message, safe_detail(run, payload))

    def verify_completion(self, kind, since):
        """Completion evidence for the scan that started at ``since`` (aware UTC datetime)."""
        run = self.runner.run("verify", env_extra={"SENTRIX_SINCE": since.astimezone(timezone.utc).isoformat()},
                              timeout=VERIFY_TIMEOUT)
        payload = parse_json_output(run.stdout)
        if run.timed_out or run.launch_error or payload is None:
            _, message = classify_failure(run, payload)
            c = Completion(outcome=UNKNOWN)
            c.caveats.append(f"Completion could not be verified: {message}")
            return c
        status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
        events, state = [], "ok"
        err = payload.get("events_error")
        if isinstance(err, dict):
            if "nomatchingeventsfound" in str(err.get("id", "")).lower().replace(" ", ""):
                state = "none"
            else:
                state = "unreadable"
        else:
            ev = payload.get("events")
            events = ev if isinstance(ev, list) else ([ev] if isinstance(ev, dict) else [])
        return decide_completion(kind, since, status, events, state)
