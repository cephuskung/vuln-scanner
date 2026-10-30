"""Windows System Scan: a malware / threat assessment of the computer running
SentriX, driven by Microsoft Defender Antivirus (see scanner/windows_defender.py
for the safe-execution rules and the PowerShell operations).

Actions
  status   protection status + Defender's existing detection records. Nothing is scanned.
  quick    Start-MpScan -ScanType QuickScan
  full     Start-MpScan -ScanType FullScan
  custom   Start-MpScan -ScanType CustomScan -ScanPath <validated path>

Outcomes (scan_info.scan.outcome) - the wording is deliberate:
  not_scanned           status-only, or Defender could not scan (disabled / unavailable / inaccessible)
  scan_finished         Defender's own evidence shows the scan completed. Detections attributable to it, if
                        any, are listed; none listed is NOT proof the computer is free of malware.
  completion_unverified Start-MpScan returned without error but SentriX could not establish that the scan
                        finished. Reported as such - never as clean.
  scan_incomplete       the scan timed out on SentriX's side or Defender logged it stopped.
  scan_failed           the command failed (permissions, service, bad path ...).

The lifecycle is the usual queued -> running -> completed/failed: 'failed' covers scan_incomplete and
scan_failed, 'completed' covers the others.

A long Defender scan does NOT occupy one of the shared scan slots (those exist to protect nmap/NVD
capacity); duplicate protection still allows only one Windows System Scan at a time.

SentriX never deletes, quarantines, restores, excludes or executes anything.
"""
import logging
from datetime import timedelta

from database import db
from risk.contextual_risk import calculate_contextual_risk, priority_label
from risk.risk_score import calculate_risk
from scanner.assessment import load_intel, asset_context_for
from scanner.inventory import local_host_info
from scanner.pipeline import _public_error
from scanner.system_collectors import SEVERITY_CVSS
from scanner.windows_defender import (
    DefenderClient, DefenderInputError, SCANNABLE_STATES, STATE_UNAVAILABLE, STATE_INACCESSIBLE,
    STATE_PASSIVE, COMPLETED, STOPPED, attribute_detections, protection_checks, validate_scan_path, utcnow,
    ATTR_CURRENT, ATTR_HISTORICAL, ATTR_UNATTRIBUTED, EXPECTED_DURATION,
)

logger = logging.getLogger(__name__)

ACTIONS = ("status", "quick", "full", "custom")
WINDOW_SLACK = timedelta(seconds=5)

LIMITATIONS = [
    "This assessment covers only the computer running the SentriX server process. Remote Windows endpoints are not "
    "supported; they need a separately designed, authenticated endpoint agent.",
    "Detections come from Microsoft Defender Antivirus. SentriX has no antivirus engine of its own and cannot see "
    "threats Defender does not report. An empty result is not proof the computer is free of malware.",
    "Defender's detection records do not identify which scan produced them. 'Current scan' means the record is new "
    "since the pre-scan baseline and falls in the scan's time window; it may include a real-time protection event.",
    "SentriX only reports. It never deletes, quarantines, restores or executes files and never changes Defender "
    "settings or exclusions.",
]


def _severity_checks(checks, asset_ctx, intel):
    for c in checks:
        if c["status"] == "fail":
            synthetic = {"cvss_score": SEVERITY_CVSS[c["severity"]], "attack_complexity": "LOW", "epss_score": None,
                         "match_confidence": 1.0, "compensating_controls": 0}
            c["contextual_priority"] = calculate_contextual_risk(synthetic, asset_ctx, intel.weights, 0, 0, False)
            c["priority_label"] = priority_label(c["contextual_priority"])


def _set_progress(scan_id, base, text):
    try:
        db.set_scan_info(scan_id, dict(base, progress=text))
    except Exception:
        logger.debug("could not record progress for scan %s", scan_id, exc_info=True)


def run_windows_system_scan(scan_id, asset_id, asset_key, request, client=None, clock=utcnow):
    """Execute a queued Windows System Scan. request: {"action": ..., "path": str | None}."""
    return _execute(scan_id, asset_id, asset_key, request, client or DefenderClient(clock=clock), clock)


def _execute(scan_id, asset_id, asset_key, request, client, clock):
    action, path = request.get("action"), request.get("path")
    try:
        db.update_scan_status(scan_id, "running")
        host = local_host_info()
        base = {"mode": "windows-defender", "action": action, "path": path, "host": host}
        _set_progress(scan_id, base, "Checking Microsoft Defender protection status")
        if action not in ACTIONS:
            raise ValueError("Unknown Windows System Scan action.")
        if action == "custom":
            path = validate_scan_path(path)
            base["path"] = path

        status = client.get_protection_status()
        checks = protection_checks(status)
        intel = load_intel()
        asset_ctx = asset_context_for(asset_id)
        _severity_checks(checks, asset_ctx, intel)

        _set_progress(scan_id, base, "Reading Defender's existing detection records")
        before, _meta_b, err_before = client.get_detections()
        baseline_ids = None if err_before else {r.detection_id for r in before}

        scan = {"kind": action if action != "status" else None, "path": path, "outcome": "not_scanned",
                "command": None, "started_at": None, "ended_at": None, "completion": None, "error": None,
                "expected_duration": EXPECTED_DURATION.get(action)}
        warnings, final_status, window = [], "completed", None
        records, meta, det_error = before, _meta_b, err_before

        if status.state in (STATE_UNAVAILABLE, STATE_INACCESSIBLE) and action == "status":
            warnings.append("Protection status could not be established: " + status.summary)
            final_status = "failed" if status.state == STATE_INACCESSIBLE else "completed"
        elif action != "status":
            if status.state not in SCANNABLE_STATES:
                final_status = "failed"
                scan["outcome"] = "not_scanned"
                scan["error"] = {"kind": status.error_kind or status.state, "message": status.summary}
                warnings.append(f"No scan was started: Microsoft Defender is {status.state}. {status.summary}")
            else:
                if status.state == STATE_PASSIVE:
                    warnings.append("Defender is in passive mode; the on-demand scan was attempted but real-time "
                                    "protection is provided by another product.")
                _set_progress(scan_id, base, f"{action.capitalize()} Scan running in Microsoft Defender (started "
                                             f"{clock().strftime('%H:%M:%S')} UTC). {EXPECTED_DURATION[action]}")
                run = client.start_scan(action, path)
                scan.update(command=run.command, started_at=run.started_at.isoformat(), ended_at=run.ended_at.isoformat(),
                            duration_seconds=round((run.ended_at - run.started_at).total_seconds(), 1))
                completion = None
                if run.command == "returned":
                    _set_progress(scan_id, base, "Verifying that Defender finished the scan")
                    completion = client.verify_completion(action, run.started_at)
                    scan["completion"] = completion.to_dict()
                    if completion.outcome == COMPLETED:
                        scan["outcome"] = "scan_finished"
                    elif completion.outcome == STOPPED:
                        scan["outcome"], final_status = "scan_incomplete", "failed"
                        warnings.append("Defender recorded this scan as stopped or failed before finishing: the result is INCOMPLETE.")
                    else:
                        scan["outcome"] = "completion_unverified"
                        warnings.append("Start-MpScan returned without an error, but SentriX could not establish that the "
                                        "scan finished. Do not treat the absence of detections as a clean result.")
                elif run.command == "timed_out":
                    scan["outcome"], final_status = "scan_incomplete", "failed"
                    scan["error"] = {"kind": run.error_kind, "message": run.message}
                    warnings.append("INCOMPLETE: " + run.message)
                else:
                    scan["outcome"], final_status = "scan_failed", "failed"
                    scan["error"] = {"kind": run.error_kind, "message": run.message, "detail": run.detail}
                    warnings.append("The scan did not run: " + (run.message or "command failed")
                                    + (f" ({run.detail})" if run.detail else ""))
                if run.command != "not_started":
                    _set_progress(scan_id, base, "Collecting Defender's threat detections")
                    records, meta, det_error = client.get_detections()
                    window = (run.started_at - timedelta(seconds=2), run.ended_at + WINDOW_SLACK)

        scan_path = path if action == "custom" else None
        attribute_detections(records, baseline_ids, window[0] if window else None, window[1] if window else None, scan_path)
        if det_error:
            warnings.append("Defender's threat detection records could not be read: " + det_error["message"]
                            + " Findings below are therefore incomplete.")
        if not meta.get("threat_names_available", True) and records:
            warnings.append("Threat names and severities could not be read from Defender; records show IDs only.")
        if meta.get("truncated"):
            warnings.append(f"Defender holds {meta['total']} detection records; only the newest {len(records)} are shown.")
        if baseline_ids is None and window:
            warnings.append("Defender's detection records could not be read before the scan, so attribution to this "
                            "scan rests on timestamps alone.")

        rows = [r.to_row() for r in records]
        counted = [r for r in records if r.attribution == ATTR_CURRENT or r.needs_attention]
        score, counts = calculate_risk(
            [{"severity": r.severity, "cvss_score": SEVERITY_CVSS.get(r.severity)} for r in counted]
            + [{"severity": c["severity"], "cvss_score": SEVERITY_CVSS[c["severity"]]} for c in checks if c["status"] == "fail"]
        )
        by_attr = {a: sum(1 for r in records if r.attribution == a) for a in (ATTR_CURRENT, ATTR_HISTORICAL, ATTR_UNATTRIBUTED)}
        det_info = {"available": det_error is None, "total": meta.get("total", len(records)), "shown": len(records),
                    "truncated": bool(meta.get("truncated")), "current_scan": by_attr[ATTR_CURRENT],
                    "historical": by_attr[ATTR_HISTORICAL], "unattributed": by_attr[ATTR_UNATTRIBUTED],
                    "needs_attention": sum(1 for r in records if r.needs_attention),
                    "baseline_available": baseline_ids is not None,
                    "error": det_error["message"] if det_error else None}
        if action != "status" and scan["outcome"] in ("scan_finished", "completion_unverified") and by_attr[ATTR_CURRENT]:
            warnings.append(f"{by_attr[ATTR_CURRENT]} detection(s) were recorded during this scan - see Threat detections.")

        info = dict(base, protection=status.to_dict(), scan=scan, detections=det_info, limitations=LIMITATIONS)
        info.pop("progress", None)
        db.save_system_checks(scan_id, checks)
        db.save_threat_findings(scan_id, rows)
        db.set_scan_info(scan_id, info)
        if asset_key:
            db.upsert_asset(asset_key, os_name=host.get("os"))
        db.update_scan_status(scan_id, final_status, total_risk=score, status_detail=" ".join(warnings) or None)
        return {"status": final_status, "scan_id": scan_id, "outcome": scan["outcome"], "protection": status,
                "records": records, "checks": checks, "warnings": warnings, "score": score, "info": info}
    except (DefenderInputError, ValueError) as e:
        db.update_scan_status(scan_id, "failed", status_detail=str(e)[:500])
        return {"status": "failed", "scan_id": scan_id, "error": str(e)}
    except Exception as e:
        logger.exception("Windows System Scan failed (scan_id=%s)", scan_id)
        detail = _public_error(e)
        db.update_scan_status(scan_id, "failed", status_detail=detail)
        return {"status": "failed", "scan_id": scan_id, "error": detail}
