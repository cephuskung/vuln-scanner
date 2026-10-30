import logging
import os
import threading

from database import db
from scanner.scanner import run_nmap_scan, discover_hosts, normalize_target
from parser.parser import parse_nmap_xml
from vulnerability.cve_lookup import search_cves, LOOKUP_FAILURES_KEY
from risk.risk_score import calculate_risk
from scanner.config_validator import validate_service
from assets.asset_intel import refresh_asset_services
from scanner.assessment import load_intel, asset_context_for, enrich_findings

logger = logging.getLogger(__name__)

# At most this many scans execute at once; the rest wait in 'queued'. Keeps a
# burst of submissions (or a large network scan plus schedules) from starting
# dozens of nmap processes and hammering NVD's rate limit simultaneously.
MAX_CONCURRENT_SCANS = max(1, int(os.environ.get("SENTRIX_MAX_CONCURRENT_SCANS", 3)))
_SCAN_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


class ScanError(RuntimeError):
    """A scan failure whose message is safe and useful to show the user."""


def _public_error(exc):
    """Failure text that is safe to persist/show: our own/nmap/validation
    messages as-is (truncated); anything else (DB errors, bugs...) becomes a
    generic message so SQL, paths or stack details never reach the UI."""
    if isinstance(exc, (RuntimeError, ValueError)):
        return (str(exc).strip() or exc.__class__.__name__)[:500]
    return "Unexpected internal error while running the scan (details are in the server log)."


def _remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def run_full_scan(target, asset_id=None, created_by=None, scan_type="manual", scan_id=None):
    """Scan one target end to end.

    scan_id (optional): an already-created scan row (status 'queued') to
    run - used by the web/scheduler job path so the user gets the scan id,
    duplicate detection and target validation up front. When omitted (CLI /
    legacy callers) the asset and scan row are created here as before.
    """
    if asset_id is None:
        asset_id = db.upsert_asset(target)
    if scan_id is None:
        scan_id = db.create_scan(target, asset_id=asset_id, created_by=created_by, scan_type=scan_type)
    with _SCAN_SLOTS:
        return _execute_scan(target, asset_id, scan_id)


def _execute_scan(target, asset_id, scan_id):
    cve_memo = {}
    warnings = []
    try:
        db.update_scan_status(scan_id, "running")
        xml_file = run_nmap_scan(target)
        try:
            results = parse_nmap_xml(xml_file)
        finally:
            _remove_quietly(xml_file)
        if not results.get("hosts"):
            # nmap exits 0 but reports no host when a hostname can't be
            # resolved - that is a failed scan, not an empty clean one.
            raise ScanError(
                "Nmap reported no hosts for this target (the hostname could not be resolved or the target is invalid)."
            )
        if results.get("os"):
            db.upsert_asset(target, os_name=results["os"])
        all_vulns = []

        intel = load_intel()
        asset_context = asset_context_for(asset_id)

        for port in results["open_ports"]:
            service = port.get("service")
            product = port.get("product")
            vendor = port.get("vendor")
            version = port.get("version")
            cpe = port.get("cpe")
            port_number = port["port"]

            vulns = search_cves(
                service=service,
                product=product,
                vendor=vendor,
                version=version,
                cpe=cpe,
                memo=cve_memo
            )

            # Configuration validation (IVMP Phase 10) - runs immediately
            # after CVE matching and before EPSS/KEV enrichment, contextual
            # risk, applicability assessment, and confidence scoring. It is
            # independent of all of those: it does not read or alter
            # cvss_score, contextual_priority, priority_label,
            # applicability_status, or vulnerability_confidence. One
            # validation per port is sufficient since all findings on this
            # port share the same detected service/product/version/cpe.
            config_result = validate_service(
                port=port_number,
                service=service,
                product=product,
                vendor=vendor,
                version=version,
                cpe=cpe,
                target=target,
            )

            for v in vulns:
                v["config_validation"] = config_result["checks"]
                v["config_evidence"] = config_result["evidence"]

            # KEV/EPSS, contextual risk, applicability and confidence - the
            # shared steps in scanner/assessment.py (also used by the Software
            # and System scans).
            enrich_findings(vulns, intel, asset_context, product, vendor, version, cpe)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("enrichment (target=%s, port=%s): %s", target, port_number, [
                    {
                        "cve": v.get("cve_id"),
                        "epss": v.get("epss_score"),
                        "kev": v.get("is_kev"),
                        "priority": v.get("contextual_priority"),
                        "label": v.get("priority_label")
                    }
                    for v in vulns[:3]
                ])
                logger.debug("confidence (target=%s, port=%s): %s", target, port_number, [
                    {
                        "cve": v.get("cve_id"),
                        "confidence": v.get("vulnerability_confidence"),
                        "reason": v.get("confidence_reason"),
                        "applicability": v.get("applicability_status"),
                    }
                    for v in vulns
                ])
            db.save_vulnerabilities(scan_id, port_number, service, vulns)

            for v in vulns:
                all_vulns.append({
                    **v,
                    "port": port_number,
                    "service": service,
                    "product": product,
                    "vendor": vendor,
                    "version": version,
                    "cpe": cpe
                })

        refresh_asset_services(asset_id, scan_id, results["open_ports"])

        score, counts = calculate_risk(all_vulns)

        # Honest outcome: a scan that finished but could not check
        # everything must say so, so "no findings" is never read as "secure".
        if not results["open_ports"]:
            warnings.append(
                "No open ports were detected. The host may be down, unreachable or filtered, "
                "so the absence of findings is inconclusive."
            )
        lookup_failures = cve_memo.get(LOOKUP_FAILURES_KEY) or []
        if lookup_failures:
            shown = ", ".join(sorted(set(lookup_failures))[:5])
            warnings.append(
                f"Vulnerability intelligence (NVD) was unavailable or incomplete for: {shown}. "
                "Findings for these services may be missing - rescan once NVD is reachable."
            )

        db.update_scan_status(
            scan_id, "completed", total_risk=score,
            status_detail=" ".join(warnings) or None,
        )

        return {
            "status": "completed",
            "scan_id": scan_id,
            "asset_id": asset_id,
            "results": results,
            "vulns": all_vulns,
            "score": score,
            "counts": counts,
            "warnings": warnings,
        }
    except Exception as e:
        logger.exception("Scan failed for target %s (scan_id=%s)", target, scan_id)
        detail = _public_error(e)
        db.update_scan_status(scan_id, "failed", status_detail=detail)
        return {"status": "failed", "scan_id": scan_id, "asset_id": asset_id, "error": detail}


def run_network_scan(target, created_by=None, parent_scan_id=None):
    """Network scan: discover live hosts in a CIDR range (nmap -sn), then run
    the normal single-host pipeline against each one, sequentially.

    Each host gets its own asset and scan record (scan_type 'network-host'),
    so findings, scoring, reports and history work exactly as for a single
    target. A parent record (scan_type 'network') tracks discovery and the
    overall outcome; its total_risk is the sum of the host scores.
    Hosts that already have an active scan are skipped, not duplicated.
    """
    target = normalize_target(target)
    if parent_scan_id is None:
        parent_scan_id = db.create_scan(target, created_by=created_by, scan_type="network")
    else:
        db.update_scan_status(parent_scan_id, "running")
    try:
        hosts = discover_hosts(target)
        if not hosts:
            detail = (f"Host discovery found no live hosts in {target}. Hosts that block ping probes "
                      "would not appear, so this does not prove the range is empty.")
            db.update_scan_status(parent_scan_id, "completed", total_risk=0, status_detail=detail)
            return {"status": "completed", "scan_id": parent_scan_id, "hosts": [], "scanned": [],
                    "failed": [], "skipped": [], "score": 0}

        scanned, failed, skipped, total = [], [], [], 0.0
        for ip in hosts:
            asset_id = db.upsert_asset(ip)
            sid = db.create_scan_if_idle(ip, asset_id=asset_id, created_by=created_by,
                                         scan_type="network-host", status="queued")
            if sid is None:
                skipped.append(ip)
                continue
            res = run_full_scan(ip, asset_id=asset_id, created_by=created_by,
                                scan_type="network-host", scan_id=sid)
            if res["status"] == "completed":
                scanned.append(ip)
                total += float(res.get("score") or 0)
            else:
                failed.append(ip)

        def _fmt(ips):
            return ", ".join(ips[:20]) + (f" (+{len(ips) - 20} more)" if len(ips) > 20 else "")

        parts = [f"Discovered {len(hosts)} live host(s); {len(scanned)} scanned"]
        if failed:
            parts.append(f"{len(failed)} failed ({_fmt(failed)})")
        if skipped:
            parts.append(f"{len(skipped)} skipped because a scan was already active ({_fmt(skipped)})")
        detail = "; ".join(parts) + ". Each host has its own scan record."
        status = "failed" if (failed and not scanned) else "completed"
        db.update_scan_status(parent_scan_id, status, total_risk=round(total, 2), status_detail=detail)
        return {"status": status, "scan_id": parent_scan_id, "hosts": hosts, "scanned": scanned,
                "failed": failed, "skipped": skipped, "score": round(total, 2)}
    except Exception as e:
        logger.exception("Network scan failed for %s (scan_id=%s)", target, parent_scan_id)
        db.update_scan_status(parent_scan_id, "failed", status_detail=_public_error(e))
        return {"status": "failed", "scan_id": parent_scan_id, "error": _public_error(e)}