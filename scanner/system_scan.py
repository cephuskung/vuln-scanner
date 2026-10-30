"""System Scan: assess a computer or server from the INSIDE (local, or remote
over SSH with key authentication).

What it does (see scanner/system_collectors.py for the checks themselves):
  * OS / kernel / host information and OS support status
  * installed-software inventory (dpkg or rpm)
  * listening network services and risky exposure
  * security configuration checks (SSH daemon, firewall, kernel hardening,
    file permissions, accounts, pending security updates, legacy services)
  * CVE assessment of the installed software that can be mapped to an NVD
    identity - through the SAME engine and the SAME assess_item() path as the
    Software Scan, so there is no second CVE engine
  * evidence-based findings, contextual priority and remediation

What it is NOT: a remote Nmap scan. Nmap (the Network Scan) sees only what a
host exposes on the wire; a System Scan reads the machine's own state, and
says explicitly when something needs credentials or root.

Findings from OS packages are never better than POTENTIAL: distributions
backport security fixes without changing the upstream version number, so an
"affected upstream version" does not prove the package is vulnerable.
"""
import contextlib
import logging

from database import db
from risk.contextual_risk import calculate_contextual_risk, priority_label
from risk.risk_score import calculate_risk
from scanner.assessment import load_intel, asset_context_for
from scanner.pipeline import _SCAN_SLOTS, _public_error
from scanner.software_scan import assess_item
from scanner.system_collectors import (
    LocalTransport, open_ssh_transport, gather, SEVERITY_CVSS,
)
from vulnerability.cve_lookup import LOOKUP_FAILURES_KEY
from vulnerability.software_catalog import map_package, upstream_version, make_item, display_name

logger = logging.getLogger(__name__)

MAX_ASSESSED_ITEMS = 40          # unique mapped software items CVE-assessed per scan (NVD is rate limited)


def build_assessment_items(packages):
    """Group installed packages into unique NVD identities.

    Returns (items, package_rows). items: one per (vendor, product, upstream
    version), each carrying the package names it came from; package_rows: one
    inventory row per package with how it will be (or was not) assessed."""
    grouped, rows = {}, []
    for pkg in packages:
        mapped = map_package(pkg["name"])
        upstream = upstream_version(pkg.get("upstream") or pkg["version"], pkg["source"])
        row = {"vendor": None, "product": pkg["name"], "version": pkg["version"], "upstream_version": upstream,
               "source": pkg["source"], "cpe_vendor": None, "cpe_product": None,
               "assessment": "not_assessed", "note": "no NVD identity mapping for this package", "findings_count": 0}
        if mapped:
            vendor, product = mapped
            row.update(cpe_vendor=vendor, cpe_product=product, vendor=vendor, note=None)
            if not upstream:
                row["note"] = "upstream version could not be determined from the package version"
            else:
                key = (vendor, product, upstream)
                grouped.setdefault(key, {"packages": []})["packages"].append(pkg["name"])
                row["_key"] = key
        rows.append(row)
    items = []
    for (vendor, product, upstream), g in grouped.items():
        item = make_item(vendor, product, upstream, "catalog", display_name(vendor, product), vendor)
        item["packages"] = sorted(set(g["packages"]))
        items.append(item)
    items.sort(key=lambda i: (i["display_product"], i["version"] or ""))
    return items, rows


def run_system_scan(scan_id, asset_id, asset_key, mode, ssh=None, use_sudo=False):
    """Execute a queued system scan. mode: 'local' | 'remote'. ssh (remote
    only): {"host","port","user","key_text","fingerprint","accept_unverified"}.
    The key lives only in this function's memory and is dropped afterwards."""
    with _SCAN_SLOTS:
        return _execute(scan_id, asset_id, asset_key, mode, ssh, use_sudo)


def _open(mode, ssh, use_sudo):
    if mode == "local":
        return contextlib.nullcontext(LocalTransport(sudo_enabled=use_sudo))
    return open_ssh_transport(ssh["host"], ssh["port"], ssh["user"], ssh["key_text"],
                              ssh.get("fingerprint"), ssh.get("accept_unverified", False), use_sudo)


def _execute(scan_id, asset_id, asset_key, mode, ssh, use_sudo):
    memo = {}
    try:
        db.update_scan_status(scan_id, "running")
        with _open(mode, ssh, use_sudo) as t:
            if ssh:
                ssh["key_text"] = None                       # no longer needed once connected
            data = gather(t)
            elevation = "root" if t.is_root else ("sudo" if t.can_elevate else "none")
            verified = getattr(t, "host_key_verified", None)
            description = t.description

        info = data["os"]
        asset_id = db.upsert_asset(asset_key, os_name=info["os_pretty"]) if asset_key else asset_id
        intel = load_intel()
        asset_ctx = asset_context_for(asset_id)

        # Contextual priority for failed configuration checks: the SAME formula as CVE findings, fed with a
        # CVSS-equivalent derived from the check's severity (observed directly => full confidence).
        for c in data["checks"]:
            if c["status"] == "fail":
                synthetic = {"cvss_score": SEVERITY_CVSS[c["severity"]], "attack_complexity": "LOW",
                             "epss_score": None, "match_confidence": 1.0, "compensating_controls": 0}
                c["contextual_priority"] = calculate_contextual_risk(synthetic, asset_ctx, intel.weights, 0, 0, False)
                c["priority_label"] = priority_label(c["contextual_priority"])

        # --- CVE assessment of mapped software (shared engine path) ---
        items, rows = build_assessment_items(data["packages"])
        all_vulns, assessed_keys = [], {}
        for item in items[:MAX_ASSESSED_ITEMS]:
            label = f"{item['display_product']} {item['version']} (package: {', '.join(item['packages'][:3])})"
            res = assess_item(item, memo, intel, asset_ctx, source=data["package_manager"],
                              distro_packaged=True, label=label)
            if res["findings"]:
                db.save_vulnerabilities(scan_id, None, label[:120], res["findings"])
            for v in res["findings"]:
                all_vulns.append({**v, "port": None, "service": label})
            assessed_keys[(item["cpe_vendor"], item["cpe_product"], item["version"])] = res
        for row in rows:
            key = row.pop("_key", None)
            if key is None:
                continue
            res = assessed_keys.get(key)
            if res is None:
                row["note"] = f"not assessed: limit of {MAX_ASSESSED_ITEMS} software items per scan reached"
            else:
                row["assessment"] = "lookup_failed" if res["lookup_failed"] else "assessed"
                row["findings_count"] = len(res["findings"])
                row["note"] = res["note"]

        db.save_software_inventory(scan_id, rows)
        db.save_system_checks(scan_id, data["checks"])

        pseudo = [{"severity": c["severity"], "cvss_score": SEVERITY_CVSS[c["severity"]]}
                  for c in data["checks"] if c["status"] == "fail"]
        score, counts = calculate_risk(all_vulns + pseudo)

        # --- honest summary of what could NOT be assessed ---
        warnings = []
        need_root = [c for c in data["checks"] if c["status"] == "unknown" and c.get("requires") == "root"]
        other_unknown = [c for c in data["checks"] if c["status"] == "unknown" and not c.get("requires")]
        if need_root and elevation == "none":
            warnings.append(f"{len(need_root)} check(s) require root and were NOT assessed (scan ran as an unprivileged "
                            "user). Re-run as root, or enable 'use sudo' with a passwordless-sudo account.")
        if other_unknown:
            warnings.append(f"{len(other_unknown)} check(s) could not be determined on this machine (see the coverage table).")
        crashed = [c["name"].replace("_", " ") for c in data["coverage"] if c["status"] == "failed"]
        if crashed:
            warnings.append("These assessment area(s) failed to run and produced NO results: " + ", ".join(crashed)
                            + " (see the coverage table and the server log).")
        if verified is False:
            warnings.append("The SSH host key was NOT verified (accepted unverified at your request): the scan could "
                            "have been answered by an impostor.")
        if not data["package_manager"]:
            warnings.append("Installed-software inventory was unavailable (no dpkg or rpm), so no CVE assessment of installed software was performed.")
        failed = memo.get(LOOKUP_FAILURES_KEY) or []
        if failed:
            warnings.append("Vulnerability data (NVD) was unavailable or incomplete for: "
                            + ", ".join(sorted(set(failed))[:6]) + ". Those packages were NOT assessed.")
        if len(items) > MAX_ASSESSED_ITEMS:
            warnings.append(f"Only the first {MAX_ASSESSED_ITEMS} of {len(items)} mappable software items were CVE-assessed.")
        if all_vulns:
            warnings.append("CVEs from OS packages are POTENTIAL at most: the distributor may have backported the fix "
                            "without changing the version number - confirm with the distribution's security tracker.")

        listeners = data["listeners"] or []
        db.set_scan_info(scan_id, {
            "mode": mode, "target": description, "hostname": info["hostname"],
            "os": info["os_pretty"], "os_id": info["os_id"], "os_version_id": info["os_version_id"],
            "kernel": info["kernel"], "arch": info["arch"], "uptime_days": info["uptime_days"],
            "elevation": elevation, "host_key_verified": verified, "package_manager": data["package_manager"],
            "counts": {"packages": len(data["packages"]), "software_mapped": len(items),
                       "software_assessed": min(len(items), MAX_ASSESSED_ITEMS), "listeners": len(listeners)},
            "coverage": data["coverage"], "listeners": listeners[:300],
        })
        db.update_scan_status(scan_id, "completed", total_risk=score, status_detail=" ".join(warnings) or None)
        return {"status": "completed", "scan_id": scan_id, "asset_id": asset_id, "vulns": all_vulns,
                "checks": data["checks"], "score": score, "counts": counts, "warnings": warnings}
    except Exception as e:
        logger.exception("System scan failed (scan_id=%s)", scan_id)
        detail = _public_error(e)
        db.update_scan_status(scan_id, "failed", status_detail=detail)
        return {"status": "failed", "scan_id": scan_id, "error": detail}
    finally:
        if ssh:
            ssh["key_text"] = None
