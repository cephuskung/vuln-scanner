"""Software Scan - "Scan this computer": discover installed applications and
assess them with the EXISTING vulnerability engine.

There is no second CVE engine here. For every distinct application this module
only (1) turns the inventory entry into an identity the engine understands
(vulnerability/software_catalog.normalize_inventory_entry) and (2) calls
scanner.software_scan.assess_item() - the same function the manual Software Scan
and the Linux System Scan use - which in turn goes through search_cves() (NVD,
CPE data, version ranges, cache) and scanner.assessment (KEV/EPSS, contextual
risk, applicability, confidence).

Bounded work (a PC can have hundreds of registry entries; NVD is rate limited):
  * entries are de-duplicated into distinct (product, version) identities,
  * entries with no usable version, driver packages and language packs are NOT
    sent to NVD (recorded with the reason),
  * at most SENTRIX_MAX_INVENTORY_ASSESSMENTS distinct identities are assessed
    per scan (default 40), recognised products first, and
  * assessment stops when SENTRIX_INVENTORY_TIME_BUDGET_SECONDS (default 1200)
    is exhausted.
Everything not assessed is stored with its reason - never presented as clean.
"""
import logging
import os
import time
from collections import Counter

from database import db
from risk.risk_score import calculate_risk
from scanner.assessment import load_intel, asset_context_for
from scanner.inventory import STATUS_COMPLETE, STATUS_PARTIAL
from scanner.pipeline import _SCAN_SLOTS, _public_error
from scanner.software_scan import assess_item
from scanner.windows_inventory import LocalWindowsInventory
from vulnerability.cve_lookup import LOOKUP_FAILURES_KEY
from vulnerability.software_catalog import normalize_inventory_entry, describe

logger = logging.getLogger(__name__)

DEFAULT_MAX_ASSESSED = 40
HARD_MAX_ASSESSED = 200
DEFAULT_TIME_BUDGET_SECONDS = 1200
SOURCE = "windows-registry"

REASON_NOTES = {
    "no_version": "no version in the registry entry - applicability is UNKNOWN, so it was not sent to NVD "
                  "(affected-version ranges cannot be evaluated without a version)",
    "driver_package": "Windows driver package - not assessed",
    "language_pack": "language pack / proofing tools - not assessed",
    "unidentifiable_name": "the name could not be turned into a product identity - not assessed",
    "over_limit": "not assessed: the per-scan application limit was reached",
    "time_budget": "not assessed: the scan's time budget ran out",
    "nvd_unavailable": "NVD lookup failed or was incomplete - NOT assessed",
}


def _env_int(name, default, low, high):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def max_assessed():
    return _env_int("SENTRIX_MAX_INVENTORY_ASSESSMENTS", DEFAULT_MAX_ASSESSED, 1, HARD_MAX_ASSESSED)


def time_budget_seconds():
    return _env_int("SENTRIX_INVENTORY_TIME_BUDGET_SECONDS", DEFAULT_TIME_BUDGET_SECONDS, 10, 6 * 3600)


def _group_key(prepared):
    item = prepared["item"]
    if item["identity_source"] == "catalog":
        return ("catalog", item["cpe_vendor"], item["cpe_product"], item["version"])
    return ("name", prepared["clean_name"].casefold(), item["version"])


def build_plan(entries):
    """Turn inventory entries into per-entry rows and distinct assessable groups.

    Returns (rows, groups): rows - one dict per entry (in input order, already carrying a
    skip reason where the entry will not be assessed); groups - {key: {"item", "rows", "label"}}
    for entries that WILL be sent to the engine, de-duplicated."""
    rows, groups = [], {}
    for entry in entries:
        prep = normalize_inventory_entry(entry.name, entry.publisher, entry.version)
        item = prep["item"]
        row = {
            "vendor": entry.publisher, "product": entry.name, "version": entry.version,
            "upstream_version": prep["version"], "source": SOURCE,
            "cpe_vendor": item["cpe_vendor"] if item else None, "cpe_product": item["cpe_product"] if item else None,
            "assessment": "not_assessed", "note": None, "findings_count": 0,
            "install_date": entry.install_date, "inventory_source": "; ".join(entry.sources),
            "collection_status": entry.collection_status, "identity_source": prep["identity_source"],
            "assessment_reason": None, "system_component": entry.system_component,
        }
        notes = []
        if entry.version and not prep["version"]:
            notes.append("the registry version string was not usable as a version")
        if prep.get("version_note"):
            notes.append(prep["version_note"])
        if prep["skip_reason"]:
            row["assessment_reason"] = prep["skip_reason"]
            notes.append(REASON_NOTES[prep["skip_reason"]])
        else:
            key = _group_key(prep)
            group = groups.setdefault(key, {"item": item, "rows": [], "label": describe(item)})
            group["rows"].append(row)
        row["note"] = "; ".join(notes) or None
        rows.append(row)
    return rows, groups


def _order_groups(groups):
    """Recognised (catalogue) products first - their NVD identity is established - then the rest, by name."""
    def sort_key(kv):
        item = kv[1]["item"]
        return (0 if item["identity_source"] == "catalog" else 1, (item["display_product"] or "").casefold(),
                item["version"] or "")
    return sorted(groups.items(), key=sort_key)


def _set_progress(scan_id, base, text):
    try:
        db.set_scan_info(scan_id, dict(base, progress=text))
    except Exception:                                  # progress is cosmetic; never fail a scan over it
        logger.debug("could not record progress for scan %s", scan_id, exc_info=True)


def run_inventory_scan(scan_id, asset_id, asset_key, provider=None, clock=time.monotonic):
    """Execute a queued 'Scan this computer' job. Lifecycle matches every other
    scan: queued -> running -> completed/failed (reason stored on failure)."""
    with _SCAN_SLOTS:
        return _execute(scan_id, asset_id, asset_key, provider or LocalWindowsInventory(), clock)


def _execute(scan_id, asset_id, asset_key, provider, clock):
    memo = {}
    try:
        db.update_scan_status(scan_id, "running")
        base_info = {"mode": "windows-inventory", "provider": getattr(provider, "name", "unknown")}
        _set_progress(scan_id, base_info, "Reading installed applications from the Windows registry")

        result = provider.collect()
        host = result.host or {}
        base_info.update(host=host, inventory_status=result.status,
                         locations=[vars(l) for l in result.locations], skipped=result.skipped, notes=result.notes)

        if result.status not in (STATUS_COMPLETE, STATUS_PARTIAL):
            detail = result.error or "The installed-software inventory could not be collected."
            db.set_scan_info(scan_id, base_info)
            db.update_scan_status(scan_id, "failed", status_detail=detail[:500])
            return {"status": "failed", "scan_id": scan_id, "error": detail}

        if asset_key:
            asset_id = db.upsert_asset(asset_key, os_name=host.get("os")) or asset_id
        intel = load_intel()
        asset_ctx = asset_context_for(asset_id)

        rows, groups = build_plan(result.entries)
        ordered = _order_groups(groups)
        limit, budget = max_assessed(), time_budget_seconds()
        started = clock()
        all_vulns, assessed_groups, time_budget_hit = [], 0, False
        tier_counts = Counter()

        for n, (key, group) in enumerate(ordered):
            if n >= limit:
                for g_key, g in ordered[n:]:
                    for r in g["rows"]:
                        r["assessment_reason"] = "over_limit"
                        r["note"] = REASON_NOTES["over_limit"] + f" (limit {limit})"
                break
            if clock() - started > budget:
                time_budget_hit = True
                for g_key, g in ordered[n:]:
                    for r in g["rows"]:
                        r["assessment_reason"] = "time_budget"
                        r["note"] = REASON_NOTES["time_budget"]
                break
            if n % 5 == 0:
                _set_progress(scan_id, base_info, f"Assessing applications against NVD ({n} of {min(len(ordered), limit)})")
            item, label = group["item"], group["label"]
            res = assess_item(item, memo, intel, asset_ctx, source=SOURCE, label=label)
            assessed_groups += 1
            first = group["rows"][0]
            for v in res["findings"]:
                ev = dict(v.get("match_evidence") or {})
                ev["inventory"] = {"name": first["product"], "publisher": first["vendor"],
                                   "installed_version": first["version"], "registry_sources": first["inventory_source"],
                                   "install_date": first["install_date"]}
                v["match_evidence"] = ev
                tier_counts[v.get("applicability_status") or "UNKNOWN"] += 1
            if res["findings"]:
                db.save_vulnerabilities(scan_id, None, label[:120], res["findings"])
                for v in res["findings"]:
                    all_vulns.append({**v, "port": None, "service": label})
            for r in group["rows"]:
                if res["lookup_failed"]:
                    r["assessment"], r["assessment_reason"] = "lookup_failed", "nvd_unavailable"
                    r["note"] = "; ".join(x for x in (r["note"], REASON_NOTES["nvd_unavailable"]) if x)
                else:
                    r["assessment"] = "assessed"
                    r["findings_count"] = len(res["findings"])
                    r["note"] = "; ".join(x for x in (r["note"], res["note"]) if x) or None

        db.save_software_inventory(scan_id, [{k: v for k, v in r.items() if k != "system_component"} for r in rows])
        score, counts = calculate_risk(all_vulns)

        by_reason = Counter(r["assessment_reason"] for r in rows if r["assessment"] != "assessed" and r["assessment_reason"])
        n_assessed = sum(1 for r in rows if r["assessment"] == "assessed")
        n_failed = sum(1 for r in rows if r["assessment"] == "lookup_failed")
        n_with_findings = sum(1 for r in rows if r["findings_count"])
        warnings = _warnings(result, rows, n_assessed, n_failed, by_reason, limit, time_budget_hit,
                             memo.get(LOOKUP_FAILURES_KEY) or [], all_vulns)

        info = dict(base_info)
        info.pop("progress", None)
        info.update(
            counts={"discovered": len(rows), "assessed": n_assessed, "assessed_products": assessed_groups,
                    "with_findings": n_with_findings, "lookup_failed": n_failed,
                    "not_assessed": dict(by_reason), "findings": len(all_vulns)},
            tiers=dict(tier_counts),
            limits={"max_assessed": limit, "time_budget_seconds": budget, "time_budget_exhausted": time_budget_hit},
        )
        db.set_scan_info(scan_id, info)
        db.update_scan_status(scan_id, "completed", total_risk=score, status_detail=" ".join(warnings) or None)
        return {"status": "completed", "scan_id": scan_id, "vulns": all_vulns, "score": score, "counts": counts,
                "warnings": warnings, "inventory": rows}
    except Exception as e:
        logger.exception("Installed-software scan failed (scan_id=%s)", scan_id)
        detail = _public_error(e)
        db.update_scan_status(scan_id, "failed", status_detail=detail)
        return {"status": "failed", "scan_id": scan_id, "error": detail}


def _warnings(result, rows, n_assessed, n_failed, by_reason, limit, time_budget_hit, failed_lookups, all_vulns):
    w = []
    if result.status == STATUS_PARTIAL:
        w.append("The registry inventory is PARTIAL: some locations or entries could not be read, so applications may "
                 "be missing from this scan.")
    if n_failed:
        w.append(f"NVD vulnerability data was unavailable or incomplete for {n_failed} application(s); they were NOT "
                 "assessed - this is not a clean result. Rescan once NVD is reachable.")
    if by_reason.get("no_version"):
        w.append(f"{by_reason['no_version']} application(s) record no version, so their applicability is UNKNOWN and "
                 "they were not sent to NVD.")
    if by_reason.get("over_limit"):
        w.append(f"Only the first {limit} distinct products were assessed; {by_reason['over_limit']} further "
                 "application(s) were not (raise SENTRIX_MAX_INVENTORY_ASSESSMENTS to assess more).")
    if time_budget_hit:
        w.append(f"The time budget ran out: {by_reason.get('time_budget', 0)} application(s) were not assessed.")
    skipped = sum(by_reason.get(k, 0) for k in ("driver_package", "language_pack", "unidentifiable_name"))
    if skipped:
        w.append(f"{skipped} entr{'y' if skipped == 1 else 'ies'} (driver packages, language packs or unidentifiable "
                 "names) were not assessed.")
    if n_assessed or all_vulns:
        w.append("Applications not in SentriX's product catalogue are matched by NAME ONLY, so their findings are "
                 "POTENTIAL at most. A CVE match shows the version falls in a vulnerable range; it does not prove the "
                 "software is exploitable on this computer.")
    if not all_vulns and not n_failed:
        w.append("No CVEs matched the assessed applications. This reflects NVD data for the identities SentriX could "
                 "establish; it is not proof that the computer is secure.")
    w.append("Registry-based inventory can miss portable applications and components without an uninstall entry.")
    return w
