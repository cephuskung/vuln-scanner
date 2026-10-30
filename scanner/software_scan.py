"""Software Scan: assess user-specified software (vendor / product / version)
against NVD using the EXISTING CVE engine.

There is no second matching engine here. Every CVE comes from
vulnerability/cve_lookup.py's search_cves() (product identity, CPE data and
affected-version ranges are all verified there), and enrichment - KEV/EPSS,
contextual risk, applicability, confidence - goes through scanner/assessment.py,
the same code the Network Scan uses. This module only:

  1. chooses how to call search_cves() for the identity the user gave us,
  2. maps the engine's applicability onto the four tiers
     CONFIRMED / PROBABLE / POTENTIAL / INDETERMINATE (see classify below),
  3. records honestly what could NOT be assessed.

Applicability tiers (deterministic, no guessing):
  CONFIRMED     the vulnerable condition was directly observed (config
                validation). A software-only scan never observes anything, so
                this tier is effectively reserved for network/system evidence.
  PROBABLE      NVD's CPE data confirms product + vendor, the exact version
                (>= 3 components) lies inside the CVE's affected range, and
                the identity was well established (catalogue/CPE/vendor+product).
  POTENTIAL     version is in the affected range, but something limits trust:
                a distribution package (fixes may be backported without a
                version bump), a partial version, or a name-only product match.
  INDETERMINATE no version known, so the affected range cannot be evaluated.
"""
import logging

from database import db
from risk.risk_score import calculate_risk
from scanner.assessment import load_intel, asset_context_for, enrich_findings
from scanner.pipeline import _SCAN_SLOTS, _public_error
from vulnerability.cve_lookup import search_cves, clean_version, LOOKUP_FAILURES_KEY
from vulnerability.software_catalog import describe, version_precision

logger = logging.getLogger(__name__)

DISTRO_ADVICE = (
    "This software came from an OS package: apply the distribution's security updates and confirm "
    "against the distributor's CVE tracker, which records fixes backported without a version change."
)


def classify(finding, base, ctx):
    """Map the engine's applicability result onto the four-tier vocabulary.

    base: assess_applicability()'s {"applicability_status", "applicability_reason"}
    ctx:  {"version", "identity_source", "retrieval", "distro_packaged"}
    """
    if base["applicability_status"] == "CONFIRMED":
        return base                                   # direct evidence of the condition: never downgrade

    if not ctx["version"]:
        return {
            "applicability_status": "INDETERMINATE",
            "applicability_reason": (
                "no version known, so the affected-version range cannot be evaluated; NVD does not tie this CVE "
                "to specific versions, so it may or may not apply to the installed release"
            ),
        }

    caveats = []
    if ctx.get("distro_packaged"):
        caveats.append("installed from a distribution package - the distributor may have backported the fix "
                       "without changing the upstream version number")
    if version_precision(ctx["version"]) < 3:
        caveats.append(f"only a partial version ({ctx['version']}) is known - the affected range may start or end within it")
    if ctx["identity_source"] == "name_only" or ctx.get("retrieval") == "keyword":
        caveats.append("the product was identified by name only (no confirmed vendor:product)")
    if base["applicability_status"] == "UNCONFIRMED":
        caveats.append(base["applicability_reason"])

    if caveats:
        return {"applicability_status": "POTENTIAL",
                "applicability_reason": "version falls in the affected range, but " + "; ".join(caveats)}
    return {
        "applicability_status": "PROBABLE",
        "applicability_reason": (
            f"{base['applicability_reason']}; identity established via {ctx['identity_source'].replace('_', ' ')}, "
            f"version {ctx['version']} is inside the CVE's affected range"
        ),
    }


def _lookup_failed(memo, product, version):
    label = f"{(product or '').lower()} {clean_version(version)}".strip()
    return label in (memo.get(LOOKUP_FAILURES_KEY) or [])


def assess_item(item, memo, intel, asset_ctx, *, source="user", distro_packaged=False, label=None):
    """Run ONE software item through the existing engine.

    Returns {"findings": [...], "retrieval": "cpe"|"keyword"|None,
             "lookup_failed": bool, "note": str|None}. The findings are fully
    enriched (priority, applicability tier, confidence, evidence)."""
    version = item["version"]
    retrieval = None
    vulns = []

    if item["cpe"]:
        retrieval = "cpe"
        vulns = search_cves(service=None, product=item["cpe_product"], vendor=item["cpe_vendor"],
                            version=version, cpe=item["cpe"], memo=memo)
        failed = _lookup_failed(memo, item["cpe_product"], version)
        # Names the user typed (not in the catalogue, not a CPE) are only trusted when NVD actually
        # has CVEs under exactly those vendor:product names. An empty answer may just mean our
        # guess at NVD's naming was wrong, so retry via the engine's own keyword path - never
        # report "nothing found" on the strength of a guessed name.
        if not vulns and not failed and item["identity_source"] == "user_names":
            retrieval = "keyword"
            vulns = search_cves(service=None, product=item["display_product"], vendor=item["display_vendor"],
                                version=version, cpe=None, memo=memo)
            failed = _lookup_failed(memo, item["display_product"], version)
    else:
        retrieval = "keyword"
        vulns = search_cves(service=None, product=item["display_product"], vendor=item["display_vendor"],
                            version=version, cpe=None, memo=memo)
        failed = _lookup_failed(memo, item["display_product"], version)

    ctx = {"version": version, "identity_source": item["identity_source"],
           "retrieval": retrieval, "distro_packaged": distro_packaged}
    for v in vulns:
        ev = dict(v.get("match_evidence") or {})
        ev.update({"identity_source": item["identity_source"], "retrieval": retrieval, "source": source,
                   "input_version": version, "distro_packaged": distro_packaged})
        v["match_evidence"] = ev
        if distro_packaged:
            v["remediation"] = f"{v.get('remediation') or ''} {DISTRO_ADVICE}".strip()

    enrich_findings(
        vulns, intel, asset_ctx, item["cpe_product"] or item["display_product"],
        item["cpe_vendor"] or item["display_vendor"], version, item["cpe"],
        refine_applicability=lambda v, base: classify(v, base, ctx),
    )

    notes = []
    if not version:
        notes.append("version unknown - affected-version ranges could not be evaluated")
    if retrieval == "keyword" and item["identity_source"] in ("name_only", "user_names"):
        notes.append("matched by product name (keyword search); vendor:product not confirmed")
    if failed:
        notes.append("NVD lookup failed or was incomplete - NOT assessed")
    return {"findings": vulns, "retrieval": retrieval, "lookup_failed": failed,
            "note": "; ".join(notes) or None}


def run_software_scan(scan_id, items, asset_id=None):
    """Execute a queued software scan. items: normalised dicts from
    vulnerability.software_catalog. Lifecycle matches every other scan:
    queued -> running -> completed/failed, with the reason stored on failure."""
    with _SCAN_SLOTS:
        return _execute(scan_id, items, asset_id)


def _execute(scan_id, items, asset_id):
    memo = {}
    try:
        db.update_scan_status(scan_id, "running")
        intel = load_intel()
        asset_ctx = asset_context_for(asset_id)
        all_vulns, inventory = [], []

        for item in items:
            res = assess_item(item, memo, intel, asset_ctx)
            label = describe(item)
            if res["findings"]:
                db.save_vulnerabilities(scan_id, None, label[:120], res["findings"])
            for v in res["findings"]:
                all_vulns.append({**v, "port": None, "service": label, "product": item["display_product"],
                                  "vendor": item["display_vendor"], "version": item["version"], "cpe": item["cpe"]})
            inventory.append({
                "vendor": item["display_vendor"], "product": item["display_product"], "version": item["version"],
                "upstream_version": item["version"], "source": "user",
                "cpe_vendor": item["cpe_vendor"], "cpe_product": item["cpe_product"],
                "assessment": "lookup_failed" if res["lookup_failed"] else "assessed",
                "note": res["note"], "findings_count": len(res["findings"]),
            })

        db.save_software_inventory(scan_id, inventory)
        score, counts = calculate_risk(all_vulns)

        warnings = []
        unknown = [i for i in inventory if not i["version"]]
        failed = [i for i in inventory if i["assessment"] == "lookup_failed"]
        if failed:
            warnings.append(
                "Vulnerability data (NVD) was unavailable or incomplete for: "
                + ", ".join(f"{i['product']} {i['version'] or ''}".strip() for i in failed)
                + ". These items were NOT assessed - this is not a clean result; rescan once NVD is reachable."
            )
        if unknown:
            warnings.append(
                f"{len(unknown)} item(s) have no version, so affected-version ranges cannot be evaluated: only CVEs "
                "NVD does not tie to specific versions can be listed (INDETERMINATE). Supply the exact version for a real assessment."
            )
        partial = [i for i in items if i["version"] and version_precision(i["version"]) < 3]
        if partial:
            warnings.append(
                "Partial version(s) given (" + ", ".join(f"{i['display_product']} {i['version']}" for i in partial)
                + "): CVEs defined by a version RANGE cannot be evaluated against a partial version and are not listed, "
                "so results for these items may be incomplete. Supply the full version (e.g. 3.0.2)."
            )
        if not all_vulns and not failed:
            warnings.append("No CVEs matched the supplied software. This reflects NVD data for the identities given, "
                            "not proof that the software is secure.")

        db.set_scan_info(scan_id, {"mode": "software", "items": len(items),
                                   "identity_sources": sorted({i["identity_source"] for i in items})})
        db.update_scan_status(scan_id, "completed", total_risk=score, status_detail=" ".join(warnings) or None)
        return {"status": "completed", "scan_id": scan_id, "vulns": all_vulns, "score": score,
                "counts": counts, "warnings": warnings}
    except Exception as e:
        logger.exception("Software scan failed (scan_id=%s)", scan_id)
        detail = _public_error(e)
        db.update_scan_status(scan_id, "failed", status_detail=detail)
        return {"status": "failed", "scan_id": scan_id, "error": detail}
