"""Shared vulnerability-assessment steps.

The Network Scan pipeline (scanner/pipeline.py), the Software Scan
(scanner/software_scan.py) and the System Scan (scanner/system_scan.py) all
turn "CVE candidates returned by the matching engine" into fully enriched
findings the same way. That logic lives here ONCE so the three scan types
cannot drift apart: KEV/EPSS enrichment, contextual risk, applicability and
confidence all go through the existing engine modules.

Nothing here does CVE matching - that remains vulnerability/cve_lookup.py's
search_cves(). This module only enriches what it returns.
"""
import logging
from types import SimpleNamespace

from database import db
from assets.asset_intel import get_asset_profile
from risk.contextual_risk import calculate_contextual_risk, priority_label
from risk.confidence import calculate_vulnerability_confidence
from vulnerability.applicability import assess_applicability

logger = logging.getLogger(__name__)


def load_intel():
    """Threat-intel + risk configuration, read once per scan."""
    blast_map = db.get_blast_radius_map()
    return SimpleNamespace(
        kev_ids=db.get_kev_cve_ids(),
        epss_map=db.get_epss_scores(),
        blast_map=blast_map,
        weights=db.get_risk_weights(),
        max_blast=max(blast_map.values()) if blast_map else 0,
    )


def asset_context_for(asset_id):
    """Exposure/criticality/business-impact used by contextual risk, or None
    when the scan is not tied to an asset (e.g. a Software Scan)."""
    if asset_id is None:
        return None
    profile = get_asset_profile(asset_id)
    if profile and profile.get("asset"):
        a = profile["asset"]
        return {
            "exposure": a.get("exposure"),
            "criticality": a.get("criticality"),
            "business_impact": a.get("business_impact"),
        }
    return None


def enrich_findings(vulns, intel, asset_context, product, vendor, version, cpe, refine_applicability=None):
    """Adds, in place, to every finding returned by search_cves():
    is_kev / epss_score, contextual_priority + priority_label,
    applicability_status/_reason and vulnerability_confidence/_reason.

    refine_applicability(finding, base_result) -> {"applicability_status",
    "applicability_reason"} lets the Software/System scans map the engine's
    CONFIRMED/PROBABLE/UNCONFIRMED onto the finer CONFIRMED / PROBABLE /
    POTENTIAL / INDETERMINATE vocabulary BEFORE confidence is computed, so the
    confidence score and its explanation always agree with the stored status.
    """
    for v in vulns:
        cve_id = v.get("cve_id")
        is_kev = bool(cve_id and cve_id in intel.kev_ids)
        epss_score = intel.epss_map.get(cve_id) if cve_id else None
        blast_radius = intel.blast_map.get(cve_id, 0) if cve_id else 0

        v["is_kev"] = is_kev
        v["epss_score"] = epss_score

        v["contextual_priority"] = calculate_contextual_risk(
            vuln=v,
            asset=asset_context,
            weights=intel.weights,
            blast_radius=blast_radius,
            max_blast_radius=intel.max_blast,
            is_kev=is_kev,
        )
        v["priority_label"] = priority_label(v["contextual_priority"])

        # Applicability (IVMP Phase 11): how well-supported is the CVE-to-
        # software correlation. Reads evidence already on the finding.
        result = assess_applicability(v, product, vendor, version, cpe)
        if refine_applicability is not None:
            result = refine_applicability(v, result)
        v["applicability_status"] = result["applicability_status"]
        v["applicability_reason"] = result["applicability_reason"]

        # Confidence (IVMP Phase 9): runs after applicability so the stored
        # status and the confidence explanation agree.
        confidence_result = calculate_vulnerability_confidence(v)
        v["vulnerability_confidence"] = confidence_result["vulnerability_confidence"]
        v["confidence_reason"] = confidence_result["confidence_reason"]
    return vulns
