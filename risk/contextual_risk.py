"""IVMP Phase 2: Context-Aware Risk Prioritisation.
IVMP Phase 7 adds EPSS as an additional factor (see below).

Complements risk_score.py (which scores a whole scan) with a per-finding
score that answers "which of these should I fix first", using more than
just CVSS: real-world exploitation data (CISA KEV), predicted near-term
exploitation probability (EPSS), how exposed the asset is, how critical it
is to the business, and how many assets share this CVE.

    ContextualRisk = w1*CVSS + w2*KEV + w3*EPSS + w4*Exposure + w5*Criticality
                   + w6*BusinessImpact + w7*ComplexityInv + w8*BlastRadius
                   - controls*0.1

That weighted sum is then scaled by match_confidence - a 0-1 value
indicating how confident the vulnerability scanner is that the match
(e.g. CPE/version match) is actually correct. A low-confidence match
should not drive urgent remediation as strongly as a high-confidence one,
even if the underlying CVE looks severe. Findings without a
match_confidence field (e.g. from scanners that don't report it) default
to 1.0, i.e. full confidence, which preserves prior scoring behavior
exactly.

KEV and EPSS are deliberately both included rather than one replacing the
other: KEV is binary and retrospective ("this HAS been exploited",
high-confidence but narrow coverage - ~1,600 CVEs). EPSS is continuous and
forward-looking ("this IS LIKELY to be exploited in the next 30 days",
probabilistic but covers nearly every published CVE). A non-KEV finding
with a high EPSS score is exactly the kind of thing raw CVSS-only scoring
would under-prioritize.

Runs alongside calculate_risk() in risk_score.py - that function is
untouched, this is a new, additive calculation.
"""

CRITICALITY_SCALE = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25}


def calculate_contextual_risk(vuln, asset, weights, blast_radius, max_blast_radius, is_kev):
    """Returns a 0-100 contextual priority score for a single finding.

    vuln: dict with cvss_score, attack_complexity, compensating_controls,
          epss_score, match_confidence (optional, defaults to 1.0)
    asset: dict with exposure, criticality, business_impact
    weights: dict from database.db.get_risk_weights()
    blast_radius: how many distinct assets share this CVE
    max_blast_radius: the largest blast_radius value across the dataset, for normalization
    is_kev: True if this CVE is in the CISA Known Exploited Vulnerabilities catalog
    """
    cvss_norm = float(vuln.get("cvss_score") or 0) / 10
    exploit = 1.0 if is_kev else 0.2
    epss = float(vuln.get("epss_score") or 0)  # already a 0-1 probability, no normalization needed
    exposure = 1.0 if (asset or {}).get("exposure") == "EXTERNAL" else 0.4
    criticality = CRITICALITY_SCALE.get((asset or {}).get("criticality"), 0.5)
    impact = CRITICALITY_SCALE.get((asset or {}).get("business_impact"), 0.5)
    complexity_inv = 1.0 if (vuln.get("attack_complexity") or "").upper() == "LOW" else 0.4
    blast = (blast_radius / max_blast_radius) if max_blast_radius else 0
    controls = float(vuln.get("compensating_controls") or 0)

    # Confidence the scanner has in this vulnerability match (e.g. CPE/version
    # match quality). Missing field defaults to 1.0 so behavior is unchanged
    # for scanners/data that don't report it.
    match_confidence = vuln.get("match_confidence")
    confidence = 1.0 if match_confidence is None else float(match_confidence)
    confidence = min(max(confidence, 0.0), 1.0)

    score = (
        weights.get("cvss", 0.30) * cvss_norm
        + weights.get("exploit", 0.20) * exploit
        + weights.get("epss", 0.10) * epss
        + weights.get("exposure", 0.15) * exposure
        + weights.get("criticality", 0.15) * criticality
        + weights.get("business_impact", 0.10) * impact
        + weights.get("complexity", 0.05) * complexity_inv
        + weights.get("blast_radius", 0.05) * blast
        - controls * 0.1
    ) * confidence

    return round(min(max(score, 0), 1) * 100, 1)


def priority_label(score):
    if score >= 70:
        return "URGENT"
    if score >= 45:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"