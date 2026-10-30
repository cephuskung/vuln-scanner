"""IVMP Phase 9: Vulnerability Confidence Scoring.

Adds a confidence score to each finding that is deliberately SEPARATE from
severity (risk/risk_score.py) and contextual_priority
(risk/contextual_risk.py):

  - severity / cvss_score    -> "how bad would this be if exploited"
  - contextual_priority      -> "how urgently should we fix this, given
                                 this asset's exposure/criticality/blast
                                 radius/KEV/EPSS"
  - vulnerability_confidence -> "how sure are we this finding is real and
                                 practically exploitable as detected"

A finding can be CRITICAL severity and still low-confidence - e.g.
CVE-2023-38408 affects OpenSSH < 9.3p2 by version, but real-world
exploitation additionally depends on ssh-agent forwarding being in use and
a loadable PKCS#11/FIDO module being reachable on the client. Version
matching alone can't confirm those conditions, so a version-only match
for that CVE should be reported with lower confidence than, say, a CVE
that's unconditionally exploitable on any listener at the matched version.

Scope note: this module scores evidence QUALITY (how well the detected
service correlates to the CVE, and whether the CVE is known to carry
extra preconditions we can't verify remotely). It does not change what
counts as a match - vulnerability/cve_lookup.py's CONFIDENCE_THRESHOLD
gate is untouched, and nothing here removes or re-filters a finding that
already passed that gate. It only annotates it.

IVMP Phase 10 update: also folds in scanner/config_validator.py's
config_validation results (attached to each finding by scanner/pipeline.py
as "config_validation" / "config_evidence"). Config validation only ever
records "confirmed" for things the scan directly observed, so a confirmed
check is corroborating evidence the finding is real - it nudges confidence
up slightly. "not_confirmed" and "unknown" checks are never treated as
negative signals here (config_validator.py is explicit that "unknown"
means "not yet determined", not "absent" or "unsafe"), so only confirmed
checks move the score, and only upward. This does not change the CVE
conditional-exploitation penalties below, and it does not touch
contextual_priority or cvss_score - config_validator.py's own
confidence_modifier field is intentionally left unused/unapplied, per its
docstring, in favor of the explicit handling here.

IVMP Phase 11 update: also applies an additive adjustment based on
vulnerability/applicability.py's applicability_status (set by
scanner/pipeline.py before this function runs, using
vulnerability/applicability.py's now-conservative CONFIRMED/PROBABLE/
UNCONFIRMED classification - see that module for how those are derived).
CONFIRMED applies no adjustment. PROBABLE and UNCONFIRMED apply a fixed
penalty large enough to be visible in the final score even when every
other signal in this module is maxed out (e.g. a clean CPE match with
product+vendor+version all present used to leave PROBABLE findings
sitting at 1.00 with only a token -0.05 applied - that was the bug this
revision fixes). This adjustment is purely additive on top of the existing
scoring below; nothing above is replaced, reordered, or recomputed
differently because of it, and the final score is still clamped to
[MIN_CONFIDENCE, MAX_CONFIDENCE].
"""

# CVEs (or CVE substrings matched in the description) that are documented
# as requiring a specific runtime configuration or user action beyond
# "the vulnerable version is running" - i.e. version match alone is not
# sufficient evidence of real-world exploitability. Deliberately a small,
# explicit list rather than a heuristic guess, so it only ever fires on
# cases we can point to a reason for; unlisted CVEs are scored purely on
# match-evidence quality.
#
# Also imported by vulnerability/applicability.py, so the two modules
# never drift out of sync on what counts as "conditional."
KNOWN_CONDITIONAL_CVES = {
    "CVE-2023-38408": "exploitation requires ssh-agent forwarding and a loadable PKCS#11/FIDO module",
}

# Free-text signals in an NVD description that suggest exploitation is
# gated on a non-default configuration, a specific attacker capability, or
# another precondition the scanner has no way to confirm remotely. This is
# a coarse, best-effort signal (used only to slightly reduce confidence
# and explain why) - it never rejects a finding outright.
#
# Also imported by vulnerability/applicability.py - see note above.
CONDITIONAL_KEYWORDS = (
    "requires that", "only if", "when configured", "non-default configuration",
    "if enabled", "must be enabled", "depends on", "under certain conditions",
)

# Mirrors scanner/config_validator.py's CONFIRMED sentinel. Not imported
# directly so this module keeps no hard dependency on the config
# validator's internals - only on the string contract it documents.
CONFIG_CONFIRMED = "confirmed"

# config_validation checks that count as corroborating evidence when
# confirmed. Each maps to the small bonus applied and the human-readable
# note appended to confidence_reason. Deliberately a short, explicit list
# (mirroring KNOWN_CONDITIONAL_CVES above) rather than "boost on any
# confirmed check" - service_exposed and version_detected are the two
# checks that directly corroborate that this finding's target evidence
# (open service, matched version) is real and not, say, a stale port scan
# or a version_detected value that never got a corresponding confirmation.
CONFIG_CONFIDENCE_BONUSES = {
    "service_exposed": (0.05, "service exposure confirmed by config validation"),
    "version_detected": (0.05, "version detection confirmed by config validation"),
}

# Applicability adjustment amounts (IVMP Phase 11, revised).
# CONFIRMED intentionally has no entry - it applies no adjustment at all.
# PROBABLE and UNCONFIRMED apply a fixed penalty within the required
# range (PROBABLE: -0.10 to -0.15, UNCONFIRMED: -0.25 to -0.35). A single
# fixed value per tier (rather than a variable amount) keeps the score
# deterministic and reproducible for the same finding.
APPLICABILITY_PROBABLE_PENALTY = 0.12
APPLICABILITY_UNCONFIRMED_PENALTY = 0.30
# Software Scan / System Scan tiers (see scanner/software_scan.py): POTENTIAL sits
# between PROBABLE and UNCONFIRMED - the version is in the affected range but
# something stops us trusting it as strongly (distribution-packaged software
# whose fixes may be backported, a partial version, or a name-only product
# match). INDETERMINATE means the affected range could not be evaluated at all
# (no version), so it takes the same penalty as UNCONFIRMED.
APPLICABILITY_POTENTIAL_PENALTY = 0.20
APPLICABILITY_INDETERMINATE_PENALTY = 0.30

APPLICABILITY_ADJUSTMENTS = {
    "PROBABLE": (
        -APPLICABILITY_PROBABLE_PENALTY,
        "Applicability PROBABLE: version affected but vulnerable condition not directly verified",
    ),
    "UNCONFIRMED": (
        -APPLICABILITY_UNCONFIRMED_PENALTY,
        "Applicability UNCONFIRMED: insufficient evidence to correlate this CVE to the detected service",
    ),
    "POTENTIAL": (
        -APPLICABILITY_POTENTIAL_PENALTY,
        "Applicability POTENTIAL: version appears affected but identity or version evidence is limited (see applicability reason)",
    ),
    "INDETERMINATE": (
        -APPLICABILITY_INDETERMINATE_PENALTY,
        "Applicability INDETERMINATE: the affected-version range could not be evaluated (version unknown)",
    ),
}

MIN_CONFIDENCE = 0.0
MAX_CONFIDENCE = 1.0


def calculate_vulnerability_confidence(vuln):
    """Returns {"vulnerability_confidence": float 0-1, "confidence_reason": str}
    for a single enriched finding.

    vuln: the same per-finding dict used throughout the pipeline - expects
    (all optional, missing = treated as absent evidence):
      - cve_id
      - match_confidence   (0-1, set by vulnerability/cve_lookup.py's
                             CPE-based scoring - the strongest single
                             signal we already have for "is this really
                             the same product/version")
      - match_evidence      dict with product/vendor/version/cpe_confirmed,
                             also set by cve_lookup.py
      - description         NVD's free-text CVE description, if available
      - config_validation    dict of check_name -> "confirmed" | "not_confirmed"
                             | "unknown", set by scanner/config_validator.py
                             via scanner/pipeline.py. Only "confirmed"
                             entries ever affect the score, and only
                             upward - see CONFIG_CONFIDENCE_BONUSES.
      - applicability_status "CONFIRMED" | "PROBABLE" | "UNCONFIRMED", set
                             by vulnerability/applicability.py via
                             scanner/pipeline.py (IVMP Phase 11). Only
                             PROBABLE/UNCONFIRMED ever affect the score,
                             and only downward - see
                             APPLICABILITY_ADJUSTMENTS.
    """
    reasons = []

    match_confidence = vuln.get("match_confidence")
    evidence = vuln.get("match_evidence") or {}

    # --- Base score ---
    # match_confidence (when present) already encodes product-identity +
    # vendor-agreement + version-agreement strength from the CPE matcher,
    # so it's the strongest starting point available. Findings with no
    # match_confidence at all (e.g. added through a path other than
    # vulnerability/cve_lookup.py's search_cves()) start from a
    # conservative baseline instead of assuming full confidence.
    if match_confidence is not None:
        score = float(match_confidence)
        reasons.append(f"CPE match confidence {score:.2f}")
    else:
        score = 0.4
        reasons.append("no CPE match confidence recorded (treated conservatively)")

    # --- Positive signals ---
    if evidence.get("cpe_confirmed"):
        reasons.append("CPE-confirmed product match")
    else:
        score -= 0.15
        reasons.append("not CPE-confirmed (keyword-only match)")

    if evidence.get("product") and evidence.get("vendor"):
        reasons.append("product and vendor both identified")
    elif evidence.get("product"):
        score -= 0.05
        reasons.append("vendor not identified")
    else:
        score -= 0.10
        reasons.append("no product identity available")

    version = evidence.get("version")
    if version:
        reasons.append(f"detected version available ({version})")
    else:
        score -= 0.15
        reasons.append("no detected version to verify against the CVE's affected range")

    # --- Negative signals: conditional / configuration-dependent exploitation ---
    cve_id = vuln.get("cve_id")
    description = (vuln.get("description") or "").lower()

    if cve_id and cve_id in KNOWN_CONDITIONAL_CVES:
        score -= 0.20
        reasons.append(f"exploitation is conditional: {KNOWN_CONDITIONAL_CVES[cve_id]} (unconfirmed by remote scan)")
    elif any(kw in description for kw in CONDITIONAL_KEYWORDS):
        score -= 0.10
        reasons.append("CVE description suggests exploitation depends on a configuration/precondition we can't confirm remotely")

    # --- Positive signals: remotely-confirmed configuration evidence ---
    # config_validation only ever marks a check "confirmed" when it was
    # directly observed from scan data (see scanner/config_validator.py);
    # "not_confirmed" and "unknown" are left alone here, since neither one
    # is evidence the finding is wrong - just evidence we don't yet know.
    config_validation = vuln.get("config_validation") or {}
    for check_name, (bonus, note) in CONFIG_CONFIDENCE_BONUSES.items():
        if config_validation.get(check_name) == CONFIG_CONFIRMED:
            score += bonus
            reasons.append(note)

    # --- Applicability adjustment (IVMP Phase 11, revised) ---
    # Additive nudge on top of everything above. applicability_status is
    # set by vulnerability/applicability.py (via scanner/pipeline.py)
    # BEFORE this function runs. CONFIRMED gets no adjustment; PROBABLE
    # and UNCONFIRMED apply a fixed penalty (see APPLICABILITY_ADJUSTMENTS)
    # large enough to move the score even when every signal above is
    # maxed out - this is what keeps a PROBABLE finding (clean CPE match,
    # product+vendor+version all present, no config evidence of the
    # specific vulnerable condition) from landing at 1.00.
    applicability_status = vuln.get("applicability_status")
    if applicability_status in APPLICABILITY_ADJUSTMENTS:
        adjustment, note = APPLICABILITY_ADJUSTMENTS[applicability_status]
        score += adjustment
        reasons.append(note)
    elif applicability_status == "CONFIRMED":
        reasons.append("Applicability CONFIRMED: vulnerable condition directly verified, no confidence adjustment")

    score = round(min(max(score, MIN_CONFIDENCE), MAX_CONFIDENCE), 2)
    reason = "; ".join(reasons)

    return {
        "vulnerability_confidence": score,
        "confidence_reason": reason,
    }