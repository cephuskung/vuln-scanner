SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "Unknown": 2,
}


def calculate_risk(vulnerabilities):
    """Total risk score plus a per-severity breakdown.

    Uses each finding's CVSS base score when available (more precise),
    falling back to a flat severity weight otherwise.
    """
    score = 0.0

    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "Unknown": 0}

    for v in vulnerabilities:
        severity = v.get("severity") or "Unknown"
        if severity not in severity_count:
            severity = "Unknown"

        cvss = v.get("cvss_score")
        score += float(cvss) if cvss is not None else SEVERITY_WEIGHTS[severity]

        severity_count[severity] += 1

    return round(score, 1), severity_count
