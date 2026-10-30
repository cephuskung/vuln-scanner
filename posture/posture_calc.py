"""IVMP Phase 4: Security Posture Management.

Computes a 0-100 score per category from every asset's *current* findings
(latest completed scan per asset - not full history, since posture should
reflect the environment as it stands today). Categories are bucketed by
service, using the same "what actually implements this service" thinking
as the CVE matching in vulnerability/cve_lookup.py.

Patch Management and Configuration Security don't have a clean 1:1 mapping
from raw scan data the way Network/Host/Web do - they're heuristics
(documented inline) rather than a precise measurement, since this scanner
doesn't do dedicated patch-age tracking or configuration auditing. Treat
those two scores as directional, not authoritative.
"""

from database import db
from risk.risk_score import SEVERITY_WEIGHTS

CATEGORY_SERVICE_MAP = {
    "network": {"ssh", "ftp", "sftp", "telnet", "smtp", "domain", "dns", "pop3", "imap"},
    "web": {"http", "https", "http-proxy", "http-alt"},
    "host": {"microsoft-ds", "smb", "netbios-ssn", "rdp", "upnp",
              "postgresql", "mysql", "mssql", "oracle", "mongodb"},
}

# how much a single point of SEVERITY_WEIGHTS costs a category score -
# tunable; higher = fewer findings needed to tank a category's score
CATEGORY_PENALTY_SCALE = 3
CONFIG_PENALTY_SCALE = 40


def _bucket(service):
    s = (service or "").lower()
    for category, services in CATEGORY_SERVICE_MAP.items():
        if s in services:
            return category
    return "host"  # unmapped services default to host-level rather than being dropped


def _category_score(vulns):
    if not vulns:
        return 100.0
    weight_sum = sum(SEVERITY_WEIGHTS.get(v.get("severity", "Unknown"), 2) for v in vulns)
    return round(max(0.0, 100 - weight_sum * CATEGORY_PENALTY_SCALE), 1)


def _patch_management_score(all_vulns):
    """Heuristic: what fraction of current findings are CRITICAL/HIGH -
    a proxy for "how much unpatched high-severity exposure exists right now"."""
    if not all_vulns:
        return 100.0
    high_crit = sum(1 for v in all_vulns if v.get("severity") in ("CRITICAL", "HIGH"))
    return round(max(0.0, 100 - (high_crit / len(all_vulns)) * 100), 1)


def _configuration_score(all_vulns):
    """Heuristic: MEDIUM/LOW findings often correlate with configuration
    weaknesses (exposed services, weak defaults) rather than unpatched CVEs -
    a weak but directionally useful signal given no dedicated config audit."""
    if not all_vulns:
        return 100.0
    medium_low = sum(1 for v in all_vulns if v.get("severity") in ("MEDIUM", "LOW"))
    return round(max(0.0, 100 - (medium_low / len(all_vulns)) * CONFIG_PENALTY_SCALE), 1)


def compute_posture():
    """Returns the current posture scores without persisting them."""
    all_vulns = db.get_current_vulnerabilities_all_assets()

    buckets = {"network": [], "web": [], "host": []}
    for v in all_vulns:
        buckets[_bucket(v.get("service"))].append(v)

    network_score = _category_score(buckets["network"])
    host_score = _category_score(buckets["host"])
    web_score = _category_score(buckets["web"])
    patch_score = _patch_management_score(all_vulns)
    config_score = _configuration_score(all_vulns)

    overall_score = round(
        (network_score + host_score + web_score + patch_score + config_score) / 5, 1
    )

    return {
        "overall_score": overall_score,
        "network_score": network_score,
        "host_score": host_score,
        "web_score": web_score,
        "patch_score": patch_score,
        "config_score": config_score,
    }


def snapshot_posture():
    """Computes and persists today's posture snapshot (upserts if one
    already exists for today, so this is safe to call more than once/day)."""
    scores = compute_posture()
    db.upsert_posture_snapshot(scores)
    return scores
