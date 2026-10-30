"""IVMP Phase 3: Attack Path Analysis - graph construction.

Models the environment as a directed graph an attacker could traverse:
  - a synthetic "internet" node
  - one node per scanned asset
  - internet -> asset, when the asset is internet-exposed (Phase 1 data)
  - asset -> asset, when the source asset has an exploitable finding
    (CRITICAL/HIGH severity, CVSS >= 7) and the target is on the same
    subnet - a simple, explainable stand-in for "an attacker who
    compromises this host can reach other hosts near it"

Edge weight = how easy the step is (lower = easier). CVSS and CISA KEV
status (Phase 2 data) both pull the weight down, since well-known,
easily-exploited, actively-exploited findings make for an easier hop.

This is intentionally a *derived* graph (built fresh from live scan data on
each request, not a separately-maintained table) so it can never drift out
of sync with what your scans actually found.
"""

import ipaddress
import networkx as nx
from database import db

EXPLOITABLE_SEVERITIES = ("CRITICAL", "HIGH")
MIN_CVSS_FOR_PIVOT = 7.0
NO_FINDING_EXPOSED_WEIGHT = 8.0  # exposed asset, but nothing confirmed exploitable yet - still a possible entry


def _same_subnet(ip_a, ip_b, prefix=24):
    try:
        network = ipaddress.ip_network(f"{ip_a}/{prefix}", strict=False)
        return ipaddress.ip_address(ip_b) in network
    except ValueError:
        return False  # non-IP targets (hostnames) can't be subnet-compared - treated as unconnected


def _exploitable_vulns(asset_id, kev_ids):
    """This asset's findings strong enough to plausibly grant an attacker a foothold."""
    vulns = db.get_asset_vulnerabilities(asset_id)
    exploitable = []
    for v in vulns:
        cvss = float(v["cvss_score"]) if v.get("cvss_score") is not None else 0.0
        if v.get("severity") in EXPLOITABLE_SEVERITIES and cvss >= MIN_CVSS_FOR_PIVOT:
            exploitable.append({**v, "cvss_score": cvss, "is_kev": v.get("cve_id") in kev_ids})
    return exploitable


def _edge_weight(best_vuln):
    kev_bonus = 2.0 if best_vuln["is_kev"] else 0.0
    return round(max(0.5, 10 - best_vuln["cvss_score"] - kev_bonus), 1)


def build_attack_graph():
    G = nx.DiGraph()
    G.add_node("internet", label="Internet", type="entrypoint", criticality=None)

    assets = db.get_assets()
    kev_ids = db.get_kev_cve_ids()
    exploitable_by_asset = {a["id"]: _exploitable_vulns(a["id"], kev_ids) for a in assets}

    for asset in assets:
        node_id = f"asset:{asset['id']}"
        G.add_node(
            node_id,
            label=asset.get("hostname") or asset.get("name") or asset["ip_address"],
            type="asset",
            criticality=asset.get("criticality"),
            exposure=asset.get("exposure"),
            ip_address=asset["ip_address"],
        )

        if asset.get("exposure") == "EXTERNAL":
            exploitable = exploitable_by_asset[asset["id"]]
            if exploitable:
                best = max(exploitable, key=lambda v: v["cvss_score"])
                weight = _edge_weight(best)
                reason = f"internet-exposed, exploitable {best.get('cve_id') or 'finding'}"
            else:
                weight = NO_FINDING_EXPOSED_WEIGHT
                reason = "internet-exposed"
            G.add_edge("internet", node_id, weight=weight, reason=reason)

    for asset in assets:
        exploitable = exploitable_by_asset[asset["id"]]
        if not exploitable:
            continue
        best = max(exploitable, key=lambda v: v["cvss_score"])
        weight = _edge_weight(best)

        for other in assets:
            if other["id"] == asset["id"]:
                continue
            if _same_subnet(asset["ip_address"], other["ip_address"]):
                G.add_edge(
                    f"asset:{asset['id']}", f"asset:{other['id']}",
                    weight=weight,
                    reason=f"lateral movement via {best.get('cve_id') or 'exploitable finding'}",
                )

    return G
