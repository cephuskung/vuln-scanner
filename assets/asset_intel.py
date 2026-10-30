"""IVMP Phase 1: Asset Intelligence.

Turns raw scan output into a maintained per-asset profile: current services,
full vulnerability history across all scans, and current risk - not just
what one scan found, but what's true about the asset right now.
"""

from database import db


def refresh_asset_services(asset_id, scan_id, open_ports):
    """Call this right after a scan completes and vulnerabilities are saved.

    Marks the asset's previous service snapshot stale and records the new
    one, so `get_current_services` always reflects the most recent scan
    while history is preserved (is_current=FALSE rows aren't deleted).
    """
    db.mark_services_stale(asset_id)
    db.insert_current_services(asset_id, scan_id, open_ports)


def get_asset_profile(asset_id):
    """Full profile used by the asset detail page / API."""
    asset = db.get_asset(asset_id)
    if asset is None:
        return None

    return {
        "asset": asset,
        "services": db.get_current_services(asset_id),
        "vulnerabilities": db.get_asset_vulnerabilities(asset_id),
        "risk_score": db.get_asset_current_risk(asset_id),
        "scan_history": db.get_asset_scan_history(asset_id),
    }
