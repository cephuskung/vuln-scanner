"""Polls scheduled_scans for due jobs and kicks off scans in a thread.

Started once from app.py with start_scheduler(execute_scan_fn).
"""

import logging

from apscheduler.schedulers.background import BackgroundScheduler
from database import db
from scanner.jobs import submit_scan, ScanRejected
from vulnerability.kev_feed import refresh_kev_cache
from vulnerability.epss_feed import refresh_epss_cache
from posture.posture_calc import snapshot_posture
import threading

logger = logging.getLogger(__name__)

_scheduler = None


def start_scheduler(execute_scan_fn=None):
    """execute_scan_fn is accepted for backward compatibility and ignored:
    due scans now go through scanner.jobs.submit_scan (validation, duplicate
    rejection, queued state, ownership)."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    _scheduler = BackgroundScheduler()

    def check_due_scans():
        for job in db.get_due_scheduled_scans():
            try:
                submit_scan(
                    job["target"], created_by=job.get("created_by"),
                    scan_type="scheduled", asset_id=job["asset_id"],
                )
            except ScanRejected as e:
                # e.g. the previous run of this schedule is still going, or
                # the stored target is no longer valid. Skip this cycle.
                logger.warning("Scheduled scan #%s for %s skipped: %s", job["id"], job["target"], e)
            except Exception:
                logger.exception("Scheduled scan #%s for %s could not be started", job["id"], job["target"])
            finally:
                db.bump_scheduled_scan(job["id"], job["interval_minutes"])

    _scheduler.add_job(check_due_scans, "interval", minutes=1, id="scheduled_scan_check")

    # Refresh the CISA KEV cache once at startup, then daily.
    threading.Thread(target=refresh_kev_cache, daemon=True).start()
    _scheduler.add_job(refresh_kev_cache, "interval", hours=24, id="kev_refresh")

    # Refresh the EPSS cache once at startup, then daily.
    threading.Thread(target=refresh_epss_cache, daemon=True).start()
    _scheduler.add_job(refresh_epss_cache, "interval", hours=24, id="epss_refresh")

    # Snapshot posture once at startup, then daily.
    threading.Thread(target=snapshot_posture, daemon=True).start()
    _scheduler.add_job(snapshot_posture, "interval", hours=24, id="posture_snapshot")

    _scheduler.start()
    return _scheduler
