"""Single entry point for starting scans from the web UI and the scheduler.

submit_scan() does, synchronously and before any background work starts:
  1. validate/normalise the target (invalid input is rejected with a clear
     message - no asset or scan row is created for it),
  2. reject a target that already has a queued/running scan (double-click,
     overlapping scheduled run),
  3. create the scan row as 'queued' so the user immediately gets a real
     scan id and the lifecycle is queued -> running -> completed/failed,
and then runs the scan in a daemon thread. The pipeline's own concurrency
cap decides when a queued scan actually starts.
"""
import hashlib
import ipaddress
import logging
import platform
import re
import threading

from database import db
from scanner.scanner import normalize_target, is_network_target, MAX_NETWORK_ADDRESSES
from scanner.pipeline import run_full_scan, run_network_scan
from scanner.software_scan import run_software_scan
from scanner.system_scan import run_system_scan
from scanner.software_inventory_scan import run_inventory_scan
from scanner.windows_system_scan import run_windows_system_scan, ACTIONS as WINDOWS_ACTIONS
from scanner.windows_defender import DefenderClient, DefenderInputError, validate_scan_path
from scanner.windows_inventory import describe_windows_os
from scanner.inventory import local_host_info
from scanner.system_collectors import (
    SystemScanError, validate_key_format, normalize_fingerprint, private_key_file, check_key_usable, _need,
)
from scanner.scanner import validate_target
from vulnerability.software_catalog import describe, MAX_ITEMS

logger = logging.getLogger(__name__)

# Serialises check-then-create so two simultaneous submissions for the same
# target can't both pass the "already active?" check.
_submit_lock = threading.Lock()


class ScanRejected(Exception):
    """The scan was not started; str(exc) is a user-facing reason."""


def _worker(_scan_id, _fn, /, *args, **kwargs):
    # positional-only: the wrapped function legitimately receives its own
    # scan_id=... keyword, which must not collide with these parameters.
    scan_id = _scan_id
    try:
        _fn(*args, **kwargs)
    except Exception:
        # run_full_scan/run_network_scan record their own failures; this is
        # the last-resort guard so a crash can never leave a scan 'queued'.
        logger.exception("Scan worker crashed (scan_id=%s)", scan_id)
        db.update_scan_status(
            scan_id, "failed",
            status_detail="Unexpected internal error while running the scan (details are in the server log).",
        )


def validate_scan_target(target):
    """Normalise a user-supplied target (IP, hostname or CIDR range) or
    raise ScanRejected with a user-facing reason; also enforces the maximum
    network size."""
    try:
        target = normalize_target(target)
    except ValueError as e:
        raise ScanRejected(str(e))
    if is_network_target(target):
        size = ipaddress.ip_network(target, strict=False).num_addresses
        if size > MAX_NETWORK_ADDRESSES:
            raise ScanRejected(
                f"{target} covers {size} addresses; the limit is {MAX_NETWORK_ADDRESSES}. Use a smaller range."
            )
    return target


def submit_scan(target, created_by=None, scan_type="manual", asset_id=None, wait=False):
    """Queue a scan and start it in the background. Returns
    (scan_id, is_network_scan). Raises ScanRejected with a user-facing
    reason when the scan is not started. wait=True runs it to completion
    in the calling thread (used by tests)."""
    target = validate_scan_target(target)
    network = is_network_target(target)

    with _submit_lock:
        if network:
            scan_id = db.create_scan_if_idle(target, None, created_by, "network", "queued")
        else:
            if asset_id is None:
                asset_id = db.upsert_asset(target)
            scan_id = db.create_scan_if_idle(target, asset_id, created_by, scan_type, "queued")
    if scan_id is None:
        raise ScanRejected(f"A scan for {target} is already queued or running.")

    if network:
        fn, args, kwargs = run_network_scan, (target,), {"created_by": created_by, "parent_scan_id": scan_id}
    else:
        fn, args, kwargs = run_full_scan, (target,), {
            "asset_id": asset_id, "created_by": created_by, "scan_type": scan_type, "scan_id": scan_id,
        }
    if wait:
        _worker(scan_id, fn, *args, **kwargs)
    else:
        threading.Thread(target=_worker, args=(scan_id, fn) + args, kwargs=kwargs, daemon=True).start()
    return scan_id, network


# ---------------------------------------------------------------------------
# Software Scan
# ---------------------------------------------------------------------------
def _software_label(items):
    """Scan target label (also the duplicate-submission key): the same
    software list can't be queued twice at once."""
    names = [describe(i) for i in items]
    if len(items) == 1:
        return f"software: {names[0]}"[:255]
    digest = hashlib.sha1("|".join(sorted(names)).encode()).hexdigest()[:8]
    return f"software: {len(items)} items [{digest}] {names[0]}, ..."[:255]


def submit_software_scan(items, created_by=None, asset_id=None, wait=False):
    """Queue a Software Scan for already-normalised items (see
    vulnerability.software_catalog). Optionally attach it to an asset so the
    asset's exposure/criticality feed contextual risk. Returns the scan id;
    raises ScanRejected with a user-facing reason."""
    if not items:
        raise ScanRejected("Enter at least one software item to assess.")
    if len(items) > MAX_ITEMS:
        raise ScanRejected(f"At most {MAX_ITEMS} software items can be assessed per scan.")
    if asset_id is not None and db.get_asset(asset_id) is None:
        raise ScanRejected("The selected asset does not exist.")
    label = _software_label(items)
    with _submit_lock:
        scan_id = db.create_scan_if_idle(label, asset_id, created_by, "software", "queued")
    if scan_id is None:
        raise ScanRejected("An identical software scan is already queued or running.")
    if wait:
        _worker(scan_id, run_software_scan, scan_id, items, asset_id)
    else:
        threading.Thread(target=_worker, args=(scan_id, run_software_scan, scan_id, items, asset_id),
                         daemon=True).start()
    return scan_id


# ---------------------------------------------------------------------------
# System Scan
# ---------------------------------------------------------------------------
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,31}$")


def validate_system_request(mode, host=None, port=None, username=None, private_key=None,
                            fingerprint=None, accept_unverified=False):
    """Validate a System Scan request up front (before anything is queued).
    Returns a normalised dict or raises ScanRejected. For remote mode this
    checks the host, port, username, key format AND that the key is usable
    (parses, no passphrase) so mistakes surface immediately."""
    if mode == "local":
        return {"mode": "local"}
    if mode != "remote":
        raise ScanRejected("Choose a scan mode: local or remote (SSH).")
    host = (host or "").strip()
    try:
        host = validate_target(host)
    except ValueError as e:
        raise ScanRejected(f"Invalid host: {e}")
    if "/" in host:
        raise ScanRejected("A system scan targets a single machine, not a network range.")
    try:
        port = int(port or 22)
    except (TypeError, ValueError):
        raise ScanRejected("SSH port must be a number.")
    if not (1 <= port <= 65535):
        raise ScanRejected("SSH port must be between 1 and 65535.")
    username = (username or "").strip()
    if not _USER_RE.match(username):
        raise ScanRejected("Enter the SSH username (letters, digits and . _ - only).")
    try:
        key_text = validate_key_format(private_key)
        fp = normalize_fingerprint(fingerprint)
        if not fp and not accept_unverified:
            raise SystemScanError("Provide the server's host key fingerprint (SHA256:...) or explicitly accept an "
                                  "unverified host key.")
        _need("ssh")
        with private_key_file(key_text) as (path, _wd):
            if not check_key_usable(path):
                raise SystemScanError("The SSH private key is invalid or passphrase-protected (not supported).")
    except SystemScanError as e:
        raise ScanRejected(str(e))
    return {"mode": "remote", "host": host, "port": port, "user": username, "key_text": key_text,
            "fingerprint": fp, "accept_unverified": bool(accept_unverified)}


def local_host_os():
    """Operating system of the computer running SentriX (patched in tests)."""
    return platform.system()


def submit_system_scan(mode, created_by=None, use_sudo=False, allow_local=False, wait=False,
                       windows_action="status", windows_path=None, windows_confirmed=False, **remote):
    """Queue a System Scan. mode 'local' inspects the machine running SentriX
    and is restricted to callers with allow_local=True (administrators);
    'remote' inspects another Linux machine over SSH with key authentication.
    SSH credentials are held in memory for the life of the scan only - never
    written to the database or logs. Returns the scan id.

    Backend selection (local mode): a Windows server runs the Microsoft Defender
    integration (the windows_* arguments); any other OS keeps the existing Linux
    checks unchanged. Remote mode is always the Linux SSH assessment."""
    if mode == "local" and local_host_os() == "Windows":
        return submit_windows_system_scan(windows_action, windows_path, confirmed=windows_confirmed,
                                          created_by=created_by, allow_local=allow_local, wait=wait)
    req = validate_system_request(mode, **remote)
    if req["mode"] == "local":
        if not allow_local:
            raise ScanRejected("Local system scans inspect the SentriX server itself and can only be started by an administrator.")
        node = platform.node() or "localhost"
        label, asset_key, scan_type, ssh = f"system:local ({node})", node, "system-local", None
    else:
        label = f"system:ssh://{req['user']}@{req['host']}:{req['port']}"
        asset_key, scan_type = req["host"], "system-remote"
        ssh = {k: req[k] for k in ("host", "port", "user", "key_text", "fingerprint", "accept_unverified")}
    with _submit_lock:
        asset_id = db.upsert_asset(asset_key)
        scan_id = db.create_scan_if_idle(label, asset_id, created_by, scan_type, "queued")
    if scan_id is None:
        raise ScanRejected(f"A system scan for {label.split(':', 1)[1]} is already queued or running.")
    args = (scan_id, run_system_scan, scan_id, asset_id, asset_key, req["mode"])
    kwargs = {"ssh": ssh, "use_sudo": bool(use_sudo)}
    if wait:
        _worker(*args, **kwargs)
    else:
        threading.Thread(target=_worker, args=args, kwargs=kwargs, daemon=True).start()
    return scan_id


# ---------------------------------------------------------------------------
# Windows: "Scan this computer" software inventory + Microsoft Defender System Scan
# ---------------------------------------------------------------------------
def _require_local_windows(allow_local, what):
    if not allow_local:
        raise ScanRejected(f"{what} inspects the SentriX server itself and can only be started by an administrator.")
    system = local_host_os()
    if system != "Windows":
        raise ScanRejected(
            f"{what} is available when the SentriX server runs on Windows; this server is running "
            f"{system or 'an unknown operating system'}. It inspects the computer that runs SentriX, not the "
            "computer your browser is on.")


def submit_local_software_scan(created_by=None, allow_local=False, wait=False, provider=None):
    """Queue 'Scan this computer': discover the applications installed on the Windows computer running the
    SentriX server and assess them through the shared vulnerability engine. Returns the scan id."""
    _require_local_windows(allow_local, "Scan this computer")
    host = local_host_info(describe_windows_os() if provider is None else None)
    node = host["computer_name"]
    label = f"software:local ({node})"[:255]
    with _submit_lock:
        asset_id = db.upsert_asset(node, os_name=host["os"])
        scan_id = db.create_scan_if_idle(label, asset_id, created_by, "software", "queued")
    if scan_id is None:
        raise ScanRejected(f"A software scan of this computer ({node}) is already queued or running.")
    args = (scan_id, run_inventory_scan, scan_id, asset_id, node)
    kwargs = {"provider": provider}
    if wait:
        _worker(*args, **kwargs)
    else:
        threading.Thread(target=_worker, args=args, kwargs=kwargs, daemon=True).start()
    return scan_id


def defender_status():
    """Synchronous protection-status read for the UI (a few seconds; never starts a scan)."""
    return DefenderClient().get_protection_status()


def validate_windows_request(action, path=None, confirmed=False):
    """(action, normalised path or None) or ScanRejected. Scans (anything but 'status') need explicit confirmation."""
    if action not in WINDOWS_ACTIONS:
        raise ScanRejected("Choose Protection status, Quick Scan, Full Scan or Custom Scan.")
    norm = None
    if action == "custom":
        try:
            norm = validate_scan_path(path)
        except DefenderInputError as e:
            raise ScanRejected(str(e))
    if action != "status" and not confirmed:
        raise ScanRejected("Confirm that you understand the scan's duration and system load before it is started.")
    return action, norm


def submit_windows_system_scan(action, path=None, confirmed=False, created_by=None, allow_local=False, wait=False,
                               client=None):
    """Queue a Microsoft Defender-backed System Scan of this computer. Returns the scan id."""
    _require_local_windows(allow_local, "A Windows System Scan")
    action, norm = validate_windows_request(action, path, confirmed)
    host = local_host_info(describe_windows_os() if client is None else None)
    node = host["computer_name"]
    label = f"system:windows-defender ({node})"[:255]
    with _submit_lock:
        asset_id = db.upsert_asset(node, os_name=host["os"])
        scan_id = db.create_scan_if_idle(label, asset_id, created_by, "system-windows", "queued")
    if scan_id is None:
        raise ScanRejected(f"A Windows System Scan for {node} is already queued or running.")
    args = (scan_id, run_windows_system_scan, scan_id, asset_id, node, {"action": action, "path": norm})
    kwargs = {"client": client}
    if wait:
        _worker(*args, **kwargs)
    else:
        threading.Thread(target=_worker, args=args, kwargs=kwargs, daemon=True).start()
    return scan_id
