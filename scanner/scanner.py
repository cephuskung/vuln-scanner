import ipaddress
import logging
import re
import subprocess
import uuid
import os

logger = logging.getLogger(__name__)

# Largest network (in addresses) a single network scan may cover. A /24 is
# 256 addresses; bigger ranges need an explicit, deliberate opt-in because
# every discovered host then gets its own full service scan.
MAX_NETWORK_ADDRESSES = int(os.environ.get("SENTRIX_MAX_NETWORK_ADDRESSES", 256))
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
def validate_target(target):
    """IVMP Phase 0: reject anything that isn't a plausible scan target
    before it reaches nmap.
    Two things this guards against:
      1. Nmap flag injection - target is passed as a positional argv entry
         (not through a shell), so classic shell injection isn't the risk,
         but a value starting with '-' (e.g. '--script=...') would be
         parsed by nmap as an option rather than a target.
      2. Obviously-invalid input reaching a subprocess call that otherwise
         has no server-side validation at all.
    Deliberately permissive on *what* counts as a target - single IPs,
    IPv6, hostnames, and CIDR ranges are all legitimate nmap targets and
    narrowing further would break real use of the scanner.
    Raises ValueError with a human-readable reason; returns the (stripped)
    target on success so callers can use the return value directly.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string")
    target = target.strip()
    if not target or target.startswith("-"):
        raise ValueError("Target cannot be empty or start with '-'")
    if "/" in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return target
        except ValueError:
            raise ValueError(f"'{target}' is not a valid CIDR range")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if _HOSTNAME_RE.match(target):
        return target
    raise ValueError(f"'{target}' is not a valid IP address, CIDR range, or hostname")
def run_nmap_scan(target):
    """Runs an nmap scan against target and returns the path to the XML output.
    Each scan gets a unique output filename so concurrent/scheduled scans
    don't clobber each other's results.
    """
    target = validate_target(target)
    output_file = os.path.join("/tmp", f"scan_{uuid.uuid4().hex}.xml")
    command = [
        "nmap",
        "-Pn",
        "-sV",
        "-T4",
    ]
    if _os_detection_enabled():
        command.append("-O")
    command += [target, "-oX", output_file]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=600)
        return output_file
    except subprocess.CalledProcessError as e:
        _remove_quietly(output_file)
        raise RuntimeError(f"Nmap scan failed: {e.stderr.decode(errors='ignore')}")
    except subprocess.TimeoutExpired:
        _remove_quietly(output_file)
        raise RuntimeError("Nmap scan timed out after 10 minutes")
    except FileNotFoundError:
        raise RuntimeError("Nmap is not installed or not on PATH")


def _os_detection_enabled():
    """OS fingerprinting (-O) is opt-in via SENTRIX_OS_DETECTION=1 and is
    only requested when nmap can actually use it (raw sockets need root /
    CAP_NET_RAW). Without it nmap exits with an error and the whole scan
    would fail, so we never add -O unprivileged."""
    if os.environ.get("SENTRIX_OS_DETECTION", "").lower() not in ("1", "true", "yes"):
        return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        logger.warning("SENTRIX_OS_DETECTION is set but the process is not root; skipping nmap -O")
        return False
    return True


def _remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def is_network_target(target):
    """True for a CIDR range covering more than one address."""
    if "/" not in target:
        return False
    return ipaddress.ip_network(target, strict=False).num_addresses > 1


def normalize_target(target):
    """validate_target() plus: a single-address CIDR ('10.0.0.5/32') is
    collapsed to the plain host so it takes the normal single-host path."""
    target = validate_target(target)
    if "/" in target:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return str(net.network_address)
    return target


def discover_hosts(target):
    """Host discovery for a network range: `nmap -sn` (ping scan, no port
    scan, no DNS) and return the IPs nmap reports as up, parsed with the
    existing multi-host parser. Ports/services are NOT probed here - each
    discovered host is then scanned individually through the normal
    single-host pipeline.

    Raises ValueError for an invalid/oversized range and RuntimeError for
    nmap failures/timeouts."""
    from parser.parser import parse_nmap_xml  # local import: avoids a cycle at import time

    target = normalize_target(target)
    if "/" not in target:
        raise ValueError("Host discovery needs a network range (CIDR)")
    net = ipaddress.ip_network(target, strict=False)
    if net.num_addresses > MAX_NETWORK_ADDRESSES:
        raise ValueError(
            f"{target} covers {net.num_addresses} addresses; the limit is "
            f"{MAX_NETWORK_ADDRESSES} (SENTRIX_MAX_NETWORK_ADDRESSES)"
        )
    output_file = os.path.join("/tmp", f"discover_{uuid.uuid4().hex}.xml")
    command = ["nmap", "-sn", "-n", "-T4", target, "-oX", output_file]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=300)
        results = parse_nmap_xml(output_file)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Nmap host discovery failed: {e.stderr.decode(errors='ignore')}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Nmap host discovery timed out after 5 minutes")
    except FileNotFoundError:
        raise RuntimeError("Nmap is not installed or not on PATH")
    finally:
        _remove_quietly(output_file)
    return [h["target"] for h in results["hosts"] if h.get("target")]
