"""IVMP Phase 10: Configuration Validation Layer.

Runs immediately after CVE matching (search_cves()) in scanner/pipeline.py,
before EPSS/KEV enrichment, contextual risk, and confidence scoring. It does
NOT feed into or alter any of those - this module only records what can be
directly, remotely verified about a service's configuration from the data
nmap already gave us. The result is attached to each finding as
config_validation / config_evidence for display and for future use, but
nothing here changes cvss_score, contextual_priority, priority_label, or
vulnerability_confidence.

Scope: SSH, Apache HTTP Server, and TLS/HTTPS. Every other service returns
a neutral, all-empty result so callers can invoke validate_service()
unconditionally for any port/service without special-casing. validate_service()
is the single dispatch point - scanner/pipeline.py calls it once per port
and doesn't need to know which validator (SSH, Apache, TLS, or none)
actually ran. Adding Apache/TLS here means pipeline.py's existing
unconditional call already covers them; pipeline.py only needed to start
passing its scan target through (an optional parameter here), so
validate_tls() can perform its existing live handshake instead of always
reporting "unknown" for handshake-dependent checks.

Hard rule: never assume a configuration setting. If something can't be
directly verified from the available data (service banner, product,
version, cpe), the corresponding check is recorded as "unknown" - never
inferred as true or false. A missing/absent check is more honest than a
guessed one; downstream consumers should treat "unknown" as "not yet
determined", not as "safe" or "vulnerable".
"""

from scanner.apache_validator import validate_apache
from scanner.tls_validator import validate_tls, is_tls_service

CONFIRMED = "confirmed"
NOT_CONFIRMED = "not_confirmed"
UNKNOWN = "unknown"

# Configuration-level properties that a plain nmap version/banner scan
# cannot directly verify - they require either an authenticated session,
# a protocol-level handshake beyond service detection, or inspection of
# sshd_config, none of which this scanner performs. Listed explicitly
# (rather than skipped) so it's clear these were considered and
# deliberately left unknown, not forgotten.
SSH_UNVERIFIABLE_FEATURES = (
    "root_login_permitted",
    "password_auth_enabled",
    "weak_kex_algorithms",
    "weak_host_key_algorithms",
    "protocol_v1_supported",
)


def _empty_result():
    return {
        "checks": {},
        "evidence": [],
        "confidence_modifier": 0.0,
    }


def _is_apache(normalized_service, normalized_product):
    """Apache is typically reported by nmap as service "http"/"https" with
    product "Apache httpd" (or similar) - service name alone doesn't
    identify it the way "ssh" does for SSH. So detection here checks the
    product string for "apache"/"httpd" in addition to allowing a literal
    "apache" service name, rather than relying on SUPPORTED_SERVICES
    membership alone."""
    if normalized_service not in {"http", "https", "apache"}:
        return False
    if normalized_service == "apache":
        return True
    return "apache" in normalized_product or "httpd" in normalized_product


def validate_service(port, service, product=None, vendor=None, version=None, cpe=None, target=None):
    """Validate what can be directly confirmed about a detected service's
    configuration, using only nmap-provided data (no active probing beyond
    what the scan already performed, except for validate_tls()'s optional
    live handshake - see scanner/tls_validator.py - which this dispatch
    forwards target to on the TLS branch only, so SSH/Apache stay exactly
    as passive as before; TLS's handshake-dependent checks report
    "unknown" only when target is not supplied, e.g. by a caller that
    doesn't have one available).

    Args:
        port:    port number the service was detected on
        service: nmap service name (e.g. "ssh", "http", "https")
        product, vendor, version, cpe: as returned by scanner/parser.py
        target:  hostname/IP to connect to for validate_tls()'s optional
                 live handshake. Optional - only used on the TLS dispatch
                 branch below; ignored by the SSH/Apache branches, which
                 never open a connection of their own. If omitted, TLS
                 handshake-dependent checks stay "unknown", same as before.

    Returns:
        {
            "checks": {check_name: "confirmed" | "not_confirmed" | "unknown", ...},
            "evidence": [str, ...],
            "confidence_modifier": float
        }

    For services this module doesn't validate, returns an empty result (no
    checks, no evidence, zero modifier) rather than guessing.

    confidence_modifier is a small, additive value intended for a future
    caller to combine with vulnerability_confidence if desired - this
    module does not apply it anywhere itself, and risk/confidence.py's
    formula is untouched by this addition.
    """
    if not service:
        return _empty_result()

    normalized_service = service.strip().lower()
    normalized_product = (product or "").strip().lower()

    if normalized_service == "ssh":
        return _validate_ssh(port, product, vendor, version)

    if _is_apache(normalized_service, normalized_product):
        result = validate_apache(port, service, product, vendor, version, cpe)
        # apache_validator.py returns only checks/evidence per its own
        # contract; add the confidence_modifier key here so every
        # validate_service() caller sees the same result shape regardless
        # of which validator ran, without apache_validator.py needing to
        # know about a field it never uses.
        result.setdefault("confidence_modifier", 0.0)
        return result

    # TLS/HTTPS dispatch. Runs only after the Apache check above, so an
    # HTTPS service already identified as Apache (product contains
    # "apache"/"httpd") is handled by validate_apache() exactly as before
    # and never reaches here - this branch only ever fires for TLS/HTTPS
    # services Apache didn't already claim (e.g. nginx on 443, a bare
    # "https" service with no product string, port 443 generally, or a
    # detection whose CPE names ssl/tls). target is forwarded here (and
    # only here) so validate_tls() can attempt its live handshake exactly
    # as tls_validator.py already documents; when a caller doesn't have a
    # target available, this stays passive exactly as before and every
    # handshake/certificate-dependent check comes back "unknown" rather
    # than guessed.
    if is_tls_service(port, normalized_service, normalized_product, cpe):
        result = validate_tls(port, service, product, vendor, version, cpe, target=target)
        result.setdefault("confidence_modifier", 0.0)
        return result

    return _empty_result()


def _validate_ssh(port, product, vendor, version):
    checks = {}
    evidence = []

    # --- service exposed ---
    # "Exposed" here means only what the scan itself observed: an open
    # port with the service responding as SSH. It says nothing about
    # network reachability from elsewhere, firewalling, or intent.
    if port is not None:
        checks["service_exposed"] = CONFIRMED
        evidence.append(f"SSH service detected open on port {port}")
    else:
        checks["service_exposed"] = UNKNOWN
        evidence.append("no port number available to confirm exposure")

    # --- version detected ---
    if version:
        checks["version_detected"] = CONFIRMED
        checks["ssh_version"] = version
        evidence.append(f"SSH version string recorded: {version}")
    else:
        checks["version_detected"] = NOT_CONFIRMED
        evidence.append("no SSH version string returned by the scan")

    # Product/vendor identity is supplementary corroborating evidence, not
    # a pass/fail check of its own.
    if product:
        label = f"product identified as {product}"
        if vendor:
            label += f" ({vendor})"
        evidence.append(label)

    # --- feature checks left unknown on purpose ---
    # These require an authenticated session, a full protocol handshake,
    # or reading sshd_config directly - none of which a version/banner
    # scan performs. Recording them as "unknown" rather than omitting
    # them makes clear they were considered, not missed.
    for feature in SSH_UNVERIFIABLE_FEATURES:
        checks[feature] = UNKNOWN
    evidence.append(
        "authentication and algorithm settings are not verifiable from a "
        "version/banner scan alone; recorded as unknown rather than assumed"
    )

    return {
        "checks": checks,
        "evidence": evidence,
        "confidence_modifier": 0.0,
    }