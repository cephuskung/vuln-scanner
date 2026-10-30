"""IVMP Phase 10 (extension): Apache HTTP Server config validation.

Sibling to the SSH validation in scanner/config_validator.py. Same contract,
same discipline: only record what the scan data directly confirms. Nothing
here is inferred or guessed.

This module does not decide WHEN it gets called - that dispatch logic lives
in scanner/config_validator.py's validate_service(), which is the single
entry point scanner/pipeline.py invokes for every port. Keeping the dispatch
centralized there (rather than duplicating service-detection logic here or
in pipeline.py) is what lets SSH behavior stay untouched and lets
risk/confidence.py stay generic - see that module's docstring.

Check-name overlap with scanner/config_validator.py's SSH checks
("service_exposed", "version_detected") is intentional, not accidental
duplication: risk/confidence.py's CONFIG_CONFIDENCE_BONUSES keys on those
two names generically ("does the scan corroborate exposure/version"), not
on the SSH validator specifically. Reusing the same names is what makes
Apache confidence scoring work automatically with zero changes to
confidence.py.
"""

CONFIRMED = "confirmed"
NOT_CONFIRMED = "not_confirmed"
UNKNOWN = "unknown"

# Apache configuration properties that a plain nmap version/banner scan
# cannot directly verify - they require either reading httpd.conf, an
# authenticated probe, or content-level requests this scanner doesn't make.
# Listed explicitly, same discipline as scanner/config_validator.py's
# SSH_UNVERIFIABLE_FEATURES, so it's clear these were considered and
# deliberately left unknown rather than omitted or assumed.
APACHE_UNVERIFIABLE_FEATURES = (
    "server_tokens_setting",
    "directory_listing_enabled",
    "mod_security_enabled",
    "tls_configuration",
    "authentication_configuration",
    "loaded_modules",
)


def validate_apache(port, service, product=None, vendor=None, version=None, cpe=None):
    """Validate what can be directly confirmed about a detected Apache HTTP
    Server instance, using only nmap-provided data (no active probing
    beyond what the scan already performed).

    Args:
        port:    port number the service was detected on
        service: nmap service name (e.g. "http", "https")
        product, vendor, version, cpe: as returned by scanner/parser.py

    Returns:
        {
            "checks": {check_name: "confirmed" | "not_confirmed" | "unknown", ...},
            "evidence": [str, ...],
        }

    Callers should assume this fires only when the caller has already
    determined the detected product is Apache HTTP Server - this function
    does not itself re-check product/service naming.
    """
    checks = {}
    evidence = []

    # --- service exposed ---
    # Same meaning as the SSH validator: only what the scan itself
    # observed - an open port with the service responding as Apache. Says
    # nothing about reachability from elsewhere, firewalling, or intent.
    if port is not None:
        checks["service_exposed"] = CONFIRMED
        evidence.append(f"Apache HTTP Server detected open on port {port}")
    else:
        checks["service_exposed"] = UNKNOWN
        evidence.append("no port number available to confirm exposure")

    # --- version detected ---
    if version:
        checks["version_detected"] = CONFIRMED
        checks["apache_version"] = version
        evidence.append(f"Apache version string recorded: {version}")
    else:
        checks["version_detected"] = NOT_CONFIRMED
        evidence.append("no Apache version string returned by the scan")

    # Product/vendor identity is supplementary corroborating evidence, not
    # a pass/fail check of its own - mirrors the SSH validator.
    if product:
        label = f"product identified as {product}"
        if vendor:
            label += f" ({vendor})"
        evidence.append(label)

    # --- feature checks left unknown on purpose ---
    # ServerTokens, directory listing, mod_security, TLS config, auth
    # config, and loaded modules all require reading httpd.conf directly,
    # an authenticated session, or content-level HTTP requests this
    # scanner doesn't perform. Recorded as "unknown" rather than omitted
    # or guessed, so it's clear they were considered, not missed.
    for feature in APACHE_UNVERIFIABLE_FEATURES:
        checks[feature] = UNKNOWN
    evidence.append(
        "ServerTokens, directory listing, mod_security, TLS, authentication, "
        "and loaded-module settings are not verifiable from a version/banner "
        "scan alone; recorded as unknown rather than assumed"
    )

    return {
        "checks": checks,
        "evidence": evidence,
    }