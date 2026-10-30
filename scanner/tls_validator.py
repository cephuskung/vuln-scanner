"""IVMP: TLS Configuration Validator.

Follows the same architecture and contract as scanner/apache_validator.py
and config_validator.py's own _validate_ssh(): a single validate_tls()
entry point that returns

    {"checks": {check_name: "confirmed" | "not_confirmed" | "unknown"},
     "evidence": [plain-text evidence strings]}

(config_validator.py adds the confidence_modifier key on top, the same
way it already does for validate_apache()'s result - this module doesn't
need to know about that field.)

Scope note: this is a REMOTE, non-invasive TLS/certificate check, same
posture as the SSH/Apache validators. It records what could actually be
observed (protocol version negotiated, cipher offered, certificate
fields) and never infers a check's status from absence of data - a check
is only ever "confirmed" when supporting evidence was actually collected.
"unknown" means "not yet determined by this scan", never "assumed safe"
and never "assumed vulnerable" - this mirrors config_validator.py's
documented contract (see its module docstring: "never assume a
configuration setting... A missing/absent check is more honest than a
guessed one").

This module does NOT perform CVE matching, does NOT compute CVSS or
contextual risk, and does NOT decide applicability status - it only
supplies the config_validation/config_evidence data those other modules
already know how to consume (see scanner/pipeline.py, unchanged).

--- TLS handshake compatibility vs. certificate validation -------------

The handshake this module performs always uses verify_mode=CERT_NONE, and
that is intentional, not a bug: this validator's entire purpose is to
report on a certificate's OWN properties (is it self-signed, is it
expired, does its name match the target) - conditions that, if verify_mode
required a valid, trusted, matching-hostname chain, would make Python's
ssl module refuse to complete the handshake at all for exactly the
certificates we most want to inspect. A verifying handshake would trade
"we can tell you it's untrusted" for "we can no longer tell you anything
about it".

Because Python's ssl.SSLSocket.getpeercert() only returns a populated,
structured dict when verification succeeded (an empty dict otherwise -
this is documented ssl module behavior, not specific to this code), this
module does not rely on it for certificate fields. Instead it retrieves
the certificate's raw DER bytes via getpeercert(binary_form=True) - which
IS populated regardless of verify_mode, since it's simply the bytes the
peer sent, no verification involved in producing it - and parses those
bytes independently using the `cryptography` package (see
_parse_certificate_der below). This project's existing dependencies
(requirements.txt) have no certificate-parsing capability of their own,
and Python's standard library has no public API for parsing arbitrary
X.509 DER bytes outside of the verification-gated ssl.getpeercert() path
- cryptography is the standard, widely-trusted library for exactly this,
used here ONLY for parsing, never for trust decisions.
"""

import ipaddress
import ssl
import socket
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

CONFIRMED = "confirmed"
NOT_CONFIRMED = "not_confirmed"
UNKNOWN = "unknown"


# --- Service detection ---------------------------------------------------

# Services this validator applies to. Deliberately explicit rather than
# "anything not SSH/HTTP" so it never silently activates for an unrelated
# service that happens to share a token.
TLS_SERVICE_NAMES = {"https", "ssl", "tls", "ssl/http", "https-alt"}
TLS_PORTS = {443}


def is_tls_service(port, normalized_service, normalized_product, cpe=None):
    """True if this port/service should be TLS-validated.

    Deliberately does NOT match here if the service already looks like
    Apache (normalized_product containing "apache"/"httpd") - that case is
    handled by validate_apache() in config_validator.py's dispatch, which
    runs before this check. This function only needs to recognize the
    TLS/HTTPS-without-Apache-identity case, plus a bare port-443 or
    ssl/tls-tagged CPE that never matched SSH or Apache above it.
    """
    if normalized_service in TLS_SERVICE_NAMES:
        return True
    if port in TLS_PORTS:
        return True
    cpe_l = (cpe or "").lower()
    if "ssl" in cpe_l or "tls" in cpe_l:
        return True
    return False


# --- Weak protocol / cipher reference data --------------------------------

# Protocol versions considered weak/deprecated. A fixed list of KNOWN-weak
# versions, not a heuristic - a version not in this list is simply not
# flagged here, it is never treated as "confirmed safe".
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

# Cipher name substrings that indicate a known-weak cipher suite. Coarse
# but explicit, matching the style of config_validator.py's SSH
# unverifiable-feature list - a cipher not matching any of these is not
# flagged, never assumed strong.
WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "MD5", "EXPORT", "NULL", "anon")

CERT_EXPIRY_WARNING_DAYS = 30

# Certificate/handshake properties this validator does not currently
# collect evidence for - listed explicitly (mirroring
# config_validator.py's SSH_UNVERIFIABLE_FEATURES pattern) so it's clear
# these were considered and deliberately left unknown, not forgotten.
TLS_UNVERIFIABLE_FEATURES = (
    "hsts_enabled",
    "perfect_forward_secrecy",
    "ocsp_status",
)


def _is_weak_cipher(cipher_name):
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return any(marker in upper for marker in WEAK_CIPHER_MARKERS)


def _get_tls_connection_info(target, port, timeout=5):
    """Best-effort, read-only TLS handshake to observe the negotiated
    protocol version, cipher, and peer certificate. Returns a dict of
    whatever it could observe; any field that couldn't be collected is
    simply absent (None), never guessed. Network/handshake failures
    return an empty dict - absence of data, not a finding.

    verify_mode stays CERT_NONE deliberately (see module docstring): this
    lets the handshake complete even against a self-signed, expired, or
    hostname-mismatched certificate, which is exactly the evidence this
    validator exists to report on. The certificate is retrieved as raw
    DER bytes (getpeercert(binary_form=True), populated regardless of
    verify_mode) rather than the structured getpeercert() dict, which
    Python only populates when verification succeeded.
    """
    info = {}
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                info["protocol_version"] = tls_sock.version()
                cipher = tls_sock.cipher()
                if cipher:
                    info["cipher_name"] = cipher[0]
                cert_der = tls_sock.getpeercert(binary_form=True)
                if cert_der:
                    info["certificate_der"] = cert_der
    except Exception:
        # Connection/handshake failure: no evidence collected, all checks
        # below fall through to "unknown" as designed.
        return {}
    return info


def _parse_certificate_der(der_bytes):
    """Parses a DER-encoded certificate independently of TLS chain
    verification (see module docstring for why getpeercert()'s own
    structured dict can't be used here).

    Returns None if the bytes can't be parsed as a certificate - never
    guess fields from a malformed/truncated certificate. Otherwise returns
    a dict with:
        not_before, not_after: timezone-aware UTC datetimes
        issuer_str, subject_str: RFC4514 canonical DN strings (used for
            the self-signed comparison - issuer == subject)
        common_name: the subject's commonName, or None
        san_dns_names: list of DNS-type Subject Alternative Name entries
        san_ip_addresses: list of IP-address-type SAN entries, as strings
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return None

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        # cryptography < 42.0 only exposes the naive, UTC-implied properties.
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    common_name = None
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attrs:
        common_name = cn_attrs[0].value

    san_dns_names = []
    san_ip_addresses = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_names = list(san_ext.value.get_values_for_type(x509.DNSName))
        san_ip_addresses = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass

    return {
        "not_before": not_before,
        "not_after": not_after,
        "issuer_str": cert.issuer.rfc4514_string(),
        "subject_str": cert.subject.rfc4514_string(),
        "common_name": common_name,
        "san_dns_names": san_dns_names,
        "san_ip_addresses": san_ip_addresses,
    }


def _evaluate_hostname_match(target, parsed_cert):
    """Compares target against the certificate's identity fields,
    distinguishing an IP-literal target from a DNS-hostname target rather
    than comparing both the same way (an IP address is never meaningfully
    checked against a certificate's DNS names).

    Returns (matched, candidate_names) - a bool and the sorted list of
    names compared against - when a meaningful comparison could be made.
    Returns None when it couldn't (e.g. an IP target against a
    certificate with no IP SAN entries, or a DNS target against a
    certificate with no usable name fields at all) - callers must record
    "unknown" in that case, never invent a match or mismatch.
    """
    try:
        ipaddress.ip_address(target)
        is_ip_target = True
    except ValueError:
        is_ip_target = False

    if is_ip_target:
        san_ips = parsed_cert.get("san_ip_addresses") or []
        if not san_ips:
            # Nothing on the certificate to meaningfully compare an IP
            # target against - most certificates only carry DNS SANs.
            return None
        return (target in san_ips, sorted(san_ips))

    candidate_names = {
        n for n in ([parsed_cert.get("common_name")] + list(parsed_cert.get("san_dns_names") or [])) if n
    }
    if not candidate_names:
        return None
    matched = target in candidate_names or any(
        name.startswith("*.") and target.endswith(name[1:]) for name in candidate_names
    )
    return (matched, sorted(candidate_names))


def validate_tls(port, service, product=None, vendor=None, version=None, cpe=None,
                  target=None, connection_info=None):
    """Validates observable TLS configuration for a detected HTTPS/TLS
    service. Same contract as _validate_ssh()/validate_apache(): returns
    {"checks": {...}, "evidence": [...]}.

    Args:
        port, service, product, vendor, version, cpe: same detection
            fields config_validator.validate_service() already receives
            and passes through to the SSH/Apache validators.
        target: hostname/IP to connect to for the live handshake. Optional
            - if omitted, no live connection is attempted and every
            handshake-dependent check stays "unknown" (never guessed).
        connection_info: optional pre-collected dict in the same shape
            _get_tls_connection_info() returns (protocol_version,
            cipher_name, certificate) - lets callers/tests supply captured
            handshake data instead of this function performing its own
            network I/O.

    Only meaningful for TLS/HTTPS services - config_validator.py's
    dispatch gates on is_tls_service() before calling this, but this
    function itself performs no CVE matching and does not decide whether
    the caller should have invoked it.
    """
    checks = {
        "service_exposed": UNKNOWN,
        "version_detected": UNKNOWN,
        "tls_version": UNKNOWN,
        "weak_cipher": UNKNOWN,
        "certificate_expired": UNKNOWN,
        "certificate_self_signed": UNKNOWN,
        "hostname_mismatch": UNKNOWN,
        "certificate_expiry": UNKNOWN,
    }
    evidence = []

    # --- generic identity checks (same names/semantics as SSH/Apache's
    # service_exposed / version_detected, relied on by
    # risk/confidence.py's CONFIG_CONFIDENCE_BONUSES) ---
    if port is not None:
        checks["service_exposed"] = CONFIRMED
        evidence.append(f"TLS service detected open on port {port}")
    else:
        evidence.append("no port number available to confirm exposure")

    if version:
        checks["version_detected"] = CONFIRMED
        evidence.append(f"detected service version: {version}")
    else:
        checks["version_detected"] = NOT_CONFIRMED
        evidence.append("no service version string returned by the scan")

    if product:
        label = f"product identified as {product}"
        if vendor:
            label += f" ({vendor})"
        evidence.append(label)

    info = connection_info
    if info is None and target:
        info = _get_tls_connection_info(target, port)
    info = info or {}

    # --- tls_version ---
    protocol_version = info.get("protocol_version")
    if protocol_version:
        if protocol_version in WEAK_TLS_VERSIONS:
            checks["tls_version"] = CONFIRMED
            evidence.append(f"weak TLS protocol version negotiated: {protocol_version}")
        else:
            checks["tls_version"] = NOT_CONFIRMED
            evidence.append(f"negotiated TLS protocol version: {protocol_version} (not in weak-version list)")
    # else: no handshake data collected - stays "unknown", not guessed.

    # --- weak_cipher ---
    cipher_name = info.get("cipher_name")
    if cipher_name:
        if _is_weak_cipher(cipher_name):
            checks["weak_cipher"] = CONFIRMED
            evidence.append(f"weak cipher suite negotiated: {cipher_name}")
        else:
            checks["weak_cipher"] = NOT_CONFIRMED
            evidence.append(f"negotiated cipher suite: {cipher_name} (not in weak-cipher list)")

    # --- certificate-derived checks (parsed independently of TLS chain
    # verification via _parse_certificate_der - see module docstring) ---
    cert_der = info.get("certificate_der")
    if cert_der:
        try:
            parsed_cert = _parse_certificate_der(cert_der)
        except Exception:
            # Best-effort: an unexpected parsing failure must not crash
            # the scan or fail other checks - just leave the
            # certificate-derived checks unknown, exactly as if no
            # certificate had been collected at all.
            parsed_cert = None

        if parsed_cert is None:
            evidence.append("certificate was received but could not be parsed; certificate checks left unknown")

        if parsed_cert:
            issuer_str = parsed_cert["issuer_str"]
            subject_str = parsed_cert["subject_str"]
            if issuer_str and subject_str:
                if issuer_str == subject_str:
                    checks["certificate_self_signed"] = CONFIRMED
                    evidence.append("certificate issuer matches subject (self-signed)")
                else:
                    checks["certificate_self_signed"] = NOT_CONFIRMED
                    evidence.append("certificate issuer differs from subject (not self-signed)")

            not_after = parsed_cert["not_after"]
            if not_after:
                now = datetime.now(timezone.utc)
                if not_after < now:
                    checks["certificate_expired"] = CONFIRMED
                    evidence.append(f"certificate expired on {not_after.isoformat()}")
                else:
                    checks["certificate_expired"] = NOT_CONFIRMED
                    days_remaining = (not_after - now).days
                    evidence.append(f"certificate valid until {not_after.isoformat()} ({days_remaining} days remaining)")
                    if days_remaining <= CERT_EXPIRY_WARNING_DAYS:
                        checks["certificate_expiry"] = CONFIRMED
                        evidence.append(
                            f"certificate expires within {CERT_EXPIRY_WARNING_DAYS} days "
                            f"({days_remaining} days remaining)"
                        )
                    else:
                        checks["certificate_expiry"] = NOT_CONFIRMED

            if target:
                hostname_result = _evaluate_hostname_match(target, parsed_cert)
                if hostname_result is None:
                    evidence.append(
                        f"target {target} could not be meaningfully compared against this certificate's "
                        f"name fields (e.g. an IP target with no IP SAN entry to compare against); "
                        f"hostname_mismatch left unknown rather than guessed"
                    )
                else:
                    matched, candidate_names = hostname_result
                    if matched:
                        checks["hostname_mismatch"] = NOT_CONFIRMED
                        evidence.append(f"certificate name(s) {candidate_names} match target {target}")
                    else:
                        checks["hostname_mismatch"] = CONFIRMED
                        evidence.append(f"certificate name(s) {candidate_names} do not match target {target}")

    # --- feature checks left unknown on purpose ---
    # hsts_enabled, perfect_forward_secrecy, ocsp_status: confirming any of
    # these requires inspecting HTTP response headers (HSTS), classifying
    # cipher key-exchange properties (PFS), or querying OCSP - none of
    # which this validator currently performs. Recorded as "unknown"
    # rather than omitted, mirroring config_validator.py's
    # SSH_UNVERIFIABLE_FEATURES pattern, so it's clear these were
    # considered, not missed.
    for feature in TLS_UNVERIFIABLE_FEATURES:
        checks[feature] = UNKNOWN
    evidence.append(
        "HSTS, perfect forward secrecy, and OCSP status are not verifiable "
        "from this scan; recorded as unknown rather than assumed"
    )

    return {"checks": checks, "evidence": evidence}