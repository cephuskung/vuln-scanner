"""Realistic NVD API responses + a fake HTTP layer, so tests exercise the REAL
vulnerability/cve_lookup.py engine (query building, CPE/version-range matching,
applicability, confidence) instead of stubbing search_cves() away."""
import re
from urllib.parse import unquote

import vulnerability.cve_lookup as cl


def cpe_match(criteria, start_incl=None, start_excl=None, end_incl=None, end_excl=None):
    m = {"vulnerable": True, "criteria": criteria}
    for key, val in (("versionStartIncluding", start_incl), ("versionStartExcluding", start_excl),
                     ("versionEndIncluding", end_incl), ("versionEndExcluding", end_excl)):
        if val:
            m[key] = val
    return m


def cve(cve_id, matches, score=7.5, severity="HIGH", published="2022-11-01T00:00:00.000",
        desc="fixture description", cwe="CWE-120"):
    return {"cve": {
        "id": cve_id, "published": published,
        "descriptions": [{"lang": "en", "value": desc}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": severity,
                                                    "attackComplexity": "LOW"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": cwe}]}],
        "configurations": [{"nodes": [{"cpeMatch": matches}]}],
    }}


OPENSSL = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"

# Modelled on real records: both affect OpenSSL 3.0.0 through 3.0.6 (fixed in 3.0.7).
CVE_3786 = cve("CVE-2022-3786", [cpe_match(OPENSSL, start_incl="3.0.0", end_excl="3.0.7")],
               desc="X.509 Email Address Variable Length Buffer Overflow")
CVE_3602 = cve("CVE-2022-3602", [cpe_match(OPENSSL, start_incl="3.0.0", end_excl="3.0.7")],
               desc="X.509 Email Address 4-byte Buffer Overflow")
# Only affects the 3.0 line from 3.0.7 up to (not including) 3.0.8 -> NOT affected at 3.0.2.
CVE_OUT_OF_RANGE = cve("CVE-2023-0286", [cpe_match(OPENSSL, start_incl="3.0.7", end_excl="3.0.8")],
                       desc="fixture: range that does not include 3.0.2")
# Pinned to one exact release (no range): the only kind of record a PARTIAL version ("3.0") can match.
CVE_EXACT_302 = cve("CVE-2099-0003", [cpe_match("cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*")],
                    desc="fixture: affects exactly 3.0.2")
# Not version-restricted at all, recent -> the only thing a version-less lookup can return.
CVE_UNCONSTRAINED = cve("CVE-2099-0001", [cpe_match(OPENSSL)], published="2025-03-01T00:00:00.000",
                        desc="fixture: NVD does not restrict this CVE to specific versions")
# Different product entirely (must never match OpenSSL even if NVD returns it).
CVE_OTHER_PRODUCT = cve("CVE-2099-0002", [cpe_match("cpe:2.3:a:other:otherproduct:*:*:*:*:*:*:*:*",
                                                    end_excl="9.9")], desc="fixture: unrelated product")

ACME = "cpe:2.3:a:acme:widget_pro:*:*:*:*:*:*:*:*"
CVE_ACME = cve("CVE-2099-1111", [cpe_match(ACME, start_incl="2.0.0", end_excl="2.5.0")], score=9.8,
               severity="CRITICAL", desc="fixture: Acme Widget Pro < 2.5.0")


class FakeNVD:
    """Install over cve_lookup.requests.get. Routes by query type:
         virtualMatchString=cpe:2.3:a:<vendor>:<product>:...  -> by_cpe["vendor:product"]
         keywordSearch=<text>                                  -> by_keyword (substring match)
    fail=True simulates an outage (every request raises)."""

    def __init__(self, monkeypatch, by_cpe=None, by_keyword=None, fail=False):
        self.by_cpe = by_cpe or {}
        self.by_keyword = by_keyword or {}
        self.fail = fail
        self.calls = []
        monkeypatch.setattr(cl.requests, "get", self._get)
        monkeypatch.setattr(cl.time, "sleep", lambda *_: None)

    class _Resp:
        status_code = 200

        def __init__(self, payload):
            self._p = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self._p

    def _get(self, url, timeout=None, **kw):
        self.calls.append(unquote(url))
        if self.fail:
            raise cl.requests.ConnectionError("simulated NVD outage")
        u = unquote(url)
        items = []
        m = re.search(r"virtualMatchString=cpe:2\.3:a:([^:]+):([^:]+):", u)
        if m:
            items = self.by_cpe.get(f"{m.group(1)}:{m.group(2)}", [])
        else:
            k = re.search(r"keywordSearch=([^&]+)", u)
            text = (k.group(1) if k else "").lower()
            for key, val in self.by_keyword.items():
                if key.lower() in text:
                    items = val
        return self._Resp({"totalResults": len(items), "vulnerabilities": items})

    def queries(self, kind):
        return [c for c in self.calls if kind in c]
