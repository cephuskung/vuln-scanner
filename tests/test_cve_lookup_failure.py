"""An NVD failure must never be cached as if it were a real answer."""
import pytest
import vulnerability.cve_lookup as cl

ARGS = dict(service="http", product="Apache httpd", vendor="apache", version="2.4.58",
            cpe="cpe:/a:apache:http_server:2.4.58")


class Resp:
    status_code = 200

    def __init__(self, payload):
        self._p = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._p


def _cache_rows(db):
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cve_cache")
    n = cur.fetchone()[0]
    conn.close()
    return n


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(cl.time, "sleep", lambda *_: None)


def test_total_failure_is_not_cached_and_is_reported(monkeypatch, db_module):
    def boom(*a, **k):
        raise cl.requests.ConnectionError("network down")
    monkeypatch.setattr(cl.requests, "get", boom)
    memo = {}
    assert cl.search_cves(memo=memo, **ARGS) == []
    assert _cache_rows(db_module) == 0                      # NOT cached
    assert memo[cl.LOOKUP_FAILURES_KEY]                     # failure surfaced to the pipeline


def test_partial_failure_is_not_cached(monkeypatch, db_module):
    calls = {"n": 0}

    def flaky(url, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:   # page 1 ok (200 candidates in total, 1 returned, no CPE data -> skipped)
            return Resp({"totalResults": 200, "vulnerabilities": [{"cve": {"id": "CVE-2099-1", "descriptions": []}}]})
        raise cl.requests.Timeout("page 2 timed out")
    monkeypatch.setattr(cl.requests, "get", flaky)
    memo = {}
    cl.search_cves(memo=memo, **ARGS)
    assert calls["n"] >= 2
    assert _cache_rows(db_module) == 0
    assert memo[cl.LOOKUP_FAILURES_KEY]


def test_successful_empty_lookup_is_cached_and_not_flagged(monkeypatch, db_module):
    monkeypatch.setattr(cl.requests, "get", lambda *a, **k: Resp({"totalResults": 0, "vulnerabilities": []}))
    memo = {}
    assert cl.search_cves(memo=memo, **ARGS) == []
    assert _cache_rows(db_module) == 1
    assert cl.LOOKUP_FAILURES_KEY not in memo
