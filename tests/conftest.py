"""Test fixtures.

Tests run against a THROWAWAY PostgreSQL database that is created from
database/schema.sql at the start of the session and dropped at the end, so
they never touch the real application database. Connection settings come
from the usual DB_* environment variables / .env (host, user, password,
port); only the database NAME is overridden.

nmap and NVD are replaced with deterministic stubs - no network access or
nmap binary is needed for the suite.
"""
import os
import sys
import uuid

import psycopg2
import pytest
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
load_dotenv(os.path.join(ROOT, ".env"))

# ---- canned nmap XML --------------------------------------------------------
XML_ONE_PORT = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.1.1.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8080"><state state="open"/>
<service name="http" product="Apache httpd" version="2.4.58" method="probed" conf="10">
<cpe>cpe:/a:apache:http_server:2.4.58</cpe></service></port></ports></host></nmaprun>"""
XML_NO_PORTS = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.1.1.1" addrtype="ipv4"/><ports></ports></host></nmaprun>"""
XML_NO_HOSTS = """<?xml version="1.0"?><nmaprun><runstats>
<hosts up="0" down="0" total="0"/></runstats></nmaprun>"""
XML_MULTI = """<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/>
<address addr="AA:BB:CC:DD:EE:01" addrtype="mac" vendor="Netgear"/>
<hostnames><hostname name="router.lan"/></hostnames><os><osmatch name="Linux 4.x"/></os>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="lighttpd" version="1.4.55"><cpe>cpe:/a:lighttpd:lighttpd:1.4.55</cpe></service></port></ports></host>
<host><status state="down"/><address addr="192.168.1.5" addrtype="ipv4"/></host>
<host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
<port protocol="tcp" portid="445"><state state="filtered"/><service name="microsoft-ds"/></port></ports></host>
</nmaprun>"""


def _admin_conn():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        dbname="postgres",
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD"),
        port=os.environ.get("DB_PORT", "5432"),
    )


@pytest.fixture(scope="session", autouse=True)
def _test_database():
    name = f"sentrix_test_{uuid.uuid4().hex[:8]}"
    conn = _admin_conn()
    conn.autocommit = True
    conn.cursor().execute(f'CREATE DATABASE "{name}"')
    conn.close()
    os.environ["DB_NAME"] = name
    from database import db
    db.init_schema()
    yield name
    conn = _admin_conn()
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s", (name,))
    cur.execute(f'DROP DATABASE IF EXISTS "{name}"')
    conn.close()


DEFAULT_WEIGHTS = {"cvss": 0.30, "exploit": 0.10, "exposure": 0.15, "criticality": 0.15,
                   "business_impact": 0.10, "complexity": 0.05, "blast_radius": 0.05, "epss": 0.10}


@pytest.fixture(autouse=True)
def clean_db(_test_database):
    from database import db
    conn = db.get_connection()
    cur = conn.cursor()
    cur.execute(
        "TRUNCATE users, scans, assets, vulnerabilities, asset_services, scheduled_scans, "
        "cve_cache, epss_scores, known_exploited_cves, posture_snapshots RESTART IDENTITY CASCADE"
    )
    for factor, weight in DEFAULT_WEIGHTS.items():
        cur.execute("UPDATE risk_weights SET weight = %s WHERE factor = %s", (weight, factor))
    conn.commit()
    cur.close()
    conn.close()
    yield


@pytest.fixture(autouse=True)
def _linux_host_by_default(monkeypatch):
    """The Linux System Scan / Software Scan tests predate the Windows backends and must behave the same
    whichever OS runs the suite. Windows tests patch ``local_host_os`` to 'Windows' themselves."""
    import scanner.jobs as jobs
    import web.app as webapp
    monkeypatch.setattr(jobs, "local_host_os", lambda: "Linux")
    monkeypatch.setattr(webapp, "local_host_os", lambda: "Linux")


@pytest.fixture
def db_module():
    from database import db
    return db


@pytest.fixture
def make_user(db_module):
    def _make(username, role="analyst", password="password123"):
        return db_module.create_user(username, generate_password_hash(password), role=role)
    return _make


@pytest.fixture
def client():
    import web.app as webapp
    webapp.app.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    return webapp.app.test_client()


@pytest.fixture
def login(client):
    def _login(username, password="password123"):
        r = client.post("/login", data={"username": username, "password": password})
        assert r.status_code == 302, "login failed"
        return client
    return _login


@pytest.fixture
def stub_scan_backends(monkeypatch, tmp_path):
    """Replace nmap and NVD in the pipeline with deterministic stubs.
    Returns a controller whose .xml / .findings / .nmap_error / .nvd_fails
    attributes steer the next scans."""
    import scanner.pipeline as pipeline
    from vulnerability.cve_lookup import LOOKUP_FAILURES_KEY

    class Ctl:
        xml = XML_ONE_PORT
        nmap_error = None
        nvd_fails = False
        findings = [{
            "cve_id": "CVE-2099-0001", "severity": "HIGH", "cvss_score": 7.5,
            "description": "stub finding", "remediation": "upgrade", "attack_complexity": "LOW",
            "cwe_id": "CWE-79", "match_confidence": 0.9,
            "match_evidence": {"product": "Apache httpd", "vendor": "apache", "version": "2.4.58", "cpe_confirmed": True},
        }]
        written = []
        hook = None  # optional callable(target) run inside the fake nmap

    ctl = Ctl()

    def fake_nmap(target):
        if ctl.hook:
            ctl.hook(target)
        if ctl.nmap_error:
            raise RuntimeError(ctl.nmap_error)
        path = tmp_path / f"scan_{len(ctl.written)}_{target.replace('/', '_')}.xml"
        path.write_text(ctl.xml)
        ctl.written.append(str(path))
        return str(path)

    def fake_cves(service, product=None, vendor=None, version=None, cpe=None, memo=None, **kw):
        if ctl.nvd_fails and memo is not None:
            memo.setdefault(LOOKUP_FAILURES_KEY, []).append(f"{product or service} {version or ''}".strip())
            return []
        return [dict(f) for f in ctl.findings]

    monkeypatch.setattr(pipeline, "run_nmap_scan", fake_nmap)
    monkeypatch.setattr(pipeline, "search_cves", fake_cves)
    return ctl
