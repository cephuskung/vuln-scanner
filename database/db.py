"""
Database access layer.
Connection settings come from environment variables so credentials are never
hardcoded in source (the original version had two different hardcoded
passwords committed to the repo - avoid that).
    DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, DB_PORT
"""
import os
import json
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
load_dotenv()
def get_connection():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        dbname=os.environ.get("DB_NAME", "vuln_platform"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD"),
        port=os.environ.get("DB_PORT", "5432"),
    )
def init_schema():
    """Run schema.sql against the configured database (idempotent)."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path) as f:
        sql = f.read()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    cur.close()
    conn.close()
def upsert_asset(ip_address, os_name=None):
    """Create the asset if new, otherwise just bump last_scanned."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM assets WHERE ip_address = %s", (ip_address,))
    row = cur.fetchone()
    if row:
        asset_id = row[0]
        cur.execute(
            "UPDATE assets SET last_scanned = NOW(), os = COALESCE(%s, os) WHERE id = %s",
            (os_name, asset_id),
        )
    else:
        cur.execute(
            """
            INSERT INTO assets (name, ip_address, os, last_scanned)
            VALUES (%s, %s, %s, NOW())
            RETURNING id
            """,
            (ip_address, ip_address, os_name),
        )
        asset_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return asset_id
def get_asset(asset_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM assets WHERE id = %s", (asset_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
def update_asset_profile(asset_id, hostname=None, exposure=None, business_impact=None, criticality=None, owner=None):
    """Analyst-editable asset metadata (used by the asset detail page)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE assets SET
            hostname = COALESCE(%s, hostname),
            exposure = COALESCE(%s, exposure),
            business_impact = COALESCE(%s, business_impact),
            criticality = COALESCE(%s, criticality),
            owner = COALESCE(%s, owner)
        WHERE id = %s
        """,
        (hostname, exposure, business_impact, criticality, owner, asset_id),
    )
    conn.commit()
    cur.close()
    conn.close()
def mark_services_stale(asset_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE asset_services SET is_current = FALSE WHERE asset_id = %s", (asset_id,))
    conn.commit()
    cur.close()
    conn.close()
def insert_current_services(asset_id, scan_id, open_ports):
    """open_ports: list of dicts with port/protocol/service/version, as returned by parser.parse_nmap_xml."""
    if not open_ports:
        return
    conn = get_connection()
    cur = conn.cursor()
    for p in open_ports:
        cur.execute(
            """
            INSERT INTO asset_services (asset_id, scan_id, port_number, protocol, service, version, is_current)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE)
            """,
            (asset_id, scan_id, p.get("port"), p.get("protocol", "tcp"), p.get("service"), p.get("version")),
        )
    conn.commit()
    cur.close()
    conn.close()
def get_current_services(asset_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT port_number, protocol, service, version, detected_at
        FROM asset_services
        WHERE asset_id = %s AND is_current = TRUE
        ORDER BY port_number
        """,
        (asset_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def get_asset_vulnerabilities(asset_id):
    """All vulnerabilities across every scan this asset has had, most recent scan first."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT v.port_number, v.service, v.cve_id, v.severity, v.cvss_score,
               v.description, v.remediation, v.cwe_id,
               v.epss_score, v.contextual_priority, v.priority_label, v.is_kev,
               s.id AS scan_id, s.scan_time
        FROM vulnerabilities v
        JOIN scans s ON s.id = v.scan_id
        WHERE s.asset_id = %s
        ORDER BY s.scan_time DESC,
            CASE v.severity
                WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1
            END DESC
        """,
        (asset_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def get_asset_scan_history(asset_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT id, status, total_risk, scan_time, scan_type
        FROM scans WHERE asset_id = %s ORDER BY scan_time DESC
        """,
        (asset_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def get_asset_current_risk(asset_id):
    """Risk score of this asset's most recent completed scan."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT total_risk FROM scans
        WHERE asset_id = %s AND status = 'completed'
        ORDER BY scan_time DESC LIMIT 1
        """,
        (asset_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return float(row[0]) if row and row[0] is not None else 0.0
def get_assets(search=None):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = """
        SELECT a.id, a.name, a.hostname, a.ip_address, a.os, a.owner, a.criticality,
               a.exposure, a.business_impact, a.tags, a.first_seen, a.last_scanned,
               COALESCE(MAX(s.total_risk), 0) AS latest_risk,
               COUNT(s.id) AS scan_count
        FROM assets a
        LEFT JOIN scans s ON s.asset_id = a.id
    """
    params = []
    if search:
        query += " WHERE a.ip_address ILIKE %s OR a.name ILIKE %s OR a.owner ILIKE %s "
        like = f"%{search}%"
        params += [like, like, like]
    query += " GROUP BY a.id ORDER BY a.last_scanned DESC NULLS LAST"
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def create_scan(target, asset_id=None, created_by=None, scan_type="manual", status="running"):
    """status defaults to 'running' (the historical behaviour, used by the
    CLI); the web job path passes 'queued' so the lifecycle is
    queued -> running -> completed/failed."""
    if status not in ("queued", "running"):
        raise ValueError("a scan can only be created as 'queued' or 'running'")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scans (target, asset_id, status, created_by, scan_type)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id
        """,
        (target, asset_id, status, created_by, scan_type),
    )
    scan_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return scan_id
def update_scan_status(scan_id, status, total_risk=None, status_detail=None):
    """status_detail (optional) is a short, non-sensitive explanation shown
    to the user: the failure reason, or warnings on a completed scan whose
    results are incomplete. None leaves any existing detail untouched."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE scans
        SET status = %s,
            total_risk = COALESCE(%s, total_risk),
            status_detail = COALESCE(%s, status_detail),
            finished_at = CASE WHEN %s IN ('completed', 'failed') THEN NOW() ELSE finished_at END
        WHERE id = %s
        """,
        (status, total_risk, status_detail, status, scan_id),
    )
    conn.commit()
    cur.close()
    conn.close()
def get_scans(search=None, status=None, severity=None, limit=200, owner_id=None):
    """Scan history with optional search/status/severity filtering.
    owner_id (optional): restrict to scans created by that user."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = """
        SELECT DISTINCT s.id, s.target, s.status, s.total_risk, s.scan_time,
               s.scan_type, a.name AS asset_name
        FROM scans s
        LEFT JOIN assets a ON a.id = s.asset_id
    """
    joins = []
    where = []
    params = []
    if severity:
        joins.append("JOIN vulnerabilities v ON v.scan_id = s.id")
        where.append("v.severity = %s")
        params.append(severity)
    if search:
        where.append("s.target ILIKE %s")
        params.append(f"%{search}%")
    if status:
        where.append("s.status = %s")
        params.append(status)
    if owner_id is not None:
        where.append("s.created_by = %s")
        params.append(owner_id)
    if joins:
        query += " " + " ".join(joins)
    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY s.scan_time DESC LIMIT %s"
    params.append(limit)
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def get_scan(scan_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT s.id, s.target, s.status, s.total_risk, s.scan_time, s.finished_at,
               s.scan_type, s.asset_id, s.created_by, s.status_detail, s.scan_info,
               a.name AS asset_name, a.os AS asset_os,
               a.exposure AS asset_exposure, a.criticality AS asset_criticality,
               a.business_impact AS asset_business_impact
        FROM scans s
        LEFT JOIN assets a ON a.id = s.asset_id
        WHERE s.id = %s
        """,
        (scan_id,),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
def get_scan_status(scan_id):
    """Lightweight poll used by the real-time status widget."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT status, total_risk, created_by, status_detail, scan_info->>'progress' AS progress "
                "FROM scans WHERE id = %s", (scan_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
def save_vulnerabilities(scan_id, port, service, vulns):
    if not vulns:
        return
    conn = get_connection()
    cur = conn.cursor()
    for v in vulns:
        cur.execute(
            """
            INSERT INTO vulnerabilities
                (scan_id, port_number, service, cve_id, severity, cvss_score,
                 description, remediation, attack_complexity, cwe_id,
                 match_confidence, match_evidence,
                 epss_score, contextual_priority, priority_label, is_kev,
                 vulnerability_confidence, confidence_reason,
                 config_validation, config_evidence,
                 applicability_status, applicability_reason)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                scan_id,
                port,
                service,
                v.get("cve_id"),
                v.get("severity", "Unknown"),
                v.get("cvss_score"),
                v.get("description"),
                v.get("remediation"),
                v.get("attack_complexity", "UNKNOWN"),
                v.get("cwe_id"),
                v.get("match_confidence"),
                json.dumps(v.get("match_evidence")),
                v.get("epss_score"),
                v.get("contextual_priority"),
                v.get("priority_label"),
                bool(v.get("is_kev", False)),
                v.get("vulnerability_confidence"),
                v.get("confidence_reason"),
                json.dumps(v.get("config_validation")) if v.get("config_validation") is not None else None,
                json.dumps(v.get("config_evidence")) if v.get("config_evidence") is not None else None,
                v.get("applicability_status"),
                v.get("applicability_reason"),
            ),
        )
    conn.commit()
    cur.close()
    conn.close()
def get_vulnerabilities(scan_id):
    """Findings for a single scan, used by the scan details page and the
    per-scan PDF report. Includes vulnerability_confidence and
    confidence_reason (IVMP confidence scoring), applicability_status /
    applicability_reason (IVMP applicability assessment), and
    match_confidence alongside the existing severity/CVSS/EPSS/
    contextual-priority/KEV fields - purely additive, no existing columns
    were removed and no risk calculation changed.

    match_confidence is included specifically because web/app.py's
    scan_detail() route recomputes contextual_priority/priority_label live
    on every view (intentionally - see the Settings page's "New scores
    apply the next time a scan's details are viewed" flash message, which
    lets an admin re-weight risk factors without rescanning).
    risk/contextual_risk.py's calculate_contextual_risk() defaults a
    missing match_confidence to 1.0 (full confidence), so without this
    column that live recompute silently overstated confidence for every
    finding whose real match_confidence was below 1.0 - the displayed
    contextual_priority could then differ from (and read higher than) the
    value scanner/pipeline.py actually calculated and stored at scan time,
    and from what scan_pdf() shows for the same finding, since scan_pdf()
    uses the stored value directly rather than recomputing."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT port_number, service, cve_id, severity, cvss_score, description,
               remediation, attack_complexity, compensating_controls, cwe_id,
               epss_score, contextual_priority, priority_label, is_kev,
               vulnerability_confidence, confidence_reason,
               applicability_status, applicability_reason, match_confidence,
               match_evidence
        FROM vulnerabilities
        WHERE scan_id = %s
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 5
                WHEN 'HIGH' THEN 4
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 2
                ELSE 1
            END DESC
        """,
        (scan_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def get_severity_stats(owner_id=None):
    """Severity distribution of the CURRENT picture: findings from each
    asset's most recent completed scan (not every historical or failed
    scan's rows, which double-counted the same finding on every rescan)."""
    own_and = " AND created_by = %s" if owner_id is not None else ""
    own_p = (owner_id,) if owner_id is not None else ()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT severity, COUNT(*) FROM (SELECT DISTINCT s.asset_id, COALESCE(v.cve_id, 'row' || v.id), v.severity"
        " FROM vulnerabilities v JOIN scans s ON s.id = v.scan_id WHERE v.scan_id IN ("
        + _LATEST_SCANS_SQL + own_and + _LATEST_SCANS_ORDER + ")) t GROUP BY severity", own_p
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "Unknown": 0}
    for severity, count in rows:
        stats[severity if severity in stats else "Unknown"] += count
    return stats
_SCAN_KIND_SQL = "CASE WHEN scan_type IN ('system-local','system-remote','system-windows') THEN 'system' WHEN scan_type = 'software' THEN 'software' ELSE 'network' END"
_LATEST_SCANS_SQL = ("SELECT DISTINCT ON (asset_id, " + _SCAN_KIND_SQL + ") id FROM scans"
                     " WHERE status = 'completed' AND asset_id IS NOT NULL")
_LATEST_SCANS_ORDER = " ORDER BY asset_id, " + _SCAN_KIND_SQL + ", scan_time DESC"


def get_kpis(owner_id=None):
    """Executive summary numbers for the KPI cards.

    critical_vulns counts findings in each asset's most recent COMPLETED
    scan only - not every row ever stored. Counting every historical row
    (and rows from failed scans) made the figure grow with each rescan of
    the same host, which overstated exposure. owner_id (optional) restricts
    every figure to scans created by that user.
    """
    own_and = " AND created_by = %s" if owner_id is not None else ""
    own_p = (owner_id,) if owner_id is not None else ()
    conn = get_connection()
    cur = conn.cursor()
    if owner_id is None:
        cur.execute("SELECT COUNT(*) FROM assets")
    else:
        cur.execute("SELECT COUNT(DISTINCT asset_id) FROM scans WHERE asset_id IS NOT NULL" + own_and, own_p)
    total_assets = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scans WHERE TRUE" + own_and, own_p)
    total_scans = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'" + own_and, own_p)
    running_scans = cur.fetchone()[0]
    cur.execute(
        "SELECT COALESCE(AVG(total_risk), 0) FROM scans "
        "WHERE status = 'completed' AND scan_type <> 'network'" + own_and, own_p
    )
    avg_risk = round(float(cur.fetchone()[0]), 1)
    cur.execute(
        "SELECT COUNT(*) FROM (SELECT DISTINCT s.asset_id, COALESCE(v.cve_id, 'row' || v.id) "
        " FROM vulnerabilities v JOIN scans s ON s.id = v.scan_id"
        " WHERE v.severity = 'CRITICAL' AND v.scan_id IN (" + _LATEST_SCANS_SQL + own_and + _LATEST_SCANS_ORDER + ")) t", own_p
    )
    critical_vulns = cur.fetchone()[0]
    cur.close()
    conn.close()
    return {
        "total_assets": total_assets,
        "total_scans": total_scans,
        "running_scans": running_scans,
        "avg_risk": avg_risk,
        "critical_vulns": critical_vulns,
    }
def get_risk_trend(limit=14, owner_id=None):
    """Last N completed scans' risk scores, oldest first - feeds the trend
    chart. Network-scan parent records (no findings of their own) are
    excluded; their per-host scans are what carry risk."""
    own_and = " AND created_by = %s" if owner_id is not None else ""
    params = ((owner_id,) if owner_id is not None else ()) + (limit,)
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT scan_time, total_risk FROM scans "
        "WHERE status = 'completed' AND scan_type <> 'network'" + own_and +
        " ORDER BY scan_time DESC LIMIT %s", params
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return list(reversed(rows))
def create_user(username, password_hash, role="analyst"):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id",
        (username, password_hash, role),
    )
    user_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return user_id
def get_user_by_username(username):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
def get_user_by_id(user_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
def any_users_exist():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT EXISTS(SELECT 1 FROM users)")
    exists = cur.fetchone()[0]
    cur.close()
    conn.close()
    return exists
def create_scheduled_scan(target, interval_minutes, created_by=None, asset_id=None):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scheduled_scans (target, asset_id, interval_minutes, next_run, created_by)
        VALUES (%s, %s, %s, NOW(), %s)
        RETURNING id
        """,
        (target, asset_id, interval_minutes, created_by),
    )
    sid = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return sid
def get_scheduled_scans(owner_id=None):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if owner_id is None:
        cur.execute("SELECT * FROM scheduled_scans ORDER BY next_run ASC")
    else:
        cur.execute("SELECT * FROM scheduled_scans WHERE created_by = %s ORDER BY next_run ASC", (owner_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_scheduled_scan(scheduled_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM scheduled_scans WHERE id = %s", (scheduled_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
def get_due_scheduled_scans():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM scheduled_scans WHERE active = TRUE AND next_run <= NOW()"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def bump_scheduled_scan(scheduled_id, interval_minutes):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE scheduled_scans
        SET next_run = NOW() + (%s || ' minutes')::interval
        WHERE id = %s
        """,
        (interval_minutes, scheduled_id),
    )
    conn.commit()
    cur.close()
    conn.close()
def set_scheduled_scan_active(scheduled_id, active):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE scheduled_scans SET active = %s WHERE id = %s", (active, scheduled_id))
    conn.commit()
    cur.close()
    conn.close()
def get_risk_weights():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT factor, weight FROM risk_weights")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {factor: float(weight) for factor, weight in rows}
def update_risk_weights(weights):
    """weights: dict of factor -> float, e.g. {'cvss': 0.3, 'exploit': 0.2, ...}"""
    conn = get_connection()
    cur = conn.cursor()
    for factor, weight in weights.items():
        cur.execute(
            "UPDATE risk_weights SET weight = %s WHERE factor = %s",
            (weight, factor),
        )
    conn.commit()
    cur.close()
    conn.close()
def replace_kev_cache(kev_entries):
    """kev_entries: list of dicts from the CISA KEV JSON feed
    (keys: cveID, dateAdded, knownRansomwareCampaignUse)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("TRUNCATE known_exploited_cves")
    for entry in kev_entries:
        cur.execute(
            """
            INSERT INTO known_exploited_cves (cve_id, date_added, ransomware_use)
            VALUES (%s, %s, %s)
            ON CONFLICT (cve_id) DO NOTHING
            """,
            (entry.get("cveID"), entry.get("dateAdded"), entry.get("knownRansomwareCampaignUse")),
        )
    conn.commit()
    cur.close()
    conn.close()
def get_kev_cve_ids():
    """Set of every CVE ID in the cached CISA KEV catalog - O(1) membership checks."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT cve_id FROM known_exploited_cves")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {r[0] for r in rows}
def replace_epss_cache(entries):
    """entries: list of (cve_id, epss_score, percentile, model_date) tuples.
    Uses execute_values for batched inserts - the EPSS dataset covers
    essentially every published CVE (~250k+ rows), so one-row-at-a-time
    INSERTs would be far too slow."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("TRUNCATE epss_scores")
    if entries:
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO epss_scores (cve_id, epss_score, percentile, model_date)
            VALUES %s
            ON CONFLICT (cve_id) DO NOTHING
            """,
            entries,
            page_size=2000,
        )
    conn.commit()
    cur.close()
    conn.close()
def get_epss_scores():
    """cve_id -> epss_score (float) for every cached CVE - O(1) lookups,
    same pattern as get_kev_cve_ids()."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT cve_id, epss_score FROM epss_scores")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {cve_id: float(score) for cve_id, score in rows}
def get_blast_radius_map():
    """CVE ID -> number of distinct assets affected by it, across all scans.
    One grouped query instead of a per-finding lookup."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT v.cve_id, COUNT(DISTINCT s.asset_id)
        FROM vulnerabilities v
        JOIN scans s ON s.id = v.scan_id
        WHERE v.cve_id IS NOT NULL
        GROUP BY v.cve_id
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return {cve_id: count for cve_id, count in rows}
def get_current_vulnerabilities_all_assets():
    """Findings from each asset's most recent COMPLETED scan of each kind
    (network / system / software) - i.e.
    the vulnerability picture of the environment as it stands today, not
    every historical finding ever recorded."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT v.service, v.severity
        FROM vulnerabilities v
        JOIN (
            SELECT DISTINCT ON (asset_id, CASE WHEN scan_type IN ('system-local','system-remote','system-windows') THEN 'system'
                                               WHEN scan_type = 'software' THEN 'software' ELSE 'network' END) id
            FROM scans
            WHERE status = 'completed' AND asset_id IS NOT NULL
            ORDER BY asset_id, CASE WHEN scan_type IN ('system-local','system-remote','system-windows') THEN 'system'
                                    WHEN scan_type = 'software' THEN 'software' ELSE 'network' END, scan_time DESC
        ) latest_scans ON latest_scans.id = v.scan_id
        """
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def upsert_posture_snapshot(scores):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO posture_snapshots
            (snapshot_date, overall_score, network_score, host_score, web_score, patch_score, config_score)
        VALUES (CURRENT_DATE, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (snapshot_date) DO UPDATE SET
            overall_score = EXCLUDED.overall_score,
            network_score = EXCLUDED.network_score,
            host_score = EXCLUDED.host_score,
            web_score = EXCLUDED.web_score,
            patch_score = EXCLUDED.patch_score,
            config_score = EXCLUDED.config_score
        """,
        (
            scores["overall_score"], scores["network_score"], scores["host_score"],
            scores["web_score"], scores["patch_score"], scores["config_score"],
        ),
    )
    conn.commit()
    cur.close()
    conn.close()
def get_posture_history(limit=30):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM posture_snapshots ORDER BY snapshot_date DESC LIMIT %s",
        (limit,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return list(reversed(rows))
def get_latest_posture():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM posture_snapshots ORDER BY snapshot_date DESC LIMIT 1")
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row
def get_all_vulnerabilities(search=None, severity=None, kev_only=False, limit=300, owner_id=None):
    """Every finding across every scan, joined with asset/scan context and
    CISA KEV status - the "everything, everywhere" triage view.

    Note: is_kev here is still computed live via the known_exploited_cves
    join (not read from the new vulnerabilities.is_kev column), so it
    always reflects the CURRENT KEV catalog - including for findings
    scanned before a CVE was added to KEV. That's what the kev_only filter
    below relies on. epss_score/contextual_priority/priority_label are the
    values persisted at scan time (see scanner/pipeline.py).
    """
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = """
        SELECT v.id, v.cve_id, v.severity, v.cvss_score, v.service, v.port_number, v.cwe_id,
               v.epss_score, v.contextual_priority, v.priority_label,
               s.id AS scan_id, s.scan_time, a.id AS asset_id,
               COALESCE(a.hostname, a.name, a.ip_address) AS asset_label,
               (k.cve_id IS NOT NULL) AS is_kev
        FROM vulnerabilities v
        JOIN scans s ON s.id = v.scan_id
        LEFT JOIN assets a ON a.id = s.asset_id
        LEFT JOIN known_exploited_cves k ON k.cve_id = v.cve_id
    """
    where = []
    params = []
    if search:
        where.append("(a.ip_address ILIKE %s OR a.hostname ILIKE %s OR a.name ILIKE %s OR v.cve_id ILIKE %s)")
        like = f"%{search}%"
        params += [like, like, like, like]
    if severity:
        where.append("v.severity = %s")
        params.append(severity)
    if kev_only:
        where.append("k.cve_id IS NOT NULL")
    if owner_id is not None:
        where.append("s.created_by = %s")
        params.append(owner_id)
    if where:
        query += " WHERE " + " AND ".join(where)
    query += """
        ORDER BY
            CASE v.severity
                WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4
                WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1
            END DESC,
            s.scan_time DESC
        LIMIT %s
    """
    params.append(limit)
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows
def get_cached_cve_lookup(service, version, ttl_days, matcher_version, empty_ttl_hours=1):
    """Returns the cached list of CVE result dicts for (service, version) if
    a row exists, was produced by the CURRENT matcher_version, and is still
    fresh - otherwise None (cache miss: never cached, expired, or computed
    under different matching logic).

    Freshness is asymmetric on purpose:
    - A NON-EMPTY result (real CVEs were found) is trusted for the full
      ttl_days, since a CVE doesn't stop existing between scans.
    - An EMPTY result ([]) is only trusted for empty_ttl_hours (default 1
      hour). An empty result is ambiguous - it can mean "NVD was checked
      and genuinely has nothing that applies" or "a transient failure /
      matcher bug produced nothing" - and there's no way to tell those
      apart from the stored row alone. Rather than risk silently reporting
      a false all-clear for days, we re-check NVD much sooner when the
      cached answer is empty.

    A row whose matcher_version doesn't match the current one is ALWAYS a
    miss, regardless of age or emptiness - it was computed under matching
    logic that may since have changed (e.g. a CPE-filtering fix), so it
    can't be trusted as-is. This is what prevents a stale result computed
    under old/buggy logic from silently outliving a fix to that logic.
    """
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT results, cached_at, matcher_version
        FROM cve_cache
        WHERE service = %s AND version = %s
        """,
        (service, version),
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return None
    if row["matcher_version"] != matcher_version:
        return None

    results = row["results"]
    age_limit = timedelta(hours=empty_ttl_hours) if not results else timedelta(days=ttl_days)

    cached_at = row["cached_at"]
    now = datetime.now(cached_at.tzinfo) if cached_at.tzinfo else datetime.now()
    if now - cached_at > age_limit:
        return None

    return results
def upsert_cve_cache(service, version, results, matcher_version):
    """Stores (or refreshes) the CVE lookup results for (service, version),
    tagged with the matcher_version that produced them (see
    get_cached_cve_lookup for why this tag matters).
    results: list of vuln dicts, the same shape vulnerability.cve_lookup
    returns and database.db.save_vulnerabilities expects - stored as-is in
    a JSONB column. ON CONFLICT bumps cached_at (and refreshes
    matcher_version) so the TTL window restarts from this successful fetch."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO cve_cache (service, version, results, cached_at, matcher_version)
        VALUES (%s, %s, %s, NOW(), %s)
        ON CONFLICT (service, version) DO UPDATE SET
            results = EXCLUDED.results,
            cached_at = NOW(),
            matcher_version = EXCLUDED.matcher_version
        """,
        (service, version, psycopg2.extras.Json(results), matcher_version),
    )
    conn.commit()
    cur.close()
    conn.close()


def create_scan_if_idle(target, asset_id=None, created_by=None, scan_type="manual", status="queued"):
    """Insert a scan row ONLY if no queued/running scan already exists for
    the same target; returns the new scan id, or None when one is active.
    The check and the insert are a single statement (callers additionally
    serialise submissions with a process-level lock), so a double-click or
    an overlapping scheduled run can't start the same target twice."""
    if status not in ("queued", "running"):
        raise ValueError("a scan can only be created as 'queued' or 'running'")
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scans (target, asset_id, status, created_by, scan_type)
        SELECT %s::varchar, %s::integer, %s::varchar, %s::integer, %s::varchar
        WHERE NOT EXISTS (
            SELECT 1 FROM scans WHERE target = %s AND status IN ('queued', 'running')
        )
        RETURNING id
        """,
        (target, asset_id, status, created_by, scan_type, target),
    )
    row = cur.fetchone()
    conn.commit()
    cur.close()
    conn.close()
    return row[0] if row else None


def fail_interrupted_scans(reason="Interrupted: the application stopped or restarted before this scan finished."):
    """Startup recovery: scans are run by in-process threads, so any scan
    still 'queued'/'running' when the application (re)starts can never
    finish. Mark them failed rather than leaving them 'running' forever.
    Returns the number of scans recovered."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE scans
        SET status = 'failed', finished_at = NOW(),
            status_detail = COALESCE(status_detail, %s)
        WHERE status IN ('queued', 'running')
        RETURNING id
        """,
        (reason,),
    )
    n = len(cur.fetchall())
    conn.commit()
    cur.close()
    conn.close()
    return n


# ---------------------------------------------------------------------------
# Software Scan / System Scan persistence
# ---------------------------------------------------------------------------
def set_scan_info(scan_id, info):
    """Attach structured, NON-SECRET facts about how a scan ran (see schema)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("UPDATE scans SET scan_info = %s WHERE id = %s", (psycopg2.extras.Json(info), scan_id))
    conn.commit()
    cur.close()
    conn.close()


def save_software_inventory(scan_id, rows):
    """rows: dicts with product, source and optionally vendor, version,
    upstream_version, cpe_vendor, cpe_product, assessment, note, findings_count."""
    if not rows:
        return
    conn = get_connection()
    cur = conn.cursor()
    psycopg2.extras.execute_batch(
        cur,
        """
        INSERT INTO software_inventory
            (scan_id, vendor, product, version, upstream_version, source, cpe_vendor, cpe_product,
             assessment, note, findings_count,
             install_date, inventory_source, collection_status, identity_source, assessment_reason)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        [
            (
                scan_id, (r.get("vendor") or None) and r["vendor"][:120], (r.get("product") or "")[:255],
                (r.get("version") or None) and r["version"][:120],
                r.get("upstream_version"), r["source"], r.get("cpe_vendor"), r.get("cpe_product"),
                r.get("assessment", "not_assessed"), r.get("note"), int(r.get("findings_count") or 0),
                r.get("install_date"), (r.get("inventory_source") or None) and r["inventory_source"][:255],
                r.get("collection_status"), r.get("identity_source"), r.get("assessment_reason"),
            )
            for r in rows
        ],
        page_size=500,
    )
    conn.commit()
    cur.close()
    conn.close()


def get_software_inventory(scan_id, assessed_only=False, limit=None, findings_first=False):
    """findings_first=True lists applications with the most findings first (used
    by the installed-application inventory view); the default ordering is
    unchanged for the existing Software/System scan views."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    query = "SELECT * FROM software_inventory WHERE scan_id = %s"
    if assessed_only:
        query += " AND assessment <> 'not_assessed'"
    if findings_first:
        query += " ORDER BY findings_count DESC, (assessment = 'not_assessed'), LOWER(product), version"
    else:
        query += " ORDER BY (assessment = 'not_assessed'), product, version"
    params = [scan_id]
    if limit:
        query += " LIMIT %s"
        params.append(limit)
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def count_software_inventory(scan_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*), COUNT(*) FILTER (WHERE assessment <> 'not_assessed') "
                "FROM software_inventory WHERE scan_id = %s", (scan_id,))
    total, assessed = cur.fetchone()
    cur.close()
    conn.close()
    return {"total": total, "assessed": assessed}


def save_system_checks(scan_id, checks):
    if not checks:
        return
    conn = get_connection()
    cur = conn.cursor()
    psycopg2.extras.execute_batch(
        cur,
        """
        INSERT INTO system_checks
            (scan_id, check_id, category, title, status, severity, evidence, remediation, requires,
             contextual_priority, priority_label)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        [
            (scan_id, c["check_id"], c["category"], c["title"], c["status"], c.get("severity"),
             c.get("evidence"), c.get("remediation"), c.get("requires"),
             c.get("contextual_priority"), c.get("priority_label"))
            for c in checks
        ],
    )
    conn.commit()
    cur.close()
    conn.close()


def get_system_checks(scan_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT * FROM system_checks WHERE scan_id = %s
        ORDER BY CASE status WHEN 'fail' THEN 0 WHEN 'unknown' THEN 1 WHEN 'info' THEN 2
                             WHEN 'pass' THEN 3 ELSE 4 END,
                 COALESCE(contextual_priority, 0) DESC, category, check_id
        """,
        (scan_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def get_assets_for_owner(owner_id):
    """Assets that appear in scans created by this user (id, name, hostname,
    ip_address) - what a non-admin may attach a Software Scan to."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT DISTINCT a.id, a.name, a.hostname, a.ip_address
        FROM assets a JOIN scans s ON s.asset_id = a.id
        WHERE s.created_by = %s ORDER BY a.ip_address
        """,
        (owner_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# Microsoft Defender threat findings (Windows System Scan)
# ---------------------------------------------------------------------------
def save_threat_findings(scan_id, rows):
    """rows: dicts from scanner.windows_defender (see ThreatRecord.to_row)."""
    if not rows:
        return
    conn = get_connection()
    cur = conn.cursor()
    psycopg2.extras.execute_batch(
        cur,
        """
        INSERT INTO threat_findings
            (scan_id, detection_id, threat_id, threat_name, severity, defender_severity, resources, process_name,
             domain_user, initial_detection_time, last_status_change, status, action_success, execution_status,
             attribution, in_scan_scope, needs_attention, evidence, remediation)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        [
            (
                scan_id, r.get("detection_id"), r.get("threat_id"), r.get("threat_name"), r.get("severity"),
                r.get("defender_severity"), psycopg2.extras.Json(r.get("resources") or []), r.get("process_name"),
                r.get("domain_user"), r.get("initial_detection_time"), r.get("last_status_change"), r.get("status"),
                r.get("action_success"), r.get("execution_status"), r.get("attribution") or "historical",
                r.get("in_scan_scope"), bool(r.get("needs_attention")),
                psycopg2.extras.Json(r.get("evidence") or {}), r.get("remediation"),
            )
            for r in rows
        ],
    )
    conn.commit()
    cur.close()
    conn.close()


def get_threat_findings(scan_id):
    """Current-scan detections first, then unresolved historical ones, then the rest."""
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        """
        SELECT * FROM threat_findings WHERE scan_id = %s
        ORDER BY CASE attribution WHEN 'current_scan' THEN 0 WHEN 'unattributed' THEN 1 ELSE 2 END,
                 needs_attention DESC,
                 CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                 initial_detection_time DESC NULLS LAST, id
        """,
        (scan_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def count_threat_findings(scan_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE attribution = 'current_scan'), "
        "COUNT(*) FILTER (WHERE needs_attention) FROM threat_findings WHERE scan_id = %s", (scan_id,))
    total, current, attention = cur.fetchone()
    cur.close()
    conn.close()
    return {"total": total, "current_scan": current, "needs_attention": attention}
