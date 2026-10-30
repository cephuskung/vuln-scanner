-- Vulnerability Scanner Platform schema
-- Run once against your Postgres database:
--   psql -U postgres -d vuln_platform -f database/schema.sql
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(20) NOT NULL DEFAULT 'analyst',  -- 'admin' | 'analyst'
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS assets (
    id            SERIAL PRIMARY KEY,
    name          VARCHAR(255),
    ip_address    VARCHAR(64) UNIQUE NOT NULL,
    os            VARCHAR(255),
    owner         VARCHAR(120),
    criticality   VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',   -- CRITICAL/HIGH/MEDIUM/LOW
    tags          VARCHAR(255),
    first_seen    TIMESTAMP NOT NULL DEFAULT NOW(),
    last_scanned  TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scans (
    id           SERIAL PRIMARY KEY,
    asset_id     INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    target       VARCHAR(255) NOT NULL,
    status       VARCHAR(20) NOT NULL DEFAULT 'queued',    -- queued/running/completed/failed
    total_risk   NUMERIC(6,2) DEFAULT 0,
    scan_time    TIMESTAMP NOT NULL DEFAULT NOW(),
    finished_at  TIMESTAMP,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    scan_type    VARCHAR(20) NOT NULL DEFAULT 'manual'     -- manual/scheduled
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id           SERIAL PRIMARY KEY,
    scan_id      INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    port_number  INTEGER,
    service      VARCHAR(120),
    cve_id       VARCHAR(40),
    severity     VARCHAR(20) NOT NULL DEFAULT 'Unknown',
    cvss_score   NUMERIC(3,1),
    description  TEXT,
    remediation  TEXT
);
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id              SERIAL PRIMARY KEY,
    target          VARCHAR(255) NOT NULL,
    asset_id        INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    interval_minutes INTEGER NOT NULL DEFAULT 1440,        -- e.g. 1440 = daily
    next_run        TIMESTAMP NOT NULL DEFAULT NOW(),
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cve_id ON vulnerabilities(cve_id);
-- ===========================================================
-- IVMP Phase 1: Asset Intelligence
-- ===========================================================
ALTER TABLE assets ADD COLUMN IF NOT EXISTS hostname VARCHAR(255);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS exposure VARCHAR(20) NOT NULL DEFAULT 'INTERNAL';       -- INTERNAL | EXTERNAL
ALTER TABLE assets ADD COLUMN IF NOT EXISTS business_impact VARCHAR(20) NOT NULL DEFAULT 'MEDIUM';   -- CRITICAL/HIGH/MEDIUM/LOW, used later for contextual risk
-- point-in-time snapshot of what's running on an asset; refreshed on every completed scan
CREATE TABLE IF NOT EXISTS asset_services (
    id           SERIAL PRIMARY KEY,
    asset_id     INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    scan_id      INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    port_number  INTEGER NOT NULL,
    protocol     VARCHAR(10) DEFAULT 'tcp',
    service      VARCHAR(120),
    version      VARCHAR(120),
    is_current   BOOLEAN NOT NULL DEFAULT TRUE,
    detected_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_services_asset ON asset_services(asset_id, is_current);
-- ===========================================================
-- IVMP Phase 2: Context-Aware Risk Prioritisation
-- ===========================================================
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS attack_complexity VARCHAR(10) DEFAULT 'UNKNOWN';   -- LOW | HIGH | UNKNOWN
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS compensating_controls NUMERIC(3,2) NOT NULL DEFAULT 0; -- analyst-entered, 0-1
-- tunable weights for the contextual risk formula (Settings page edits these)
CREATE TABLE IF NOT EXISTS risk_weights (
    id     SERIAL PRIMARY KEY,
    factor VARCHAR(30) UNIQUE NOT NULL,
    weight NUMERIC(4,2) NOT NULL
);
INSERT INTO risk_weights (factor, weight) VALUES
    ('cvss', 0.30), ('exploit', 0.10), ('exposure', 0.15), ('criticality', 0.15),
    ('business_impact', 0.10), ('complexity', 0.05), ('blast_radius', 0.05)
ON CONFLICT (factor) DO NOTHING;
-- cached copy of the CISA Known Exploited Vulnerabilities catalog (refreshed by web/scheduler.py)
CREATE TABLE IF NOT EXISTS known_exploited_cves (
    cve_id           VARCHAR(40) PRIMARY KEY,
    date_added       DATE,
    ransomware_use   VARCHAR(10),
    refreshed_at     TIMESTAMP NOT NULL DEFAULT NOW()
);
-- ===========================================================
-- IVMP Phase 7: Threat Intel Expansion (EPSS + CWE)
-- ===========================================================
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cwe_id VARCHAR(20);
-- cached daily EPSS snapshot (refreshed by web/scheduler.py)
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id        VARCHAR(40) PRIMARY KEY,
    epss_score    NUMERIC(8,7),
    percentile    NUMERIC(8,7),
    model_date    DATE,
    refreshed_at  TIMESTAMP NOT NULL DEFAULT NOW()
);
INSERT INTO risk_weights (factor, weight) VALUES ('epss', 0.10)
ON CONFLICT (factor) DO NOTHING;
-- ===========================================================
-- IVMP Phase 4: Security Posture Management
-- ===========================================================
CREATE TABLE IF NOT EXISTS posture_snapshots (
    id            SERIAL PRIMARY KEY,
    snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE UNIQUE,
    overall_score NUMERIC(5,2),
    network_score NUMERIC(5,2),
    host_score    NUMERIC(5,2),
    web_score     NUMERIC(5,2),
    patch_score   NUMERIC(5,2),
    config_score  NUMERIC(5,2)
);
-- ===========================================================
-- NVD Lookup Cache
-- ===========================================================
CREATE TABLE IF NOT EXISTS cve_cache (
    id              SERIAL PRIMARY KEY,
    service         VARCHAR(120) NOT NULL,
    version         VARCHAR(64) NOT NULL DEFAULT '',
    results         JSONB NOT NULL,
    cached_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    matcher_version VARCHAR(64),
    UNIQUE (service, version)
);
ALTER TABLE cve_cache ADD COLUMN IF NOT EXISTS matcher_version VARCHAR(64);
CREATE INDEX IF NOT EXISTS idx_cve_cache_lookup ON cve_cache(service, version);
-- ===========================================================
-- IVMP Phase 8: Centralized Contextual Risk (CLI + Web parity)
-- ===========================================================
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_score NUMERIC(8,7);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS contextual_priority NUMERIC(5,1);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS priority_label VARCHAR(20);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS is_kev BOOLEAN NOT NULL DEFAULT FALSE;
-- ===========================================================
-- IVMP Phase 9: Vulnerability Confidence Scoring
-- ===========================================================
-- Confidence that a reported finding is a REAL, exploitable match - distinct
-- from severity (how bad it would be) and contextual_priority (how urgently
-- to fix it). A CVE can be CRITICAL severity and still low-confidence (e.g.
-- weak version evidence, or exploitation gated on a configuration we can't
-- confirm remotely, like CVE-2023-38408's dependence on ssh-agent
-- forwarding + PKCS#11 loading). Populated by risk/confidence.py at scan
-- time (see scanner/pipeline.py). Nullable so existing rows (scanned before
-- this migration) read back as NULL rather than breaking.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS vulnerability_confidence NUMERIC(3,2);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS confidence_reason TEXT;
-- ===========================================================
-- IVMP Phase 10: Configuration Validation Layer
-- ===========================================================
-- What can be directly, remotely confirmed about a detected service's
-- configuration (currently SSH only - see scanner/config_validator.py),
-- separate from cve_id matching, contextual_priority, and
-- vulnerability_confidence, none of which this phase touches.
-- config_validation: JSON object of check_name -> "confirmed" |
--   "not_confirmed" | "unknown" (e.g. {"service_exposed": "confirmed",
--   "version_detected": "confirmed", "ssh_version": "OpenSSH 8.9p1",
--   "root_login_permitted": "unknown", ...}).
-- config_evidence: JSON array of the plain-text evidence strings that
--   back those checks.
-- Both nullable so existing rows (scanned before this migration, or for
-- services not yet supported by the validator) read back as NULL rather
-- than breaking.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS config_validation JSONB;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS config_evidence JSONB;
-- ===========================================================
-- IVMP Phase 11: CVE Applicability Assessment
-- ===========================================================
-- Distinguishes how well-supported the CVE-to-detected-service
-- correlation is (CONFIRMED / PROBABLE / UNCONFIRMED), separate from
-- severity, contextual_priority, and vulnerability_confidence - see
-- vulnerability/applicability.py. Nullable so existing rows (scanned
-- before this migration) read back as NULL rather than breaking.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS applicability_status VARCHAR(20);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS applicability_reason TEXT;
-- ===========================================================
-- IVMP Phase 12: Risk Weight Correction
-- ===========================================================
-- The Phase 7 addition of the 'epss' weight (0.10, above) was never offset
-- by reducing any existing weight, so the seeded risk_weights totaled 1.10
-- instead of 1.00. risk/contextual_risk.py's score is a weighted sum that
-- gets clamped to [0, 1] before being scaled to 0-100, so a total above
-- 1.00 let high-scoring findings flatten to exactly 100 instead of being
-- distinguishable from each other.
-- 'exploit' (CISA KEV - binary, retrospective "this HAS been exploited")
-- and 'epss' (continuous, forward-looking "this IS LIKELY to be exploited")
-- both measure exploitation likelihood - see contextual_risk.py's module
-- docstring - so the fix splits their combined pre-Phase-7 budget of 0.20
-- evenly between the two: 'exploit' drops from 0.20 to 0.10, 'epss' stays
-- at 0.10, restoring the total to exactly 1.00 without touching any other
-- factor.
-- This UPDATE only touches rows still at the old buggy default (0.20) -
-- an admin who has already customized 'exploit' via the Settings page is
-- left untouched, and re-running this script is a no-op once applied.
UPDATE risk_weights SET weight = 0.10 WHERE factor = 'exploit' AND weight = 0.20;
-- ===========================================================
-- IVMP Phase 13: Match Confidence Persistence
-- ===========================================================
-- database/db.py::save_vulnerabilities() has always inserted match_confidence
-- and match_evidence (populated by vulnerability/cve_lookup.py::search_cves()
-- and read by risk/contextual_risk.py, risk/confidence.py, and
-- vulnerability/applicability.py during the same scan), but the columns
-- backing them were never added to this schema - so any scan that found at
-- least one real CVE failed at this INSERT with:
--   psycopg2.errors.UndefinedColumn: column "match_confidence" of relation
--   "vulnerabilities" does not exist
-- match_confidence is a 0-1 score built from fixed component weights (see
-- cve_lookup.py::_score_match(): {0.50|0.40} + {0.30|0.25|0.20} +
-- {0.20|0.18|0.15}), never more than 2 decimal places - same shape as the
-- existing vulnerability_confidence column, so it gets the same type.
-- match_evidence is a plain JSON-serializable dict (product/vendor/version/
-- cpe_confirmed) passed through json.dumps() before insert, exactly like the
-- existing config_validation/config_evidence columns - same type as those.
-- Both nullable, no default, so existing rows (scanned before this
-- migration) read back as NULL rather than breaking, matching every prior
-- phase's convention above.
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS match_confidence NUMERIC(3,2);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS match_evidence JSONB;
-- ===========================================================
-- IVMP Phase 14: Scan lifecycle detail + ownership lookups
-- ===========================================================
-- status_detail: human-readable, non-sensitive explanation attached to a
-- scan's final state - the failure reason for 'failed' scans, or warnings
-- for 'completed' ones whose results are incomplete (e.g. the NVD lookup
-- was unavailable, or no open ports were found so the absence of findings
-- is inconclusive). Nullable: existing rows simply have no detail.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS status_detail TEXT;
-- Per-user scan history/scoping queries filter on created_by.
CREATE INDEX IF NOT EXISTS idx_scans_created_by ON scans(created_by);
-- ===========================================================
-- IVMP Phase 15: Software Scan + System Scan
-- ===========================================================
-- scan_info: structured, non-secret facts about HOW a scan ran - for system
-- scans the OS/kernel/host details, local-vs-remote mode, privilege level,
-- host-key verification state, per-collector coverage (what ran, what was
-- skipped and why) and the listening-socket table. Never holds credentials.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_info JSONB;

-- Software assessed by a scan: the user-entered items of a Software Scan, or
-- the installed-package inventory of a System Scan. 'assessment' says whether
-- the CVE engine actually evaluated the item - an item that was NOT assessed
-- (no CPE mapping, unknown version, NVD unavailable) is never presented as
-- "no vulnerabilities".
CREATE TABLE IF NOT EXISTS software_inventory (
    id               SERIAL PRIMARY KEY,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vendor           VARCHAR(120),
    product          VARCHAR(255) NOT NULL,
    version          VARCHAR(120),
    upstream_version VARCHAR(120),
    source           VARCHAR(30) NOT NULL,                       -- user | dpkg | rpm
    cpe_vendor       VARCHAR(120),
    cpe_product      VARCHAR(120),
    assessment       VARCHAR(20) NOT NULL DEFAULT 'not_assessed', -- assessed | not_assessed | lookup_failed
    note             TEXT,
    findings_count   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_software_inventory_scan ON software_inventory(scan_id);

-- Results of a System Scan's configuration / exposure checks. A check that
-- could not be performed is stored as 'unknown' (with what it requires),
-- never as 'pass'.
CREATE TABLE IF NOT EXISTS system_checks (
    id                  SERIAL PRIMARY KEY,
    scan_id             INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id            VARCHAR(80) NOT NULL,
    category            VARCHAR(40) NOT NULL,
    title               TEXT NOT NULL,
    status              VARCHAR(20) NOT NULL,   -- pass | fail | unknown | info | not_applicable
    severity            VARCHAR(20),            -- meaningful for 'fail'
    evidence            TEXT,
    remediation         TEXT,
    requires            VARCHAR(20),            -- NULL | root (privilege the check needs)
    contextual_priority NUMERIC(5,1),
    priority_label      VARCHAR(20)
);
CREATE INDEX IF NOT EXISTS idx_system_checks_scan ON system_checks(scan_id);

-- ===========================================================
-- IVMP Phase 16: Windows software inventory + Microsoft Defender threat scan
-- ===========================================================
-- Purely additive (ALTER ... ADD COLUMN IF NOT EXISTS / CREATE TABLE IF NOT EXISTS):
-- existing scans, inventories and findings are untouched, and re-running this
-- file is a no-op once applied.

-- Per-application facts collected from the Windows registry. All nullable, so
-- rows written by earlier Software/System scans read back as NULL.
ALTER TABLE software_inventory ADD COLUMN IF NOT EXISTS install_date       VARCHAR(10);   -- ISO date, when the registry holds a valid one
ALTER TABLE software_inventory ADD COLUMN IF NOT EXISTS inventory_source   VARCHAR(255);  -- registry location(s) the entry was read from
ALTER TABLE software_inventory ADD COLUMN IF NOT EXISTS collection_status  VARCHAR(20);   -- complete | partial (a field such as the version was missing)
ALTER TABLE software_inventory ADD COLUMN IF NOT EXISTS identity_source    VARCHAR(20);   -- catalog | name_only | none (how the NVD identity was established)
ALTER TABLE software_inventory ADD COLUMN IF NOT EXISTS assessment_reason  VARCHAR(40);   -- machine-readable reason an item was NOT assessed

-- Threat detections reported by Microsoft Defender Antivirus (System Scan on
-- Windows). 'attribution' separates detections that belong to the current scan
-- window from historical records that were already present. Defender does not
-- say which scan produced a detection, so attribution is time/baseline based
-- and is stored as such - see scanner/windows_defender.py.
CREATE TABLE IF NOT EXISTS threat_findings (
    id                     SERIAL PRIMARY KEY,
    scan_id                INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    detection_id           VARCHAR(80),
    threat_id              VARCHAR(40),
    threat_name            TEXT,
    severity               VARCHAR(20),            -- CRITICAL | HIGH | MEDIUM | LOW | Unknown (mapped from Defender's severity)
    defender_severity      VARCHAR(20),            -- Defender's own label: Severe | High | Moderate | Low | Unknown
    resources              JSONB,                  -- affected file / process / registry resources as reported
    process_name           TEXT,
    domain_user            TEXT,
    initial_detection_time TIMESTAMPTZ,
    last_status_change     TIMESTAMPTZ,
    status                 VARCHAR(40),            -- Detected | Quarantined | Removed | Blocked | Allowed | ... | status code N
    action_success         BOOLEAN,
    execution_status       VARCHAR(30),
    attribution            VARCHAR(20) NOT NULL DEFAULT 'historical',   -- current_scan | historical | unattributed
    in_scan_scope          BOOLEAN,                -- custom scans: resource lies under the scanned path (NULL = not applicable/unknown)
    needs_attention        BOOLEAN NOT NULL DEFAULT FALSE,              -- not resolved by Defender (still detected / allowed / action failed)
    evidence               JSONB,                  -- the raw fields Defender returned for this record
    remediation            TEXT
);
CREATE INDEX IF NOT EXISTS idx_threat_findings_scan ON threat_findings(scan_id);
