SELECT current_database(), current_user;

CREATE TABLE IF NOT EXISTS vuln_nvd_cache (
    cache_key TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vuln_finding (
    stage_run_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,

    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,

    product TEXT NOT NULL,
    version TEXT NOT NULL,
    cpe TEXT NOT NULL,
    cve_id TEXT NOT NULL,

    cvss_score NUMERIC(4,1),
    severity TEXT,
    status TEXT NOT NULL,

    evidence JSONB NOT NULL,

    created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_vuln_finding PRIMARY KEY (
        stage_run_id,
        host,
        port,
        protocol,
        cve_id
    ),

    CONSTRAINT chk_vuln_port
        CHECK (port BETWEEN 1 AND 65535),

    CONSTRAINT chk_vuln_cvss
        CHECK (
            cvss_score IS NULL
            OR cvss_score BETWEEN 0 AND 10
        ),

    CONSTRAINT chk_vuln_status
        CHECK (
            status IN (
                'POTENTIAL',
                'LIKELY_AFFECTED',
                'NEEDS_REVIEW',
                'NOT_AFFECTED'
            )
        )
);


-- ==========================================
-- INDEXES
-- ==========================================

CREATE INDEX IF NOT EXISTS idx_vuln_finding_scan
    ON vuln_finding(scan_id);

CREATE INDEX IF NOT EXISTS idx_vuln_finding_cve
    ON vuln_finding(cve_id);

CREATE INDEX IF NOT EXISTS idx_vuln_finding_host
    ON vuln_finding(host);