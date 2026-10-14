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


-- ==========================================
-- Tạo bản lưu CPE Công khai
-- ==========================================
CREATE TABLE IF NOT EXISTS vuln_cpe_dictionary (
    cpe_name_id UUID PRIMARY KEY,
    cpe_name TEXT NOT NULL UNIQUE,

    part CHAR(1) NOT NULL
        CHECK (part IN ('a', 'o', 'h')),

    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT,

    display_name TEXT,

    deprecated BOOLEAN NOT NULL DEFAULT FALSE,

    titles JSONB NOT NULL DEFAULT '[]'::jsonb,
    refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    deprecated_by JSONB NOT NULL DEFAULT '[]'::jsonb,
    raw_data JSONB NOT NULL DEFAULT '{}'::jsonb,

    nvd_created_at TIMESTAMPTZ,
    nvd_modified_at TIMESTAMPTZ,

    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_cpe_format
        CHECK (cpe_name LIKE 'cpe:2.3:%')
);

CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product
    ON vuln_cpe_dictionary (part, vendor, product);

CREATE INDEX IF NOT EXISTS idx_cpe_version
    ON vuln_cpe_dictionary (part, vendor, product, version);

CREATE INDEX IF NOT EXISTS idx_cpe_modified
    ON vuln_cpe_dictionary (nvd_modified_at);

CREATE INDEX IF NOT EXISTS idx_cpe_active
    ON vuln_cpe_dictionary (vendor, product)
    WHERE deprecated = FALSE;