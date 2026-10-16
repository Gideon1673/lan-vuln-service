from sqlalchemy import text
from app.common.database import db


def load_findings(scan_id: str, stage_run_id: str) -> list[dict]:

    # 1. Lấy CVE findings từ F1
    with db.connect() as conn:
        cve_rows = conn.execute(
            text("""
                SELECT
                    host,
                    cve_id,
                    cvss_score,
                    severity
                FROM vuln_finding
                WHERE scan_id = :scan_id
                  AND stage_run_id = :stage_run_id
                  AND status IN ('LIKELY_AFFECTED', 'POTENTIAL', 'NEEDS_REVIEW')
            """),
            {
                "scan_id": scan_id,
                "stage_run_id": stage_run_id
            }
        ).mappings().all()

        # 2. Lấy Misconfig findings từ F2
        misconfig_rows = conn.execute(
            text("""
                SELECT host, rule_id, severity
                FROM vuln_misconfig_finding
                WHERE scan_id = :scan_id AND stage_run_id = :stage_run_id
            """),
            {
                "scan_id": scan_id,
                "stage_run_id": stage_run_id
            }
        ).mappings().all()

    # 3. Chuẩn hóa tất cả findings
    findings = []

    for row in cve_rows:
        findings.append({
            "type": "CVE",
            "host": row["host"],
            "identifier": row["cve_id"],
            "score": (
                float(row["cvss_score"])
                if row["cvss_score"] is not None
                else None
            ),
            "severity": row["severity"]
        })

    for row in misconfig_rows:
        findings.append({
            "type": "MISCONFIG",
            "host": row["host"],
            "identifier": row["rule_id"],
            "score": None,
            "severity": row["severity"]
        })

    return findings
