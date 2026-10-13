import json

from sqlalchemy import text
from app.common.database import db


def save_findings(request: dict, findings: list):
    stage_run_id = request['data']["stage_run_id"]
    scan_id = request["scan_id"]

    with db.transaction() as conn:
        # Xóa kết quả cũ của cùng lần chạy stage.
        conn.execute(
            text("DELETE FROM vuln_finding WHERE stage_run_id = :stage_run_id"),
            {"stage_run_id": stage_run_id}
        )

        if not findings: return

        sql = text("""
                   INSERT INTO vuln_finding (stage_run_id, scan_id, host, port, protocol, product, version, cpe, cve_id,
                                             cvss_score, severity, status, evidence)
                   VALUES (:stage_run_id, :scan_id, :host, :port, :protocol, :product, :version, :cpe, :cve_id,
                           :cvss_score, :severity, :status, CAST(:evidence AS jsonb))
                   """)
        params = [
            {
                **finding,
                "stage_run_id": stage_run_id,
                "scan_id": scan_id,
                "evidence": json.dumps(finding["evidence"])
            }
            for finding in findings
        ]

        conn.execute(sql, params)


def get_findings(scan_id: str):
    with db.connect() as conn:
        rows = conn.execute(
            text("SELECT * FROM vuln_finding WHERE scan_id = :scan_id ORDER BY host, cvss_score DESC NULLS LAST"),
            {"scan_id": scan_id}
        ).mappings().all()

    findings = []

    for row in rows:
        finding = dict(row)

        if finding["cvss_score"] is not None:
            finding["cvss_score"] = float(finding["cvss_score"])

        finding["created_at"] = finding["created_at"].isoformat()
        findings.append(finding)

    return findings
