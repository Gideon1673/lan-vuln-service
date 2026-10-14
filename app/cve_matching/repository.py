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


# Tìm tên phần mềm trong bảng vuln_cpe_alias.
# Kiểm tra vendor/product tương ứng có tồn tại trong vuln_cpe_dictionary và chưa bị deprecated
def find_product_by_alias(alias: str) -> dict | None:
    sql = text("""
        SELECT
            a.part,
            a.vendor,
            a.product
        FROM vuln_cpe_alias a
        WHERE a.alias = :alias
          AND EXISTS (
              SELECT 1
              FROM vuln_cpe_dictionary c
              WHERE c.part = a.part
                AND c.vendor = a.vendor
                AND c.product = a.product
                AND c.deprecated = FALSE
          )
        LIMIT 1
    """)

    with db.connect() as conn:
        row = conn.execute(
            sql,
            {"alias": alias}
        ).mappings().first()

    return dict(row) if row else None


# def find_products(name: str, version: str | None = None, limit: int = 10) -> list[dict]:
#     name = " ".join(name.lower().split())
#     if not name: return []
#     if limit < 1: raise ValueError("limit must be positive")
#
#     sql = text("""
#         WITH candidates AS (
#             SELECT
#                 part,
#                 vendor,
#                 product,
#                 display_name,
#                 CASE
#                     WHEN LOWER(product) = :name THEN 100
#                     WHEN LOWER(REPLACE(product, '_', ' ')) = :name THEN 90
#                     WHEN LOWER(display_name) = :name THEN 80
#                     WHEN LOWER(display_name) LIKE '%' || :name || '%' THEN 60
#                     WHEN LOWER(REPLACE(product, '_', ' ')) LIKE '%' || :name || '%' THEN 40
#                     ELSE 0
#                 END AS score
#             FROM vuln_cpe_dictionary
#             WHERE deprecated = FALSE
#               AND (
#                   LOWER(product) = :name
#                   OR LOWER(REPLACE(product, '_', ' ')) = :name
#                   OR LOWER(display_name) LIKE '%' || :name || '%'
#                   OR LOWER(REPLACE(product, '_', ' ')) LIKE '%' || :name || '%'
#               )
#               AND (
#                   CAST(:version AS TEXT) IS NULL
#                   OR version = :version
#                   OR version = '*'
#                   OR version = '-'
#               )
#         )
#         SELECT part, vendor, product, MAX(score) AS score, MIN(display_name) AS display_name
#         FROM candidates
#         GROUP BY part, vendor, product
#         ORDER BY score DESC, vendor, product
#         LIMIT :limit
#     """)
#
#     with db.connect() as conn:
#         rows = conn.execute(
#             sql,
#             {
#                 "name": name,
#                 "version": version,
#                 "limit": limit
#             }
#         ).mappings().all()
#
#     return [dict(row) for row in rows]


def find_product_by_cpe(part: str, vendor: str, product: str) -> dict | None:
    """Xác nhận định danh sản phẩm tồn tại trong NVD CPE Dictionary."""

    sql = text("""
        SELECT part, vendor, product
        FROM vuln_cpe_dictionary
        WHERE part = :part
          AND vendor = :vendor
          AND product = :product
          AND deprecated = FALSE
        LIMIT 1
    """)

    with db.connect() as conn:
        row = conn.execute(sql, {
            "part": part,
            "vendor": vendor,
            "product": product
        }).mappings().first()
    return dict(row) if row else None


def find_products(name: str, limit: int = 10) -> list[dict]:
    name = " ".join(name.lower().split())

    if not name:
        return []

    sql = text("""
        WITH candidates AS (
            SELECT
                part, vendor, product,
                CASE
                    WHEN LOWER(product) = :name THEN 100
                    WHEN LOWER(REPLACE(product, '_', ' ')) = :name THEN 90
                    WHEN LOWER(display_name) = :name THEN 80
                    WHEN LOWER(display_name) LIKE '%' || :name || '%'
                        THEN 60
                    ELSE 0
                END AS score
            FROM vuln_cpe_dictionary
            WHERE deprecated = FALSE
              AND (
                  LOWER(product) = :name
                  OR LOWER(REPLACE(product, '_', ' ')) = :name
                  OR LOWER(display_name) LIKE '%' || :name || '%'
              )
        )
        SELECT part, vendor, product, MAX(score) AS score
        FROM candidates
        WHERE score > 0
        GROUP BY part, vendor, product
        ORDER BY score DESC, vendor, product
        LIMIT :limit
    """)

    with db.connect() as conn:
        rows = conn.execute(sql, {
            "name": name,
            "limit": limit
        }).mappings().all()

    return [dict(row) for row in rows]


def find_cpe_names(part: str,vendor: str,product: str,version: str) -> list[str]:
    """Tìm CPE Names chính thức theo sản phẩm và phiên bản."""
    sql = text("""
        SELECT cpe_name
        FROM vuln_cpe_dictionary
        WHERE part = :part
          AND vendor = :vendor
          AND product = :product
          AND version = :version
          AND deprecated = FALSE
        ORDER BY cpe_name
    """)

    with db.connect() as conn:
        rows = conn.execute(
            sql,
            {
                "part": part,
                "vendor": vendor,
                "product": product,
                "version": version
            }
        ).scalars().all()

    return list(rows)
