import json
import re

from sqlalchemy import text
from app.common.database import db
from app.common.finding_id import create_finding_id


def save_findings(request: dict, findings: list):
    stage_run_id = request['data']["stage_run_id"]
    scan_id = request["scan_id"]
    for finding in findings:
        finding["finding_id"] = create_finding_id(
            "CVE", scan_id, stage_run_id, finding["host"],
            finding.get("port"), finding.get("protocol"), finding["cve_id"],
        )

    with db.transaction() as conn:
        # Xóa kết quả cũ của cùng lần chạy stage.
        conn.execute(
            text("DELETE FROM vuln_finding WHERE stage_run_id = :stage_run_id"),
            {"stage_run_id": stage_run_id}
        )

        if not findings: return

        sql = text("""
                   INSERT INTO vuln_finding (finding_id, stage_run_id, scan_id, host, port, protocol, product, version, cpe, cve_id,
                                             cvss_score, severity, status, evidence)
                   VALUES (:finding_id, :stage_run_id, :scan_id, :host, :port, :protocol, :product, :version, :cpe, :cve_id,
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
    if limit < 1: raise ValueError("limit must be positive")
    name = " ".join(name.lower().split())

    if not name: return []

    search_name = " ".join(re.sub(r"[_-]+", " ", name).split())
    words = search_name.split()
    # Khớp cụm nguyên từ ở mọi vị trí, ưu tiên cụm dài hơn.
    phrases = sorted({
        " ".join(words[start:end])
        for start in range(len(words))
        for end in range(start + 1, len(words) + 1)
        if end - start < len(words) and len(" ".join(words[start:end])) >= 3
    }, key=lambda value: (-len(value.split()), value))
    phrase_params = {f"phrase_{index}": value for index, value in enumerate(phrases)}
    product_name = "LOWER(REPLACE(REPLACE(product, '_', ' '), '-', ' '))"
    phrase_scores = " ".join(
        f"WHEN {product_name} = :phrase_{index} THEN {80 + min(len(value.split()), 9)}"
        for index, value in enumerate(phrases)
    )
    tokens = sorted({word for word in words if len(word) >= 3})
    token_params = {f"token_{index}": _search_pattern(value) for index, value in enumerate(tokens)}
    token_matches = " + ".join(
        f"CASE WHEN {product_name} LIKE :token_{index} ESCAPE '\\' "
        f"OR LOWER(display_name) LIKE :token_{index} ESCAPE '\\' THEN 1 ELSE 0 END"
        for index in range(len(tokens))
    ) or "0"

    sql = text(f"""
        WITH candidates AS (
            SELECT
                part, vendor, product,
                CASE
                    WHEN LOWER(product) = :name THEN 100
                    WHEN {product_name} = :search_name THEN 90
                    WHEN LOWER(display_name) = :name THEN 90
                    {phrase_scores}
                    WHEN {product_name} LIKE :display_pattern ESCAPE '\\'
                        OR LOWER(display_name) LIKE :display_pattern ESCAPE '\\'
                        THEN 60
                    ELSE CASE WHEN ({token_matches}) > 0
                        THEN 40 + CASE WHEN ({token_matches}) > 3 THEN 39 ELSE ({token_matches}) * 10 END
                        ELSE 0 END
                END AS score
            FROM vuln_cpe_dictionary
            WHERE deprecated = FALSE
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
            "search_name": search_name,
            **phrase_params,
            **token_params,
            "display_pattern": _search_pattern(search_name),
            "limit": limit
        }).mappings().all()

    return [dict(row) for row in rows]


def _search_pattern(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


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
