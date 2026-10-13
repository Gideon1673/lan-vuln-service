import json

from datetime import datetime, timedelta, timezone
from sqlalchemy import text

from app.common.database import db


def get_cache(key: str, ttl_hours: int):
    with db.connect() as conn:
        row = conn.execute(
            text("SELECT payload, fetched_at FROM vuln_nvd_cache WHERE cache_key = :key"),
            {"key": key}
        ).mappings().first()

    if row is None: return None

    expiry = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)

    if row["fetched_at"] < expiry: return None

    return row["payload"]


def save_cache(key: str, payload):
    with db.transaction() as conn:
        conn.execute(
            text("""
                 INSERT INTO vuln_nvd_cache (cache_key, payload, fetched_at)
                 VALUES (:key, CAST(:payload AS jsonb), NOW())
                 ON CONFLICT (cache_key)
                     DO UPDATE SET payload    = EXCLUDED.payload,
                                   fetched_at = EXCLUDED.fetched_at
                 """),
            {"key": key, "payload": json.dumps(payload)}
        )
