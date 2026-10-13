import logging

from app.nvd.catalog import NvdCatalog

logger = logging.getLogger(__name__)


def resolve_cpes(normalized, catalog=None):
    catalog = catalog or NvdCatalog()
    resolved = []
    seen = set()

    for software in normalized:
        part = software["part"]
        vendor = software["vendor"]
        product = software["product"]
        version = software["version"]

        candidate = (
            f"cpe:2.3:{part}:{vendor}:{product}:"
            f"{version}:*:*:*:*:*:*:*"
        )

        key = (
            software["service"]["host"],
            software["service"]["port"],
            software["service"]["protocol"],
            candidate
        )

        if key in seen:
            continue

        seen.add(key)
        resolved.append((software, candidate))

    logger.info("CPE candidates: %d", len(resolved))
    return resolved
