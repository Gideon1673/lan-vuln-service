import logging

from sqlalchemy import text

from app.common.database import db
from app.nvd.catalog import NvdCatalog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def refresh():
    catalog = NvdCatalog()

    with db.connect() as conn:
        keys = conn.execute(text("SELECT cache_key FROM vuln_nvd_cache ORDER BY cache_key")).scalars().all()

    for key in keys:
        try:
            parts = key.split("|")

            if parts[0] == "cpe" and len(parts) == 5:
                _, part, vendor, product, version = parts

                catalog.cpes({
                    "part": part,
                    "vendor": vendor,
                    "product": product,
                    "version": version
                }, force=True)

            elif parts[0] == "cves" and len(parts) == 4:
                _, part, vendor, product = parts

                catalog.cves({
                    "part": part,
                    "vendor": vendor,
                    "product": product
                }, force=True)

            logger.info("Refreshed NVD cache: %s", key)

        except Exception:
            logger.exception("Cannot refresh NVD cache: %s", key)


if __name__ == "__main__":
    refresh()
