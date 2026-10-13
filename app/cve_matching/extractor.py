import json
import logging
import re

logger = logging.getLogger(__name__)


def extract_software(request: dict) -> list[dict]:
    inputs = request["data"]["inputs"]
    services = []

    # Step 1: Extract HTTP banners
    for snapshot in inputs.get("snapshots", []):
        if snapshot.get("source") != "banner": continue

        try:
            raw = snapshot.get("raw_config") or "{}"
            config = json.loads(raw) if isinstance(raw, str) else raw

            if not isinstance(config, dict): continue

            banner = config.get("Server", "")
            apache = re.search(r"Apache/(\d+(?:\.\d+)+)", banner, re.IGNORECASE)

            if apache:
                services.append({
                    "host": snapshot["ip"],
                    "port": 0,  # Unknown port
                    "protocol": "tcp",
                    "product": "Apache httpd",
                    "version": apache.group(1),
                    "banner": banner,
                    "source": "HTTP_BANNER",
                    "distribution": (
                        "Ubuntu"
                        if "Ubuntu" in banner
                        else None
                    )
                })

        except (ValueError, TypeError, KeyError):
            logger.warning("Invalid snapshot: %s", snapshot.get("ip"))

    return services
