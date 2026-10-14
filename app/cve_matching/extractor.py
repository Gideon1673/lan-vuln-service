"""Bước này trích xuất thông tin phần mềm, duyệt qua các snapshot mà discovery quét được"""
import logging

logger = logging.getLogger(__name__)


def _extract_services(devices: list[dict]) -> list[dict]:
    software = []

    for device in devices:
        if not isinstance(device, dict): continue

        host = device.get("ip")
        if not host: continue

        for port_data in device.get("ports") or []:
            if not isinstance(port_data, dict): continue

            service = port_data.get("service") or {}
            if not isinstance(service, dict): continue

            product = service.get("product")
            if not isinstance(product, str) or not product.strip(): continue

            version = service.get("version")
            if not isinstance(version, str) or not version.strip(): version = None

            port = port_data.get("port")
            if type(port) is not int or not 1 <= port <= 65535: port = None

            cpe = service.get("cpe") or []
            if isinstance(cpe, str): cpe = [cpe]
            if not isinstance(cpe, list): cpe = []

            software.append({
                "host": host,
                "port": port,
                "protocol": port_data.get("protocol", "tcp"),
                "product": product.strip(),
                "version": version,
                "cpe_hint": [item for item in cpe if isinstance(item, str) and item.strip()],
                "source": "SERVICE_FINGERPRINT",
                "banner": service.get("banner")
            })

    return software


def _extract_os(devices: list[dict]) -> list[dict]:
    """Read OS fingerprint observations without guessing versions."""
    observations = []

    for device in devices:
        if not isinstance(device, dict): continue

        host = device.get("ip")
        os_info = device.get("os")

        if not host or not isinstance(os_info, dict): continue

        name = os_info.get("name")
        if not isinstance(name, str) or not name.strip(): continue

        version = os_info.get("version")
        if not isinstance(version, str) or not version.strip(): version = None

        observations.append({
            "host": host,
            "port": None,
            "protocol": None,
            "product": name.strip(),
            "version": version,
            "cpe_hint": os_info.get("cpe") or [],
            "source": "OS_FINGERPRINT",
            "os_raw": name.strip()
        })

    return observations


def extract_software(request: dict) -> list[dict]:
    inputs = request["data"]["inputs"]
    devices = inputs.get("devices") or []

    results = _extract_services(devices)
    results.extend(_extract_os(devices))

    unique = []
    seen = set()

    for item in results:
        key = (
            item["host"],
            item["port"],
            item["protocol"],
            item["product"],
            item["version"],
            item["source"]
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)

    logger.info("Extracted %d software/OS observations", len(unique))
    return unique
