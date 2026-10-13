import logging

from app.cve_matching.matching import get_cvss, check_criterion
from app.nvd.catalog import NvdCatalog

logger = logging.getLogger(__name__)


def match_cves(resolved, catalog=None):
    catalog = catalog or NvdCatalog()
    findings = {}
    cve_cache = {}

    for software, cpe_name in resolved:
        service = software["service"]

        # Tránh đọc lại NVD cho cùng một CPE
        if cpe_name not in cve_cache:
            cve_cache[cpe_name] = catalog.cves(cpe_name)

        for cve in cve_cache[cpe_name]:
            cve_id = cve.get("id")
            if not cve_id: continue
            if cve.get("vulnStatus", "").lower() == "rejected": continue

            status = _match_status(cve, cpe_name)

            if status is None: continue

            score, severity = get_cvss(cve)

            finding = {
                "host": service["host"],
                "port": service["port"],
                "protocol": service["protocol"],
                "product": software["product"],
                "version": software["version"],
                "cpe": cpe_name,
                "cve_id": cve_id,
                "cvss_score": score,
                "severity": severity,
                "status": status,
                "evidence": {
                    "source": "NVD",
                    "cpe_name": cpe_name,
                    "banner": service.get("banner"),
                    "reference": "https://nvd.nist.gov/vuln/detail/" + cve_id,
                    "note": (
                        "CPE/version candidate; "
                        "patch status not verified"
                    )
                }
            }

            # Một CVE có thể khớp nhiều CPE nhưng chỉ lưu một finding cho mỗi service.
            key = (service["host"], service["port"], service["protocol"], cve_id)

            previous = findings.get(key)

            if previous is None:
                findings[key] = finding
            elif previous["status"] == "NEEDS_REVIEW" and status == "POTENTIAL":
                findings[key] = finding

    result = list(findings.values())
    logger.info("CVE matching completed: cpes=%d findings=%d", len(resolved), len(result))

    return result


def _same_product(item, cpe_name):
    expected = item.get("criteria", "").split(":")
    actual = cpe_name.split(":")

    if len(expected) != 13 or len(actual) != 13: return False

    return all(expected[i] in ("*", actual[i]) for i in (2, 3, 4))


# tìm các điều kiện CPE ở mọi độ sâu
def _iter_matches(node):
    for item in node.get("cpeMatch", []):
        yield item

    for child in node.get("nodes", []):
        yield from _iter_matches(child)


def _match_status(cve, cpe_name):
    potential = False
    needs_review = False

    for config in cve.get("configurations", []):
        nodes = config.get("nodes", [])
        simple_config = (len(nodes) == 1 and config.get("operator", "OR") == "OR" and not config.get("negate", False))

        for node in nodes:
            criteria = node.get("cpeMatch", [])
            simple_node = (
                    simple_config
                    and node.get("operator", "OR") == "OR"
                    and not node.get("negate", False)
                    and not node.get("nodes")
                    and all(item.get("vulnerable", False) for item in criteria)
            )

            for item in _iter_matches(node):
                if not item.get("vulnerable", False): continue
                if not _same_product(item, cpe_name): continue
                result = check_criterion(item, cpe_name)

                if result is False: continue

                if result is True and simple_node:
                    potential = True
                else:
                    needs_review = True

    if potential: return "POTENTIAL"

    if needs_review: return "NEEDS_REVIEW"

    return None
