"""Bước này là bước tìm kiếm các CVE lỗ hổng công khai của các CPE mà ta đã định danh được trước đó.

Rồi kiểm tra điều kiện ảnh hưởng của CVE
"""

import logging

from app.cve_matching.matching import check_criterion
from app.cve_matching.finding_generate import build_finding
from app.nvd.catalog import NvdCatalog

logger = logging.getLogger(__name__)


def match_cves(resolved, catalog=None):
    catalog = catalog or NvdCatalog()
    findings = {}
    cve_cache = {}

    for software, cpe_name in resolved:
        service = software["service"]

        method = software.get("cpe_resolution", "OFFICIAL")

        # 1. Xác định phương thức truy vấn NVD
        #   - VIRTUAL_MATCH: Không tìm thấy CPE phiên bản chính xác
        #   - OFFICIAL: CPE đã tìm thấy trong PostgreSQL
        if method == "VIRTUAL_MATCH":
            match_string = software["virtual_match_string"]
            cache_key = ("VIRTUAL_MATCH", match_string)
        else:
            cache_key = ("OFFICIAL", cpe_name)

        # 2. Truy vấn NVD hoặc dùng cache trong lượt matching
        if cache_key not in cve_cache:
            if method == "VIRTUAL_MATCH":
                cve_cache[cache_key] = catalog.cves_virtual(match_string)
            else:
                cve_cache[cache_key] = catalog.cves(cpe_name)

        # 3. Kiểm tra từng CVE với phiên bản thực tế
        for cve in cve_cache[cache_key]:
            cve_id = cve.get("id")
            if not cve_id: continue
            if cve.get("vulnStatus", "").lower() == "rejected": continue

            status = _match_status(cve, cpe_name)

            if status is None: continue

            # 4. Tạo finding
            finding = build_finding(software=software, cpe_name=cpe_name, cve=cve, status=status)

            # 5. Loại bỏ CVE trùng trên cùng service
            key = (service["host"], service.get("port"), service.get("protocol"), cve_id)

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
