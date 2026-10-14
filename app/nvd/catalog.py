import logging

from app.nvd import service_config
from app.nvd.nvd_client import NvdClient
from app.nvd.repository import get_cache, save_cache

logger = logging.getLogger(__name__)


# NvdCatalog chỉ thực hiện:
#    1. Kiểm tra cache thông qua repository.
#    2. Gọi NvdClient nếu cache thiếu hoặc hết hạn.
#    3. Lọc dữ liệu trả về.
#    4. Ghi cache thông qua repository.
#    5. Trả kết quả cho F1.

class NvdCatalog:

    def __init__(self):
        self.client = NvdClient()

    def cpes(self, software, force=False):
        part = software["part"]
        vendor = software["vendor"]
        product = software["product"]
        version = software["version"]

        key = f"cpe|{part}|{vendor}|{product}|{version}"

        if not force:
            cached = get_cache(key, service_config.nvd_cache_hours)
            if cached is not None:
                return cached

        match_string = f"cpe:2.3:{part}:{vendor}:{product}:{version}"

        products = self.client.get_all(
            "cpes/2.0",
            {"cpeMatchString": match_string},
            "products"
        )

        names = []

        for item in products:
            cpe = item["cpe"]
            if cpe.get("deprecated"): continue

            name = cpe["cpeName"]
            parts = name.split(":")

            if len(parts) != 13: continue

            if parts[2] == part and parts[3] == vendor and parts[4] == product and parts[5].lower() == version.lower():
                names.append(name)

        names = sorted(set(names))
        save_cache(key, names)
        logger.info("CPE resolved: product=%s version=%s count=%d", product, version, len(names))

        return names

    def cves(self, cpe_name, force=False):
        key = f"cves|{cpe_name}"

        if not force:
            cached = get_cache(key, service_config.nvd_cache_hours)
            if cached is not None: return cached

        vulnerabilities = self.client.get_all("cves/2.0", {"cpeName": cpe_name}, "vulnerabilities")

        cves = [
            item["cve"]
            for item in vulnerabilities
            if item["cve"].get("vulnStatus", "").lower() != "rejected"
        ]

        save_cache(key, cves)
        logger.info("CVE loaded: cpe=%s count=%d", cpe_name, len(cves))

        return cves

    def cves_virtual(self, match_string: str, force=False):
        """tìm CVE theo CPE Match Criteria"""

        key = f"cves_virtual|{match_string}"

        if not force:
            cached = get_cache(key, service_config.nvd_cache_hours)
            if cached is not None: return cached

        vulnerabilities = self.client.get_all("cves/2.0", {"virtualMatchString": match_string}, "vulnerabilities")

        cves = [
            item["cve"]
            for item in vulnerabilities
            if item["cve"].get("vulnStatus", "").lower() != "rejected"
        ]

        save_cache(key, cves)

        logger.info("Virtual CVE lookup: match=%s count=%d", match_string, len(cves))

        return cves
