"""Chuẩn hóa tên và kiểu dữ liệu để Rule Engine xử lý nhất quán"""

"""Chuẩn hóa bằng chứng Discovery cho Rule Engine."""

import logging
from copy import deepcopy

logger = logging.getLogger(__name__)


class MisconfigEvidenceNormalizer:
    SERVICE_ALIASES = {
        "microsoft-ds": "smb",
        "netbios-ssn": "smb",
        "www": "http",
        "www-http": "http",
        "ssl/http": "https",
    }

    OS_FAMILIES = {
        "windows": ("windows", "microsoft windows"),
        "linux": ("linux", "ubuntu", "debian", "fedora", "centos", "red hat", "rhel", "rocky", "alma", "openwrt", "oracle linux"),
        "macos": ("macos", "mac os", "darwin"),
        "freebsd": ("freebsd",),
    }

    def normalize(self, evidence: dict) -> dict:
        """Chuẩn hóa toàn bộ bằng chứng sau bước Extractor"""
        if not isinstance(evidence, dict):
            raise ValueError("Evidence must be a dictionary")

        devices = evidence.get("devices", [])
        if not isinstance(devices, list):
            raise ValueError("Evidence devices must be a list")

        result = deepcopy(evidence)
        result["devices"] = [self._normalize_device(device) for device in devices]

        logger.info("Normalized Discovery evidence: devices=%d", len(result["devices"]))
        return result

    def _normalize_device(self, device: dict) -> dict:
        """Chuẩn hóa hệ điều hành và danh sách cổng của thiết bị"""
        if not isinstance(device, dict):
            raise ValueError("Device must be a dictionary")

        ports = device.get("ports", [])
        if not isinstance(ports, list):
            raise ValueError("Device ports must be a list")

        result = deepcopy(device)
        result["os"] = self._normalize_os(device.get("os"))
        result["ports"] = [self._normalize_port(port) for port in ports]
        return result

    def _normalize_os(self, os_info: dict | None) -> dict | None:
        """Chuẩn hóa thông tin OS và xác định OS family"""
        if not os_info:
            return None
        if not isinstance(os_info, dict):
            raise ValueError("OS information must be a dictionary")

        result = deepcopy(os_info)
        name = self._string(os_info.get("name"))
        version = self._string(os_info.get("version"))
        family = None

        if name:
            name_lower = name.lower()
            for os_family, keywords in self.OS_FAMILIES.items():
                if any(keyword in name_lower for keyword in keywords):
                    family = os_family
                    break

        result["name"] = name
        result["version"] = version
        result["family"] = family
        return result

    def _normalize_port(self, port: dict) -> dict:
        """Chuẩn hóa số cổng, protocol, state và service"""
        if not isinstance(port, dict):
            raise ValueError("Port must be a dictionary")

        result = deepcopy(port)
        result["port"] = self._port_number(port.get("port"))
        result["protocol"] = self._lower(port.get("protocol"))
        result["state"] = self._lower(port.get("state"))
        result["service"] = self._normalize_service(port.get("service"))
        return result

    def _normalize_service(self, service: dict | None) -> dict | None:
        """Chuẩn hóa tên dịch vụ và giữ nguyên thông tin fingerprint"""
        if service is None:
            return None
        if not isinstance(service, dict):
            raise ValueError("Service must be a dictionary")

        result = deepcopy(service)
        name = self._lower(service.get("name"))
        result["name"] = self.SERVICE_ALIASES.get(name, name)
        return result

    @staticmethod
    def _port_number(value) -> int | None:
        """Chuyển số cổng sang integer nếu hợp lệ"""
        try:
            if isinstance(value, bool):
                return None
            number = int(value)
            return number if 1 <= number <= 65535 else None
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _string(value) -> str | None:
        """Chuẩn hóa giá trị thành chuỗi"""
        if value is None: return None
        return str(value).strip() or None

    @staticmethod
    def _lower(value) -> str | None:
        """Chuẩn hóa chuỗi về chữ thường"""
        return value.strip().lower() or None if isinstance(value, str) else None

