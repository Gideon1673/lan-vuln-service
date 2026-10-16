"""Đánh giá rule misconfiguration dựa trên bằng chứng Discovery."""
import logging

logger = logging.getLogger(__name__)


class MisconfigRuleEngine:
    """Đối chiếu từng rule với dữ liệu của một thiết bị."""

    def evaluate(self, device: dict, rule: dict) -> dict:
        """Đánh giá một rule và trả kết quả MATCH, UNKNOWN hoặc NOT_APPLICABLE."""
        spec = rule.get("normalized_rule")
        if not isinstance(spec, dict):
            return self._result(device, rule, "UNKNOWN", "Invalid normalized rule")

        applicability = spec.get("applicability")
        condition = spec.get("condition")

        if not isinstance(applicability, dict) or not isinstance(condition, dict):
            return self._result(device, rule, "UNKNOWN", "Invalid rule specification")

        applicable = self._check_applicability(device, applicability)
        if applicable is False:
            return self._result(device, rule, "NOT_APPLICABLE", "Rule does not apply to this OS")
        if applicable is None:
            return self._result(device, rule, "UNKNOWN", "OS applicability cannot be determined")

        if spec.get("evaluation_type") != "SERVICE_EXPOSURE":
            return self._result(device, rule, "UNKNOWN", "Unsupported evaluation type")

        if condition.get("operator") != "SERVICE_PRESENT":
            return self._result(device, rule, "UNKNOWN", "Unsupported rule operator")

        return self._evaluate_service_present(device, rule, condition)

    @staticmethod
    def _check_applicability(device: dict, applicability: dict) -> bool | None:
        """Kiểm tra rule có áp dụng cho hệ điều hành của thiết bị hay không."""
        if applicability.get("verified"):
            return None

        families = applicability.get("os_families")
        if not isinstance(families, list) or not families:
            return None

        if any(not isinstance(name, str) or not name.strip() for name in families):
            return None

        os_info = device.get("os")
        if not isinstance(os_info, dict):
            return None

        family = os_info.get("family")
        if not isinstance(family, str) or not family.strip():
            return None

        allowed = {name.strip().lower() for name in families}
        return family.strip().lower() in allowed

    def _evaluate_service_present(self, device: dict, rule: dict, condition: dict) -> dict:
        """Phát hiện dịch vụ bị cấm đang thực sự mở trên mạng."""
        protocol = condition.get("protocol")
        service_names = condition.get("service_names")

        if protocol not in {"tcp", "udp"}:
            return self._result(device, rule, "UNKNOWN", "Invalid service protocol")

        if not isinstance(service_names, list) or not service_names:
            return self._result(device, rule, "UNKNOWN", "Invalid service names")

        if any(not isinstance(name, str) or not name.strip() for name in service_names):
            return self._result(device, rule, "UNKNOWN", "Invalid service names")

        if "product_names" in condition:
            return self._result(device, rule, "UNKNOWN", "Product matching is not supported")

        ports = device.get("ports")
        if not isinstance(ports, list):
            return self._result(device, rule, "UNKNOWN", "Network service evidence is missing")

        expected_names = {name.strip().lower() for name in service_names}

        for port in ports:
            if not isinstance(port, dict):
                continue

            if port.get("protocol") != protocol or port.get("state") != "open":
                continue

            service = port.get("service")
            if not isinstance(service, dict):
                continue

            name = service.get("name")
            if not isinstance(name, str) or name.strip().lower() not in expected_names:
                continue

            evidence = {
                "port": port.get("port"),
                "protocol": port["protocol"],
                "state": port["state"],
                "service": name
            }

            logger.info("Misconfiguration detected: host=%s rule=%s", device.get("ip"), rule.get("external_rule_id"))
            return self._result(device, rule, "MATCH", "Forbidden network service detected", evidence)

        # Không tìm thấy dịch vụ không đồng nghĩa dịch vụ đã bị vô hiệu hóa.
        return self._result(device, rule, "UNKNOWN", "No confirmed matching service exposure")

    @staticmethod
    def _result(
        device: dict,
        rule: dict,
        status: str,
        reason: str,
        evidence: dict | None = None
    ) -> dict:
        """Tạo cấu trúc kết quả đánh giá thống nhất."""
        return {
            "device_ip": device.get("ip"),
            "normalized_rule_id": rule.get("id"),
            "external_rule_id": rule.get("external_rule_id"),
            "status": status,
            "reason": reason,
            "evidence": evidence
        }
