"""Trích xuất devices, ports, snapshots từ Discovery payload:
    - chuyển Discovery payload thành các bản ghi bằng chứng gắn với từng thiết bị
    - con này không tự kết luận SSH cấu hình yếu hoặc Apache có misconfiguration. Nó chỉ ghi nhận bằng chứng đã thu thập
"""
import logging
from copy import deepcopy
from ipaddress import ip_address

logger = logging.getLogger(__name__)


class MisconfigEvidenceExtractor:
    def extract(self, request: dict) -> dict:
        if not isinstance(request, dict):
            raise ValueError("Assessment request must be an object")

        payload = self._get_inputs(request)

        devices = payload.get("devices", [])
        snapshots = payload.get("snapshots", [])

        if not isinstance(devices, list):
            raise ValueError("devices must be a list")

        if not isinstance(snapshots, list):
            raise ValueError("snapshots must be a list")

        extracted_devices = {}
        unmatched_snapshots = []

        # Step 1: Extract hosts, OS and network services.
        for index, device in enumerate(devices):
            extracted = self._extract_device(device, index)
            ip = extracted["ip"]

            if ip in extracted_devices:
                raise ValueError(f"Duplicate device IP: {ip}")

            extracted_devices[ip] = extracted

        # Step 2: Attach configuration snapshots by IP.
        for index, snapshot in enumerate(snapshots):
            extracted = self._extract_snapshot(snapshot, index)

            ip = extracted["ip"]

            if ip not in extracted_devices:
                unmatched_snapshots.append(extracted)
                continue

            extracted_devices[ip]["snapshots"].append({
                "source": extracted["source"],
                "raw_config": extracted["raw_config"],
                "metadata": extracted["metadata"],
            })

        result = {
            "scan_id": request.get("scan_id"),
            "stage_run_id": request.get("stage_run_id"),
            "devices": list(extracted_devices.values()),
            "unmatched_snapshots": unmatched_snapshots,
        }

        logger.info(
            "Misconfig evidence extracted: "
            "scan_id=%s devices=%d snapshots=%d unmatched=%d",
            result["scan_id"],
            len(extracted_devices),
            len(snapshots),
            len(unmatched_snapshots),
        )

        return result

    @staticmethod
    def _get_inputs(request: dict) -> dict:
        """
        Supported formats:
            1. request["data"]["inputs"]
            2. request["inputs"]
            3. request itself
        """

        if "data" in request:
            data = request["data"]

            if not isinstance(data, dict): raise ValueError("data must be an object")

            if "inputs" in data:
                inputs = data["inputs"]
            else:
                inputs = data

        elif "inputs" in request:
            inputs = request["inputs"]

        else:
            inputs = request

        if not isinstance(inputs, dict): raise ValueError("Discovery inputs must be an object")

        return inputs

    @classmethod
    def _validate_ip(cls, value, field: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field} must be an IP address")

        try:
            return str(ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError(f"Invalid {field}: {value}") from exc

    def _extract_device(self, device: dict, index: int) -> dict:
        if not isinstance(device, dict):
            raise ValueError(f"devices[{index}] must be an object")

        ip = self._validate_ip(device.get("ip"), f"devices[{index}].ip")

        os_info = device.get("os")
        ports = device.get("ports", [])

        if os_info is not None and not isinstance(os_info, dict):
            raise ValueError(
                f"devices[{index}].os must be an object"
            )

        if not isinstance(ports, list):
            raise ValueError(f"devices[{index}].ports must be a list")

        extracted_ports = [
            self._extract_port(port, index, port_index)
            for port_index, port in enumerate(ports)
        ]

        return {
            "ip": ip,
            "os": deepcopy(os_info) if os_info else None,
            "ports": extracted_ports,
            "snapshots": [],
        }

    @staticmethod
    def _extract_port(port: dict, device_index: int, port_index: int) -> dict:
        if not isinstance(port, dict):
            raise ValueError(f"devices[{device_index}].ports[{port_index}] must be an object")

        service = port.get("service")

        if service is not None and not isinstance(service, dict):
            raise ValueError("Port service must be an object")

        return {
            "port": port.get("port"),
            "protocol": port.get("protocol"),
            "state": port.get("state"),
            "service": deepcopy(service) if service else None,
        }

    def _extract_snapshot(self, snapshot: dict, index: int, ) -> dict:
        if not isinstance(snapshot, dict):
            raise ValueError(f"snapshots[{index}] must be an object")

        ip = self._validate_ip(snapshot.get("ip"), f"snapshots[{index}].ip")

        metadata = {
            key: deepcopy(value)
            for key, value in snapshot.items()
            if key not in {"ip", "source", "raw_config"}
        }

        return {
            "ip": ip,
            "source": snapshot.get("source"),
            "raw_config": deepcopy(snapshot.get("raw_config")),
            "metadata": metadata,
        }
