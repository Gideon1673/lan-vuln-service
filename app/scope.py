import ipaddress
import requests

from app import service_config


def validate_request(event):
    if event.get("event") != "platform.assessment.stage.requested":
        raise ValueError("Invalid event type")

    if not event.get("scan_id"):
        raise ValueError("Missing scan_id")

    data = event.get("data") or {}

    if not data.get("stage_run_id"):
        raise ValueError("Missing stage_run_id")

    inputs = data.get("inputs") or {}

    if not isinstance(inputs.get("devices"), list):
        raise ValueError("Invalid devices")

    if not isinstance(inputs.get("snapshots"), list):
        raise ValueError("Invalid snapshots")


def validate_scope(request):
    cidr = request["cidr"]
    services = request["data"]["services"]

    network = ipaddress.ip_network(cidr, strict=False)

    hosts = {service["host"] for service in services}

    # Nếu không có host, vẫn xác nhận phạm vi CIDR.
    targets = sorted(hosts) if hosts else [None]

    for host in targets:
        if host is not None:
            ip = ipaddress.ip_address(host)

            if ip not in network:
                raise ValueError(f"Host {host} is outside {cidr}")

        params = {"cidr": cidr}

        if host is not None:
            params["ip"] = host

        response = requests.get(service_config.scope_check_url, params=params, timeout=10)
        response.raise_for_status()

        if response.json().get("allowed") is not True:
            raise PermissionError(f"Scope denied for {host or cidr}")
