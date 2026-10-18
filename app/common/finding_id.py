import json
from uuid import NAMESPACE_URL, uuid5


def create_finding_id(kind: str, scan_id: str, stage_run_id: str, *identity) -> str:
    """Giữ cùng ID cho finding khi chạy lại cùng stage."""
    key = json.dumps(["lan-vuln-service", kind, scan_id, stage_run_id, *identity], separators=(",", ":"))
    return str(uuid5(NAMESPACE_URL, key))
