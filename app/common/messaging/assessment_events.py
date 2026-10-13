from typing import Any
from uuid import uuid4

from app.common.messaging import (bus, BaseEvent, EventKeys)


def publish_step_completed(
        request: dict,
        step: str,
        result: dict[str, Any] | None = None,
        *,
        seq: int = 1,
        duration_ms: int = 0,
        warnings: list | None = None
):
    data = request["data"]
    stage_run_id = data["stage_run_id"]

    result = dict(result) if result is not None else {}
    if step == "cve_matching" and "findings" in result:
        result["findings"] = [
            {
                **finding,
                "finding_id": finding.get("finding_id") or str(uuid4()),
                "ip": finding.get("ip") or finding["host"],
                "reference_url": finding.get("reference_url") or finding["evidence"]["reference"]
            }
            for finding in result["findings"]
        ]

    event = BaseEvent(
        event=EventKeys.STEP_COMPLETED,
        scan_id=request["scan_id"],
        data={
            "stage_run_id": stage_run_id,
            "step": step,
            "seq": seq,
            "status": "success",
            "duration_ms": duration_ms,
            "result": result,
            "warnings": warnings if warnings is not None else [],
            "error": None
        }
    )
    bus.publish(EventKeys.STEP_COMPLETED, event)


def publish_step_failed(request: dict, step: str, error: Exception):
    event = BaseEvent(
        event=EventKeys.STEP_FAILED,
        scan_id=request["scan_id"],
        data={
            "stage_run_id": request["data"]["stage_run_id"],
            "step": step,
            "status": "failed",
            "error": str(error)[:500]
        }
    )
    bus.publish(EventKeys.STEP_FAILED, event)


def publish_stage_completed(request: dict):
    event = BaseEvent(
        event=EventKeys.STAGE_COMPLETED,
        scan_id=request["scan_id"],
        data={"stage_run_id": request["data"]["stage_run_id"], "status": "success"}
    )

    bus.publish(EventKeys.STAGE_COMPLETED, event)
