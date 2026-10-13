from app.common.messaging import (bus, BaseEvent, EventKeys)


def publish_step_completed(
        request: dict,
        step: str,
        items: int = 0,
        last_step: bool = False
):
    data = request["data"]
    stage_run_id = data["stage_run_id"]

    event = BaseEvent(
        event=EventKeys.STEP_COMPLETED,
        event_id=f"{stage_run_id}:{step}:COMPLETED",
        scan_id=request["scan_id"],
        stage_run_id=stage_run_id,
        stage=request.get("stage", "F1"),
        step=step,
        status="success",
        items=items,
        last_step=last_step,
        data={"attempt": data.get("attempt", 1)}
    )
    bus.publish(EventKeys.STEP_COMPLETED, event)


def publish_step_failed(request: dict, step: str, error: Exception):
    event = BaseEvent(
        event=EventKeys.STEP_FAILED,
        event_id=f"{request['stage_run_id']}:{step}:FAILED",
        scan_id=request["scan_id"],
        stage_run_id=request["stage_run_id"],
        stage=request["stage"],
        step=step,
        status="FAILED",
        data={"error": str(error)[:500]}
    )
    bus.publish(EventKeys.STEP_FAILED, event)


def publish_stage_completed(request: dict):
    event = BaseEvent(
        event=EventKeys.STAGE_COMPLETED,
        event_id=f"{request['stage_run_id']}:STAGE:COMPLETED",
        scan_id=request["scan_id"],
        stage_run_id=request["stage_run_id"],
        stage=request["stage"],
        status="COMPLETED"
    )

    bus.publish(EventKeys.STAGE_COMPLETED, event)
