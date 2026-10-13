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