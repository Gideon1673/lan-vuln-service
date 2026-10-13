from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass
class BaseEvent:
    event: str
    scan_id: str | None = None
    stage_run_id: str | None = None
    stage: str | None = None
    step: str | None = None
    status: str | None = None
    last_step: bool | None = None
    items: int | None = None
    data: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            key: value
            for key, value in asdict(self).items()
            if value is not None
        }
