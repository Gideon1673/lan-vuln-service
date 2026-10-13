import logging

from app.common.config import RabbitMQConfig
from app.common.messaging.assessment_events import publish_step_completed, publish_stage_completed
from app.common.messaging.rabbitmq import RabbitEventBus
from app.common.messaging.event_keys import EventKeys

from app.cve_matching.runner import run as run_cve_matching
from app.misconfig_detection.runner import run as run_misconfig_detection
from app.risk_scoring.runner import run as run_risk_scoring
from app.scope import validate_request

logger = logging.getLogger(__name__)

bus = RabbitEventBus(RabbitMQConfig.from_env())


def handle_assessment(event):
    validate_request(event)
    context = {"step": "cve_matching"}

    def completed(step, result, **details):
        publish_step_completed(event, step, result, **details)

    run_cve_matching(event, completed)

    context["step"] = "misconfig_detection"
    run_misconfig_detection(event, completed)

    context["step"] = "risk_scoring"
    run_risk_scoring(event, completed)

    publish_stage_completed(event)


def handle_scan_cancelled(event):
    scan_id = event["scan_id"]
    logger.info("Received scan cancellation: scan_id=%s", scan_id)

    # TODO: Đánh dấu scan đã bị hủy trong database.


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", )
    bus.subscribe(EventKeys.ASSESSMENT_REQUESTED, handle_assessment)
    bus.subscribe(EventKeys.SCAN_CANCELLED, handle_scan_cancelled)
    bus.start()


if __name__ == "__main__":
    main()
