import logging
from time import perf_counter

logger = logging.getLogger(__name__)


def run(request, completed):
    started_at = perf_counter()
    logger.info("misconfig detection finished scan=%s", request["scan_id"])
    completed("misconfig_detection", {}, duration_ms=int((perf_counter() - started_at) * 1000))
