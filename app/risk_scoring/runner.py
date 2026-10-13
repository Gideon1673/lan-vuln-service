import logging
from time import perf_counter

logger = logging.getLogger(__name__)


def run(request, completed):
    started_at = perf_counter()
    logger.info("risk_scoring detection finished scan=%s", request["scan_id"])
    completed("risk_scoring", {}, duration_ms=int((perf_counter() - started_at) * 1000))
