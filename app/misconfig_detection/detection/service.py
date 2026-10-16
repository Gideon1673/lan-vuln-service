import logging

from app.misconfig_detection.detection.extractor import MisconfigEvidenceExtractor
from app.misconfig_detection.detection.evidence_normalizer import MisconfigEvidenceNormalizer
from app.misconfig_detection.detection.rule_loader import MisconfigRuleLoader
from app.misconfig_detection.detection.engine import MisconfigRuleEngine
from app.misconfig_detection.detection.finding import MisconfigFindingFactory
from app.misconfig_detection.detection.finding_repository import MisconfigFindingRepository

logger = logging.getLogger(__name__)


class MisconfigDetectionService:

    def __init__(self):
        self.extractor = MisconfigEvidenceExtractor()
        self.evidence_normalizer = MisconfigEvidenceNormalizer()
        self.rule_loader = MisconfigRuleLoader()
        self.engine = MisconfigRuleEngine()
        self.finding_factory = MisconfigFindingFactory()
        self.finding_repository = MisconfigFindingRepository()


