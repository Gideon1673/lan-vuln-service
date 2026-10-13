import logging

from app.cve_matching.extractor import extract_software
from app.nvd.catalog import NvdCatalog

from app.cve_matching.normalize import normalize
from app.cve_matching.cpe import resolve_cpes
from app.cve_matching.cve import match_cves
from app.cve_matching.repository import save_findings

logger = logging.getLogger(__name__)


def run(request, completed, context):
    catalog = NvdCatalog()

    # STEP 1: NORMALIZE SOFTWARE
    context["step"] = "NORMALIZE_SOFTWARE"
    services = extract_software(request)

    normalized = [
        result
        for service in services
        if (result := normalize(service)) is not None
    ]

    # STEP 2: RESOLVE CPE
    context["step"] = "RESOLVE_CPE"
    resolved = resolve_cpes(normalized, catalog=catalog)

    # STEP 3: MATCH CVE
    context["step"] = "MATCH_CVE"
    findings = match_cves(resolved, catalog=catalog)

    # STEP 4: SAVE FINDINGS
    context["step"] = "SAVE_FINDINGS"
    save_findings(request, findings)

    logger.info("cve matching finished scan=%s software=%d findings=%d",
                request["scan_id"], len(normalized), len(findings))

    completed("cve_matching", len(findings))
