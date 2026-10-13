class EventKeys:

    # Incoming Events
    ASSESSMENT_REQUESTED = "platform.assessment.stage.requested"
    SCAN_CANCELLED = "platform.scan.cancelled"

    # Outgoing Events
    STEP_COMPLETED = "assessment.step.completed"
    STAGE_COMPLETED = "assessment.stage.completed"
    STEP_FAILED = "assessment.step.failed"

    # Vulnerability Findings
    CVE_MATCHED = "vuln.cve.matched"
    MISCONFIG_DETECTED = "vuln.misconfig.detected"
    VERIFIED = "vuln.verified"