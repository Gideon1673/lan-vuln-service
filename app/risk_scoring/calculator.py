
"""Calculate aggregate risk score for one host."""

from typing import Any


MISCONFIG_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "INFO": 0.0,
}

ADDITIONAL_FINDING_WEIGHT = 0.2


def get_finding_score(finding: dict[str, Any]) -> float | None:
    finding_type = str(finding.get("type") or "").upper()

    if finding_type == "CVE":
        score = finding.get("score")
        if score is None: return None

        try:
            score = float(score)
        except (TypeError, ValueError):
            return None

        if not 0.0 <= score <= 10.0: return None

        return score

    if finding_type == "MISCONFIG":
        severity = str(finding.get("severity") or "").upper()
        return MISCONFIG_SCORES.get(severity)

    return None


def get_risk_level(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0: return "LOW"
    return "NONE"


def calculate(findings: list[dict[str, Any]]) -> dict[str, Any]:
    unique_findings = {}

    for finding in findings:
        key = (str(finding.get("type") or "").upper(), str(finding.get("identifier") or ""))

        # Ignore malformed records with missing identity
        if not key[0] or not key[1]: continue

        score = get_finding_score(finding)
        existing = unique_findings.get(key)

        # Keep the record with the highest valid score
        if existing is None:
            unique_findings[key] = (finding, score)
        elif score is not None and (existing[1] is None or score > existing[1]):
            unique_findings[key] = (finding, score)

    # 2. Collect valid scores
    scores = [
        score
        for _, score in unique_findings.values()
        if score is not None
    ]

    finding_count = len(unique_findings)
    scored_count = len(scores)

    # 3. No scoreable findings
    if not scores:
        return {
            "score": 0.0,
            "level": "NONE",
            "finding_count": finding_count,
            "scored_count": 0,
        }

    # 4. Calculate aggregate risk
    max_score = max(scores)

    if max_score == 0.0:
        risk_score = 0.0
    else:
        risk_score = min(10.0, max_score + ADDITIONAL_FINDING_WEIGHT * (scored_count - 1))

    risk_score = round(risk_score, 2)

    # 5. Classify result
    return {
        "score": risk_score,
        "level": get_risk_level(risk_score),
        "finding_count": finding_count,
        "scored_count": scored_count,
    }
