def calculate_risk_level(cvss):
    """
    Convert a CVSS score into a VANTAGE risk level.
    """

    if cvss is None:
        return "UNKNOWN"

    if cvss >= 9.0:
        return "CRITICAL"

    if cvss >= 7.0:
        return "HIGH"

    if cvss >= 4.0:
        return "MEDIUM"

    if cvss > 0.0:
        return "LOW"

    return "NONE"


def score_finding(finding):
    """
    Add risk information to a normalized CVE finding.
    """

    cvss = finding.get("cvss")

    risk_level = calculate_risk_level(cvss)

    return {
        **finding,
        "risk_score": cvss,
        "risk_level": risk_level
    }


def rank_findings(findings):
    """
    Rank vulnerability findings from highest risk to lowest risk.

    Tie-breaker:
    1. Higher CVSS first
    2. CVE ID alphabetically
    """

    scored_findings = [
        score_finding(finding)
        for finding in findings
    ]

    scored_findings.sort(
        key=lambda finding: (
            finding["risk_score"] is not None,
            finding["risk_score"] or 0,
            finding["cve_id"]
        ),
        reverse=True
    )

    for rank, finding in enumerate(scored_findings, start=1):
        finding["risk_rank"] = rank

    return scored_findings
