from datetime import datetime, timezone

from engine_vantage.scanner import scan_target
from engine_vantage.cve_lookup import search_cves, normalize_cve
from engine_vantage.cve_matcher import cve_matches_product
from engine_vantage.risk_scorer import rank_findings


def run_vantage(target):
    """
    Run the complete standalone VANTAGE pipeline.

    Pipeline:
        Nmap scan
            -> detected product/service/version
            -> NVD keyword search (candidate discovery)
            -> CPE applicability matching
            -> three-state classification:
                MATCH         -> confirmed findings (risk-scored)
                INDETERMINATE -> indeterminate candidates (reported separately)
                NO_MATCH      -> rejected (counted only)

    Risk scoring operates only on confirmed applicable findings.
    Indeterminate candidates are never automatically risk-ranked.
    """

    scan_time = datetime.now(timezone.utc).isoformat()

    ports = scan_target(target)

    confirmed_findings = []
    indeterminate_findings = []
    lookup_errors = []
    total_candidates = 0

    for port in ports:
        service = port.get("service")
        product = port.get("product", "unknown")
        version = port.get("version")

        if not service or not version:
            continue

        if version.lower() == "unknown":
            continue

        if product == "unknown":
            keyword = service
        else:
            keyword = product

        try:
            cve_results = search_cves(keyword)

        except RuntimeError as exc:
            lookup_errors.append({
                "host": port["host"],
                "port": port["port"],
                "service": service,
                "product": product,
                "version": version,
                "error": str(exc)
            })
            continue

        total_candidates += len(cve_results)

        for cve_result in cve_results:
            result = cve_matches_product(
                cve_result,
                product,
                version
            )

            if result["state"] == "NO_MATCH":
                continue

            finding = normalize_cve(cve_result)

            finding["host"] = port["host"]
            finding["port"] = port["port"]
            finding["protocol"] = port["protocol"]
            finding["service"] = service
            finding["product"] = product
            finding["version"] = version
            finding["applicability"] = result["state"]
            finding["applicability_evidence"] = result["evidence"]

            if result["state"] == "MATCH":
                confirmed_findings.append(finding)
            elif result["state"] == "INDETERMINATE":
                indeterminate_findings.append(finding)

    # Risk scoring operates only on confirmed applicable findings
    ranked_findings = rank_findings(confirmed_findings)

    return {
        "target": target,
        "scan_time": scan_time,
        "ports": ports,
        "findings": ranked_findings,
        "indeterminate": indeterminate_findings,
        "lookup_errors": lookup_errors,
        "candidate_count": total_candidates
    }
