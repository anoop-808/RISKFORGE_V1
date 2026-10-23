from collections import Counter

from flask import Flask, render_template, request

from engine_vantage.database import save_scan_results
from engine_vantage.formatter import make_readable
from engine_vantage.vantage import run_vantage


app = Flask(__name__)


def _scan_summary(result):
    ports = result.get("ports", [])
    findings = result.get("findings", [])
    severity_counts = Counter(
        (finding.get("risk_level") or finding.get("severity") or "UNKNOWN").upper()
        for finding in findings
    )
    return {
        "open_services": sum(port.get("state", "").lower() == "open" for port in ports),
        "confirmed_findings": len(findings),
        "indeterminate": len(result.get("indeterminate", [])),
        "lookup_errors": len(result.get("lookup_errors", [])),
        "severity_counts": dict(severity_counts),
    }


@app.route("/")
def index():
    return render_template("index.html", target="", error=None)


@app.route("/scan", methods=["POST"])
def scan():
    target = (request.form.get("target_ip") or "").strip()

    if not target:
        return render_template(
            "index.html",
            target=target,
            error="Enter a target IP address before starting a scan.",
        ), 400

    try:
        result = run_vantage(target)
        save_scan_results(result)
    except (ValueError, RuntimeError) as exc:
        return render_template("index.html", target=target, error=str(exc)), 400
    except Exception:
        return render_template(
            "index.html",
            target=target,
            error="The scan could not be completed. Check the target and service logs.",
        ), 500

    readable = make_readable(result["ports"])

    return render_template(
        "results.html",
        results=readable,
        scan=result,
        ports=result.get("ports", []),
        findings=result.get("findings", []),
        indeterminate=result.get("indeterminate", []),
        lookup_errors=result.get("lookup_errors", []),
        summary=_scan_summary(result),
        target=result.get("target", target),
    )


if __name__ == "__main__":
    app.run(debug=True)
