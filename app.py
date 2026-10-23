from collections import Counter

import ipaddress
import os
import secrets
from urllib.parse import urlsplit

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from flask import Flask, jsonify, render_template, request

from engine_vantage.database import save_scan_results
from engine_vantage.database import fetch_findings, fetch_scan_history
from engine_vantage.formatter import make_readable
from engine_vantage.vantage import run_vantage
from engine_vantage.network_discovery import DiscoveryError, discover_network
from engine_vantage.host_discovery import HostDiscoveryError, discover_hosts


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("RISKFORGE_SECRET_KEY", secrets.token_hex(32))
_scope_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="vantage-scope-preview")


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


@app.get("/history")
def history():
    return render_template("history.html", scans=fetch_scan_history())


@app.get("/discovery")
def discovery_page():
    return render_template("discovery.html")


@app.get("/findings")
def findings_page():
    return render_template("findings.html", findings=fetch_findings())


def _same_origin():
    for header in ("Origin", "Referer"):
        value = request.headers.get(header)
        if value and urlsplit(value).netloc != request.host:
            return False
    return True


def _scope_input():
    return request.get_json(silent=True) or request.form


def _find_candidate(discovery, interface, cidr, local_address):
    return next(
        (candidate for candidate in discovery["candidates"]
         if candidate["interface"] == interface
         and candidate["ipv4_cidr"] == cidr
         and candidate["local_address"] == local_address),
        None,
    )


@app.get("/api/network/discovery")
def network_discovery():
    """Read-only, passive network discovery; never starts Nmap or writes history."""
    if not _same_origin():
        return jsonify({"ok": False, "error": "Cross-site discovery requests are not allowed."}), 403
    try:
        return jsonify({"ok": True, "discovery": discover_network()})
    except DiscoveryError as exc:
        return jsonify({"ok": False, "error": str(exc), "discovery": None})


@app.post("/scan/scope/preview")
def scope_preview():
    if not _same_origin():
        return jsonify({"ok": False, "error": "Cross-site scope requests are not allowed."}), 403
    values = _scope_input()
    confirm = values.get("confirm") in {True, "true", "1", 1}
    token = values.get("scope_token")
    try:
        discovery = discover_network()
    except DiscoveryError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503

    if confirm:
        if not isinstance(token, str):
            return jsonify({"ok": False, "error": "A valid scope preview is required first."}), 400
        try:
            signed = _scope_serializer.loads(token, max_age=300)
        except (BadSignature, SignatureExpired):
            return jsonify({"ok": False, "error": "The scope preview expired or is invalid. Refresh discovery and try again."}), 400
        candidate = _find_candidate(discovery, signed.get("interface"), signed.get("cidr"), signed.get("local_address"))
        if not candidate or not candidate["eligible"]:
            return jsonify({"ok": False, "error": "The selected network changed or is no longer eligible."}), 409
        confirmation_token = _scope_serializer.dumps({
            "confirmed": True,
            "interface": candidate["interface"],
            "cidr": candidate["ipv4_cidr"],
            "local_address": candidate["local_address"],
        })
        return jsonify({
            "ok": True, "confirmed": True,
            "message": "The authorized scope was confirmed. Host discovery is available for this network.",
            "confirmation_token": confirmation_token,
            "scope": {"interface": candidate["interface"], "ipv4_cidr": candidate["ipv4_cidr"], "local_address": candidate["local_address"]},
        })

    interface = values.get("interface")
    cidr = values.get("ipv4_cidr")
    local_address = values.get("local_address")
    if not all(isinstance(value, str) and value for value in (interface, cidr, local_address)):
        return jsonify({"ok": False, "error": "Select a discovered IPv4 network before previewing its scope."}), 400
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        local_ip = ipaddress.ip_address(local_address)
    except ValueError:
        return jsonify({"ok": False, "error": "The selected IP or CIDR is invalid."}), 400
    if network.version != 4 or network.prefixlen < 24:
        return jsonify({"ok": False, "error": "Phase 1 permits only IPv4 networks of /24 or narrower."}), 400
    candidate = _find_candidate(discovery, interface, str(network), str(local_ip))
    if not candidate or not candidate["eligible"]:
        return jsonify({"ok": False, "error": "The selected network is not a current eligible discovery candidate."}), 409
    hosts = [str(host) for host in network.hosts() if host != local_ip]
    warnings = ["Discovery is not proof of authorization. Confirm that this exact scope is approved."]
    warnings.extend(item["message"] for item in candidate.get("issues", []))
    signed = _scope_serializer.dumps({"interface": interface, "cidr": str(network), "local_address": str(local_ip)})
    return jsonify({"ok": True, "confirmed": False, "scope_token": signed, "scope": {
        "interface": interface, "local_address": str(local_ip), "ipv4_cidr": str(network),
        "host_count": len(hosts), "excluded_addresses": [str(local_ip)], "warnings": warnings,
    }})


@app.post("/scan/hosts/discover")
def discover_hosts_route():
    """Run Nmap -sn only after a fresh, explicit scope confirmation."""
    if not _same_origin():
        return jsonify({"ok": False, "error": "Cross-site host-discovery requests are not allowed."}), 403
    values = _scope_input()
    token = values.get("confirmation_token")
    if not isinstance(token, str):
        return jsonify({"ok": False, "error": "Confirm an eligible scope before discovering hosts."}), 400
    try:
        signed = _scope_serializer.loads(token, max_age=300)
    except (BadSignature, SignatureExpired):
        return jsonify({"ok": False, "error": "The scope confirmation expired or is invalid. Refresh and reconfirm the scope."}), 400
    if signed.get("confirmed") is not True:
        return jsonify({"ok": False, "error": "Host discovery requires an explicit scope confirmation."}), 400
    try:
        network = ipaddress.ip_network(signed.get("cidr"), strict=True)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "The confirmed network is invalid."}), 400
    if network.version != 4 or network.prefixlen < 24:
        return jsonify({"ok": False, "error": "Host discovery only permits confirmed IPv4 networks of /24 or narrower."}), 400
    try:
        discovery = discover_network()
    except DiscoveryError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    candidate = _find_candidate(discovery, signed.get("interface"), str(network), signed.get("local_address"))
    if not candidate or not candidate["eligible"]:
        return jsonify({"ok": False, "error": "The confirmed network changed or is no longer eligible."}), 409
    local_addresses = [
        address["address"]
        for interface in discovery.get("interfaces", [])
        for address in interface.get("ipv4_addresses", [])
        if isinstance(address, dict) and isinstance(address.get("address"), str)
    ]
    try:
        result = discover_hosts(str(network), local_addresses)
    except HostDiscoveryError as exc:
        return jsonify({"ok": False, "error": str(exc), "network": str(network)}), 502
    return jsonify({"ok": True, "result": result})


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
