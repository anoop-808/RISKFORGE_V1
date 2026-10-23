"""Passive Linux network configuration discovery for VANTAGE scope selection."""

import ipaddress
import json
import subprocess
from datetime import datetime, timezone


_COMMAND_TIMEOUT = 2


class DiscoveryError(RuntimeError):
    """A safe, user-facing discovery failure."""


def _run_ip(arguments):
    try:
        completed = subprocess.run(
            ["ip", *arguments], capture_output=True, text=True,
            timeout=_COMMAND_TIMEOUT, check=False,
        )
    except FileNotFoundError as exc:
        raise DiscoveryError("The Linux ip command is not available.") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError("Local network discovery timed out.") from exc
    except OSError as exc:
        raise DiscoveryError("Local network discovery is unavailable.") from exc
    if completed.returncode != 0:
        raise DiscoveryError("The operating system rejected local network discovery.")
    try:
        value = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise DiscoveryError("The operating system returned malformed network data.") from exc
    if not isinstance(value, list):
        raise DiscoveryError("The operating system returned an unexpected network shape.")
    return value


def _issue(message, severity="warning"):
    return {"severity": severity, "message": message}


def _address_info(raw):
    if not isinstance(raw, dict) or raw.get("family") not in {"inet", "inet6"}:
        return None
    try:
        address = ipaddress.ip_address(raw.get("local"))
        prefixlen = int(raw.get("prefixlen"))
        if prefixlen < 0 or prefixlen > address.max_prefixlen:
            return None
    except (ValueError, TypeError):
        return None
    return {"address": str(address), "prefix_length": prefixlen}


def _route_map(routes):
    result = {}
    if not isinstance(routes, list):
        return result
    for route in routes:
        if not isinstance(route, dict) or not isinstance(route.get("dev"), str):
            continue
        dev = route["dev"]
        if route.get("dst") == "default" and route.get("gateway"):
            result.setdefault(dev, {})["gateway"] = str(route["gateway"])
        if route.get("dst") and route.get("dst") != "default":
            try:
                network = ipaddress.ip_network(route["dst"], strict=False)
            except (ValueError, TypeError):
                continue
            result.setdefault(dev, {}).setdefault("routes", []).append(str(network))
    return result


def discover_network():
    """Return a stable, non-probing discovery document for the local Linux host."""
    discovered_at = datetime.now(timezone.utc).isoformat()
    interfaces_raw = _run_ip(["-j", "addr"])
    routes_raw = _run_ip(["-j", "route"])
    routes = _route_map(routes_raw)
    interfaces, candidates, issues = [], [], []

    for raw in interfaces_raw:
        if not isinstance(raw, dict) or not isinstance(raw.get("ifname"), str):
            issues.append(_issue("An interface entry was ignored because it was malformed."))
            continue
        name = raw["ifname"]
        raw_flags = raw.get("flags", [])
        if not isinstance(raw_flags, list):
            raw_flags = []
        flags = [flag for flag in raw_flags if isinstance(flag, str)]
        operstate = raw.get("operstate") if isinstance(raw.get("operstate"), str) else "unknown"
        raw_addresses = raw.get("addr_info", [])
        if not isinstance(raw_addresses, list):
            raw_addresses = []
        addresses = [item for item in (_address_info(value) for value in raw_addresses) if item]
        ipv4 = [item for item in addresses if "." in item["address"]]
        ipv6 = [item for item in addresses if ":" in item["address"]]
        interface = {
            "name": name, "operational_state": operstate, "flags": flags,
            "ipv4_addresses": ipv4, "ipv6_addresses": ipv6, "candidates": [], "issues": [],
        }
        if not addresses:
            interface["issues"].append(_issue("This interface has no assigned IP address."))
        route_info = routes.get(name, {})
        interface["routes"] = route_info.get("routes", [])
        interface["gateway"] = route_info.get("gateway")
        for address in addresses:
            ip = ipaddress.ip_address(address["address"])
            network = ipaddress.ip_network(f'{address["address"]}/{address["prefix_length"]}', strict=False)
            address["network"] = str(network)
            address["gateway"] = route_info.get("gateway")
            address["routes"] = route_info.get("routes", [])
            address["eligible"] = False
            if ip.is_loopback or network.is_loopback:
                address["eligibility_reason"] = "Loopback addresses are not assessable scope candidates."
            elif ip.is_link_local or network.is_link_local:
                address["eligibility_reason"] = "Link-local addresses are not assessable scope candidates."
            elif ip.version == 6:
                address["eligibility_reason"] = "IPv6 is displayed for inventory only; Phase 1 scope preview is IPv4-only."
            elif network.prefixlen < 24:
                address["eligibility_reason"] = "Only IPv4 networks no broader than /24 are eligible in Phase 1."
            elif operstate.lower() not in {"up", "unknown"}:
                address["eligibility_reason"] = "The interface is not operationally up."
            else:
                address["eligible"] = True
                address["eligibility_reason"] = "Eligible for IPv4 scope preview."
        for address in ipv4:
            ip = ipaddress.ip_address(address["address"])
            network = ipaddress.ip_network(f'{address["address"]}/{address["prefix_length"]}', strict=False)
            eligible, candidate_issues = True, []
            if ip.is_loopback or network.is_loopback:
                interface["issues"].append(_issue(f"Loopback network {network} was excluded from assessment candidates."))
                continue
            elif ip.is_link_local or network.is_link_local:
                interface["issues"].append(_issue(f"Link-local network {network} was excluded from assessment candidates."))
                continue
            if network.prefixlen < 24:
                eligible = False
                candidate_issues.append(_issue("Only IPv4 networks no broader than /24 are eligible in Phase 1."))
            if operstate.lower() not in {"up", "unknown"}:
                eligible = False
                candidate_issues.append(_issue("The interface is not operationally up."))
            candidate = {
                "interface": name, "operational_state": operstate,
                "local_address": str(ip), "ipv4_cidr": str(network),
                "gateway": route_info.get("gateway"), "routes": route_info.get("routes", []),
                "eligible": eligible, "issues": candidate_issues,
            }
            interface["candidates"].append(candidate)
            candidates.append(candidate)
        interfaces.append(interface)

    return {"version": 1, "discovered_at": discovered_at, "interfaces": interfaces,
            "candidates": candidates, "issues": issues}


def discovery_response():
    try:
        return {"ok": True, "discovery": discover_network()}
    except DiscoveryError as exc:
        return {"ok": False, "error": str(exc), "discovery": None}
