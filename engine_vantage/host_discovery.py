"""Authorized IPv4 host discovery using Nmap's ping-scan mode."""

import ipaddress
from datetime import datetime, timezone

try:
    import nmap
except ImportError:  # Keep passive inventory usable when the integration is absent.
    nmap = None


_HOST_TIMEOUT = "30s"


class HostDiscoveryError(RuntimeError):
    """A safe, user-facing host-discovery failure."""


def discover_hosts(network, local_addresses=()):
    """Discover responding IPv4 hosts in one already-authorized canonical network."""
    if not isinstance(network, str) or "/" not in network:
        raise HostDiscoveryError("The confirmed host-discovery scope must be a canonical IPv4 CIDR network.")
    try:
        target = ipaddress.ip_network(network, strict=True)
    except (TypeError, ValueError) as exc:
        raise HostDiscoveryError("The confirmed host-discovery scope is invalid.") from exc
    if str(target) != network:
        raise HostDiscoveryError("The confirmed host-discovery scope must be a canonical IPv4 CIDR network.")
    if target.version != 4 or target.prefixlen < 24:
        raise HostDiscoveryError("Host discovery only permits confirmed IPv4 networks of /24 or narrower.")
    try:
        excluded = {ipaddress.ip_address(address) for address in local_addresses}
    except (TypeError, ValueError) as exc:
        raise HostDiscoveryError("The local address data is invalid.") from exc
    excluded = {address for address in excluded if address.version == 4}
    if nmap is None:
        raise HostDiscoveryError("The Nmap Python integration is not available.")
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=str(target), arguments=f"-sn --host-timeout {_HOST_TIMEOUT} --max-retries 1")
        hosts = scanner.all_hosts()
    except getattr(nmap, "PortScannerError", Exception) as exc:
        raise HostDiscoveryError(f"Nmap host discovery failed: {exc}") from exc
    except Exception as exc:
        raise HostDiscoveryError("Nmap host discovery could not be completed safely.") from exc

    discovered = set()
    for host in hosts or []:
        try:
            address = ipaddress.ip_address(host)
        except (TypeError, ValueError):
            continue
        if address.version == 4 and address in target and address not in excluded:
            discovered.add(str(address))
    return {
        "network": str(target),
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "hosts": sorted(discovered, key=ipaddress.ip_address),
        "local_addresses": sorted({str(address) for address in excluded}, key=ipaddress.ip_address),
        "warning": "A nonresponsive device is not confirmed offline by this discovery.",
    }
