from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from engine_vantage.host_discovery import HostDiscoveryError, discover_hosts


def _nmap(scanner):
    return SimpleNamespace(PortScanner=Mock(return_value=scanner), PortScannerError=RuntimeError)


def test_host_discovery_uses_ping_scan_and_filters_results():
    scanner = Mock()
    scanner.all_hosts.return_value = [
        "192.168.56.104", "192.168.56.103", "192.168.56.104",
        "192.168.56.1", "192.168.57.1", "::1", "not-an-ip",
    ]
    with patch("engine_vantage.host_discovery.nmap", _nmap(scanner)):
        result = discover_hosts("192.168.56.0/24", ["192.168.56.1"])

    assert result["hosts"] == ["192.168.56.103", "192.168.56.104"]
    assert result["local_addresses"] == ["192.168.56.1"]
    assert "offline" in result["warning"]
    kwargs = scanner.scan.call_args.kwargs
    assert kwargs["hosts"] == "192.168.56.0/24"
    assert "-sn" in kwargs["arguments"]
    assert "-sV" not in kwargs["arguments"]


def test_host_discovery_accepts_canonical_single_host_network():
    scanner = Mock()
    scanner.all_hosts.return_value = ["192.168.56.1"]
    with patch("engine_vantage.host_discovery.nmap", _nmap(scanner)):
        result = discover_hosts("192.168.56.1/32")
    assert result["network"] == "192.168.56.1/32"
    assert result["hosts"] == ["192.168.56.1"]


@pytest.mark.parametrize("network", [
    "192.168.0.0/16", "2001:db8::/64", "192.168.56.1",
    "192.168.56.1/24", "192.168.56.0/024", "not-a-cidr",
])
def test_host_discovery_rejects_unsupported_network(network):
    with pytest.raises(HostDiscoveryError):
        discover_hosts(network)


def test_host_discovery_handles_nmap_failure():
    scanner = Mock()
    scanner.scan.side_effect = RuntimeError("nmap unavailable")
    with patch("engine_vantage.host_discovery.nmap", _nmap(scanner)):
        with pytest.raises(HostDiscoveryError, match="Nmap host discovery failed"):
            discover_hosts("192.168.56.0/24")


def test_host_discovery_handles_missing_integration():
    with patch("engine_vantage.host_discovery.nmap", None):
        with pytest.raises(HostDiscoveryError, match="not available"):
            discover_hosts("192.168.56.0/24")
