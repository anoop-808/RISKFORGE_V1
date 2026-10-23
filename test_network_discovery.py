import json
import subprocess
from unittest.mock import patch

import pytest

from engine_vantage.network_discovery import DiscoveryError, discover_network


ADDR = [
    {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "operstate": "UNKNOWN", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
    {"ifname": "wlan0", "flags": ["BROADCAST", "UP"], "operstate": "UP", "addr_info": [{"family": "inet", "local": "192.168.1.23", "prefixlen": 24}, {"family": "inet6", "local": "fe80::1", "prefixlen": 64}]},
    {"ifname": "vboxnet0", "flags": ["BROADCAST", "UP"], "operstate": "UP", "addr_info": [{"family": "inet", "local": "192.168.56.1", "prefixlen": 24}]},
    {"ifname": "docker0", "flags": ["BROADCAST"], "operstate": "DOWN", "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16}]},
    {"ifname": "br0", "flags": ["BROADCAST", "UP"], "operstate": "UP", "addr_info": []},
]
ROUTES = [{"dst": "default", "gateway": "192.168.1.1", "dev": "wlan0"}, {"dst": "192.168.1.0/24", "dev": "wlan0"}]


def _completed(value, code=0):
    return subprocess.CompletedProcess([], code, json.dumps(value), "")


@patch("engine_vantage.network_discovery.subprocess.run")
def test_discovery_classifies_addresses_routes_and_interfaces(run):
    run.side_effect = [_completed(ADDR), _completed(ROUTES)]
    result = discover_network()
    assert {item["interface"] for item in result["candidates"]} == {"wlan0", "vboxnet0", "docker0"}
    wlan = next(item for item in result["candidates"] if item["interface"] == "wlan0")
    assert wlan["ipv4_cidr"] == "192.168.1.0/24"
    assert wlan["gateway"] == "192.168.1.1"
    assert wlan["routes"] == ["192.168.1.0/24"]
    assert wlan["eligible"] is True
    assert next(item for item in result["interfaces"] if item["name"] == "wlan0")["ipv6_addresses"]
    docker = next(item for item in result["candidates"] if item["interface"] == "docker0")
    assert docker["eligible"] is False
    assert "no broader than /24" in docker["issues"][0]["message"]
    assert next(item for item in result["interfaces"] if item["name"] == "br0")["issues"]


@pytest.mark.parametrize("error", [FileNotFoundError(), subprocess.TimeoutExpired(["ip"], 2), OSError()])
@patch("engine_vantage.network_discovery.subprocess.run")
def test_discovery_command_failures_are_safe(run, error):
    run.side_effect = error
    with pytest.raises(DiscoveryError):
        discover_network()


@patch("engine_vantage.network_discovery.subprocess.run")
def test_discovery_rejects_bad_json_and_shapes(run):
    run.return_value = subprocess.CompletedProcess([], 0, "not json", "")
    with pytest.raises(DiscoveryError):
        discover_network()
    run.return_value = _completed({})
    with pytest.raises(DiscoveryError):
        discover_network()


@patch("engine_vantage.network_discovery.subprocess.run")
def test_discovery_rejects_nonzero_command(run):
    run.return_value = _completed([], code=1)
    with pytest.raises(DiscoveryError):
        discover_network()

