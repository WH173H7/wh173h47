from __future__ import annotations

import ipaddress

import pytest

from pyshield.discovery import (
    DiscoveryError,
    MAX_PROBE_HOSTS,
    parse_arp_table,
    parse_default_route,
    parse_interface_ipv4,
    _netmask_to_prefix,
    probe_subnet,
)


def test_subnet_calculation_from_interface_values():
    ip, netmask = parse_interface_ipv4(
        "inet 192.168.0.3 netmask 0xffffff00 broadcast 192.168.0.255"
    )
    prefix = _netmask_to_prefix(netmask)
    assert str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)) == "192.168.0.0/24"


def test_parse_valid_arp_entries():
    output = """
    ? (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    ? (192.168.0.7) at 11:22:33:44:55:66 on en0 ifscope [ethernet]
    """
    devices = parse_arp_table(output, interface="en0")
    assert [(d.ip, d.mac) for d in devices] == [
        ("192.168.0.1", "aa:bb:cc:dd:ee:ff"),
        ("192.168.0.7", "11:22:33:44:55:66"),
    ]


def test_ignore_incomplete_and_wrong_interface_entries():
    output = """
    ? (192.168.0.1) at (incomplete) on en0 ifscope [ethernet]
    ? (192.168.0.8) at aa:bb:cc:dd:ee:01 on awdl0 ifscope [ethernet]
    ? (192.168.0.9) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]
    """
    devices = parse_arp_table(output, interface="en0")
    assert [d.ip for d in devices] == ["192.168.0.9"]


def test_parse_gateway_and_interface():
    output = """
    route to: default
    destination: default
       gateway: 192.168.0.1
     interface: en0
    """
    assert parse_default_route(output) == ("192.168.0.1", "en0")


def test_probe_host_limit(monkeypatch):
    with pytest.raises(DiscoveryError, match="maximum"):
        probe_subnet("10.0.0.0/16", "10.0.0.2", "10.0.0.1")


def test_parse_interface_mac():
    from pyshield.discovery import parse_interface_mac

    output = """
    en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
        ether 38:f9:d3:67:47:ba
        inet 192.168.0.3 netmask 0xffffff00 broadcast 192.168.0.255
    """
    assert parse_interface_mac(output) == "38:f9:d3:67:47:ba"
