from __future__ import annotations

import json

import pytest

from pyshield.discovery import DiscoveredDevice
from pyshield.router import (
    RouterError,
    RouterStations,
    fetch_station_info,
    merge_router_macs,
    parse_station_response,
)


def test_parse_mf935_station_response():
    result = parse_station_response(
        json.dumps({
            "station_mac": "38:f9:d3:67:47:ba;3a:92:3a:a8:aa:75",
            "sta_count": "2",
            "sta_ip_status": "",
        }),
        "192.168.0.1",
    )
    assert result.gateway == "192.168.0.1"
    assert result.station_count == 2
    assert result.normalized_macs == [
        "38:f9:d3:67:47:ba",
        "3a:92:3a:a8:aa:75",
    ]


def test_parse_deduplicates_and_ignores_invalid_macs():
    result = parse_station_response(
        '{"station_mac":"AA:BB:CC:DD:EE:FF;bad;aa:bb:cc:dd:ee:ff","sta_count":"2"}',
        "192.168.0.1",
    )
    assert result.normalized_macs == ["aa:bb:cc:dd:ee:ff"]
    assert result.station_count == 2


def test_rejects_invalid_json():
    with pytest.raises(RouterError, match="invalid JSON"):
        parse_station_response("not-json", "192.168.0.1")


def test_rejects_invalid_count():
    with pytest.raises(RouterError, match="sta_count"):
        parse_station_response('{"station_mac":"aa:bb:cc:dd:ee:ff","sta_count":"x"}', "192.168.0.1")


def test_merge_enriches_arp_match_and_adds_unknown_router_mac():
    devices = [
        DiscoveredDevice("192.168.0.4", "AA:BB:CC:DD:EE:FF", "arp"),
        DiscoveredDevice("192.168.0.3", None, "local"),
    ]
    stations = RouterStations(
        "192.168.0.1",
        ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"],
        2,
    )
    merged = merge_router_macs(devices, stations)
    assert merged[0].source == "router+arp"
    assert merged[-1].ip == "unknown"
    assert merged[-1].mac == "11:22:33:44:55:66"


def test_fetch_station_info_uses_multi_data(monkeypatch):
    import json
    import urllib.request

    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({
                "station_mac": "aa:bb:cc:dd:ee:ff",
                "sta_count": "1",
            }).encode()

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = fetch_station_info("192.168.0.1")

    assert result.station_count == 1
    assert result.gateway == "192.168.0.1"
    assert "multi_data=1" in captured["url"]
    assert "cmd=station_mac%2Csta_count%2Cm_sta_count" in captured["url"]
