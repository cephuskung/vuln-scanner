import os
import pytest
from parser.parser import parse_nmap_xml
from scanner.scanner import validate_target, normalize_target, is_network_target
from scanner.jobs import validate_scan_target, ScanRejected
from tests.conftest import XML_MULTI, XML_ONE_PORT, XML_NO_HOSTS


def _parse(tmp_path, xml):
    p = tmp_path / "x.xml"
    p.write_text(xml)
    return parse_nmap_xml(str(p))


def test_single_host_keeps_legacy_shape(tmp_path):
    r = _parse(tmp_path, XML_ONE_PORT)
    assert r["target"] == "10.1.1.1" and r["open_ports"][0]["port"] == 8080
    for f in ("port", "protocol", "state", "service", "product", "vendor", "version", "cpe",
              "extrainfo", "method", "conf"):
        assert f in r["open_ports"][0]
    assert r["open_ports"][0]["vendor"] == "apache"      # derived from the CPE


def test_multi_host_parses_all_up_hosts_and_ignores_down(tmp_path):
    r = _parse(tmp_path, XML_MULTI)
    assert [h["target"] for h in r["hosts"]] == ["192.168.1.1", "192.168.1.10"]
    h = r["hosts"][0]
    assert (h["mac_address"], h["mac_vendor"], h["hostname"], h["os"]) == \
        ("AA:BB:CC:DD:EE:01", "Netgear", "router.lan", "Linux 4.x")
    assert [p["port"] for p in r["hosts"][1]["open_ports"]] == [22]   # filtered 445 excluded
    assert r["target"] == "192.168.1.1" and r["open_ports"] == h["open_ports"]   # legacy = first host


def test_zero_hosts(tmp_path):
    r = _parse(tmp_path, XML_NO_HOSTS)
    assert r["hosts"] == [] and r["target"] is None and r["open_ports"] == []


@pytest.mark.parametrize("bad", ["", "   ", "-sV", "--script=evil", "a b", "x;rm -rf /", "10.0.0.0/99",
                                 "host_name", "a" * 300, "$(id)", "`id`", "http://x.com"])
def test_invalid_targets_rejected(bad):
    with pytest.raises(ValueError):
        validate_target(bad)


@pytest.mark.parametrize("good", ["127.0.0.1", "::1", "example.com", "host-1.lan", "10.0.0.0/24", "fe80::/120"])
def test_valid_targets_accepted(good):
    assert validate_target(good) == good


def test_single_address_cidr_collapses_to_host():
    assert normalize_target("10.0.0.5/32") == "10.0.0.5"
    assert not is_network_target("10.0.0.5/32") and is_network_target("10.0.0.0/30")


def test_network_size_limit_enforced():
    assert validate_scan_target("10.0.0.0/24") == "10.0.0.0/24"
    with pytest.raises(ScanRejected, match="limit"):
        validate_scan_target("10.0.0.0/16")
