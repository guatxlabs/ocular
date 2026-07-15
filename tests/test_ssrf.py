import socket

import pytest

from engine.ssrf import is_ip_allowed, resolve_allowed_ip, validate_capture_url


def test_file_scheme_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("file:///etc/passwd")


def test_other_disallowed_schemes_rejected():
    for url in ("gopher://127.0.0.1/", "ftp://example.com/", "data:text/html,x"):
        with pytest.raises(ValueError):
            validate_capture_url(url)


def test_empty_host_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http:///path")


def test_loopback_ip_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://127.0.0.1")


def test_loopback_hostname_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://localhost")


def test_metadata_ip_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://169.254.169.254/")


def test_private_rfc1918_ip_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://10.0.0.1")


def test_private_rfc1918_ip_192_168_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://192.168.1.1")


def test_link_local_ipv6_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://[fe80::1]")


def test_ipv6_loopback_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://[::1]")


def test_multicast_ipv4_rejected():
    # Durcissement audit 3g I1 : le multicast doit aussi être rejeté au submit
    # (cohérent avec is_ip_allowed, source unique).
    with pytest.raises(ValueError):
        validate_capture_url("http://239.255.255.250/")


def test_multicast_ipv6_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://[ff02::1]/")


def test_public_url_accepted():
    validate_capture_url("https://example.com")


def test_public_ip_literal_accepted():
    validate_capture_url("http://93.184.216.34")


def test_cgnat_ip_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://100.64.0.1/")


def test_cgnat_ip_rejected_second():
    with pytest.raises(ValueError):
        validate_capture_url("http://100.100.100.100/")


def test_decimal_encoded_loopback_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://2130706433/")


def test_ipv4_mapped_ipv6_loopback_rejected():
    with pytest.raises(ValueError):
        validate_capture_url("http://[::ffff:127.0.0.1]/")


# --- is_ip_allowed ---------------------------------------------------------

@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "192.168.1.1",
        "100.64.0.1",
        "100.100.100.100",
        "::1",
        "fe80::1",
        "fd00::1",
        "0.0.0.0",
        # multicast (audit 3g I1) : `is_global` seul les laissait passer.
        "224.0.0.1",            # multicast local IPv4
        "239.255.255.250",      # SSDP (découverte de services internes)
        "ff02::1",              # multicast link-local IPv6 (all-nodes)
        "ff02::fb",             # mDNS IPv6
    ],
)
def test_is_ip_allowed_rejects_internal(ip):
    assert is_ip_allowed(ip) is False


def test_is_ip_allowed_rejects_multicast_objects():
    import ipaddress

    assert is_ip_allowed(ipaddress.ip_address("224.0.0.1")) is False
    assert is_ip_allowed(ipaddress.ip_address("239.255.255.250")) is False
    assert is_ip_allowed(ipaddress.ip_address("ff02::1")) is False


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
    ],
)
def test_is_ip_allowed_accepts_public(ip):
    assert is_ip_allowed(ip) is True


def test_is_ip_allowed_accepts_ipaddress_object():
    import ipaddress

    assert is_ip_allowed(ipaddress.ip_address("8.8.8.8")) is True
    assert is_ip_allowed(ipaddress.ip_address("127.0.0.1")) is False


def test_is_ip_allowed_non_ip_string_returns_false():
    for bogus in ("not-an-ip", "example.com", "", "999.999.999.999"):
        assert is_ip_allowed(bogus) is False


# --- resolve_allowed_ip -----------------------------------------------------

def test_resolve_allowed_ip_private_literal_returns_none():
    assert resolve_allowed_ip("127.0.0.1", 80) is None
    assert resolve_allowed_ip("169.254.169.254", 80) is None
    assert resolve_allowed_ip("10.0.0.5") is None


def test_resolve_allowed_ip_public_literal_returns_ip():
    assert resolve_allowed_ip("8.8.8.8", 80) == "8.8.8.8"


def test_resolve_allowed_ip_host_resolving_private_then_public(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "evil.example"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_allowed_ip("evil.example", 443) == "93.184.216.34"


def test_resolve_allowed_ip_host_resolving_only_private(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_allowed_ip("internal.example", 80) is None


def test_resolve_allowed_ip_dns_failure_returns_none(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert resolve_allowed_ip("nonexistent.invalid", 80) is None
