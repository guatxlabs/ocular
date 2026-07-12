import pytest

from engine.ssrf import validate_capture_url


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
