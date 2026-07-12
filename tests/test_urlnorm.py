import hashlib

from engine.urlnorm import normalize_url, url_input_hash


def test_normalize_lowercases_scheme_host_keeps_path():
    assert normalize_url("HTTPS://Example.COM/Path?q=1#frag") == "https://example.com/Path?q=1"


def test_same_url_diff_case_host_same_hash():
    assert url_input_hash("https://EXAMPLE.com/a") == url_input_hash("https://example.com/a")


def test_hash_format():
    h = url_input_hash("https://example.com")
    assert h == "sha256:" + hashlib.sha256(normalize_url("https://example.com").encode()).hexdigest()


def test_scheme_less_gets_https_and_lowercases_host():
    assert normalize_url("EXAMPLE.com/A") == "https://example.com/A"


def test_default_port_stripped():
    assert normalize_url("https://Example.com:443/a") == "https://example.com/a"
    assert normalize_url("http://Example.com:80/a") == "http://example.com/a"


def test_nondefault_port_kept():
    assert normalize_url("https://example.com:8443/a") == "https://example.com:8443/a"


def test_empty_path_becomes_slash():
    assert normalize_url("https://Example.com") == "https://example.com/"


def test_ipv6_host_keeps_brackets():
    assert normalize_url("https://[::1]:8443/a") == "https://[::1]:8443/a"


def test_ipv6_host_lowercased():
    assert normalize_url("http://[FE80::1]/") == "http://[fe80::1]/"


def test_ipv6_default_port_stripped():
    assert normalize_url("https://[::1]:443/a") == "https://[::1]/a"
