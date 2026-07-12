import hashlib

from engine.urlnorm import normalize_url, url_input_hash


def test_normalize_lowercases_scheme_host_keeps_path():
    assert normalize_url("HTTPS://Example.COM/Path?q=1#frag") == "https://example.com/Path?q=1"


def test_same_url_diff_case_host_same_hash():
    assert url_input_hash("https://EXAMPLE.com/a") == url_input_hash("https://example.com/a")


def test_hash_format():
    h = url_input_hash("https://example.com")
    assert h == "sha256:" + hashlib.sha256(normalize_url("https://example.com").encode()).hexdigest()
