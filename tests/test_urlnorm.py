# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib

import pytest

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


# --- Task H : normalisation à la soumission (domaine nu -> https, scheme respecté) ---


def test_bare_domain_gets_https_prefix():
    assert normalize_url("example.com") == "https://example.com/"


def test_explicit_http_scheme_respected():
    assert normalize_url("http://example.com") == "http://example.com/"


def test_explicit_https_scheme_respected():
    assert normalize_url("https://example.com") == "https://example.com/"


# --- Bug 3i : schemes non-réseau (data:/mailto:/javascript:/...) et entrées
# tordues ne doivent JAMAIS crasher normalize_url (plus de 500 en amont) ---


def test_data_uri_does_not_crash_and_keeps_scheme():
    # Avant le fix : "https://" était préfixé aveuglément -> "https://data:text/html,..."
    # -> urlsplit().port levait ValueError("Port could not be cast...") -> 500.
    # Un scheme connu sans "//" (ici "data:") ne doit PAS être préfixé.
    result = normalize_url("data:text/html,<h1>x")
    assert result.startswith("data:")


def test_mailto_does_not_crash_and_keeps_scheme():
    result = normalize_url("mailto:a@b.c")
    assert result.startswith("mailto:")


def test_javascript_scheme_does_not_crash():
    result = normalize_url("javascript:alert(1)")
    assert result.startswith("javascript:")


def test_file_scheme_does_not_crash():
    result = normalize_url("file:///etc/passwd")
    assert result.startswith("file:")


def test_host_port_without_scheme_still_gets_https_prefix():
    # "example.com:8080" n'a PAS de scheme (pas de "://", pas dans la liste des
    # schemes connus sans "//") -> ne doit pas être confondu avec un scheme,
    # et doit bien recevoir le préfixe https:// (host:port préservé).
    assert normalize_url("example.com:8080") == "https://example.com:8080/"


def test_malformed_scheme_like_input_raises_value_error_not_crash():
    # Un scheme inconnu sans "//" (ex. "abc:notaport") se fait préfixer
    # "https://" comme un host nu -> "https://abc:notaport" -> port invalide.
    # Le code ne doit jamais laisser fuiter la ValueError brute d'urlsplit :
    # il doit lever une ValueError explicite et documentée ("URL invalide").
    with pytest.raises(ValueError):
        normalize_url("abc:notaport")
