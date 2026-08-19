# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validation OIDC JWT in-app (`web/oidc.py`) — opt-in strict et fail-closed.

Trois familles, dans l'ordre d'importance :

1. **L'opt-in éteint (défaut) ne change RIEN.** `web.oidc.validate_bearer` est
   remplacée par une fonction qui EXPLOSE : si un chemin l'appelait alors que
   `OCULAR_OIDC_ENABLED` est absent, le test rougirait. C'est la garantie de
   non-régression du comportement bearer/forward-auth existant.
2. **La primitive RSA est confrontée à une référence externe.** Les signatures
   ci-dessous ont été produites par `cryptography` (hors de ce dépôt, hors de ce
   code) sur une entrée connue. Un vérificateur maison qui ne s'accorderait
   qu'avec son propre signeur ne prouverait rien — en particulier les préfixes
   DER `DigestInfo`, recopiés de la RFC 8017, sont validés ICI et nulle part
   ailleurs.
3. **Chaque anomalie est un REFUS.** Signature fausse, `alg` interdit (`none`,
   `HS256`), `iss`/`aud` non conformes, `exp` dépassé, `kid` inconnu, JWKS
   injoignable, module trop court : `None`, jamais « on laisse passer ».

AUCUN RÉSEAU. Le cache JWKS reçoit sa fonction de récupération par injection —
aucun test n'ouvre de socket, et le compteur d'appels sert à prouver le cache.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
from starlette.requests import Request

from web import oidc

# Sentinelle « ce claim doit être ABSENT » (distincte de `None`, qui est une
# valeur présente et non numérique — les deux cas doivent être testables).
_ABSENT = object()

# --- Matériel de test -------------------------------------------------------
# Paire RSA 2048 bits générée POUR LES TESTS et pour eux seuls. Écrite en
# entiers décimaux plutôt qu'en PEM : ce n'est pas un secret (elle ne protège
# rien, elle n'a jamais servi ailleurs) et cette forme ne ressemble pas à une
# clé fuitée pour un scanner de secrets.
N = 24247185849598494870816756548682094020958735969308099179723956650612184529433828506212851577884163562797244691585977000040705775842709359519296876603989382429173784509115173516045432883446218557651201670537499701541723732037382042514548124966387917553794007473439034947481331706087905310105485841236068359388729483611735572405720737794745568947064134446667550247940562586675260851767617366862302218487541602569192167549171402559179389697036553149030102401174767170250006977521707208211921934772051371590324577490045181312012649602370423949069481747866115092472365941296448016585470088141886103509504952359574489132689  # noqa: E501
E = 65537
D = 1167442023323123080323286539115347544306960008667505393229915323355484397196140764840113679567491749393267165445728131223848111801403283812517292180459035814554469326528630667802876828622659567739913630199725098500903496864586438238231248846572589988369921686711654236832327691263782160207526015677764901825214398476369899524995483480661440131910939501717927371619097064356265631260757784048846295243580204621334575405310243034943917340901434634317441647766447873781638301573341228443311699930038840359762030700970403786070890398893014724872142822074741401743352637320407822681684760838076202519835650189838460171053  # noqa: E501

# Signatures de RÉFÉRENCE : produites par `cryptography` (PKCS1v15) avec la clé
# ci-dessus, sur `_REF_INPUT`. Elles fixent la conformité de la primitive à une
# implémentation tierce, y compris les préfixes DER de chaque condensat.
_REF_INPUT = b"ocular.oidc.reference.signing-input"
_REF_SIGS = {
    "RS256": (
        "lAeKIs3TbM3QYM6tZd6VeZIXelu++pwpHSA1oR6Iyej/bSJMbJ7rimqVNwB7VpfhawM6bunRCdzY/jeT"
        "AsebwUsozZeWK9RPpj0FxfHf3rFjDIpKV6OcbCan5i8Pw+Pt5vGEtj348tilnEy4nw8vRvg+bofDe6an"
        "Fqy4ELwhih4g3U52ssBPAOOPyHpkr28YU4T0Qt9v38teAKDM7gXWgADTEkXL+N9cR7ouwRAFq+tC3EdQ"
        "ABTuUp1e6opMbwJw2TlGs3QQw1aVqwrkI7OWHS0gtbDmM6nLrIwuJdpZ2RM2m59+zdh2paBvliwQM2dR"
        "V3C0aOnbhoZQI5hhAud6mA=="
    ),
    "RS384": (
        "lPxXCoVB+r2qbLnNinNPNOpWIJaTSyJX/eHk+uILxZQtwXRn5l/1ES9NZGMaWkjKiWTIaiAU7I4fA4Hi"
        "tgFy8hw/EbUfI7YqKCNNchJmRSkgKkITq+NK4IOZP5iMsQ7wW50pi4qMFkFYl+qVDlUxCB/4lqEYQlmD"
        "TwjgkqbVSjbOnbfHOQY7xMgozw+VXS/RCwSsFf9VE71FWgDk4lchI4HdUfmn70vzmD44UZjGSbeoES7D"
        "DSWUQACsYL/zFXJoJ7h9gir6/SE+Rp1ODsCoptOaruJwduyck/zsQPk7IdCC1cRCe6BUZNKSChRTPJap"
        "xWnXNFtsbJsrV4HHKrRPCQ=="
    ),
    "RS512": (
        "CLeBIFPvUFmiiysYSXZrSv54B0UjJ27ggSPYCzoG5ojuIlGlbqKlIEWartMdfqzPUw9b1IjDzEySjhpR"
        "YV8aVQ0XtiXDM6yTo7eADNjCeze4eLL9LVVOl2Wka5/hz9cbUu7fDACbSKbROxR1KDrmRuqrrI3tvCmc"
        "CvtDNDsfLBXtX6BkxKMDartZGf+dtf2GHDh7Wkmn9YdPiwI1+6CwYxe6bqiyhJ+l4H+5D+ygRLsP2mpw"
        "yPib+hSfbNPRuhzgpRCoMRed8Jk/OYlXRqZC89YyqIJ5pS76jHVzp5b3kLOaKect+OWv6gPbFZSfBvT0"
        "P7tYkb5VnEyINBUy80O7Sg=="
    ),
}

ISS = "https://idp.example/realms/soc"
AUD = "ocular"
JWKS_URL = "https://idp.example/realms/soc/protocol/openid-connect/certs"
NOW = 1_700_000_000.0


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int_b64u(value: int) -> str:
    return _b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


JWK = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
       "n": _int_b64u(N), "e": _int_b64u(E)}


def _sign(signing_input: bytes, alg: str = "RS256") -> bytes:
    """Signeur PKCS#1 v1.5 en Python pur (`pow(m, d, n)`). Il partage les
    préfixes DER du module vérifié — c'est précisément pourquoi la conformité de
    ces préfixes est établie à part, contre `_REF_SIGS`."""
    digest_info = oidc._DIGEST_INFO[alg] + oidc._HASH[alg](signing_input).digest()
    k = (N.bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - 3 - len(digest_info)) + b"\x00" + digest_info
    return pow(int.from_bytes(em, "big"), D, N).to_bytes(k, "big")


def _claims(**over) -> dict:
    base = {"iss": ISS, "aud": AUD, "exp": NOW + 300, "sub": "uuid-1",
            "preferred_username": "alice"}
    base.update(over)
    return {k: v for k, v in base.items() if v is not _ABSENT}


def _patched_validate(inner):
    """`web.identity` appelle `validate_bearer` SANS `now` (horloge réelle). Pour
    que les jetons de test restent valides quelle que soit la date d'exécution de
    la suite, on fige `now` à ce niveau plutôt que de dater les jetons au moment
    du test — ce qui ne prouverait plus rien sur `exp`."""
    def wrapper(authorization, cache, now):
        return inner(authorization, cache, NOW)
    return wrapper


def _jwt(claims: dict, *, alg: str = "RS256", kid: str | None = "k1",
         typ: str | None = "JWT", corrupt: bool = False) -> str:
    header: dict = {"alg": alg}
    if kid is not None:
        header["kid"] = kid
    if typ is not None:
        header["typ"] = typ
    h_b64 = _b64u(json.dumps(header).encode())
    p_b64 = _b64u(json.dumps(claims).encode())
    sign_alg = alg if alg in oidc._HASH else "RS256"
    sig = bytearray(_sign(f"{h_b64}.{p_b64}".encode("ascii"), sign_alg))
    if corrupt:
        sig[-1] ^= 0x01
    return f"{h_b64}.{p_b64}.{_b64u(bytes(sig))}"


def _bearer(claims: dict, **kw) -> str:
    return "Bearer " + _jwt(claims, **kw)


class _Clock:
    """Horloge injectable — le cache JWKS ne doit jamais dépendre du temps réel."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def _cache(keys=(JWK,), *, boom: bool = False, clock: _Clock | None = None) -> oidc.JwksCache:
    clock = clock or _Clock()
    calls: list[str] = []

    def fetch(url: str) -> list[dict]:
        calls.append(url)
        if boom:
            raise OSError("JWKS injoignable (simulé — aucun socket ouvert)")
        return [dict(k) for k in keys]

    cache = oidc.JwksCache(fetch=fetch, ttl=300, clock=clock)
    cache.calls = calls          # type: ignore[attr-defined]
    return cache


@pytest.fixture
def oidc_on(monkeypatch):
    monkeypatch.setenv("OCULAR_OIDC_ENABLED", "1")
    monkeypatch.setenv("OCULAR_OIDC_ISSUER", ISS)
    monkeypatch.setenv("OCULAR_OIDC_AUDIENCE", AUD)
    monkeypatch.setenv("OCULAR_OIDC_JWKS_URL", JWKS_URL)
    for var in ("OCULAR_OIDC_USERNAME_CLAIM", "OCULAR_OIDC_GROUPS_CLAIM",
                "OCULAR_OIDC_CLOCK_SKEW", "OCULAR_OIDC_ALLOW_INSECURE_JWKS",
                "OCULAR_TRUST_FORWARD_AUTH", "OCULAR_ADMIN_GROUP"):
        monkeypatch.delenv(var, raising=False)


# ============================================================================
# 1. La primitive RSA, contre une référence produite HORS de ce code
# ============================================================================


@pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
def test_primitive_accepte_une_signature_de_reference_cryptography(alg):
    """Le vérificateur maison s'accorde avec `cryptography` sur les trois
    condensats — donc les préfixes DER recopiés de la RFC 8017 sont les bons."""
    sig = base64.b64decode(_REF_SIGS[alg])
    assert oidc.rsa_pkcs1v15_verify(N, E, alg, _REF_INPUT, sig) is True


@pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512"])
def test_primitive_refuse_un_bit_retourne(alg):
    sig = bytearray(base64.b64decode(_REF_SIGS[alg]))
    sig[0] ^= 0x80
    assert oidc.rsa_pkcs1v15_verify(N, E, alg, _REF_INPUT, bytes(sig)) is False


def test_primitive_refuse_une_entree_modifiee():
    sig = base64.b64decode(_REF_SIGS["RS256"])
    assert oidc.rsa_pkcs1v15_verify(N, E, "RS256", _REF_INPUT + b"!", sig) is False


def test_primitive_refuse_une_signature_de_longueur_incorrecte():
    sig = base64.b64decode(_REF_SIGS["RS256"])
    assert oidc.rsa_pkcs1v15_verify(N, E, "RS256", _REF_INPUT, sig[:-1]) is False
    assert oidc.rsa_pkcs1v15_verify(N, E, "RS256", _REF_INPUT, sig + b"\x00") is False


def test_primitive_refuse_une_signature_non_canonique():
    """`s` et `s + n` produisent le même bloc modulo n : accepter `s >= n`
    rendrait la signature malléable (plusieurs encodages pour une même preuve).
    La longueur est ici correcte — c'est bien le contrôle de canonicité qui mord."""
    k = (N.bit_length() + 7) // 8
    assert oidc.rsa_pkcs1v15_verify(N, E, "RS256", _REF_INPUT, N.to_bytes(k, "big")) is False


def _icbrt(x: int) -> int:
    """Racine cubique entière (dichotomie) — les flottants ne portent pas un
    entier de 3 000 bits."""
    lo, hi = 1, 1 << ((x.bit_length() + 2) // 3 + 2)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** 3 <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def test_primitive_refuse_une_forgerie_bleichenbacher_sur_e3():
    """LA raison d'être de la reconstruction intégrale du bloc.

    On FABRIQUE ici, sans aucune clé privée, une signature que tout vérificateur
    PERMISSIF accepterait : avec `e = 3`, il suffit d'une racine cubique pour
    obtenir un bloc qui COMMENCE par `00 01 FF…FF 00 || DigestInfo(H(m))` — le
    reste du bloc étant du remplissage arbitraire. Un vérificateur qui *cherche*
    le condensat au lieu d'exiger le bloc entier signe ainsi n'importe quoi.

    Le test le prouve dans les deux sens : le préfixe EST celui qu'un analyseur
    naïf reconnaîtrait, et `rsa_pkcs1v15_verify` refuse quand même."""
    msg = b"jeton force sans cle privee"
    n = (1 << 3071) | 1            # module 3072 bits : s³ < n, donc pas de réduction
    k = (n.bit_length() + 7) // 8
    digest_info = oidc._DIGEST_INFO["RS256"] + hashlib.sha256(msg).digest()
    # Seulement 8 octets de bourrage (le minimum RFC 8017) au lieu des 330 que la
    # taille du module impose : c'est ce raccourci qui rend la racine cubique
    # accessible, et que la comparaison intégrale refuse.
    plausible = b"\x00\x01" + b"\xff" * 8 + b"\x00" + digest_info
    forged = _icbrt(int.from_bytes(plausible, "big") << (8 * (k - len(plausible)))) + 1

    block = (forged ** 3).to_bytes(k, "big")
    assert block[:len(plausible)] == plausible, "la forgerie doit leurrer un analyseur naïf"
    assert oidc.rsa_pkcs1v15_verify(n, 3, "RS256", msg, forged.to_bytes(k, "big")) is False


def test_primitive_refuse_un_module_trop_court():
    """Une clé RSA < 2048 bits est refusée AVANT tout calcul : un JWKS empoisonné
    ne peut pas faire descendre le niveau de sécurité en publiant une clé faible."""
    with pytest.raises(oidc._Refused):
        oidc.rsa_pkcs1v15_verify(N >> 1100, E, "RS256", _REF_INPUT, b"\x00" * 118)


def test_primitive_refuse_un_exposant_degenere():
    """`e = 1` fait de l'« exponentiation » l'identité : n'importe quel bloc bien
    formé passerait. `e` pair n'est pas un exposant RSA."""
    for bad_e in (0, 1, 2, 4):
        with pytest.raises(oidc._Refused):
            oidc.rsa_pkcs1v15_verify(N, bad_e, "RS256", _REF_INPUT, b"\x00" * 256)


# ============================================================================
# 2. Chemin nominal
# ============================================================================


def test_jeton_valide_rend_les_claims(oidc_on):
    claims = oidc.validate_bearer(_bearer(_claims()), cache=_cache(), now=NOW)
    assert claims is not None
    assert oidc.identity_from_claims(claims) == "alice"


def test_aud_peut_etre_une_liste(oidc_on):
    claims = oidc.validate_bearer(_bearer(_claims(aud=["account", AUD])), cache=_cache(), now=NOW)
    assert claims is not None


def test_kid_absent_accepte_si_le_jwks_ne_contient_qu_une_cle(oidc_on):
    token = _bearer(_claims(), kid=None)
    assert oidc.validate_bearer(token, cache=_cache(), now=NOW) is not None


def test_typ_at_jwt_rfc9068_accepte(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims(), typ="at+jwt"), cache=_cache(), now=NOW) \
        is not None


def test_typ_absent_accepte(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims(), typ=None), cache=_cache(), now=NOW) is not None


def test_le_jwks_n_est_recupere_qu_une_fois_pour_plusieurs_jetons(oidc_on):
    cache = _cache()
    for _ in range(5):
        assert oidc.validate_bearer(_bearer(_claims()), cache=cache, now=NOW) is not None
    assert cache.calls == [JWKS_URL]


# ============================================================================
# 3. Fail-closed — chaque anomalie est un refus
# ============================================================================


def test_signature_falsifiee_refusee(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims(), corrupt=True), cache=_cache(), now=NOW) is None


def test_charge_utile_modifiee_apres_signature_refusee(oidc_on):
    """Le scénario réel : on prend un jeton valide et on réécrit son `sub`."""
    h_b64, p_b64, s_b64 = _jwt(_claims()).split(".")
    forged = _b64u(json.dumps(_claims(preferred_username="admin")).encode())
    assert oidc.validate_bearer(f"Bearer {h_b64}.{forged}.{s_b64}", cache=_cache(), now=NOW) \
        is None


def test_alg_none_refuse(oidc_on):
    h_b64 = _b64u(json.dumps({"alg": "none", "typ": "JWT", "kid": "k1"}).encode())
    p_b64 = _b64u(json.dumps(_claims()).encode())
    assert oidc.validate_bearer(f"Bearer {h_b64}.{p_b64}.", cache=_cache(), now=NOW) is None


def test_alg_symetrique_refuse(oidc_on):
    """Confusion d'algorithme : `HS256` signé avec la clé PUBLIQUE lue dans le
    JWKS (que l'attaquant peut télécharger). Refusé sur la liste blanche, avant
    même de chercher une clé."""
    public = json.dumps(JWK).encode()
    h_b64 = _b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    p_b64 = _b64u(json.dumps(_claims()).encode())
    mac = hmac.new(public, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    assert oidc.validate_bearer(f"Bearer {h_b64}.{p_b64}.{_b64u(mac)}", cache=_cache(), now=NOW) \
        is None


@pytest.mark.parametrize("alg", ["PS256", "ES256", "RS1", "rs256", ""])
def test_algs_hors_liste_blanche_refuses(oidc_on, alg):
    assert oidc.validate_bearer(_bearer(_claims(), alg=alg), cache=_cache(), now=NOW) is None


def test_issuer_non_conforme_refuse(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims(iss="https://evil.example")),
                                cache=_cache(), now=NOW) is None


def test_issuer_prefixe_refuse(oidc_on):
    """Comparaison EXACTE : `https://idp.example/realms/soc.evil.example` ne doit
    pas passer pour l'issuer attendu."""
    assert oidc.validate_bearer(_bearer(_claims(iss=ISS + ".evil.example")),
                                cache=_cache(), now=NOW) is None


def test_audience_non_conforme_refuse(oidc_on):
    """Le jeton est authentique et signé par le BON IdP — mais émis pour une
    autre application du même realm. Sans contrôle d'`aud`, il ouvrirait Ocular."""
    assert oidc.validate_bearer(_bearer(_claims(aud="autre-app")), cache=_cache(), now=NOW) is None


def test_audience_account_de_keycloak_refusee_par_defaut(oidc_on):
    """Piège Keycloak documenté : sans *audience mapper*, `aud` vaut `account`."""
    assert oidc.validate_bearer(_bearer(_claims(aud="account")), cache=_cache(), now=NOW) is None


def test_jeton_expire_refuse(oidc_on):
    token = _bearer(_claims(exp=NOW - 3600))
    assert oidc.validate_bearer(token, cache=_cache(), now=NOW) is None


def test_expiration_tolere_la_derive_horloge_configuree(oidc_on, monkeypatch):
    """`exp` dépassé de 30 s : accepté avec la tolérance par défaut (60 s),
    refusé avec une tolérance nulle."""
    token = _bearer(_claims(exp=NOW - 30))
    assert oidc.validate_bearer(token, cache=_cache(), now=NOW) is not None
    monkeypatch.setenv("OCULAR_OIDC_CLOCK_SKEW", "0")
    assert oidc.validate_bearer(token, cache=_cache(), now=NOW) is None


def test_exp_absent_refuse(oidc_on):
    """Un jeton sans expiration ne se révoque jamais."""
    assert oidc.validate_bearer(_bearer(_claims(exp=_ABSENT)), cache=_cache(), now=NOW) is None


def test_exp_non_numerique_refuse(oidc_on):
    for bad in ("9999999999", True, None, {"x": 1}):
        assert oidc.validate_bearer(_bearer(_claims(exp=bad)), cache=_cache(), now=NOW) is None


def test_nbf_futur_refuse(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims(nbf=NOW + 3600)), cache=_cache(), now=NOW) is None


def test_kid_inconnu_refuse(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims(), kid="autre"), cache=_cache(), now=NOW) is None


def test_kid_absent_refuse_si_le_jwks_est_ambigu(oidc_on):
    """Deux clés utilisables et aucun `kid` : on ne devine pas."""
    second = dict(JWK, kid="k2")
    token = _bearer(_claims(), kid=None)
    assert oidc.validate_bearer(token, cache=_cache(keys=(JWK, second)), now=NOW) is None


def test_cle_de_chiffrement_ignoree(oidc_on):
    """`use: enc` n'est pas une clé de signature — le JWKS ne fournit alors
    aucune clé utilisable."""
    enc = dict(JWK, use="enc")
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(keys=(enc,)), now=NOW) is None


def test_cle_annoncant_un_autre_alg_ignoree(oidc_on):
    other = dict(JWK, alg="RS512")
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(keys=(other,)), now=NOW) is None


def test_cle_faible_du_jwks_refusee(oidc_on):
    """Un JWKS qui publierait une clé de 1024 bits ne doit pas faire baisser le
    niveau de sécurité, même si la signature « colle »."""
    weak = dict(JWK, n=_int_b64u(N >> 1100))
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(keys=(weak,)), now=NOW) is None


def test_jwks_injoignable_refuse(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(boom=True), now=NOW) is None


def test_jwks_vide_refuse(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(keys=()), now=NOW) is None


@pytest.mark.parametrize("bad", [
    "", "Bearer", "Bearer ", "Basic abc", "Bearer abc", "Bearer a.b",
    "Bearer a.b.c.d", "Bearer $$$.$$$.$$$", "Bearer " + "a" * 9000,
])
def test_jetons_malformes_refuses(oidc_on, bad):
    assert oidc.validate_bearer(bad, cache=_cache(), now=NOW) is None


def test_typ_inattendu_refuse(oidc_on):
    assert oidc.validate_bearer(_bearer(_claims(), typ="JWE"), cache=_cache(), now=NOW) is None


# --- Configuration incomplète / non sûre = refus de TOUT jeton --------------


@pytest.mark.parametrize("missing", ["OCULAR_OIDC_ISSUER", "OCULAR_OIDC_AUDIENCE",
                                     "OCULAR_OIDC_JWKS_URL"])
def test_configuration_incomplete_refuse_tout(oidc_on, monkeypatch, missing):
    monkeypatch.delenv(missing, raising=False)
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(), now=NOW) is None


def test_jwks_en_clair_refuse_sauf_opt_in(oidc_on, monkeypatch):
    """Le JWKS est l'ancre de confiance : en clair, il se substitue. HTTPS exigé
    par défaut, `http://` seulement sur opt-in explicite (IdP interne)."""
    monkeypatch.setenv("OCULAR_OIDC_JWKS_URL", "http://keycloak:8080/certs")
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(), now=NOW) is None
    monkeypatch.setenv("OCULAR_OIDC_ALLOW_INSECURE_JWKS", "1")
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(), now=NOW) is not None


def test_jwks_scheme_exotique_refuse(oidc_on, monkeypatch):
    monkeypatch.setenv("OCULAR_OIDC_JWKS_URL", "file:///etc/passwd")
    monkeypatch.setenv("OCULAR_OIDC_ALLOW_INSECURE_JWKS", "1")
    assert oidc.validate_bearer(_bearer(_claims()), cache=_cache(), now=NOW) is None


# ============================================================================
# 4. Cache JWKS — rotation de clé, et anti-amplification
# ============================================================================


def test_kid_inconnu_declenche_une_seule_relecture_apres_le_delai(oidc_on):
    """Rotation de clé côté IdP : le nouveau `kid` est inconnu du cache, donc une
    relecture est tentée — mais AU PLUS une par `_MIN_REFETCH_S`, sinon des
    jetons à `kid` aléatoire feraient marteler l'IdP par Ocular, sans être
    authentifiés."""
    clock = _Clock()
    cache = _cache(clock=clock)
    assert oidc.validate_bearer(_bearer(_claims()), cache=cache, now=NOW) is not None
    assert cache.calls == [JWKS_URL]

    # Rafale de `kid` inconnus juste après : aucun appel supplémentaire.
    for _ in range(10):
        assert oidc.validate_bearer(_bearer(_claims(), kid="inconnu"), cache=cache, now=NOW) is None
    assert cache.calls == [JWKS_URL]

    # Passé le délai, une (et une seule) relecture est tentée.
    clock.t += oidc._MIN_REFETCH_S + 1
    assert oidc.validate_bearer(_bearer(_claims(), kid="inconnu"), cache=cache, now=NOW) is None
    assert cache.calls == [JWKS_URL, JWKS_URL]


def test_cache_expire_apres_son_ttl(oidc_on):
    clock = _Clock()
    cache = _cache(clock=clock)
    assert oidc.validate_bearer(_bearer(_claims()), cache=cache, now=NOW) is not None
    clock.t += 301
    assert oidc.validate_bearer(_bearer(_claims()), cache=cache, now=NOW) is not None
    assert cache.calls == [JWKS_URL, JWKS_URL]


# ============================================================================
# 5. Projection des claims (identité / groupes)
# ============================================================================


def test_identite_repli_sur_sub(oidc_on, monkeypatch):
    monkeypatch.setenv("OCULAR_OIDC_USERNAME_CLAIM", "absent")
    assert oidc.identity_from_claims(_claims()) == "uuid-1"


def test_identite_none_si_aucun_claim_exploitable(oidc_on):
    assert oidc.identity_from_claims({"preferred_username": "  ", "sub": 42}) is None


def test_groupes_liste_simple(oidc_on):
    assert oidc.groups_from_claims({"groups": [" a ", "admins", "", 7]}) == ["a", "admins"]


def test_groupes_chemin_pointe_keycloak(oidc_on, monkeypatch):
    monkeypatch.setenv("OCULAR_OIDC_GROUPS_CLAIM", "realm_access.roles")
    claims = {"realm_access": {"roles": ["ocular-admins", "default-roles"]}}
    assert oidc.groups_from_claims(claims) == ["ocular-admins", "default-roles"]


def test_groupes_absents_ou_non_listables(oidc_on):
    assert oidc.groups_from_claims({}) == []
    assert oidc.groups_from_claims({"groups": {"a": 1}}) == []
    assert oidc.groups_from_claims({"groups": "a, b"}) == ["a", "b"]


# ============================================================================
# 6. Intégration `web.identity` — et LA garantie de non-régression
# ============================================================================


def _request(headers: dict[str, str]) -> Request:
    raw = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/jobs/x", "headers": raw})


def test_opt_in_off_web_oidc_n_est_jamais_sollicite(monkeypatch):
    """LE test de non-régression : sans `OCULAR_OIDC_ENABLED`, aucun chemin
    d'identité n'appelle `validate_bearer`. Le comportement reste celui d'avant,
    octet pour octet."""
    from web import identity as web_identity

    monkeypatch.delenv("OCULAR_OIDC_ENABLED", raising=False)
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)

    def _boom(*a, **kw):  # pragma: no cover - ne doit jamais être appelé
        raise AssertionError("validate_bearer() appelée alors que l'OIDC est désactivé")

    monkeypatch.setattr(web_identity, "validate_bearer", _boom)

    req = _request({"Authorization": "Bearer " + _jwt(_claims())})
    assert web_identity.resolve_identity(req, bearer_ok=False) == (False, None, "none")
    assert web_identity.resolve_identity(req, bearer_ok=True) == (True, "token", "bearer")
    assert web_identity.resolve_groups(req) == []


def test_resolve_identity_oidc(oidc_on, monkeypatch):
    from web import identity as web_identity

    monkeypatch.setattr(oidc, "_DEFAULT_CACHE", _cache())
    monkeypatch.setattr(oidc, "_validate", _patched_validate(oidc._validate))
    req = _request({"Authorization": _bearer(_claims())})
    assert web_identity.resolve_identity(req, bearer_ok=False) == (True, "alice", "oidc")


def test_resolve_identity_oidc_refuse_un_jeton_falsifie(oidc_on, monkeypatch):
    from web import identity as web_identity

    monkeypatch.setattr(oidc, "_DEFAULT_CACHE", _cache())
    monkeypatch.setattr(oidc, "_validate", _patched_validate(oidc._validate))
    req = _request({"Authorization": _bearer(_claims(), corrupt=True)})
    assert web_identity.resolve_identity(req, bearer_ok=False) == (False, None, "none")


def test_bearer_statique_prime_sur_oidc(oidc_on, monkeypatch):
    """Ordre de préséance : une requête déjà tranchée par le bearer statique
    n'est pas re-tranchée par l'OIDC."""
    from web import identity as web_identity

    monkeypatch.setattr(oidc, "_DEFAULT_CACHE", _cache())
    req = _request({"Authorization": "Bearer s3cret"})
    assert web_identity.resolve_identity(req, bearer_ok=True) == (True, "token", "bearer")


def test_resolve_groups_reunit_forward_auth_et_oidc(oidc_on, monkeypatch):
    from web import identity as web_identity

    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    monkeypatch.setattr(oidc, "_DEFAULT_CACHE", _cache())
    monkeypatch.setattr(oidc, "_validate", _patched_validate(oidc._validate))
    req = _request({
        "Authorization": _bearer(_claims(groups=["depuis-jwt", "commun"])),
        "X-Forwarded-Groups": "depuis-proxy, commun",
    })
    assert web_identity.resolve_groups(req) == ["depuis-proxy", "commun", "depuis-jwt"]


def test_has_admin_group_via_claim_oidc(oidc_on, monkeypatch):
    from web import identity as web_identity

    monkeypatch.setenv("OCULAR_ADMIN_GROUP", "ocular-admins")
    monkeypatch.setattr(oidc, "_DEFAULT_CACHE", _cache())
    monkeypatch.setattr(oidc, "_validate", _patched_validate(oidc._validate))
    req = _request({"Authorization": _bearer(_claims(groups=["ocular-admins"]))})
    assert web_identity.has_admin_group(req) is True

    req2 = _request({"Authorization": _bearer(_claims(groups=["users"]))})
    assert web_identity.has_admin_group(req2) is False


def test_claims_valides_une_seule_fois_par_requete(oidc_on, monkeypatch):
    """`/auth/whoami` appelle `resolve_identity` PUIS `resolve_groups` : sans
    mémoïsation dans le scope, la signature serait vérifiée deux fois."""
    from web import identity as web_identity

    seen: list[int] = []
    real = oidc._validate

    def counting(*a, **kw):
        seen.append(1)
        return real(*a, **kw)

    monkeypatch.setattr(oidc, "_DEFAULT_CACHE", _cache())
    monkeypatch.setattr(oidc, "_validate", _patched_validate(counting))
    req = _request({"Authorization": _bearer(_claims())})
    web_identity.resolve_identity(req, bearer_ok=False)
    web_identity.resolve_groups(req)
    assert seen == [1]


# ============================================================================
# 7. Bout en bout à travers le middleware `web.app._auth`
# ============================================================================


def _live_claims(**over) -> dict:
    """Jeton daté sur l'HORLOGE RÉELLE : ces tests-ci traversent `web.app`, qui
    n'a aucun moyen d'injecter `now` — c'est justement le chemin de production."""
    return _claims(exp=time.time() + 300, **over)


def _app_client(monkeypatch, tmp_path, *, token=None, with_oidc=True, admin_group=None):
    import fakeredis
    from fastapi.testclient import TestClient

    from bus.queue import RedisJobQueue
    from web import oidc as web_oidc
    from web.app import app, get_queue

    for var in ("OCULAR_TOKEN", "OCULAR_TRUST_FORWARD_AUTH", "OCULAR_ADMIN_TOKEN",
                "OCULAR_ADMIN_GROUP", "OCULAR_OIDC_ENABLED"):
        monkeypatch.delenv(var, raising=False)
    if token is not None:
        monkeypatch.setenv("OCULAR_TOKEN", token)
    if admin_group is not None:
        monkeypatch.setenv("OCULAR_ADMIN_GROUP", admin_group)
    if with_oidc:
        monkeypatch.setenv("OCULAR_OIDC_ENABLED", "1")
        monkeypatch.setenv("OCULAR_OIDC_ISSUER", ISS)
        monkeypatch.setenv("OCULAR_OIDC_AUDIENCE", AUD)
        monkeypatch.setenv("OCULAR_OIDC_JWKS_URL", JWKS_URL)
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.setattr(web_oidc, "_DEFAULT_CACHE", _cache())
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(fakeredis.FakeStrictRedis())
    return TestClient(app, raise_server_exceptions=False)


def test_e2e_oidc_seul_autorise_sans_jeton_statique(monkeypatch, tmp_path):
    """Déploiement purement OIDC : aucun `OCULAR_TOKEN` à distribuer, l'IdP fait
    foi. Sans le troisième terme dans la garde fail-closed de `_auth`, ce
    déploiement répondrait 503 sur toutes ses routes."""
    c = _app_client(monkeypatch, tmp_path, token=None)
    r = c.get("/auth/whoami", headers={"Authorization": _bearer(_live_claims())})
    assert r.status_code == 200
    assert r.json() == {"identity": "alice", "method": "oidc", "groups": [], "is_admin": False}


def test_e2e_jeton_falsifie_401(monkeypatch, tmp_path):
    c = _app_client(monkeypatch, tmp_path, token=None)
    r = c.get("/auth/whoami", headers={"Authorization": _bearer(_live_claims(), corrupt=True)})
    assert r.status_code == 401


def test_e2e_jeton_expire_401(monkeypatch, tmp_path):
    c = _app_client(monkeypatch, tmp_path, token=None)
    r = c.get("/auth/whoami", headers={"Authorization": _bearer(_claims(exp=NOW - 10))})
    assert r.status_code == 401


def test_e2e_bearer_statique_coexiste_avec_oidc(monkeypatch, tmp_path):
    c = _app_client(monkeypatch, tmp_path, token="s3cret")
    assert c.get("/auth/whoami", headers={"Authorization": "Bearer s3cret"}).json()["method"] \
        == "bearer"
    assert c.get("/auth/whoami",
                 headers={"Authorization": _bearer(_live_claims())}).json()["method"] == "oidc"
    assert c.get("/auth/whoami", headers={"Authorization": "Bearer autre"}).status_code == 401


def test_e2e_opt_in_off_un_jwt_valide_ne_donne_aucun_acces(monkeypatch, tmp_path):
    """Symétrique du test anti-spoofing du forward-auth : sans l'opt-in, un jeton
    par ailleurs PARFAITEMENT valide n'ouvre rien."""
    c = _app_client(monkeypatch, tmp_path, token="s3cret", with_oidc=False)
    r = c.get("/auth/whoami", headers={"Authorization": _bearer(_live_claims())})
    assert r.status_code == 401


def test_e2e_admin_via_claim_de_groupes(monkeypatch, tmp_path):
    """`DELETE /saved` accordé par le claim de groupes du JWT — parité avec le
    forward-auth, et le 503 « aucun mécanisme admin configuré » ne doit pas
    tomber alors que le mécanisme groupe EST armé par l'OIDC."""
    c = _app_client(monkeypatch, tmp_path, token=None, admin_group="ocular-admins")
    admin = {"Authorization": _bearer(_live_claims(groups=["ocular-admins"]))}
    simple = {"Authorization": _bearer(_live_claims(groups=["users"]))}
    assert c.get("/auth/whoami", headers=admin).json()["is_admin"] is True
    assert c.get("/auth/whoami", headers=simple).json()["is_admin"] is False
    assert c.delete("/saved", headers=simple).status_code == 403
    assert c.delete("/saved", headers=admin).status_code == 200
