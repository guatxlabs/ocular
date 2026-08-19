# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validation OIDC JWT **in-app** — Keycloak/Authentik SANS reverse-proxy.

Le forward-auth (`web/identity.py`) couvre le cas proxifié, de loin le plus
courant : un oauth2-proxy/Authelia authentifie et injecte l'identité en en-tête.
Ce module couvre l'autre cas — Ocular exposé directement, le client présentant
lui-même le jeton d'accès de l'IdP en `Authorization: Bearer <jwt>`.

DIFFÉRENCE DE NATURE AVEC LE FORWARD-AUTH. Là, la sécurité repose sur un tiers
(« le proxy strippe bien la copie cliente de l'en-tête ») ; ici, sur une
vérification faite par Ocular lui-même : signature RSA contre la clé publique
publiée par l'IdP (JWKS), puis `iss` / `aud` / `exp`. Un client peut forger
l'en-tête qu'il veut, il ne peut pas forger la signature.

MÊME MODÈLE D'OPT-IN, POURTANT. `OCULAR_OIDC_ENABLED` est OFF par défaut et,
tant qu'il l'est, ce module n'est jamais sollicité : aucun jeton n'est lu, aucun
appel sortant n'est émis, `resolve_identity` se comporte octet pour octet comme
avant. C'est vérifié par un test qui fait EXPLOSER `validate_bearer` si elle est
appelée alors que l'opt-in est éteint.

TOUT REFUS EST UN REFUS. Chaque anomalie — JWKS injoignable, `kid` inconnu,
signature fausse, `iss`/`aud` non conformes, `exp` dépassé, `alg` hors liste —
rend `None`, jamais « on laisse passer dans le doute ». `_Refused` est interne
et n'est JAMAIS propagée à l'appelant : `resolve_identity` doit rester totale.

## Pourquoi aucune bibliothèque JWT n'est ajoutée

Ce dépôt n'embarque ni PyJWT ni `cryptography` (cf. `pyproject.toml`). Les faire
entrer coûterait ~5 Mo de roue native (OpenSSL statique) dans les images `web` et
`broker`, pour une fonction **désactivée par défaut**. Et ce n'est pas là qu'est
le risque : les CVE des bibliothèques JWT sont presque toutes des fautes de
POLITIQUE — `alg: none` accepté, HS256 vérifié avec la clé PUBLIQUE RSA
(confusion d'algorithme), `aud` non contrôlé, `kid` traversant le système de
fichiers. Cette politique reste à écrire quoi qu'il arrive, et elle est ici
explicite (§ ci-dessous).

Ce qui est fait à la main se réduit donc à la vérification RSASSA-PKCS1-v1_5,
soit une exponentiation modulaire et une comparaison d'octets. Deux propriétés
la rendent sûre :

1. **Aucun secret n'intervient** — vérifier n'utilise que la clé PUBLIQUE. Il
   n'y a pas de canal auxiliaire à protéger, contrairement à une signature.
2. **Aucune ANALYSE du bourrage.** La faute historique (forgeries à la
   Bleichenbacher sur `e=3`) vient des implémentations qui *cherchent* le
   condensat dans le bloc déchiffré et tolèrent des octets après lui. Ici le
   bloc attendu est RECONSTRUIT en entier puis comparé avec
   `hmac.compare_digest` : il n'y a rien à analyser, donc rien à tolérer.

La primitive est en outre confrontée, dans les tests, à une signature de
RÉFÉRENCE produite par `cryptography` — la conformité n'est pas auto-attestée.

## Politique de validation (l'endroit où le risque vit réellement)

- `alg` ∈ {RS256, RS384, RS512}, **liste blanche**. `none`, `HS*` (symétrique) et
  `PS*`/`ES*` sont refusés. La confusion d'algorithme est structurellement
  impossible : la clé vient du JWKS avec `kty: RSA` et le seul chemin de code
  existant est une vérification RSA — le `alg` du jeton ne CHOISIT jamais la
  famille de clé, il ne choisit que la fonction de hachage.
- La clé est cherchée par `kid` **dans le JWKS**, jamais quelque part d'après une
  valeur du jeton. Sans `kid`, une seule clé utilisable est tolérée ; deux ⇒ refus
  (on ne devine pas).
- Module RSA < 2048 bits ⇒ refus.
- `iss` ET `aud` sont EXIGÉS et comparés exactement. Sans `aud`, un jeton émis
  par le même IdP pour une autre application ouvrirait Ocular.
- `exp` est EXIGÉ (un jeton sans expiration est un jeton éternel) ; `nbf` est
  vérifié s'il est présent ; tolérance d'horloge `OCULAR_OIDC_CLOCK_SKEW`.
- La charge utile n'est désérialisée **qu'après** que la signature a été
  vérifiée : aucun JSON contrôlé par l'attaquant n'est analysé avant.

## Limites assumées

- **L'appel JWKS est synchrone** sur un chemin `async` (`web.app._auth`). Il
  n'arrive qu'au premier jeton puis une fois par `OCULAR_OIDC_JWKS_TTL` (300 s
  par défaut), et son échéance est courte (`OCULAR_OIDC_HTTP_TIMEOUT`, 5 s) —
  mais un IdP lent immobilise le worker pendant ce délai. Le rendre non bloquant
  exigerait de rendre `resolve_identity` asynchrone, ce qui remonterait jusqu'aux
  chemins WebSocket : hors périmètre de ce point.
- **PS256/ES256 non pris en charge** (bourrage PSS / courbes elliptiques). Ni
  Keycloak ni Authentik ne les émettent par défaut ; un refus explicite vaut
  mieux qu'un support approximatif.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import threading
import time
import urllib.request
from urllib.parse import urlsplit

from engine.limits import warn_once
from ocular_logging import get_logger
from ocular_settings import (
    oidc_allow_insecure_jwks,
    oidc_audience,
    oidc_clock_skew,
    oidc_enabled,
    oidc_groups_claim,
    oidc_http_timeout,
    oidc_issuer,
    oidc_jwks_ttl,
    oidc_jwks_url,
    oidc_username_claim,
)

log = get_logger("web.oidc")

# Préfixes DER `DigestInfo` de EMSA-PKCS1-v1_5 (RFC 8017 §9.2, note 1). Ce sont
# des constantes de la spec, pas des valeurs calculées : les recopier est le seul
# choix possible sans analyseur ASN.1. Elles sont VÉRIFIÉES par le test qui
# confronte la primitive à une signature produite par `cryptography`.
_DIGEST_INFO = {
    "RS256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "RS384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "RS512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_HASH = {"RS256": hashlib.sha256, "RS384": hashlib.sha384, "RS512": hashlib.sha512}

# `typ` de l'en-tête JOSE. Keycloak/Authentik émettent `JWT`, la RFC 9068
# (jetons d'accès JWT) impose `at+jwt`. Absent est toléré : `typ` est facultatif
# dans la spec JOSE, et ce ne sont ni `iss`, ni `aud`, ni la signature.
_ALLOWED_TYP = {"jwt", "at+jwt", "application/at+jwt"}

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_MIN_MODULUS_BITS = 2048
# Un jeton Keycloak chargé en rôles atteint 2-4 Kio ; au-delà de 8 Kio, la plupart
# des frontaux refusent déjà l'en-tête. Borne d'abord le travail de décodage.
_MAX_TOKEN_BYTES = 8192
_MAX_JWKS_BYTES = 256 * 1024
# Intervalle minimal entre deux récupérations JWKS. Sans lui, un `kid` inconnu
# force un appel sortant : envoyer des jetons à `kid` aléatoire suffirait à faire
# marteler l'IdP par Ocular (amplification), sur le chemin d'authentification
# donc sans être authentifié. 30 s : une rotation de clé reste prise en compte en
# moins d'une minute, très en deçà du préavis d'un IdP.
_MIN_REFETCH_S = 30

# Motifs de refus qui signifient « cette requête ne porte tout simplement pas de
# JWT » — cas NORMAL dès qu'un autre mécanisme d'auth coexiste (bearer statique,
# forward-auth). Les journaliser produirait une ligne WARNING par requête.
_QUIET = {"pas-de-bearer", "bearer-vide", "format-jwt-invalide"}


class _Refused(Exception):
    """Refus interne. Ne franchit jamais `validate_bearer` : le motif est
    journalisé, l'appelant ne voit que `None` (aucune réflexion vers le client —
    dire *pourquoi* un jeton est refusé est un oracle offert à l'attaquant)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- Décodage base64url / JSON, bornés -------------------------------------


def _check_b64url(seg: str) -> None:
    """Rejette tout ce qui n'est pas du base64url canonique. `base64.urlsafe_
    b64decode` est PERMISSIF par défaut (il ignore les caractères hors alphabet) :
    contrôler l'alphabet ici évite d'avoir à raisonner sur ce que cette permissivité
    autoriserait ailleurs."""
    if not _B64URL_RE.match(seg):
        raise _Refused("segment-b64url-invalide")
    # Un reste de 1 caractère est impossible en base64 (4n+1 n'encode rien).
    if len(seg) % 4 == 1:
        raise _Refused("segment-b64url-invalide")


def _b64url_decode(seg: str) -> bytes:
    _check_b64url(seg)
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except (binascii.Error, ValueError) as exc:
        raise _Refused("segment-b64url-invalide") from exc


def _json_object(seg: str, what: str) -> dict:
    try:
        obj = json.loads(_b64url_decode(seg))
    except (ValueError, UnicodeDecodeError) as exc:
        raise _Refused(f"{what}-json-invalide") from exc
    if not isinstance(obj, dict):
        raise _Refused(f"{what}-non-objet")
    return obj


# --- Récupération du JWKS ---------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Ne suit AUCUNE redirection — même raison que dans `web/llm.py`, en plus
    grave : le JWKS est l'ANCRE DE CONFIANCE. Suivre un 3xx laisserait l'hôte
    configuré déplacer silencieusement l'endroit d'où viennent les clés qui
    autorisent les analystes. Un 3xx lève `HTTPError` → refus."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _fetch_jwks_http(url: str, timeout: float) -> list[dict]:
    """Récupère le document JWKS. Lecture BORNÉE (`_MAX_JWKS_BYTES`) : l'échéance
    borne le TEMPS, pas les OCTETS — un endpoint compromis pourrait sinon streamer
    un corps illimité dans le conteneur `web` (OOM)."""
    opener = urllib.request.build_opener(_NoRedirect())
    req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read(_MAX_JWKS_BYTES + 1)
    if len(raw) > _MAX_JWKS_BYTES:
        raise _Refused("jwks-trop-volumineux")
    doc = json.loads(raw.decode("utf-8", "replace"))
    keys = doc.get("keys") if isinstance(doc, dict) else None
    if not isinstance(keys, list):
        raise _Refused("jwks-malforme")
    return [k for k in keys if isinstance(k, dict)]


def _usable(jwk: dict, alg: str) -> bool:
    """Une clé n'est retenue que si elle est explicitement compatible : RSA, à
    usage de signature, et — si elle annonce un `alg` — le MÊME que celui du
    jeton. Une clé de chiffrement (`use: enc`) n'a rien à faire ici."""
    if jwk.get("kty") != "RSA":
        return False
    use = jwk.get("use")
    if use is not None and use != "sig":
        return False
    key_alg = jwk.get("alg")
    if key_alg is not None and key_alg != alg:
        return False
    return isinstance(jwk.get("n"), str) and isinstance(jwk.get("e"), str)


def _pick(keys: list[dict], kid: str | None, alg: str) -> dict | None:
    usable = [k for k in keys if _usable(k, alg)]
    if kid:
        for k in usable:
            if k.get("kid") == kid:
                return k
        return None
    # Sans `kid`, on n'accepte que l'absence d'ambiguïté. Essayer toutes les clés
    # serait tout aussi sûr (elles viennent toutes du JWKS de confiance) mais
    # rendrait le refus impossible à diagnostiquer.
    return usable[0] if len(usable) == 1 else None


class JwksCache:
    """Cache JWKS — **injectable** : `fetch` remplace l'appel réseau (les tests
    n'ouvrent jamais de socket) et `clock` remplace l'horloge.

    Sérialisé par un verrou : sous rafale, plusieurs requêtes concurrentes ne
    déclenchent qu'UNE récupération (la première), les autres lisent le cache
    qu'elle vient de remplir plutôt que de partir en troupeau vers l'IdP.
    """

    def __init__(self, *, fetch=None, ttl: int | None = None,
                 min_refetch: int = _MIN_REFETCH_S, clock=time.monotonic) -> None:
        self._fetch = fetch
        self._ttl = ttl
        self._min_refetch = min_refetch
        self._clock = clock
        self._lock = threading.Lock()
        self._url: str | None = None
        self._keys: list[dict] = []
        self._loaded_at: float | None = None
        self._last_attempt: float | None = None

    def _load(self, url: str) -> None:
        fetch = self._fetch
        self._last_attempt = self._clock()
        try:
            keys = fetch(url) if fetch else _fetch_jwks_http(url, oidc_http_timeout())
        except _Refused:
            raise
        except Exception as exc:  # noqa: BLE001 - toute panne réseau/parsing = refus
            raise _Refused("jwks-injoignable") from exc
        if not isinstance(keys, list):
            raise _Refused("jwks-malforme")
        self._url, self._keys, self._loaded_at = url, keys, self._clock()

    def select(self, url: str, kid: str | None, alg: str) -> dict:
        """Rend la clé à utiliser, ou lève `_Refused`. Recharge si le cache est
        périmé, ou s'il ne contient pas le `kid` demandé et que la dernière
        tentative est assez ancienne (rotation de clé côté IdP)."""
        ttl = self._ttl if self._ttl is not None else oidc_jwks_ttl()
        with self._lock:
            now = self._clock()
            fresh = (
                self._url == url
                and self._loaded_at is not None
                and (now - self._loaded_at) < ttl
            )
            if not fresh:
                self._load(url)
            jwk = _pick(self._keys, kid, alg)
            if jwk is None and self._last_attempt is not None \
                    and (self._clock() - self._last_attempt) >= self._min_refetch:
                self._load(url)
                jwk = _pick(self._keys, kid, alg)
            if jwk is None:
                raise _Refused("kid-inconnu")
            return jwk


_DEFAULT_CACHE = JwksCache()


# --- Vérification RSASSA-PKCS1-v1_5 ----------------------------------------


def rsa_pkcs1v15_verify(n: int, e: int, alg: str, signing_input: bytes,
                        signature: bytes) -> bool:
    """`True` si `signature` est une signature RSASSA-PKCS1-v1_5 valide de
    `signing_input` sous la clé publique `(n, e)`.

    Le bloc attendu est reconstruit ENTIÈREMENT — `0x00 0x01 || 0xFF… || 0x00 ||
    DigestInfo(H(m))` — puis comparé d'un bloc. Aucun octet n'est analysé, donc
    aucun octet ne peut être toléré : c'est ce qui ferme les forgeries à la
    Bleichenbacher, qui exploitent les vérificateurs cherchant le condensat *dans*
    le bloc au lieu de l'exiger à sa place exacte.

    `compare_digest` n'est pas requis par le modèle de menace (tout est public)
    mais ne coûte rien et évite d'avoir à le justifier à chaque relecture."""
    if n.bit_length() < _MIN_MODULUS_BITS:
        raise _Refused("modulus-trop-court")
    if e < 3 or e % 2 == 0:
        raise _Refused("exposant-invalide")
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        # Signature non canonique : `s` et `s + n` donneraient le même bloc.
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest_info = _DIGEST_INFO[alg] + _HASH[alg](signing_input).digest()
    pad_len = k - 3 - len(digest_info)
    if pad_len < 8:  # RFC 8017 : au moins 8 octets de bourrage
        raise _Refused("modulus-trop-court")
    expected = b"\x00\x01" + b"\xff" * pad_len + b"\x00" + digest_info
    return hmac.compare_digest(em, expected)


def _verify_with_jwk(jwk: dict, alg: str, signing_input: bytes, signature: bytes) -> bool:
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return rsa_pkcs1v15_verify(n, e, alg, signing_input, signature)


# --- Validation du jeton ----------------------------------------------------


def _bearer_token(authorization: str) -> str:
    if authorization[:7].lower() != "bearer ":
        raise _Refused("pas-de-bearer")
    token = authorization[7:].strip()
    if not token:
        raise _Refused("bearer-vide")
    if len(token.encode("utf-8", "ignore")) > _MAX_TOKEN_BYTES:
        raise _Refused("jeton-trop-long")
    return token


def _jwks_endpoint() -> str:
    """URL JWKS validée. HTTPS EXIGÉ sauf opt-in explicite : qui répond à la
    place du JWKS choisit les clés publiques, donc signe les jetons qu'il veut,
    donc s'authentifie en tant que n'importe qui — admin compris."""
    url = oidc_jwks_url()
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        warn_once("OCULAR_OIDC_JWKS_URL n'est ni http ni https — tout jeton est refusé")
        raise _Refused("jwks-url-invalide")
    if scheme == "http" and not oidc_allow_insecure_jwks():
        warn_once(
            "OCULAR_OIDC_JWKS_URL est en clair (http) — poser "
            "OCULAR_OIDC_ALLOW_INSECURE_JWKS=1 pour l'assumer ; tout jeton est refusé"
        )
        raise _Refused("jwks-non-https")
    return url


def _numeric_claim(claims: dict, name: str) -> float | None:
    value = claims.get(name)
    if value is None:
        return None
    # `isinstance(True, int)` vaut True en Python : un `exp: true` passerait pour
    # un horodatage de 1 (donc expiré) — ici c'est un refus, pas une coïncidence.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _Refused(f"{name}-non-numerique")
    return float(value)


def _validate(authorization: str, cache: JwksCache, now: float | None) -> dict:
    # Le jeton est reconnu AVANT de regarder la configuration : une requête qui
    # ne porte pas de JWT (bearer statique, forward-auth, rien du tout) doit
    # coûter un `startswith` et sortir en silence, pas déclencher les WARNINGs
    # de configuration à chaque appel.
    parts = _bearer_token(authorization).split(".")
    if len(parts) != 3:
        raise _Refused("format-jwt-invalide")
    h_b64, p_b64, s_b64 = parts
    for seg in parts:
        _check_b64url(seg)

    issuer, audience = oidc_issuer(), oidc_audience()
    if not issuer or not audience or not oidc_jwks_url():
        # Fail-closed : une configuration OIDC incomplète refuse TOUT jeton. Dit
        # une fois par processus (`warn_once`) — sinon une ligne par requête.
        warn_once(
            "OIDC activé mais incomplet — OCULAR_OIDC_ISSUER / _AUDIENCE / _JWKS_URL "
            "sont tous requis ; tout jeton est refusé"
        )
        raise _Refused("configuration-incomplete")
    endpoint = _jwks_endpoint()

    header = _json_object(h_b64, "entete")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in _DIGEST_INFO:
        # Ferme `alg: none` et `alg: HS256` (qui, avec un vérificateur naïf,
        # ferait signer par la clé PUBLIQUE que l'attaquant lit dans le JWKS).
        raise _Refused("alg-non-autorise")
    typ = header.get("typ")
    if typ is not None and (not isinstance(typ, str) or typ.lower() not in _ALLOWED_TYP):
        raise _Refused("typ-non-autorise")
    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise _Refused("kid-non-textuel")

    jwk = cache.select(endpoint, kid, alg)
    if not _verify_with_jwk(jwk, alg, f"{h_b64}.{p_b64}".encode("ascii"), _b64url_decode(s_b64)):
        raise _Refused("signature-invalide")

    # À PARTIR D'ICI SEULEMENT le contenu est digne d'être analysé : la charge
    # utile n'est désérialisée qu'une fois la signature établie.
    claims = _json_object(p_b64, "charge")
    if claims.get("iss") != issuer:
        raise _Refused("iss-non-conforme")
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if audience not in [a for a in auds if isinstance(a, str)]:
        raise _Refused("aud-non-conforme")

    skew = oidc_clock_skew()
    when = time.time() if now is None else now
    exp = _numeric_claim(claims, "exp")
    if exp is None:
        # Un jeton sans `exp` ne se révoque jamais : refus, pas tolérance.
        raise _Refused("exp-absent")
    if when > exp + skew:
        raise _Refused("jeton-expire")
    nbf = _numeric_claim(claims, "nbf")
    if nbf is not None and when < nbf - skew:
        raise _Refused("jeton-pas-encore-valide")
    return claims


def validate_bearer(authorization: str, *, cache: JwksCache | None = None,
                    now: float | None = None) -> dict | None:
    """Claims du jeton si — et seulement si — il est intégralement valide.
    `None` dans TOUS les autres cas, y compris l'absence de jeton.

    Ne lève jamais : `resolve_identity` doit rester totale sur un chemin
    d'authentification. Le motif du refus est journalisé (jamais le jeton), sauf
    les motifs `_QUIET` qui signifient seulement « pas de JWT ici »."""
    if not oidc_enabled():
        return None
    try:
        return _validate(authorization or "", cache or _DEFAULT_CACHE, now)
    except _Refused as exc:
        if exc.reason not in _QUIET:
            log.warning("oidc rejected reason=%s", exc.reason)
        return None


# --- Projection des claims vers le modèle d'identité d'Ocular ---------------


def identity_from_claims(claims: dict) -> str | None:
    """Identité affichable. `OCULAR_OIDC_USERNAME_CLAIM` d'abord, `sub` en repli
    (seul identifiant garanti par la spec, mais illisible dans un audit). `None`
    si aucune des deux n'est une chaîne non vide — et sans identité, pas
    d'autorisation."""
    for name in (oidc_username_claim(), "sub"):
        value = claims.get(name) if name else None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def groups_from_claims(claims: dict) -> list[str]:
    """Groupes IdP, alimentant `OCULAR_ADMIN_GROUP` exactement comme l'en-tête
    groupes du forward-auth. Le chemin peut être POINTÉ (`realm_access.roles`)
    parce que les rôles Keycloak sont imbriqués. Une valeur qui n'est ni une
    liste ni une chaîne rend `[]` : pas de groupe deviné."""
    node: object = claims
    for part in oidc_groups_claim().split("."):
        if not isinstance(node, dict):
            return []
        node = node.get(part)
    if isinstance(node, str):
        node = node.split(",")
    if not isinstance(node, list):
        return []
    return [g.strip() for g in node if isinstance(g, str) and g.strip()]
