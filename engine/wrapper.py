# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mécanique commune aux runners `runner_analysis/render.py` (profil analysis,
Chromium/Playwright) et `runner_recon/capture.py` (profil capture, Camoufox) :
hash de référence des blobs, listeners réseau/console, construction de
l'`OcularResult`, émission du wrapper JSON sur stdout.

Chaque runner reste responsable de sa propre logique métier (moteur navigateur,
détection Turnstile, calcul des `static_findings`/verdict) — ce module ne
factorise QUE la mécanique répétée entre les deux profils, pour qu'il n'y ait
qu'une seule implémentation à maintenir (cf. task-2-brief.md, exigence DRY)."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel

from engine.result import (
    POST_DATA_MAX_CHARS,
    Artifacts,
    ConsoleEntry,
    DomInfo,
    DynamicStep,
    NetworkEntry,
    OcularResult,
    Screenshot,
    StealthInfo,
    TruncatableEntry,
    Truncation,
    residual_paths,
    shed_targets,
)
from engine.limits import artifact_cap, env_cap as _env_cap_impl, source_budget
from engine.static import HtmlScan
from engine.triage import compute_triage
from ocular_logging import get_logger

_log = get_logger("wrapper")
_DEFAULT_MAX_POST_DATA_BYTES = 32 * 1024        # 32 KiB — même échelle que l'URL
                                                # (un corps de formulaire porte la
                                                # même preuve qu'une query string)
_DEFAULT_MAX_NETWORK_ENTRIES = 5000
_DEFAULT_MAX_CONSOLE_ENTRIES = 5000
# Plafonds par ENTRÉE. La cardinalité seule ne borne rien : une page hostile n'a
# pas besoin d'émettre beaucoup d'entrées, il lui suffit d'en émettre UNE énorme
# (un `console.log` de 20 Mio suffisait à produire un résultat de 20,0 Mio qui
# s'annonçait complet). Chaque valeur est un budget MÉMOIRE, donc en OCTETS UTF-8.
#
# Valeurs CALIBRÉES SUR UNE MESURE de contenu réel, pas sur l'intuition « 4 Kio
# dépassent déjà la limite pratique des navigateurs » — qui était fausse et
# coupait de la preuve. Distribution relevée sur 34 335 URL réellement émises par
# les 1 437 pages réelles du corpus de calibration (attributs src/href/action/
# data/srcset/poster) :
#     p50 = 39 o · p95 = 89 o · p99 = 110 o · p99,9 = 126 o · p99,99 = 9 639 o
#     max = 12 703 o — toute la queue est faite d'URI `data:` (images inline,
#     que Playwright rapporte ENTIÈRES dans `request.url`)
# À 4 096 o, 8 de ces 34 335 URL réelles étaient coupées ; à 16 384 o, zéro.
#
# CONTRE-MESURE, sur un corpus PLUS LARGE de la même machine (24 009 fichiers
# HTML réels, 23 644 pages porteuses d'au moins une URL, 1 531 962 URL, mêmes
# attributs) : p50 = 45 o · p95 = 89 o · p99 = 113 o · p99,9 = 139 o ·
# p99,99 = 210 o · max = 242 002 o. Le corps de la distribution concorde ; la
# QUEUE, non — à 16 384 o, 110 de ces 1 531 962 URL sont coupées, et 99 le sont
# encore à 32 768 o (0,0065 %). « Zéro coupée » n'est donc pas une propriété du
# plafond, c'est une propriété du corpus qui l'a mesuré : aucun plafond par
# entrée ne rend la queue vide, parce que la queue est faite d'URI `data:` dont
# la taille est celle de l'image inline. C'est ce qui justifie le BUDGET CUMULÉ
# ci-dessous plutôt qu'un plafond par entrée toujours plus haut.
#
# Console : la taille du texte émis à l'exécution n'est pas bornée par la taille
# du code source, donc mesurer les appels `console.*` du corpus (n=576, max
# 5 782 o) ne donne qu'une BORNE BASSE — un `console.log(JSON.stringify(obj))`
# fait 30 o de source et des dizaines de Kio de sortie. Les observations réelles
# qui dimensionnent ce plafond sont donc des sorties d'exécution : trace de pile
# SPA webpack ~9,6 Kio, dump JSON d'API ~17,4 Kio. 32 768 o = ~1,9× la plus
# grande. C'est une extrapolation à partir de 2 points, et elle est dite comme
# telle plutôt que présentée comme une distribution.
_DEFAULT_MAX_URL_BYTES = 32 * 1024              # 32 KiB — cf. distribution ci-dessus
# En-têtes : AUCUN producteur ne remplit `network[].headers` aujourd'hui
# (`_on_request` ne les collecte pas), donc aucune distribution réelle n'est
# mesurable. Le plafond reste où il était : on ne déplace pas un chiffre qu'on
# ne peut pas mesurer.
_DEFAULT_MAX_HEADERS_BYTES = 8 * 1024           # 8 KiB, tout le dict
_DEFAULT_MAX_CONSOLE_TEXT_BYTES = 32 * 1024     # 32 KiB — cf. ci-dessus
_DEFAULT_MAX_TITLE_BYTES = 32 * 1024            # 32 KiB — `final_url` suit la
                                                # distribution des URL ci-dessus
_DEFAULT_MAX_FINDINGS = 5000
# Budget CUMULÉ du tampon de session — la borne qui manquait.
#
# Les plafonds par entrée bornent CHAQUE entrée, jamais leur SOMME : le produit
# « cardinalité × taille par entrée » est ce que la page retient dans le
# conteneur de session, pour TOUTE la durée de la session interactive (le
# délestage du résultat, lui, n'a lieu qu'au `/capture`). Mesuré par le
# haut-de-marque NOYAU (`resource.getrusage(...).ru_maxrss`), tampons remplis via
# les vrais listeners de `NetworkCapture.attach`, 5 000 requêtes + 5 000 messages
# console au plafond, trois exécutions par ligne :
#   - plafonds par entrée à 4 096 / 8 192 / 8 192 o. : 97,7 Mio retenus,
#     ru_maxrss 31 -> 153 Mio (153/153/153) ;
#   - plafonds par entrée à 32 768 o. (les actuels), SANS budget cumulé :
#     468,8 Mio retenus, ru_maxrss 31 -> 503-505 Mio ;
#   - mêmes plafonds AVEC le budget cumulé ci-dessous : 63,9 Mio retenus,
#     ru_maxrss 31 -> 96-97 Mio.
# Relever les plafonds par entrée pour ne plus couper de contenu légitime a donc
# multiplié par 4,8 la mémoire que la page dicte, dans un conteneur à
# `--memory 2g` PARTAGÉ avec Camoufox. Ce coût-là n'avait pas été mesuré.
#
# Le budget cumulé borne la SOMME sans rendre son plafond à la première entrée
# venue : au dépassement, ce sont des entrées ENTIÈRES qui sortent (côté le moins
# probant selon `keep`), comptées comme tout le reste. Valeur retenue : 32 Mio
# PAR TAMPON (réseau et console en ont chacun un), soit un texte retenu borné par
# 64 Mio.
#
# Calibrage sur le SOUS-ENSEMBLE REQUÊTE du corpus réel — `src`/`srcset`/`poster`
# /`data`, `href` d'un `<link>`, `action` d'un `<form>`. Un `<a href>` est une
# NAVIGATION, pas une requête : le compter surestimerait le tampon (une page de
# documentation à 20 832 liens n'émet pas 20 832 requêtes). 266 142 URL de
# requête sur 23 137 pages réelles :
#     par page : p50 = 180 o · p95 = 537 o · p99 = 1 340 o · p99,9 = 1 630 o
#     max = 6 205 374 o (87 requêtes, dont des URI `data:` de 242 002 o)
#     nombre de requêtes par page : p50 = 11 · p99,9 = 50 · max = 87
# 32 Mio = 5,4× la page réelle la plus lourde du corpus. Ce corpus ne mesure PAS
# le texte console (il n'est pas lisible dans le HTML source) : pour la console,
# ce budget est une borne d'exploitation, pas une calibration — dit comme tel.
_DEFAULT_MAX_CAPTURE_BUFFER_BYTES = 32 * 1024 * 1024
# Budget du résultat SÉRIALISÉ. Les plafonds par entrée ne suffisent pas à le
# garantir : `json.dumps` échappe un octet de contrôle en `\u00XX`, soit ×6 — une
# page qui remplit 5000 entrées d'octets nuls au plafond par entrée en vigueur
# (32 768 o.) produit 937,5 Mio de JSON à partir de 156,2 Mio de texte.
# La garantie est donc MESURÉE (`_shed_to_json_cap`), pas arithmétique.
# Dimensionné pour que `wrapper_payload` reste sous le plafond de lecture de
# `/capture` (128 Mio) : 32 Mio de résultat + 2 artefacts au défaut de 32 Mio
# encodés en base64 (2 × 44 739 244 o. = 85,3 Mio) = 123 032 920 o. = 117,3 Mio.
# Cf. docs/DEPLOY-SECURITY.md §2.10.
_DEFAULT_MAX_RESULT_JSON_BYTES = 32 * 1024 * 1024
# Bornes hautes : une configuration ne doit pas pouvoir RETIRER un plafond (cf.
# §2.10). Les relever augmente proportionnellement l'empreinte mémoire du runner.
_HARD_MAX_ENTRIES = 20000
_HARD_MAX_TEXT_BYTES = 64 * 1024
# Borne haute du budget cumulé : 128 Mio par tampon, soit 256 Mio de texte retenu
# au maximum autorisé — sous les 468,8 Mio mesurés ci-dessus, qui étaient
# atteignables SANS aucune configuration.
_HARD_MAX_CAPTURE_BUFFER_BYTES = 128 * 1024 * 1024
_HARD_MAX_RESULT_JSON_BYTES = 128 * 1024 * 1024
# Tours de délestage. Chaque tour vise directement le ratio mesuré, donc converge
# en 1-2 tours ; la borne existe pour qu'un cas pathologique termine, pas pour
# être atteinte.
_SHED_MAX_ROUNDS = 8


def _max_artifact_bytes() -> int:
    """Cap de taille d'UN artefact (DOM ou screenshot) stocké dans le wrapper.
    Anti-OOM : une page HOSTILE peut gonfler son DOM (`body.innerHTML =
    'x'.repeat(5e8)`) et produire un blob de centaines de Mo que le broker
    (mem_limit 1g) lirait en entier depuis stdout du runner. `0` = illimité.
    Réglable via `OCULAR_MAX_ARTIFACT_BYTES`.

    Résolu par `engine.limits`, seul propriétaire de la paire `/capture` : les
    blobs occupent une part du plafond de LECTURE, et cette part était lue ici
    sans jamais être confrontée à ce plafond. Une configuration où les blobs
    seuls dépassent la lecture est corrigée ICI AUSSI, pas seulement sur le
    budget du résultat."""
    return artifact_cap()


def _env_cap(name: str, default: int, hard_max: int) -> int:
    """Plafond entier de configuration. Délègue à `engine.limits.env_cap`, seul
    propriétaire de la lecture d'un plafond : c'est là que vivent le plancher, la
    borne haute, et la mémoïsation du WARNING (sans quoi le volume de journal est
    dicté par le trafic que la page choisit d'émettre — mesuré : 2 000 requêtes
    de page produisaient 4 000 lignes identiques)."""
    return _env_cap_impl(name, default, hard_max)


def _clip_utf8(text: Any, cap: int) -> tuple[Any, bool]:
    """Coupe `text` à `cap` OCTETS UTF-8 sur une frontière de point de code ;
    renvoie `(valeur, a_été_coupé)`. Les plafonds de ce module sont des budgets
    MÉMOIRE : les appliquer en caractères (`text[:cap]`) laissait passer 2 à 4×
    le budget annoncé selon l'encodage, multiplié par le nombre d'entrées.
    Non-`str` rendu tel quel. `errors=replace`/`ignore` : une page hostile peut
    produire des demi-paires de substitution, jamais une exception ici."""
    if not isinstance(text, str):
        return text, False
    if len(text) <= cap and text.isascii():
        # Chemin rapide SAIN. Il disait auparavant « un caractère vaut au moins
        # un octet : sous le cap en caractères, on est forcément sous le cap en
        # octets » — la prémisse est vraie, la conclusion est l'inverse. Un
        # caractère valant de 1 à 4 octets, `len(text) <= cap` ne borne les
        # octets qu'à `4 * cap`. Mesuré sur 2067ee7, aux plafonds PUBLIÉS de
        # l'époque : 8 000 caractères « é » (16 000 octets) étaient conservés
        # ENTIERS pour un plafond annoncé à 8 192 octets — ×2,0 — et rendus avec
        # `coupé = False`, donc sans même être comptés dans `text_truncated`.
        # ×4,0 avec des points de code sur 4 octets. `str.isascii()` est un test
        # de drapeau O(1) en CPython : la garde redevient exacte sans coûter.
        return text, False
    raw = text.encode("utf-8", "replace")
    if len(raw) <= cap:
        return text, False
    return raw[:cap].decode("utf-8", "ignore"), True


def _max_post_data_bytes() -> int:
    """Taille max CONSERVÉE du corps d'une requête capturée, en OCTETS UTF-8.
    `OCULAR_MAX_POST_DATA_BYTES`, défaut `_DEFAULT_MAX_POST_DATA_BYTES` (32 768
    octets), borné par `POST_DATA_MAX_CHARS` (65 536, le plafond du modèle — un
    plafond en octets borne aussi les caractères, donc le modèle ne peut pas être
    mis en défaut). Au dépassement le corps est TRONQUÉ, l'entrée marquée
    `post_data_truncated` et comptée dans `OcularResult.truncation`."""
    return _env_cap("OCULAR_MAX_POST_DATA_BYTES", _DEFAULT_MAX_POST_DATA_BYTES, POST_DATA_MAX_CHARS)


def _max_url_bytes() -> int:
    """`OCULAR_MAX_URL_BYTES`, défaut `_DEFAULT_MAX_URL_BYTES` (32 768 octets ; la
    distribution qui l'a calibré est en tête de module). L'URL vient de la page :
    AVANT tout plafond, 5000 entrées à 20 Ko d'URL avaient été mesurées à 96,2 Mio
    de résultat, linéaire (200 Ko/URL ≈ 1 Gio). Aujourd'hui ce même trafic reste
    sous le budget du résultat — c'est ce que vérifie
    tests/test_result_size_limits_adverse.py::test_five_thousand_fat_urls_stay_under_the_published_budget."""
    return _env_cap("OCULAR_MAX_URL_BYTES", _DEFAULT_MAX_URL_BYTES, _HARD_MAX_TEXT_BYTES)


def _max_headers_bytes() -> int:
    """`OCULAR_MAX_HEADERS_BYTES`, défaut `_DEFAULT_MAX_HEADERS_BYTES` (8 192
    octets) pour TOUT le dict d'en-têtes d'une entrée (clés + valeurs)."""
    return _env_cap("OCULAR_MAX_HEADERS_BYTES", _DEFAULT_MAX_HEADERS_BYTES, _HARD_MAX_TEXT_BYTES)


def _max_console_text_bytes() -> int:
    """`OCULAR_MAX_CONSOLE_TEXT_BYTES`, défaut `_DEFAULT_MAX_CONSOLE_TEXT_BYTES`
    (32 768 octets) par message."""
    return _env_cap("OCULAR_MAX_CONSOLE_TEXT_BYTES", _DEFAULT_MAX_CONSOLE_TEXT_BYTES,
                    _HARD_MAX_TEXT_BYTES)


def _max_title_bytes() -> int:
    """`OCULAR_MAX_TITLE_BYTES`, défaut `_DEFAULT_MAX_TITLE_BYTES` (32 768
    octets) — `document.title` et `final_url` sont écrits par la page au même
    titre que le reste."""
    return _env_cap("OCULAR_MAX_TITLE_BYTES", _DEFAULT_MAX_TITLE_BYTES, _HARD_MAX_TEXT_BYTES)


def _max_capture_buffer_bytes() -> int:
    """Budget CUMULÉ, en octets UTF-8, du tampon retenu par UN `NetworkCapture`
    pour UNE famille d'entrées (réseau, console). `OCULAR_MAX_CAPTURE_BUFFER_BYTES`,
    défaut `_DEFAULT_MAX_CAPTURE_BUFFER_BYTES` (33 554 432 octets), borné par
    `_HARD_MAX_CAPTURE_BUFFER_BYTES` (134 217 728). Les plafonds par entrée
    bornent chaque entrée, jamais leur somme : c'est ce budget-ci qui borne la
    mémoire que la page dicte pendant TOUTE la session (cf. tête de module)."""
    return _env_cap("OCULAR_MAX_CAPTURE_BUFFER_BYTES", _DEFAULT_MAX_CAPTURE_BUFFER_BYTES,
                    _HARD_MAX_CAPTURE_BUFFER_BYTES)


def _max_findings() -> int:
    """`OCULAR_MAX_FINDINGS`, défaut 5000. `analyze_html` produit UN finding par
    match : un DOM de 2 Mio fait de `document.cookie;` répété en produit 131 072,
    soit 21,9 Mio de JSON à lui seul. Le surplus est compté dans
    `OcularResult.truncation.findings_dropped`."""
    return _env_cap("OCULAR_MAX_FINDINGS", _DEFAULT_MAX_FINDINGS, _HARD_MAX_ENTRIES)


def _max_network_entries() -> int:
    """Nombre max d'entrées réseau conservées. `OCULAR_MAX_NETWORK_ENTRIES`,
    défaut 5000. Au dépassement, les entrées SUIVANTES sont rejetées — on garde
    les PREMIÈRES (la chaîne de chargement initiale est ce qui documente la
    page ; c'est aussi ce qui garde `_req_index` borné) — et comptées dans
    `OcularResult.truncation.network_dropped`. Le tier interactif inverse ce
    choix (cf. `NetworkCapture(keep=...)`)."""
    return _env_cap("OCULAR_MAX_NETWORK_ENTRIES", _DEFAULT_MAX_NETWORK_ENTRIES, _HARD_MAX_ENTRIES)


def _max_console_entries() -> int:
    """Idem pour le journal console : `OCULAR_MAX_CONSOLE_ENTRIES`, défaut 5000,
    surplus compté dans `OcularResult.truncation.console_dropped`."""
    return _env_cap("OCULAR_MAX_CONSOLE_ENTRIES", _DEFAULT_MAX_CONSOLE_ENTRIES, _HARD_MAX_ENTRIES)


def _max_result_json_bytes() -> int:
    """`OCULAR_MAX_RESULT_JSON_BYTES`, défaut 32 Mio : taille max du résultat une
    fois SÉRIALISÉ (cf. `_shed_to_json_cap`).

    Résolu par `engine.limits` AVEC son plafond de lecture `/capture` et la part
    que les blobs base64 y prennent : une valeur qui ferait dépasser la lecture
    est ramenée, jamais approuvée en silence. Mesuré avant : tout réglage
    au-dessus de ~42,7 Mio cassait `/capture` sans le moindre WARNING, alors que
    la borne haute autorisée était 128 Mio."""
    return source_budget("capture")


def _mark_truncated(entry: dict[str, Any], field: str) -> None:
    """Pose le marqueur PAR ENTRÉE. `truncated_fields` NOMME le champ amputé :
    un compteur global (`Truncation.text_truncated`) dit qu'une coupe a eu lieu
    quelque part, il ne désigne aucune entrée — l'analyste voyait donc une URL
    d'apparence complète et ne pouvait pas savoir qu'il lui en manquait la fin.
    Le modèle portait déjà ce motif pour `post_data` et pour lui seul."""
    marks = entry.get("truncated_fields")
    if not isinstance(marks, list):
        marks = []
        entry["truncated_fields"] = marks
    if field not in marks:
        marks.append(field)


def _clip_field(entry: dict[str, Any], field: str, cap: int) -> bool:
    """SEUL endroit où un champ texte d'une entrée est coupé. La coupe et son
    marqueur sont posés par le MÊME appel : il n'existe pas de chemin qui coupe
    sans nommer le champ coupé, et il n'y a rien à « ne pas oublier » quand un
    champ s'ajoute. Renvoie True si la coupe a eu lieu."""
    value, cut = _clip_utf8(entry.get(field), cap)
    if cut:
        entry[field] = value
        _mark_truncated(entry, field)
    return cut


def _truncate_post_data(entry: dict[str, Any], cap: int) -> bool:
    """`post_data` passe par le point unique comme tout autre champ. Le booléen
    historique `NetworkEntry.post_data_truncated` reste servi, mais il est
    DÉRIVÉ de `truncated_fields` par le modèle : une seule source de vérité."""
    return _clip_field(entry, "post_data", cap)


def _clip_entry_text(entry: dict[str, Any], url_cap: int, headers_cap: int) -> int:
    """Borne les champs texte d'UNE entrée réseau autres que `post_data` (qui a
    son propre plafond). Renvoie le nombre de champs coupés, à compter dans
    `Truncation.text_truncated` — le compteur global reste, en plus du marqueur
    par entrée : il répond à « le résultat est-il complet ? », l'autre à
    « CETTE ligne-là est-elle complète ? »."""
    cut = int(_clip_field(entry, "url", url_cap))
    headers = entry.get("headers")
    if isinstance(headers, dict) and headers:
        # Budget GLOBAL du dict : 200 en-têtes de 8 Kio pèsent autant qu'un seul
        # de 1,6 Mio. On garde les premiers en-têtes jusqu'à épuisement.
        kept: dict[str, str] = {}
        used = 0
        dropped = False
        for key, value in headers.items():
            cost = len(str(key).encode("utf-8", "replace")) + len(str(value).encode("utf-8", "replace"))
            if used + cost > headers_cap:
                dropped = True
                break
            kept[key] = value
            used += cost
        if dropped:
            entry["headers"] = kept
            _mark_truncated(entry, "headers")
            cut += 1
    return cut


def sha256_ref(data: bytes) -> str:
    """Référence de contenu-adressage d'un blob (screenshot, DOM, ...)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _entry_bytes(value: Any) -> int:
    """Coût MÉMOIRE d'une entrée collectée, en octets UTF-8, DÉRIVÉ de son
    contenu : toute chaîne compte, où qu'elle soit dans le dict. Un champ ajouté
    demain au dict d'entrée (`_on_request` en pose quatre aujourd'hui) est compté
    sans que personne ne relise cette fonction. Les scalaires non-texte ne sont
    pas dictés par la page (statut HTTP, booléens) : ils ne comptent pas."""
    if isinstance(value, str):
        return len(value.encode("utf-8", "replace"))
    if isinstance(value, dict):
        return sum(_entry_bytes(k) + _entry_bytes(v) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return sum(_entry_bytes(v) for v in value)
    return 0


class NetworkCapture:
    """Arme les listeners `page.on("request"/"response"/"console")` communs aux
    deux moteurs (Playwright sync pour Chromium, Playwright async pour Camoufox
    partagent la même API d'événements). Collecte dans des listes de DICTS
    neutres — pas de dépendance au moteur, pas de conversion Pydantic ici (elle
    se fait dans `ResultBuilder.build`, au moment de composer l'`OcularResult`).

    DEUX bornes, appliquées au MÊME endroit (`_admit`) pour les deux familles
    d'entrées : la CARDINALITÉ (combien d'entrées) et le VOLUME CUMULÉ (combien
    d'octets retenus). La première seule laissait la page dicter
    `cardinalité × plafond par entrée` de mémoire résidente pendant toute la
    session — 468,8 Mio mesurés aux plafonds actuels (cf. tête de module)."""

    def __init__(self, keep: str = "first") -> None:
        self.network: list[dict[str, Any]] = []
        self.console: list[dict[str, Any]] = []
        self._req_index: dict[Any, dict[str, Any]] = {}
        self._req_order: list[Any] = []
        # Coût mémoire de chaque entrée RETENUE, par famille. Tenu à jour à
        # l'insertion et à l'éviction ; re-dérivé si la liste a été modifiée
        # ailleurs (les runners y ajoutent leurs propres messages console).
        self._costs: dict[str, list[int]] = {"network": [], "console": []}
        self._bytes: dict[str, int] = {"network": 0, "console": 0}
        # Ce qui a été REJETÉ ou coupé, reporté dans `OcularResult.truncation`
        # via `truncation()` : le résultat dit ce qu'il ne contient pas.
        self.dropped_network = 0
        self.dropped_console = 0
        self.truncated_post_data = 0
        self.truncated_text = 0
        # Quelle extrémité survit quand le plafond de cardinalité mord.
        #
        # `first` (défaut, tier BATCH) : une capture one-shot est dominée par la
        # chaîne de chargement initiale, c'est elle qui documente la page.
        #
        # `last` (tier INTERACTIF) : le raisonnement s'inverse. La capture y est
        # armée une fois pour toute la SESSION, et l'analyste pilote la page
        # précisément pour DÉCLENCHER l'exfiltration — donc pour produire les
        # requêtes les plus tardives. Garder les premières y jetait, en silence,
        # exactement la preuve recherchée : le POST d'exfiltration émis après le
        # 5000e appel disparaissait sans laisser de trace côté analyste.
        self.keep = keep if keep in ("first", "last") else "first"

    def truncation(self) -> Truncation:
        """État de troncature de CETTE capture, à passer à `ResultBuilder.build`."""
        return Truncation(
            network_dropped=self.dropped_network,
            console_dropped=self.dropped_console,
            post_data_truncated=self.truncated_post_data,
            text_truncated=self.truncated_text,
        )

    def retained_bytes(self, bucket: str) -> int:
        """Octets de texte actuellement RETENUS pour cette famille d'entrées.
        Exposé parce qu'un budget qu'on ne peut pas lire ne se mesure pas."""
        self._resync(bucket)
        return self._bytes[bucket]

    def _resync(self, bucket: str) -> None:
        """Re-dérive le coût du tampon si la liste a bougé hors de `_admit` — les
        runners y ajoutent leurs propres messages (`runner_analysis/render.py`,
        `runner_recon/capture.py`). Sans ça, la comptabilité dériverait de la
        réalité, et un budget qui compte faux ne borne rien."""
        entries = getattr(self, bucket)
        if len(self._costs[bucket]) != len(entries):
            self._costs[bucket] = [_entry_bytes(e) for e in entries]
            self._bytes[bucket] = sum(self._costs[bucket])

    def _evict_oldest(self, bucket: str) -> None:
        entries = getattr(self, bucket)
        entries.pop(0)
        self._bytes[bucket] -= self._costs[bucket].pop(0)
        if bucket == "network" and self._req_order:
            # La clé d'index sort AVEC l'entrée — `_req_index` reste donc borné
            # par la liste, exactement comme en mode `first` où la requête
            # n'était jamais indexée.
            self._req_index.pop(self._req_order.pop(0), None)
        setattr(self, f"dropped_{bucket}", getattr(self, f"dropped_{bucket}") + 1)

    def _admit(self, bucket: str, entry: dict[str, Any], count_cap: int) -> bool:
        """SEUL point d'insertion dans un tampon, pour les deux familles.

        Deux bornes y sont appliquées ensemble : la CARDINALITÉ (`count_cap`) et
        le VOLUME CUMULÉ (`_max_capture_buffer_bytes`). Séparées, la première ne
        bornait rien en mémoire — 5000 entrées au plafond par entrée de 32 Kio
        font 468,8 Mio retenus, mesurés au `ru_maxrss`, pour toute la durée de la
        session interactive.

        `keep` décide QUI sort : en mode `last` (tier interactif) on évince les
        plus ANCIENNES pour faire de la place à la preuve tardive ; en mode
        `first` (tier batch) on refuse la nouvelle. Dans les deux cas c'est
        COMPTÉ (`dropped_*` -> `truncation`), jamais silencieux. Renvoie True si
        l'entrée est retenue."""
        self._resync(bucket)
        entries = getattr(self, bucket)
        cost = _entry_bytes(entry)
        budget = _max_capture_buffer_bytes()
        while len(entries) >= count_cap or self._bytes[bucket] + cost > budget:
            if not entries or self.keep != "last":
                # Plus rien à évincer (entrée plus lourde que le budget entier),
                # ou tier batch : c'est la nouvelle entrée qui ne rentre pas.
                setattr(self, f"dropped_{bucket}", getattr(self, f"dropped_{bucket}") + 1)
                return False
            self._evict_oldest(bucket)
        entries.append(entry)
        self._costs[bucket].append(cost)
        self._bytes[bucket] += cost
        return True

    def attach(self, page: Any) -> None:
        def _on_request(req: Any) -> None:
            # Plafonds de TAILLE par champ : une page hostile n'a pas besoin
            # d'émettre beaucoup d'entrées, il lui suffit d'en émettre une seule,
            # énorme. La cardinalité et le volume cumulé sont appliqués par
            # `_admit`.
            entry = {
                "url": req.url,
                "method": req.method,
                "resource_type": getattr(req, "resource_type", None),
                "post_data": getattr(req, "post_data", None),
            }
            if _truncate_post_data(entry, _max_post_data_bytes()):
                self.truncated_post_data += 1
            self.truncated_text += _clip_entry_text(entry, _max_url_bytes(), _max_headers_bytes())
            if not self._admit("network", entry, _max_network_entries()):
                return
            self._req_index[req] = entry
            self._req_order.append(req)

        def _on_response(resp: Any) -> None:
            entry = self._req_index.get(resp.request)
            if entry is not None:
                entry["status"] = resp.status

        def _on_console(msg: Any) -> None:
            entry = {"level": msg.type, "text": msg.text}
            if _clip_field(entry, "text", _max_console_text_bytes()):
                self.truncated_text += 1
            self._admit("console", entry, _max_console_entries())

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("console", _on_console)


def _escaped_len(value: Any) -> int:
    """Coût SÉRIALISÉ d'une valeur, calculé sans jamais matérialiser plus d'un
    scalaire à la fois. Un modèle est descendu champ par champ, une liste élément
    par élément : le pic mémoire est celui du plus gros scalaire, pas celui du
    document. Les 2 octets par conteneur/paire sont les délimiteurs JSON."""
    if isinstance(value, str):
        return len(json.dumps(value))
    if isinstance(value, BaseModel):
        return sum(_escaped_len(v) for v in value.__dict__.values()) + 2 * len(value.__dict__)
    if isinstance(value, dict):
        return sum(_escaped_len(k) + _escaped_len(v) for k, v in value.items()) + 2
    if isinstance(value, (list, tuple, set)):
        return sum(_escaped_len(v) for v in value) + 2
    return len(json.dumps(value, default=str))


def _escaped_cost(result: OcularResult, targets: list[tuple[Any, str, str]]) -> int:
    """Coût SÉRIALISÉ de ce que le délestage PEUT retirer, mesuré élément par
    élément.

    Le pré-élagage comptait auparavant des longueurs de texte BRUT (`len(e.url)`),
    en ignorant à la fois les en-têtes et le facteur d'échappement : `json.dumps`
    rend un octet de contrôle en `\\u00XX`, soit ×6. Un résultat 6 fois au-dessus
    du plafond passait donc le pré-élagage, et la garde anti-OOM matérialisait le
    JSON complet pour le découvrir — mesuré, sur le pire cas publié : 443 Mio de
    pic RSS, soit ~22 % du budget mémoire du runner d'analyse, EN PLUS de
    Chromium, et ce pic était déclenché par le contenu de la page.

    Il énumérait AUSSI les champs à la main (`url`, `post_data`, `headers`,
    `text`, `match`, `context`), donc il ignorait tout champ neuf exactement
    comme le délestage ignorait `dom.forms`. Il porte désormais sur les MÊMES
    cibles que le délestage, dérivées du modèle. `_json_size` reste le juge
    final ; il n'est simplement plus le premier appelé."""
    return sum(_escaped_len(getattr(owner, field)) for owner, field, _ in targets)


def _json_size(result: OcularResult) -> int:
    """Taille du résultat une fois sérialisé, avec le sérialiseur d'`emit_wrapper`
    (`json.dumps` par défaut, donc `ensure_ascii=True`). C'est la borne
    PESSIMISTE : le tier interactif sérialise via Starlette en
    `ensure_ascii=False`, toujours ≤ à cette mesure."""
    return len(json.dumps(result.model_dump(mode="json")))


def _shed_to_json_cap(result: OcularResult, cap: int) -> Truncation:
    """Ramène le résultat SÉRIALISÉ sous `cap` octets et renvoie ce qui a été
    délesté (à ajouter aux compteurs de `Truncation`).

    Pourquoi mesurer plutôt que calculer : les plafonds par entrée bornent le
    TEXTE, pas le JSON. `json.dumps` échappe un octet de contrôle en `\\u00XX`,
    soit ×6 — 5000 entrées d'octets nuls au plafond par entrée en vigueur
    (32 768 o.) pèsent 156,2 Mio de texte et 937,5 Mio de JSON. Aucune
    arithmétique de plafonds ne tient cette promesse ; une mesure suivie d'un
    délestage, si — c'est la charge `console-nuls-echappement-x6` de
    tests/test_result_size_limits_adverse.py.

    CE QUI EST DÉLESTÉ EST DÉRIVÉ DU MODÈLE (`engine.result.shed_targets`), pas
    d'une liste écrite ici. La liste écrite ici — `console`, `network`,
    `static_findings` — omettait `dom.forms` et `dom.mailtos`, que les quatre
    tiers remplissent DEPUIS LE CONTENU DE LA PAGE : mesuré avec
    `OCULAR_MAX_RESULT_JSON_BYTES=262144`, un résultat dont la masse est dans ces
    deux listes sortait à 725 493 octets, `truncation` à zéro, donc annoncé
    COMPLET. Un champ de volume variable ajouté demain ne peut plus manquer ici :
    sans déclaration, `engine.result` refuse de s'importer.

    Le délestage retire la MÊME FRACTION de chaque liste (l'ordre de parcours ne
    hiérarchise donc rien), il est COMPTÉ dans `Truncation`, et il NOMME le champ
    dans `truncated_fields` quand le porteur en a un. Il ne touche pas aux champs
    déclarés `KEEP` (`screenshots`, `dynamic_steps`, `triage.signals`, les
    marqueurs eux-mêmes). Si le résultat dépasse ENCORE après délestage complet,
    l'écart est journalisé ET porté dans `truncation.over_cap_bytes` : la garde
    dit qu'elle n'a pas tenu, au lieu de rendre un résultat qui s'annonce
    complet."""
    shed = Truncation()
    targets = shed_targets(result)
    for _ in range(_SHED_MAX_ROUNDS):
        estimate = _escaped_cost(result, targets)
        if estimate > cap:
            ratio = cap / estimate
        else:
            size = _json_size(result)
            if size <= cap:
                return shed
            ratio = cap / size
        # Marge de 10 % : converge en un ou deux tours au lieu de raser la liste.
        keep = max(0.0, ratio * 0.9)
        remaining = 0
        for owner, field, counter in targets:
            entries = getattr(owner, field)
            kept = int(len(entries) * keep)
            if kept < len(entries):
                setattr(owner, field, entries[:kept])
                setattr(shed, counter, getattr(shed, counter) + len(entries) - kept)
                if isinstance(owner, TruncatableEntry):
                    marks = list(owner.truncated_fields)
                    if field not in marks:
                        owner.truncated_fields = [*marks, field]
            remaining += kept
        if remaining == 0:
            break
    size = _json_size(result)
    if size > cap:
        # Reste ce que le délestage ne touche pas : le socle d'identité du job et
        # les champs déclarés KEEP/RESIDUAL (`engine.result.residual_paths()`).
        # On le MESURE, on le journalise et on le MARQUE, au lieu de refuser : un
        # refus durable est précisément le déni de service qu'on ferme ici.
        shed.over_cap_bytes = size - cap
        _log.warning(
            "résultat encore à %d octets après délestage complet (plafond %d, "
            "dépassement %d) — la masse restante est hors des champs délestables : %s",
            size, cap, size - cap, ", ".join(residual_paths()),
        )
    return shed


class ResultBuilder:
    """Construit progressivement les blobs (screenshots, DOM) référencés par
    `sha256_ref`, puis assemble l'`OcularResult` final. Ne connaît rien du
    moteur de rendu ni des findings — c'est de la pure mécanique de wrapper."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.screenshots: list[Screenshot] = []
        self.artifacts = Artifacts()

    def add_screenshot(self, step: int, phase: str, png: bytes, viewport: str = "1280x720") -> Optional[str]:
        # Un PNG tronqué serait invalide -> on IGNORE un screenshot hors-cap
        # (le résultat n'aura pas cette capture) plutôt que de corrompre l'image.
        cap = _max_artifact_bytes()
        if cap and len(png) > cap:
            _log.warning("screenshot ignoré step=%d phase=%s bytes=%d > cap=%d (page hostile bloatée ?)",
                         step, phase, len(png), cap)
            return None
        ref = sha256_ref(png)
        self.blobs[ref] = png
        self.screenshots.append(Screenshot(step=step, phase=phase, image_ref=ref, viewport=viewport))
        return ref

    def set_dom(self, dom_html: bytes) -> Optional[str]:
        if not dom_html:
            return None
        # Le DOM est un artefact de CONSULTATION : on le tronque au cap (reste
        # affichable) plutôt que d'OOM. Le hash porte sur les octets réellement
        # stockés (contenu-adressage cohérent).
        cap = _max_artifact_bytes()
        if cap and len(dom_html) > cap:
            _log.warning("DOM tronqué bytes=%d > cap=%d (page hostile bloatée ?)", len(dom_html), cap)
            dom_html = dom_html[:cap]
        ref = sha256_ref(dom_html)
        self.blobs[ref] = dom_html
        self.artifacts = Artifacts(dom_html_ref=ref, har_ref=self.artifacts.har_ref)
        return ref

    def build(
        self,
        *,
        job_id: str,
        profile: str,
        target: str,
        input_hash: Optional[str],
        verdict: str,
        dom_info: Optional[DomInfo] = None,
        stealth: Optional[StealthInfo] = None,
        static_findings: "Optional[list | HtmlScan]" = None,
        network: Optional[list[dict[str, Any]]] = None,
        console: Optional[list[dict[str, Any]]] = None,
        dynamic_steps: Optional[list] = None,
        truncation: Optional[Truncation] = None,
    ) -> tuple[OcularResult, dict[str, bytes]]:
        # Les détections et LA PART DE DOCUMENT QU'ON N'A PAS REGARDÉE voyagent
        # dans le MÊME objet (`HtmlScan`) : un appelant ne peut pas transmettre
        # les unes en perdant l'autre. C'est ce qui rend le marqueur exhaustif
        # sans avoir à l'ajouter tier par tier. Une simple liste reste acceptée
        # pour les résultats composés à la main (tests) : aucun document n'a
        # alors été balayé, donc rien n'a pu être écarté.
        if isinstance(static_findings, HtmlScan):
            _findings = list(static_findings.findings)
            _html_chars_dropped = static_findings.chars_dropped
        else:
            _findings = list(static_findings or [])
            _html_chars_dropped = 0
        _dom = dom_info or DomInfo()
        # Choke-point des plafonds, symétrique de celui des artefacts
        # (`add_screenshot`/`set_dom`). Trois familles, toutes dictées par la page
        # analysée : la CARDINALITÉ des listes, la TAILLE de chaque champ texte,
        # et — parce que ni l'une ni l'autre ne borne le JSON échappé — la taille
        # MESURÉE du résultat sérialisé. `truncation` reporte ce qu'un
        # `NetworkCapture` a déjà rejeté en amont ; ce qui est déjà borné ne l'est
        # pas deux fois (les compteurs ne doublent pas : re-couper une valeur déjà
        # sous le plafond ne compte rien).
        _raw_network = list(network or [])
        _raw_console = list(console or [])
        _body_cap = _max_post_data_bytes()
        _url_cap, _headers_cap = _max_url_bytes(), _max_headers_bytes()
        _text_cap, _title_cap = _max_console_text_bytes(), _max_title_bytes()
        _kept_network: list[dict[str, Any]] = []
        _body_truncated = 0
        _text_truncated = 0
        for _n in _raw_network[: _max_network_entries()]:
            _entry = dict(_n)
            if _truncate_post_data(_entry, _body_cap):
                _body_truncated += 1
            _text_truncated += _clip_entry_text(_entry, _url_cap, _headers_cap)
            _kept_network.append(_entry)
        _kept_console = []
        for _c in _raw_console[: _max_console_entries()]:
            _entry_c = dict(_c)
            _text_truncated += int(_clip_field(_entry_c, "text", _text_cap))
            _kept_console.append(_entry_c)
        # `document.title` et `final_url` sont écrits par la page au même titre
        # que le reste — un titre de 10 Mio dictait 10 Mio de résultat.
        # Même point unique : le DOM passe par un dict le temps de la coupe, donc
        # `title`/`final_url` gagnent le marqueur par entrée comme les autres.
        _dom_fields: dict[str, Any] = {"title": _dom.title, "final_url": _dom.final_url}
        _cut_dom = int(_clip_field(_dom_fields, "title", _title_cap))
        _cut_dom += int(_clip_field(_dom_fields, "final_url", _title_cap))
        if _cut_dom:
            _dom = _dom.model_copy(update=_dom_fields)
            _text_truncated += _cut_dom
        _findings_cap = _max_findings()
        _findings_dropped = max(0, len(_findings) - _findings_cap)
        _findings = _findings[:_findings_cap]
        _upstream = truncation or Truncation()
        # Ce que CE build vient de retirer, puis somme DÉRIVÉE avec l'amont : un
        # compteur que ce bloc ne connaît pas (parce qu'il vient d'être ajouté au
        # modèle, ou parce que seul `NetworkCapture` le pose) traverse au lieu
        # d'être perdu en chemin.
        _here = Truncation(
            network_dropped=len(_raw_network) - len(_kept_network),
            console_dropped=len(_raw_console) - len(_kept_console),
            post_data_truncated=_body_truncated,
            findings_dropped=_findings_dropped,
            text_truncated=_text_truncated,
            html_chars_dropped=_html_chars_dropped,
        )
        _truncation = Truncation(**{
            name: getattr(_upstream, name) + getattr(_here, name)
            for name in Truncation.model_fields
        })
        triage = compute_triage(
            _findings, verdict=verdict,
            network=_kept_network, console=_kept_console, dom=_dom,
        )
        result = OcularResult(
            job_id=job_id,
            profile=profile,
            target=target,
            input_hash=input_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            verdict=verdict,
            screenshots=self.screenshots,
            network=[NetworkEntry(**n) for n in _kept_network],
            console=[ConsoleEntry(**c) for c in _kept_console],
            dom=_dom,
            static_findings=_findings,
            # 3c : journal du mode scripté (déjà des `DynamicStep`, construits
            # par runner_recon/capture.py::journal_to_dynamic_steps). Absent
            # (None) -> liste vide, comme tout autre champ optionnel ici.
            dynamic_steps=[
                d if isinstance(d, DynamicStep) else DynamicStep(**d)
                for d in (dynamic_steps or [])
            ],
            stealth=stealth,
            triage=triage,
            artifacts=self.artifacts,
            truncation=_truncation,
        )
        # Dernière garde, MESURÉE : les plafonds ci-dessus bornent le texte, pas
        # le JSON échappé. Après ce point, `_json_size(result) <= cap` — c'est
        # cette propriété-là qui est testée, et c'est elle qui empêche le plafond
        # de LECTURE côté web de se transformer en refus permanent.
        _shed = _shed_to_json_cap(result, _max_result_json_bytes())
        if _shed != Truncation():
            # Somme DÉRIVÉE du modèle : la version littérale recopiait six noms
            # de compteurs et laissait tomber ceux qu'elle ne connaissait pas —
            # un compteur ajouté à `Truncation` disparaissait donc du résultat
            # sans que rien ne le signale. `_shed` ne porte que ce que le
            # délestage vient de faire (tout le reste y vaut 0), la somme est
            # donc exacte pour chaque compteur, y compris `over_cap_bytes`.
            _truncation = Truncation(**{
                name: getattr(_truncation, name) + getattr(_shed, name)
                for name in Truncation.model_fields
            })
            result.truncation = _truncation
        if _truncation != Truncation():
            # Dérivé du MODÈLE, jamais réécrit à la main : une liste de champs
            # recopiée dans un format littéral se désynchronise au premier
            # compteur ajouté, et le compteur neuf disparaît du journal sans que
            # rien ne le signale (c'est ce qui venait d'arriver à
            # `html_chars_dropped`). Le broker fait déjà pareil côté réception.
            _log.warning(
                "résultat tronqué %s",
                " ".join(f"{k}={v}" for k, v in sorted(_truncation.model_dump().items())),
            )
        return result, self.blobs


def wrapper_payload(result: OcularResult, blobs: dict[str, bytes]) -> dict:
    """Forme `{result, blobs(base64)}` du wrapper d'échange runner<->web. Source
    unique : le tier batch l'émet sur stdout (`emit_wrapper`), le tier interactif
    la renvoie telle quelle en réponse HTTP (session_server /capture)."""
    return {
        "result": result.model_dump(mode="json"),
        "blobs": {ref: base64.b64encode(data).decode() for ref, data in blobs.items()},
    }


def emit_wrapper(result: OcularResult, blobs: dict[str, bytes]) -> None:
    """Écrit `{result, blobs(base64)}` sur stdout — LE seul flux stdout du
    runner, consommé par broker/launcher.py. Les logs partent ailleurs (stderr)."""
    sys.stdout.write(json.dumps(wrapper_payload(result, blobs)) + "\n")
