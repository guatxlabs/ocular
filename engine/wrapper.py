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
    DEFAULT_CLIP_COUNTER,
    FIELD_VOLUME,
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
    Volume,
    clip_fields,
    clip_targets,
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
# Budget par DÉFAUT d'un champ `CLIP` qui ne nomme pas le sien (cf.
# `_CLIP_BUDGETS`). Même échelle que les trois budgets calibrés ci-dessus : un
# champ texte dicté par la page est de la même famille que l'URL, le message
# console et le titre, et 32 Kio est la valeur que leur calibration a retenue.
_DEFAULT_MAX_TEXT_BYTES = 32 * 1024
_DEFAULT_MAX_FINDINGS = 5000
# Budget CUMULÉ du tampon de session — la borne qui manquait.
#
# Les plafonds par entrée bornent CHAQUE entrée, jamais leur SOMME : le produit
# « cardinalité × taille par entrée » est ce que la page retient dans le
# conteneur de session, pour TOUTE la durée de la session interactive (le
# délestage du résultat, lui, n'a lieu qu'au `/capture`).
#
# MÉTHODE DE MESURE, parce que le chiffre ne veut rien dire sans elle. Haut-de-
# marque NOYAU (`resource.getrusage(RUSAGE_SELF).ru_maxrss`), tampons remplis via
# les VRAIS listeners de `NetworkCapture.attach`, 5 000 requêtes + 5 000 messages
# console, chaînes DISTINCTES par entrée (sans quoi la RSS mesure une seule copie
# partagée, pas le volume retenu), CHAQUE CHAMP ÉMIS EXACTEMENT À SON PLAFOND
# (`url`, `post_data`, texte console) ; trois exécutions par ligne :
#   - plafonds par entrée à 4 096 / 8 192 / 8 192 o. : 97,9 Mio retenus,
#     ru_maxrss 31 -> 151 Mio (151/151/151) ;
#   - plafonds par entrée à 32 768 o. (les actuels), SANS budget cumulé :
#     469,0 Mio retenus, ru_maxrss 31 -> 503 Mio (503/503/503) ;
#   - mêmes plafonds AVEC le budget cumulé ci-dessous : 63,9 Mio retenus,
#     ru_maxrss 31 -> 95-96 Mio (96/95/96).
# Relever les plafonds par entrée pour ne plus couper de contenu légitime a donc
# multiplié par 4,8 la mémoire que la page dicte, dans un conteneur à
# `--memory 2g` PARTAGÉ avec Camoufox. Ce coût-là n'avait pas été mesuré.
#
# CE QUE CES TROIS LIGNES NE DISENT PAS, et qu'un exploitant doit savoir avant de
# dimensionner : elles supposent une page qui émet PILE le plafond. Ce que la
# page émet AU-DESSUS du plafond existe en mémoire le temps d'être coupé, et ce
# transitoire n'est retenu par aucun budget. Mesuré sur ce dépôt, mêmes 5 000 +
# 5 000 entrées, budget cumulé actif, en faisant émettre à la page un multiple du
# plafond :
#     émis ×1 -> 63,9 Mio retenus, ru_maxrss 31 ->  95-96 Mio (96/95/96)
#     émis ×2 -> 64,0 Mio retenus, ru_maxrss 32 -> 163 Mio (163/163/163)
#     émis ×4 -> 64,0 Mio retenus, ru_maxrss 32 -> 225 Mio (225/225/225)
# Le VOLUME RETENU est bien borné par le budget (64 Mio dans les trois cas) —
# c'est la propriété que ce module garantit. Le PIC RÉSIDENT, lui, suit ce que la
# page choisit d'émettre. Le seul chiffre sur lequel dimensionner sans hypothèse
# de contenu est donc le volume retenu : 2 × `OCULAR_MAX_CAPTURE_BUFFER_BYTES`.
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


def _get(entry: Any, field: str) -> Any:
    return entry.get(field) if isinstance(entry, dict) else getattr(entry, field, None)


def _set(entry: Any, field: str, value: Any) -> None:
    if isinstance(entry, dict):
        entry[field] = value
    else:
        setattr(entry, field, value)


def _mark_truncated(entry: Any, field: str) -> None:
    """Pose le marqueur PAR ENTRÉE. `truncated_fields` NOMME le champ amputé :
    un compteur global (`Truncation.text_truncated`) dit qu'une coupe a eu lieu
    quelque part, il ne désigne aucune entrée — l'analyste voyait donc une URL
    d'apparence complète et ne pouvait pas savoir qu'il lui en manquait la fin.
    Le modèle portait déjà ce motif pour `post_data` et pour lui seul.

    Marche sur un DICT (coupe avant construction du modèle — `post_data` a une
    longueur maximale que le modèle REFUSE) comme sur une INSTANCE (coupe du
    résultat déjà bâti). `engine.result` garantit que tout porteur d'un champ
    `CLIP` hérite de `TruncatableEntry` : il y a donc toujours un endroit où
    NOMMER la coupe."""
    marks = _get(entry, "truncated_fields")
    if not isinstance(marks, list):
        marks = []
        _set(entry, "truncated_fields", marks)
    if field not in marks:
        marks.append(field)
        if not isinstance(entry, dict):
            # pydantic ne revalide pas une affectation : la liste doit être
            # RÉ-AFFECTÉE pour que le porteur voie sa propre marque quand elle
            # existait déjà (`model_copy` partage l'objet liste).
            _set(entry, "truncated_fields", marks)


def _clip_mapping(mapping: dict[Any, Any], cap: int) -> tuple[dict[Any, Any], bool]:
    """Réduit un DICTIONNAIRE de texte à son budget GLOBAL : 200 en-têtes de
    8 Kio pèsent autant qu'un seul de 1,6 Mio. On garde les premières paires
    jusqu'à épuisement du budget."""
    kept: dict[Any, Any] = {}
    used = 0
    for key, value in mapping.items():
        cost = (len(str(key).encode("utf-8", "replace"))
                + len(str(value).encode("utf-8", "replace")))
        if used + cost > cap:
            return kept, True
        kept[key] = value
        used += cost
    return mapping, False


def _clip_field(entry: Any, field: str, cap: int) -> bool:
    """SEUL endroit où un champ de volume variable est coupé. La coupe et son
    marqueur sont posés par le MÊME appel : il n'existe pas de chemin qui coupe
    sans nommer le champ coupé, et il n'y a rien à « ne pas oublier » quand un
    champ s'ajoute. Renvoie True si la coupe a eu lieu.

    Les DEUX formes que `engine.result` autorise pour un champ `CLIP` sont
    traitées ici, choisies sur la VALEUR et non sur le nom du champ : une chaîne
    est coupée en octets UTF-8, un dictionnaire de texte est réduit à son budget
    global. Toute autre forme est refusée à l'import du modèle."""
    value = _get(entry, field)
    if isinstance(value, dict):
        kept, cut = _clip_mapping(value, cap)
    else:
        kept, cut = _clip_utf8(value, cap)
    if cut:
        _set(entry, field, kept)
        _mark_truncated(entry, field)
    return cut


# Budgets en octets des champs `CLIP`, par NOM de budget déclaré dans
# `engine.result.FIELD_VOLUME`. C'est la seule liste écrite ici, et elle est
# CONFRONTÉE au modèle à l'import (ci-dessous) : un champ déclaré coupable sur un
# budget que ce module n'implémente pas fait échouer l'import au lieu de sortir
# non coupé.
_CLIP_BUDGETS: dict[str, Any] = {
    "url": _max_url_bytes,
    "headers": _max_headers_bytes,
    "post_data": _max_post_data_bytes,
    "console_text": _max_console_text_bytes,
    "title": _max_title_bytes,
    # Budget par DÉFAUT : un champ `CLIP` qui ne nomme pas le sien. Même échelle
    # (32 Kio) que les trois budgets calibrés sur du contenu réel ci-dessus
    # (URL/console/titre) — c'est un plafond par entrée de la même famille, pas
    # une valeur nouvelle. Réglable par `OCULAR_MAX_TEXT_BYTES`.
    "": lambda: _env_cap("OCULAR_MAX_TEXT_BYTES", _DEFAULT_MAX_TEXT_BYTES,
                         _HARD_MAX_TEXT_BYTES),
}

_budgets_inconnus = sorted({
    decl.budget for decl in FIELD_VOLUME.values()
    if decl.volume is Volume.CLIP and decl.budget not in _CLIP_BUDGETS
})
if _budgets_inconnus:
    raise RuntimeError(
        f"budgets de coupe inconnus de engine.wrapper : {_budgets_inconnus} — un "
        "champ déclaré CLIP sur un budget qui n'existe pas ne serait jamais coupé."
    )


def _clip_declared(entry: Any, cls: type) -> dict[str, int]:
    """Coupe TOUS les champs que le MODÈLE déclare coupables sur cette classe, et
    rend `{compteur: nombre de champs coupés}`.

    C'est le pendant de `shed_targets` pour la nature voisine : plus aucun nom de
    champ n'est écrit sur le chemin de la coupe. Un champ `CLIP` ajouté demain à
    `NetworkEntry`, `ConsoleEntry` ou `DomInfo` est coupé sans que personne ne
    relise cette fonction, et compté sous le compteur que sa déclaration nomme
    (`text_truncated` par défaut)."""
    cut: dict[str, int] = {}
    for field, decl in clip_fields(cls):
        if _clip_field(entry, field, _CLIP_BUDGETS[decl.budget]()):
            counter = decl.counter or DEFAULT_CLIP_COUNTER
            cut[counter] = cut.get(counter, 0) + 1
    return cut


def _clip_result(result: OcularResult) -> dict[str, int]:
    """Filet de bout de chaîne : coupe tout champ `CLIP` du résultat DÉJÀ BÂTI,
    où qu'il vive dans l'arbre — y compris sur un porteur que `ResultBuilder
    .build` ne remplit pas lui-même. Rend `{compteur: champs coupés}`.

    Les coupes faites en amont (sur les dicts d'entrée) ne comptent pas deux
    fois : re-couper une valeur déjà sous son budget ne coupe rien."""
    cut: dict[str, int] = {}
    for owner, field, decl in clip_targets(result):
        if _clip_field(owner, field, _CLIP_BUDGETS[decl.budget]()):
            counter = decl.counter or DEFAULT_CLIP_COUNTER
            cut[counter] = cut.get(counter, 0) + 1
    return cut


def _sum_counters(base: Truncation, *cuts: dict[str, int]) -> Truncation:
    """Somme DÉRIVÉE du modèle : un compteur ajouté à `Truncation` traverse au
    lieu d'être perdu en chemin."""
    total = base.model_dump()
    for cut in cuts:
        for counter, n in cut.items():
            total[counter] = total.get(counter, 0) + n
    return Truncation(**total)


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
        # via `truncation()` : le résultat dit ce qu'il ne contient pas. Les
        # coupes sont tenues PAR COMPTEUR DÉCLARÉ (`engine.result`), pas par un
        # attribut par champ : un champ `CLIP` ajouté demain arrive avec son
        # compteur et traverse jusqu'au résultat sans qu'on relise cette classe.
        self.dropped_network = 0
        self.dropped_console = 0
        self._cut: dict[str, int] = {}
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
        return _sum_counters(
            Truncation(network_dropped=self.dropped_network,
                       console_dropped=self.dropped_console),
            self._cut,
        )

    def retained_bytes(self, bucket: str) -> int:
        """Octets de texte actuellement RETENUS pour cette famille d'entrées,
        RE-DÉRIVÉS DU CONTENU à chaque lecture.

        Exposé parce qu'un budget qu'on ne peut pas lire ne se mesure pas — et
        re-dérivé parce qu'une comptabilité incrémentale ne peut pas voir un
        REMPLACEMENT en place (une entrée échangée contre une plus lourde sans
        changer la longueur de la liste) : mesuré, l'ancien coût restait annoncé
        (1 012 octets annoncés pour 10 000 000 réellement retenus). La lecture
        rend donc toujours le coût RÉEL, et le réinjecte dans la comptabilité —
        le `_admit` suivant borne alors sur la bonne valeur.

        Coût : O(octets retenus). C'est un chemin d'OBSERVATION, pas le chemin
        d'insertion (`_admit` reste incrémental)."""
        entries = getattr(self, bucket)
        self._costs[bucket] = [_entry_bytes(e) for e in entries]
        self._bytes[bucket] = sum(self._costs[bucket])
        return self._bytes[bucket]

    def _resync(self, bucket: str) -> None:
        """Re-dérive le coût du tampon si la liste a bougé hors de `_admit` — les
        runners y ajoutent leurs propres messages (`runner_analysis/render.py`,
        `runner_recon/capture.py`). Sans ça, la comptabilité dériverait de la
        réalité, et un budget qui compte faux ne borne rien.

        Le déclencheur est la LONGUEUR : c'est ce que coûte O(1) à l'insertion.
        Un REMPLACEMENT en place (même longueur, entrée plus lourde) échappe donc
        à ce test — il est rattrapé par `retained_bytes()`, et aucun appelant du
        dépôt ne le fait : c'est vérifié par une garde dérivée des tampons
        eux-mêmes (tests/test_capture_buffer_accounting.py), pas par relecture."""
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

    def _count(self, cut: dict[str, int]) -> None:
        """Reporte les coupes sous le compteur que la DÉCLARATION nomme."""
        for counter, n in cut.items():
            self._cut[counter] = self._cut.get(counter, 0) + n

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
            self._count(_clip_declared(entry, NetworkEntry))
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
            self._count(_clip_declared(entry, ConsoleEntry))
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
    deux listes sortait à 491 245 octets (×1,87 le plafond), `truncation` à zéro,
    donc annoncé COMPLET. C'est la mesure du VRAI chemin page -> extracteurs ->
    `build` : les plafonds d'extraction en retiennent 100 de chaque et tronquent
    chaque élément, donc une page de 120 formulaires + 120 mailto n'en fait
    passer que 100. Un champ de volume variable ajouté demain ne peut plus manquer ici :
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
        # Les champs COUPÉS sont ceux que le MODÈLE déclare `CLIP` (`clip_fields`),
        # avec le budget que leur déclaration nomme. Aucun nom de champ n'est
        # écrit ici : la version précédente en énumérait six (`url`, `headers`,
        # `post_data`, `text`, `title`, `final_url`) et déclarer un septième
        # champ coupable ne faisait donc RIEN.
        _cut: dict[str, int] = {}

        def _tally(cuts: dict[str, int]) -> None:
            for _counter, _n in cuts.items():
                _cut[_counter] = _cut.get(_counter, 0) + _n

        _kept_network: list[dict[str, Any]] = []
        for _n in _raw_network[: _max_network_entries()]:
            _entry = dict(_n)
            _tally(_clip_declared(_entry, NetworkEntry))
            _kept_network.append(_entry)
        _kept_console = []
        for _c in _raw_console[: _max_console_entries()]:
            _entry_c = dict(_c)
            _tally(_clip_declared(_entry_c, ConsoleEntry))
            _kept_console.append(_entry_c)
        # Le DOM n'est PAS coupé ici : ses champs (`title`, `final_url`, et ceux
        # qu'on lui ajoutera) sont pris en charge par le filet de bout de chaîne
        # `_clip_result`, sur le résultat bâti. Ce qui doit être coupé AVANT la
        # construction, c'est ce que le MODÈLE refuserait (`post_data` porte une
        # longueur maximale) et ce que le triage lit (les entrées réseau/console,
        # qu'il reçoit sous forme de dicts).
        #
        # Copie DÉFENSIVE : la coupe et son marqueur mutent l'instance, et
        # l'appelant nous a prêté la sienne. Le marqueur reçoit sa propre liste,
        # sans quoi il écrirait dans celle de l'appelant.
        _dom = _dom.model_copy(update={"truncated_fields": list(_dom.truncated_fields)})
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
            findings_dropped=_findings_dropped,
            html_chars_dropped=_html_chars_dropped,
        )
        _truncation = _sum_counters(
            Truncation(**{name: getattr(_upstream, name) + getattr(_here, name)
                          for name in Truncation.model_fields}),
            _cut,
        )
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
        # Filet de bout de chaîne pour la coupe : les trois porteurs ci-dessus
        # sont ceux que CE build remplit, mais un champ `CLIP` peut vivre
        # ailleurs dans l'arbre (sur un porteur qu'un autre chemin construit).
        # `_clip_result` parcourt le résultat BÂTI et coupe tout ce que le modèle
        # déclare coupable, où qu'il soit — ce qui vient d'être coupé au-dessus
        # est déjà sous son budget, donc n'est pas compté deux fois.
        _late = _clip_result(result)
        if _late:
            _truncation = _sum_counters(_truncation, _late)
            result.truncation = _truncation
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
