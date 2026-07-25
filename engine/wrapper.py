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
import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional

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
    Truncation,
)
from engine.limits import env_cap as _env_cap_impl, source_budget
from engine.static import HtmlScan
from engine.triage import compute_triage
from ocular_logging import get_logger

_log = get_logger("wrapper")
_DEFAULT_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024  # 32 MiB
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
# À 4 096 o, 8 de ces 34 335 URL réelles étaient coupées ; à 16 384 o, zéro. Le
# plafond retenu est 32 768 o, soit ~2× la plus grande observation réelle
# CONNUE (16 030 o, mesurée indépendamment sur une image inline).
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
# Budget du résultat SÉRIALISÉ. Les plafonds par entrée ne suffisent pas à le
# garantir : `json.dumps` échappe un octet de contrôle en `\u00XX`, soit ×6 — une
# page qui remplit 5000 entrées d'octets nuls produit 246 Mio à partir de 40 Mio
# de texte. La garantie est donc MESURÉE (`_shed_to_json_cap`), pas arithmétique.
# Dimensionné pour que `wrapper_payload` reste sous le plafond de lecture de
# `/capture` (128 Mio) : 32 Mio de résultat + 2 artefacts au défaut de 32 Mio
# encodés en base64 (85,4 Mio) = 117,4 Mio. Cf. docs/DEPLOY-SECURITY.md §2.10.
_DEFAULT_MAX_RESULT_JSON_BYTES = 32 * 1024 * 1024
# Bornes hautes : une configuration ne doit pas pouvoir RETIRER un plafond (cf.
# §2.10). Les relever augmente proportionnellement l'empreinte mémoire du runner.
_HARD_MAX_ENTRIES = 20000
_HARD_MAX_TEXT_BYTES = 64 * 1024
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
    Réglable via `OCULAR_MAX_ARTIFACT_BYTES`."""
    try:
        return max(0, int(os.environ.get("OCULAR_MAX_ARTIFACT_BYTES", str(_DEFAULT_MAX_ARTIFACT_BYTES))))
    except ValueError:
        return _DEFAULT_MAX_ARTIFACT_BYTES


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
    `OCULAR_MAX_POST_DATA_BYTES`, défaut 8192, borné par `POST_DATA_MAX_CHARS`
    (65536, le plafond du modèle — un plafond en octets borne aussi les
    caractères, donc le modèle ne peut pas être mis en défaut). Au dépassement le
    corps est TRONQUÉ, l'entrée marquée `post_data_truncated` et comptée dans
    `OcularResult.truncation`."""
    return _env_cap("OCULAR_MAX_POST_DATA_BYTES", _DEFAULT_MAX_POST_DATA_BYTES, POST_DATA_MAX_CHARS)


def _max_url_bytes() -> int:
    """`OCULAR_MAX_URL_BYTES`, défaut 4096 octets. L'URL vient de la page : la
    revue a mesuré 5000 entrées à 20 Ko d'URL = 96,2 Mio de résultat, linéaire
    (200 Ko/URL ≈ 1 Gio). 4 Kio dépassent déjà la limite pratique des navigateurs
    et des serveurs — la valeur de preuve au-delà est nulle."""
    return _env_cap("OCULAR_MAX_URL_BYTES", _DEFAULT_MAX_URL_BYTES, _HARD_MAX_TEXT_BYTES)


def _max_headers_bytes() -> int:
    """`OCULAR_MAX_HEADERS_BYTES`, défaut 8192 octets pour TOUT le dict d'en-têtes
    d'une entrée (clés + valeurs)."""
    return _env_cap("OCULAR_MAX_HEADERS_BYTES", _DEFAULT_MAX_HEADERS_BYTES, _HARD_MAX_TEXT_BYTES)


def _max_console_text_bytes() -> int:
    """`OCULAR_MAX_CONSOLE_TEXT_BYTES`, défaut 8192 octets par message."""
    return _env_cap("OCULAR_MAX_CONSOLE_TEXT_BYTES", _DEFAULT_MAX_CONSOLE_TEXT_BYTES,
                    _HARD_MAX_TEXT_BYTES)


def _max_title_bytes() -> int:
    """`OCULAR_MAX_TITLE_BYTES`, défaut 4096 octets — `document.title` et
    `final_url` sont écrits par la page au même titre que le reste."""
    return _env_cap("OCULAR_MAX_TITLE_BYTES", _DEFAULT_MAX_TITLE_BYTES, _HARD_MAX_TEXT_BYTES)


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


class NetworkCapture:
    """Arme les listeners `page.on("request"/"response"/"console")` communs aux
    deux moteurs (Playwright sync pour Chromium, Playwright async pour Camoufox
    partagent la même API d'événements). Collecte dans des listes de DICTS
    neutres — pas de dépendance au moteur, pas de conversion Pydantic ici (elle
    se fait dans `ResultBuilder.build`, au moment de composer l'`OcularResult`).
    """

    def __init__(self, keep: str = "first") -> None:
        self.network: list[dict[str, Any]] = []
        self.console: list[dict[str, Any]] = []
        self._req_index: dict[Any, dict[str, Any]] = {}
        self._req_order: list[Any] = []
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

    def attach(self, page: Any) -> None:
        def _on_request(req: Any) -> None:
            # Plafond de CARDINALITÉ (anti-OOM, même justification que les
            # artefacts) : une page hostile peut émettre des requêtes sans fin.
            # Plafonds de TAILLE par champ : elle peut aussi bien n'en émettre
            # qu'une seule, énorme — la cardinalité ne borne alors rien.
            entry = {
                "url": req.url,
                "method": req.method,
                "resource_type": getattr(req, "resource_type", None),
                "post_data": getattr(req, "post_data", None),
            }
            if _truncate_post_data(entry, _max_post_data_bytes()):
                self.truncated_post_data += 1
            self.truncated_text += _clip_entry_text(entry, _max_url_bytes(), _max_headers_bytes())
            cap = _max_network_entries()
            if len(self.network) >= cap:
                if self.keep != "last":
                    self.dropped_network += 1
                    return
                # Fenêtre glissante : la plus ancienne sort, avec sa clé d'index
                # — `_req_index` reste donc borné par la liste, exactement comme
                # dans le mode `first` où la requête n'était jamais indexée.
                self.network.pop(0)
                self._req_index.pop(self._req_order.pop(0), None)
                self.dropped_network += 1
            self.network.append(entry)
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
            cap = _max_console_entries()
            if len(self.console) >= cap:
                if self.keep != "last":
                    self.dropped_console += 1
                    return
                self.console.pop(0)
                self.dropped_console += 1
            self.console.append(entry)

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("console", _on_console)


def _escaped_cost(result: OcularResult) -> int:
    """Coût SÉRIALISÉ des champs dictés par la page, mesuré CHAMP PAR CHAMP.

    Le pré-élagage comptait auparavant des longueurs de texte BRUT (`len(e.url)`),
    en ignorant à la fois les en-têtes et le facteur d'échappement : `json.dumps`
    rend un octet de contrôle en `\\u00XX`, soit ×6. Un résultat 6 fois au-dessus
    du plafond passait donc le pré-élagage, et la garde anti-OOM matérialisait le
    JSON complet pour le découvrir — mesuré, sur le pire cas publié : 443 Mio de
    pic RSS, soit ~22 % du budget mémoire du runner d'analyse, EN PLUS de
    Chromium, et ce pic était déclenché par le contenu de la page.

    Mesurer champ par champ donne la MÊME grandeur que `_json_size` sur la part
    que la page contrôle, avec un pic mémoire d'UN champ au lieu du document
    entier. `_json_size` reste le juge final ; il n'est simplement plus le
    premier appelé."""
    total = 0
    for entry in result.network:
        total += len(json.dumps(entry.url)) + len(json.dumps(entry.post_data or ""))
        if entry.headers:
            total += len(json.dumps(entry.headers))
    for line in result.console:
        total += len(json.dumps(line.text))
    for finding in result.static_findings:
        total += len(json.dumps(finding.match)) + len(json.dumps(finding.context))
    return total


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
    soit ×6 — 5000 entrées d'octets nuls au plafond de 8 Kio pèsent 40 Mio de
    texte mais 246 Mio de JSON. Aucune arithmétique de plafonds ne tient cette
    promesse ; une mesure suivie d'un délestage, si.

    Le délestage est PROPORTIONNEL et ordonné du moins vers le plus probant
    (console, puis réseau, puis détections), et il est COMPTÉ : un résultat
    allégé le dit. Il ne touche jamais aux `screenshots`, aux `dynamic_steps`
    (journal d'actions de l'analyste) ni au `triage`."""
    shed = Truncation()
    if not (result.network or result.console or result.static_findings):
        return shed
    for _ in range(_SHED_MAX_ROUNDS):
        estimate = _escaped_cost(result)
        if estimate > cap:
            ratio = cap / estimate
        else:
            size = _json_size(result)
            if size <= cap:
                return shed
            ratio = cap / size
        # Marge de 10 % : converge en un ou deux tours au lieu de raser la liste.
        keep = max(0.0, ratio * 0.9)
        for name, counter in (("console", "console_dropped"),
                              ("network", "network_dropped"),
                              ("static_findings", "findings_dropped")):
            entries = getattr(result, name)
            kept = int(len(entries) * keep)
            if kept < len(entries):
                setattr(result, name, entries[:kept])
                setattr(shed, counter, getattr(shed, counter) + len(entries) - kept)
        if not (result.network or result.console or result.static_findings):
            break
    size = _json_size(result)
    if size > cap:
        # Reste le socle non dicté par la page (identité du job, refs de blobs,
        # triage). On le journalise au lieu de refuser : un refus durable est
        # précisément le déni de service qu'on ferme ici.
        _log.warning("résultat encore à %d octets après délestage complet (plafond %d)", size, cap)
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
        _truncation = Truncation(
            network_dropped=_upstream.network_dropped + len(_raw_network) - len(_kept_network),
            console_dropped=_upstream.console_dropped + len(_raw_console) - len(_kept_console),
            post_data_truncated=_upstream.post_data_truncated + _body_truncated,
            findings_dropped=_upstream.findings_dropped + _findings_dropped,
            text_truncated=_upstream.text_truncated + _text_truncated,
            html_chars_dropped=_upstream.html_chars_dropped + _html_chars_dropped,
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
        # Dernière garde, MESURÉE : les plafonds ci-dessus bornent le texte, pas
        # le JSON échappé. Après ce point, `_json_size(result) <= cap` — c'est
        # cette propriété-là qui est testée, et c'est elle qui empêche le plafond
        # de LECTURE côté web de se transformer en refus permanent.
        _shed = _shed_to_json_cap(result, _max_result_json_bytes())
        if _shed != Truncation():
            _truncation = Truncation(
                network_dropped=_truncation.network_dropped + _shed.network_dropped,
                console_dropped=_truncation.console_dropped + _shed.console_dropped,
                post_data_truncated=_truncation.post_data_truncated,
                findings_dropped=_truncation.findings_dropped + _shed.findings_dropped,
                text_truncated=_truncation.text_truncated,
                html_chars_dropped=_truncation.html_chars_dropped,
            )
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
