# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plafonds de configuration, et surtout les PAIRES indissociables
« budget de la SOURCE / plafond de LECTURE ».

POURQUOI CE MODULE EXISTE. Une réponse interne hors plafond de lecture est
refusée (fail-closed) et rendue en `502`. C'est correct — à condition que la
SOURCE soit bornée SOUS le plafond de lecture. Sinon la réponse dépasse à chaque
appel et la fonction devient inaccessible pour le restant de la session : la
garde anti-OOM se transforme en déni de service, déclenché par le contenu de la
page. L'invariant est donc :

    plafond_de_lecture  >=  budget_de_la_source  +  part_réservée

Il n'était vérifié QUE D'UN CÔTÉ : baisser le plafond de lecture journalisait un
WARNING, RELEVER le budget de la source ne journalisait rien. Et le code
SANCTIONNAIT des valeurs qui brisent son propre invariant — la borne haute
autorisée pour `OCULAR_MAX_LIVE_JSON_BYTES` (32 Mio) valait DEUX FOIS le plafond
de lecture par défaut (16 Mio). Mesuré bout en bout avec cette valeur, que le
code accepte : corps `/live` de 23,45 Mio, `truncation` à zéro (donc annoncé
COMPLET), `502` à chaque poll, et ZÉRO WARNING.

CE QUI CHANGE. Les deux variables d'une paire sont résolues ICI, ENSEMBLE, par
le même appel — les deux côtés du réseau appellent `resolve()`, il n'existe donc
pas d'endroit où l'une soit lue sans l'autre. Une configuration qui brise
l'invariant n'est plus approuvée en silence : le budget de la SOURCE est ramené
sous le plafond de lecture, et c'est journalisé.

POURQUOI CORRIGER LA SOURCE ET NON LE PLAFOND DE LECTURE. Produire moins ne peut
jamais rendre une réponse illisible ; relever le plafond de lecture augmenterait
au contraire la mémoire que la page analysée peut faire consommer au web
(mem_limit 1g) puis à Redis, monté sur tmpfs. La correction va donc toujours dans
le sens qui réduit ce que la page contrôle.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import NamedTuple, Optional

from ocular_logging import get_logger

_log = get_logger("limits")

# Un WARNING de configuration décrit un fait STABLE du processus. Émis à chaque
# lecture, il devenait proportionnel au trafic que la page analysée choisit
# d'émettre : les plafonds par entrée sont relus à chaque requête et à chaque
# message console, soit 2 lignes par requête — 2 000 requêtes de page ->
# 4 000 lignes identiques, sur le cas même que le WARNING doit signaler.
# Mémoïsé par MESSAGE FORMATÉ (donc par variable ET par valeur retenue) : un
# changement réel reste dit, une répétition ne l'est pas.
_said: set[str] = set()


def warn_once(fmt: str, *args: object) -> None:
    key = fmt % args
    if key in _said:
        return
    _said.add(key)
    _log.warning(fmt, *args)


def reset_warnings() -> None:
    """Vide la mémoire des WARNINGs — réservé aux tests, qui doivent pouvoir
    observer l'émission plusieurs fois dans un même processus."""
    _said.clear()


def env_cap(name: str, default: int, hard_max: int, floor: int = 1) -> int:
    """Plafond entier de configuration. Ne lève JAMAIS (une valeur illisible
    retombe sur le défaut — même règle qu'`ocular_settings`), mais ne substitue
    JAMAIS EN SILENCE : toute valeur illisible ou hors bornes est journalisée
    avec la valeur retenue, une fois par processus.

    Plancher et borne haute : ce que ces plafonds bornent est dicté par la page
    hostile — l'exploitation peut les baisser, jamais les retirer. Le plancher
    est un piège connu : `OCULAR_MAX_ARTIFACT_BYTES`, variable voisine, documente
    bien « 0 = illimité », si bien qu'un exploitant transposant la convention
    obtiendrait ici l'inverse de son intention (UNE seule entrée conservée).
    D'où le WARNING, qui nomme la variable."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        warn_once("%s=%r illisible — plafond laissé au défaut %d", name, raw, default)
        return default
    clamped = min(max(floor, val), hard_max)
    if clamped != val:
        warn_once(
            "%s=%d hors bornes [%d, %d] — plafond ramené à %d "
            "(ces plafonds se baissent, ils ne se retirent pas ; « 0 = illimité » "
            "ne vaut QUE pour OCULAR_MAX_ARTIFACT_BYTES)",
            name, val, floor, hard_max, clamped,
        )
    return clamped


class _Pair(NamedTuple):
    source_var: str
    source_default: int
    source_hard_max: int
    source_floor: int    # sous ce budget, la source ne peut plus produire de réponse utile
    read_var: str
    read_default: int
    read_hard_max: int
    blobs: bool          # la réponse transporte-t-elle des blobs base64 ?


_MiB = 1024 * 1024

# Plancher du budget d'un résultat `/capture`. Le socle non dicté par la page —
# identité du job, réfs sha256 des blobs, triage — a été MESURÉ sur ce dépôt :
# 867 octets sérialisés pour un résultat vide, 1 361 avec une identité complète,
# un screenshot et le bloc `stealth`. Le plancher est fixé à 65 536 octets, soit
# ~48× le socle mesuré : c'est un CHOIX (laisser de la place à des entrées, pas
# seulement à l'identité), pas une mesure. Sous ce plancher, `/capture` ne
# rendrait qu'un résultat vidé de sa preuve — ce n'est pas une configuration à
# approuver, fût-ce en la journalisant.
_CAPTURE_SOURCE_FLOOR = 64 * 1024

# Les DEUX paires du système. Chaque ligne est une réponse interne : une source
# qui la produit, un plafond qui la lit.
PAIRS: dict[str, _Pair] = {
    # `/live` : JSON seul (fenêtres de 500 entrées).
    "live": _Pair("OCULAR_MAX_LIVE_JSON_BYTES", 8 * _MiB, 32 * _MiB, 1024,
                  "OCULAR_MAX_INTERNAL_JSON_BYTES", 16 * _MiB, 512 * _MiB, False),
    # `/capture` : le résultat JSON **plus** les blobs en base64, cf. `reserved`.
    "capture": _Pair("OCULAR_MAX_RESULT_JSON_BYTES", 32 * _MiB, 128 * _MiB, _CAPTURE_SOURCE_FLOOR,
                     "OCULAR_MAX_INTERNAL_CAPTURE_BYTES", 128 * _MiB, 512 * _MiB, True),
}

_DEFAULT_MAX_ARTIFACT_BYTES = 32 * _MiB


def _allowance(artifact_cap: int) -> int:
    """Part du plafond de lecture que les BLOBS consomment. `wrapper_payload` les
    transporte en base64 (×4/3) et une capture en produit au plus deux (DOM +
    screenshot)."""
    return 2 * ((artifact_cap + 2) // 3 * 4)


def _largest_artifact_cap(room: int) -> int:
    """Plus grand plafond d'artefact dont la part base64 tient dans `room`.
    Inverse de `_allowance`, arrondi vers le bas puis VÉRIFIÉ (l'arrondi entier
    de `_allowance` n'est pas exactement inversible)."""
    cap = max(1, (room // 8) * 3)
    while cap > 1 and _allowance(cap) > room:
        cap -= 1
    return cap


def _env_artifact_cap() -> int:
    """`OCULAR_MAX_ARTIFACT_BYTES` tel que configuré. `0` = illimité (seule
    variable de la famille à suivre cette convention)."""
    raw = os.environ.get("OCULAR_MAX_ARTIFACT_BYTES")
    if raw is None:
        return _DEFAULT_MAX_ARTIFACT_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        warn_once("OCULAR_MAX_ARTIFACT_BYTES=%r illisible — plafond laissé au défaut %d",
                  raw, _DEFAULT_MAX_ARTIFACT_BYTES)
        return _DEFAULT_MAX_ARTIFACT_BYTES


def artifact_allowance() -> Optional[int]:
    """Part réservée aux blobs pour la configuration courante. `None` quand
    `OCULAR_MAX_ARTIFACT_BYTES=0` (« illimité ») : la part n'est alors pas
    calculable, donc l'invariant n'est pas vérifiable — c'est dit plutôt que
    deviné."""
    cap = _env_artifact_cap()
    return None if cap == 0 else _allowance(cap)


@dataclass(frozen=True)
class Budget:
    """Termes EFFECTIFS d'une paire, après réconciliation."""
    source: int          # ce que la source s'autorise à produire
    read_cap: int        # ce que le lecteur s'autorise à lire
    reserved: int        # part du plafond de lecture prise par autre chose (blobs)
    clamped: bool        # True si la configuration brisait l'invariant
    artifact_cap: int = 0  # plafond EFFECTIF d'un artefact (0 = illimité, ou paire sans blobs)

    @property
    def headroom(self) -> int:
        return self.read_cap - self.reserved - self.source


def resolve(pair: str) -> Budget:
    """Résout TOUTES les variables de `pair` et rend les termes effectifs.

    C'est le seul endroit où l'une d'elles est lue : il n'existe donc pas de
    chemin qui en lise une sans confronter les autres. Une configuration qui
    brise l'invariant est corrigée SUR TOUS SES TERMES, blobs compris, jamais
    approuvée en silence.

    POURQUOI TOUS LES TERMES. Corriger la seule source ne peut pas rétablir la
    fonction quand la part réservée aux blobs dépasse à elle seule le plafond de
    lecture. Mesuré avec `OCULAR_MAX_INTERNAL_CAPTURE_BYTES=67108864` (64 Mio,
    valeur DANS les bornes) : part des blobs 89 478 488 o. (85,3 Mio) > lecture
    67 108 864 o., budget de la source ramené à **1 octet**, `/capture` en 502
    permanent — pendant que le WARNING affirmait que sans correction « la
    fonction resterait inaccessible », donc qu'avec elle, non."""
    spec = PAIRS[pair]
    read_floor = spec.source_floor + (_allowance(1) if spec.blobs else 0)
    source = env_cap(spec.source_var, spec.source_default, spec.source_hard_max)
    read_cap = env_cap(spec.read_var, spec.read_default, spec.read_hard_max, floor=read_floor)
    if not spec.blobs:
        reserved, art_cap = 0, 0
    else:
        art_cap = _env_artifact_cap()
        if art_cap == 0:
            warn_once(
                "OCULAR_MAX_ARTIFACT_BYTES=0 (« illimité ») : la part de %s prise par "
                "les blobs n'est pas calculable, l'invariant « lecture >= source » ne "
                "peut donc pas être vérifié pour %s — choix d'exploitation explicite, "
                "cf. docs/DEPLOY-SECURITY.md §2.10",
                spec.read_var, pair,
            )
            return Budget(source=source, read_cap=read_cap, reserved=0, clamped=False,
                          artifact_cap=0)
        reserved = _allowance(art_cap)
    available = read_cap - reserved
    if source <= available:
        return Budget(source=source, read_cap=read_cap, reserved=reserved, clamped=False,
                      artifact_cap=art_cap)
    if available >= spec.source_floor:
        # Un budget de source réduit reste un budget de source utilisable : la
        # correction porte sur la SOURCE, produire moins ne peut pas rendre une
        # réponse illisible.
        warn_once(
            "%s=%d dépasse ce que %s=%d permet de LIRE (%d disponibles après %d "
            "réservés aux blobs) — budget de la source ramené à %d. Non corrigé, la "
            "réponse dépasserait à chaque appel et la fonction resterait "
            "inaccessible pour le restant de la session (cf. DEPLOY-SECURITY §2.10).",
            spec.source_var, source, spec.read_var, read_cap, available, reserved, available,
        )
        return Budget(source=available, read_cap=read_cap, reserved=reserved, clamped=True,
                      artifact_cap=art_cap)
    # Ici, la part des blobs ne laisse même pas le plancher de la source :
    # ramener la source seule produirait un budget absurde (1 octet a été mesuré)
    # en se déclarant satisfait. On corrige donc AUSSI le plafond des artefacts,
    # et on DIT ce que la configuration perd.
    corrected_art = _largest_artifact_cap(read_cap - spec.source_floor)
    corrected_reserved = _allowance(corrected_art)
    corrected_source = read_cap - corrected_reserved
    warn_once(
        "%s=%d est INCOMPATIBLE avec OCULAR_MAX_ARTIFACT_BYTES=%d : les blobs "
        "réserveraient à eux seuls %d octets sur %d lisibles, il ne resterait pas "
        "le plancher de %d octets nécessaire au résultat. Corrigé sur les DEUX "
        "termes — artefacts ramenés à %d octets (tout screenshot plus gros est "
        "IGNORÉ, le DOM est TRONQUÉ à cette taille), budget du résultat ramené à "
        "%d. `/capture` répond, avec ces pertes-là (cf. DEPLOY-SECURITY §2.10).",
        spec.read_var, read_cap, art_cap, reserved, read_cap, spec.source_floor,
        corrected_art, corrected_source,
    )
    return Budget(source=corrected_source, read_cap=read_cap, reserved=corrected_reserved,
                  clamped=True, artifact_cap=corrected_art)


def artifact_cap() -> int:
    """Plafond EFFECTIF d'UN artefact (DOM, screenshot), invariant déjà appliqué.
    `0` = illimité, choix d'exploitation explicite."""
    return resolve("capture").artifact_cap


def source_budget(pair: str) -> int:
    """Ce que la source s'autorise à produire, invariant déjà appliqué."""
    return resolve(pair).source


def read_cap(pair: str) -> int:
    """Ce que le lecteur s'autorise à lire, invariant déjà confronté."""
    return resolve(pair).read_cap
