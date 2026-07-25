# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import types
from enum import Enum
from typing import Any, Literal, NamedTuple, Optional, Union, get_args, get_origin

from pydantic import BaseModel, Field, model_validator

Severity = Literal["critical", "high", "medium", "low"]
Verdict = Literal["benign", "suspicious", "malicious", "unknown"]
Profile = Literal["capture", "analysis"]


class Screenshot(BaseModel):
    step: int
    phase: str
    image_ref: str
    viewport: str


# Plafond DUR, en CARACTÈRES, du corps d'une requête capturée — c'est l'unité de
# `max_length` en pydantic, et elle diffère de celle du plafond d'exploitation.
# `post_data` vient de la page ANALYSÉE : une page hostile peut y mettre des
# mégaoctets PAR requête, qui traversent ensuite stdout du runner, le broker,
# Redis (monté sur tmpfs, donc en RAM de l'hôte) puis SQLite.
#
# Le plafond d'EXPLOITATION, lui, est `OCULAR_MAX_POST_DATA_BYTES` (cf.
# `engine.wrapper._max_post_data_bytes` pour sa valeur et sa calibration)
# et s'applique en OCTETS UTF-8 :
# c'est la seule unité qui borne réellement la mémoire, un caractère pouvant
# valoir jusqu'à 4 octets. Comme un plafond en octets borne aussi le nombre de
# caractères, `build()` ne peut jamais produire un `post_data` que ce modèle
# refuserait. Quelques Kio suffisent à établir un indice d'exfiltration (même
# esprit que `match[:200]` dans engine/static.py).
POST_DATA_MAX_CHARS = 65536


class TruncatableEntry(BaseModel):
    """Toute entrée dont un champ texte peut être coupé par les plafonds
    anti-OOM. `truncated_fields` NOMME les champs amputés de CETTE entrée.

    Pourquoi par entrée et pas seulement en compteur global : `truncation`
    répond à « ce résultat est-il complet ? », jamais à « CETTE ligne-là
    est-elle complète ? ». Une URL coupée était rendue à l'analyste avec
    exactement l'apparence d'une URL entière — sur une balise GET de kit de
    phishing, les identifiants volés vivent dans la query string, et c'est
    précisément la fin de l'URL qui disparaissait."""
    truncated_fields: list[str] = Field(default_factory=list)

    def truncated(self, field: str) -> bool:
        return field in self.truncated_fields


class NetworkEntry(TruncatableEntry):
    url: str
    method: str
    status: Optional[int] = None
    headers: dict[str, str] = Field(default_factory=dict)
    post_data: Optional[str] = Field(default=None, max_length=POST_DATA_MAX_CHARS)
    # Alias HISTORIQUE de `"post_data" in truncated_fields`, conservé pour les
    # payloads 1.0 déjà en base et pour l'UI. DÉRIVÉ, jamais posé de son côté :
    # deux marqueurs indépendants finissent toujours par diverger.
    post_data_truncated: bool = False
    resource_type: Optional[str] = None
    initiator: Optional[str] = None

    @model_validator(mode="after")
    def _reconcile_post_data_marker(self) -> "NetworkEntry":
        """Réconcilie l'alias dans LES DEUX SENS, en un seul endroit : un payload
        neuf ne porte que `truncated_fields`, un payload déjà stocké ne porte que
        `post_data_truncated`, et les deux se relisent pareil."""
        if self.post_data_truncated and "post_data" not in self.truncated_fields:
            self.truncated_fields = [*self.truncated_fields, "post_data"]
        elif "post_data" in self.truncated_fields and not self.post_data_truncated:
            self.post_data_truncated = True
        return self


class ConsoleEntry(TruncatableEntry):
    level: str
    text: str
    location: Optional[str] = None


class StaticFinding(BaseModel):
    rule: str
    severity: Severity
    match: str
    line: int
    context: str


class DynamicStep(BaseModel):
    action: str
    screenshot_ref: Optional[str] = None
    triggered_requests: list[str] = Field(default_factory=list)
    # Champs 3c (mode scripté) : issue d'exécution d'un step rejoué par
    # runner_recon/steps_exec.py::run_steps. Optionnels + valeurs par défaut
    # rétro-compatibles : un `DynamicStep` 3a existant (sans ces champs) reste
    # un payload valide (`ok` défaut à True, les deux autres à None).
    ok: bool = True
    duration_ms: Optional[int] = None
    error: Optional[str] = None


class DomInfo(TruncatableEntry):
    title: str = ""
    final_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)   # [{action, method}] — cf. static.extract_forms
    mailtos: list[str] = Field(default_factory=list)  # cibles mailto: — cf. static.extract_mailtos
    links: list[str] = Field(default_factory=list)


class StealthInfo(BaseModel):
    engine: Literal["camoufox", "chromium"]
    # Tri-état : True = challenge Turnstile résolu ; False = challenge présent
    # mais NON résolu ; None = aucun challenge / non applicable (ex. analyse HTML
    # pure, ou session interactive sans challenge). None n'affiche AUCUN badge
    # « passé/non passé » (cf. saved_store: None -> NULL, UI: badge omis) — évite
    # le faux « Turnstile non passé » sur les captures sans Turnstile.
    turnstile_solved: Optional[bool] = None
    challenge: Optional[str] = None


class TriageSignal(BaseModel):
    key: str
    label: str
    weight: float
    detail: str = ""


class Triage(BaseModel):
    """2e avis natif, parallèle au verdict règles (jamais un écrasement).
    `score` 0-100 = priorité « à regarder » ; sa décomposition intégrale est
    dans `signals` (Σ des weight affichés == score). `weights_version` trace le
    jeu de poids (BUILTIN ou calibré) ayant produit ce score."""
    score: int
    band: Literal["low", "medium", "high"]
    second_opinion: Verdict
    # None quand le verdict règles n'est pas un avis comparable (ex. "unknown").
    agrees_with_rules: Optional[bool]
    signals: list[TriageSignal] = Field(default_factory=list)
    weights_version: str


class Artifacts(BaseModel):
    har_ref: Optional[str] = None
    dom_html_ref: Optional[str] = None


class Truncation(BaseModel):
    """Marqueur EXPLICITE de ce que le résultat NE contient pas, parce que les
    plafonds anti-OOM ont mordu (cf. `engine.wrapper`). Un résultat amputé sans
    le dire est un angle mort : l'analyste croirait voir tout le trafic d'une
    page qui en a émis cent fois plus. Tous les compteurs à 0 = résultat
    complet.

    Deux familles distinctes, à ne pas confondre en lisant un résultat :
      - `*_dropped` = des ÉLÉMENTS ENTIERS manquent (requêtes, messages,
        détections) — c'est de la preuve absente ;
      - `text_truncated` = des éléments sont PRÉSENTS mais un de leurs champs
        texte a été coupé (URL, en-têtes, texte console, titre de page). Le
        compteur porte sur le nombre de CHAMPS coupés, pas d'entrées ;
      - `html_chars_dropped` = le document n'a pas été balayé EN ENTIER par
        l'analyse statique (`engine.static.analysis_window`). Ce n'est ni de la
        preuve absente ni un champ coupé : c'est une zone du document où AUCUNE
        détection n'a été cherchée. Sans ce compteur, un verdict « benign » sur
        un document partiellement analysé serait indiscernable d'un verdict
        « benign » sur un document lu en entier ;
      - `over_cap_bytes` = le résultat DÉPASSE ENCORE son plafond après
        délestage complet. Ce n'est pas une amputation, c'est l'aveu que la
        garde n'a pas pu tenir sa promesse : ce qui reste vit dans des champs
        que le délestage ne touche pas (`residual_paths()`)."""
    network_dropped: int = 0
    console_dropped: int = 0
    post_data_truncated: int = 0
    findings_dropped: int = 0
    text_truncated: int = 0
    html_chars_dropped: int = 0
    # Éléments retirés d'une liste délestable qui n'a PAS de compteur dédié.
    # Il n'y a pas un compteur par champ : le nom du champ délesté est nommé
    # dans `truncated_fields` quand son porteur en a un, et le journal du runner
    # le nomme toujours (message dérivé de ce modèle).
    other_dropped: int = 0
    over_cap_bytes: int = 0


class OcularResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    job_id: str
    profile: Profile
    target: str
    input_hash: Optional[str] = None
    timestamp: str
    verdict: Verdict = "unknown"
    screenshots: list[Screenshot] = Field(default_factory=list)
    network: list[NetworkEntry] = Field(default_factory=list)
    console: list[ConsoleEntry] = Field(default_factory=list)
    dom: DomInfo = Field(default_factory=DomInfo)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    dynamic_steps: list[DynamicStep] = Field(default_factory=list)
    stealth: Optional[StealthInfo] = None
    triage: Optional[Triage] = None
    artifacts: Artifacts = Field(default_factory=Artifacts)
    # Compteurs à 0 par défaut : un payload 1.0 antérieur (déjà en base) reste
    # valide et se lit comme « rien n'a été tronqué ».
    truncation: Truncation = Field(default_factory=Truncation)

    @classmethod
    def model_json_schema(cls, *args, **kwargs):
        schema = super().model_json_schema(*args, **kwargs)
        required = set(schema.get("required", []))
        required.add("schema_version")
        schema["required"] = sorted(required)
        return schema


# --- Nature de CHAQUE champ de volume variable --------------------------------
#
# POURQUOI CETTE TABLE. Le délestage anti-OOM (`engine.wrapper._shed_to_json_cap`)
# portait sur un tuple de trois noms écrit à la main — `console`, `network`,
# `static_findings`. `dom.forms` et `dom.mailtos` sont remplis DEPUIS LE CONTENU
# DE LA PAGE par les quatre tiers (`runner_analysis/render.py`,
# `runner_recon/capture.py`, `runner_recon_vnc/session_server.py` ×2, tous via
# `static.extract_forms`/`extract_mailtos`) et n'y étaient pas. Mesuré sur ce
# dépôt avec `OCULAR_MAX_RESULT_JSON_BYTES=262144` (valeur DANS les bornes
# publiées), un résultat dont toute la masse est dans ces deux listes sortait à
# 725 493 octets — ×2,8 le plafond — avec `truncation` à zéro, donc annoncé
# COMPLET, et sans le moindre WARNING.
#
# Une liste de noms écrite à la main est fausse dès qu'un champ s'ajoute, et
# c'est le troisième tour de suite qu'elle l'est. Ici, la garde ne peut plus
# rater un champ : elle parcourt le MODÈLE, et tout champ de volume variable non
# déclaré ci-dessous fait ÉCHOUER L'IMPORT du module (`_check_declarations`).
# Ajouter un champ sans en déclarer la nature n'est donc pas un angle mort : ce
# n'est pas exécutable.


class Volume(str, Enum):
    """Ce que la garde anti-OOM fait du champ — pas ce qu'on croit de sa taille."""

    SHED = "shed"          # liste délestée par `_shed_to_json_cap` jusqu'à repasser sous le plafond
    CLIP = "clip"          # champ texte coupé au point de coupe unique (`_clip_field`)
    KEEP = "keep"          # jamais délesté : marqueur de coupe, ou preuve produite par l'analyste
    FIXED = "fixed"        # volume NON dicté par la page (identité du job, réfs sha256, tables du dépôt)
    RESIDUAL = "residual"  # ni coupé ni délesté : un dépassement y est MESURÉ et dit (`truncation.over_cap_bytes`)


class Decl(NamedTuple):
    volume: Volume
    counter: str = ""      # SHED : compteur de `Truncation` où compter les éléments retirés


_S, _C, _K, _F, _R = Volume.SHED, Volume.CLIP, Volume.KEEP, Volume.FIXED, Volume.RESIDUAL

# Clé = `Classe.champ`. La classe peut être une classe de BASE : `TruncatableEntry
# .truncated_fields` couvre ses trois sous-classes, et une sous-classe neuve hérite
# de la déclaration sans qu'on ait à y penser (recherche par MRO).
FIELD_VOLUME: dict[str, Decl] = {
    # -- le résultat lui-même
    "OcularResult.job_id":                  Decl(_F),
    "OcularResult.target":                  Decl(_F),   # soumis par l'analyste
    "OcularResult.input_hash":              Decl(_F),
    "OcularResult.timestamp":               Decl(_F),
    "OcularResult.screenshots":             Decl(_K),   # preuve image, jamais délestée
    "OcularResult.network":                 Decl(_S, "network_dropped"),
    "OcularResult.console":                 Decl(_S, "console_dropped"),
    "OcularResult.static_findings":         Decl(_S, "findings_dropped"),
    "OcularResult.dynamic_steps":           Decl(_K),   # journal d'actions de l'analyste
    # -- entrées
    "TruncatableEntry.truncated_fields":    Decl(_K),   # délester le marqueur effacerait la preuve de la coupe
    "Screenshot.phase":                     Decl(_F),
    "Screenshot.image_ref":                 Decl(_F),
    "Screenshot.viewport":                  Decl(_F),
    "NetworkEntry.url":                     Decl(_C),
    "NetworkEntry.method":                  Decl(_R),
    "NetworkEntry.headers":                 Decl(_C),
    "NetworkEntry.post_data":               Decl(_C),
    "NetworkEntry.resource_type":           Decl(_R),
    "NetworkEntry.initiator":               Decl(_R),
    "ConsoleEntry.level":                   Decl(_R),
    "ConsoleEntry.text":                    Decl(_C),
    "ConsoleEntry.location":                Decl(_R),
    "StaticFinding.rule":                   Decl(_F),   # libellé du motif, table du dépôt
    "StaticFinding.match":                  Decl(_R),
    "StaticFinding.context":                Decl(_R),
    "DynamicStep.action":                   Decl(_F),   # nom de step du script de l'analyste
    "DynamicStep.screenshot_ref":           Decl(_F),
    "DynamicStep.triggered_requests":       Decl(_S, "other_dropped"),
    "DynamicStep.error":                    Decl(_R),
    # -- DOM : c'est ici que la liste écrite à la main manquait deux champs
    "DomInfo.title":                        Decl(_C),
    "DomInfo.final_url":                    Decl(_C),
    "DomInfo.redirect_chain":               Decl(_S, "other_dropped"),
    "DomInfo.forms":                        Decl(_S, "other_dropped"),
    "DomInfo.mailtos":                      Decl(_S, "other_dropped"),
    "DomInfo.links":                        Decl(_S, "other_dropped"),
    # -- reste
    "StealthInfo.challenge":                Decl(_R),
    "TriageSignal.key":                     Decl(_F),
    "TriageSignal.label":                   Decl(_F),   # libellé du jeu de poids, pas de la page
    "TriageSignal.detail":                  Decl(_F),
    "Triage.signals":                       Decl(_K),   # Σ des poids == score : délester falsifierait le score
    "Triage.weights_version":               Decl(_F),
    "Artifacts.har_ref":                    Decl(_F),
    "Artifacts.dom_html_ref":               Decl(_F),
}

_NONE = type(None)
# Types dont la taille sérialisée est bornée par le TYPE lui-même. Tout le reste
# est traité comme de volume variable — y compris une annotation dont la forme
# n'est pas reconnue : la garde échoue FERMÉE, elle exige une déclaration.
_FIXED_WIDTH = (bool, int, float, _NONE)


def _variable_volume(annotation: Any) -> bool:
    """Le champ peut-il peser un volume que le TYPE ne borne pas ?"""
    origin = get_origin(annotation)
    if origin is Literal:
        return False       # l'ensemble des valeurs est fini et écrit dans le type
    if origin in (Union, types.UnionType):
        return any(_variable_volume(a) for a in get_args(annotation) if a is not _NONE)
    if origin in (list, dict, set, frozenset, tuple):
        return True
    if isinstance(annotation, type):
        if issubclass(annotation, BaseModel):
            return False   # descendu comme sous-arbre, pas comme volume propre
        if annotation in _FIXED_WIDTH:
            return False
    return True


def _nested_models(annotation: Any) -> list[type[BaseModel]]:
    """Modèles imbriqués dans une annotation, où qu'ils soient (`list[X]`,
    `Optional[X]`, `dict[str, X]`…)."""
    found: list[type[BaseModel]] = []
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    for arg in get_args(annotation):
        found.extend(_nested_models(arg))
    return found


def model_tree() -> dict[str, type[BaseModel]]:
    """Toutes les classes atteignables depuis `OcularResult`, DÉRIVÉES du modèle."""
    found: dict[str, type[BaseModel]] = {}
    stack: list[type[BaseModel]] = [OcularResult]
    while stack:
        cls = stack.pop()
        if cls.__name__ in found:
            continue
        found[cls.__name__] = cls
        for field in cls.model_fields.values():
            stack.extend(_nested_models(field.annotation))
    return found


def declaration(cls: type[BaseModel], field: str) -> Optional[Decl]:
    """Déclaration du champ, cherchée le long du MRO (une classe de base déclare
    pour toutes ses filles)."""
    for base in cls.__mro__:
        decl = FIELD_VOLUME.get(f"{base.__name__}.{field}")
        if decl is not None:
            return decl
    return None


def undeclared_fields(tree: Optional[dict[str, type[BaseModel]]] = None) -> list[str]:
    """Champs de volume variable SANS déclaration. Non vide = import refusé.
    `tree` n'existe que pour permettre de VÉRIFIER cette garde sur un modèle
    fabriqué (cf. tests/test_result_bounds_derived.py) : une garde qu'on ne peut
    pas mettre en défaut n'est pas une garde éprouvée."""
    missing = []
    for name, cls in (tree if tree is not None else model_tree()).items():
        for field, info in cls.model_fields.items():
            if _variable_volume(info.annotation) and declaration(cls, field) is None:
                missing.append(f"{name}.{field}")
    return sorted(missing)


def stale_declarations() -> list[str]:
    """Déclarations qui ne correspondent à aucun champ du modèle — une table qui
    garde des noms morts ne prouve plus rien de ce qu'elle décrit."""
    live = {f"{name}.{field}"
            for name, cls in model_tree().items()
            for field in cls.model_fields}
    live |= {f"{base.__name__}.{field}"
             for _, cls in model_tree().items()
             for base in cls.__mro__ if issubclass(base, BaseModel)
             for field in getattr(base, "model_fields", {})}
    return sorted(set(FIELD_VOLUME) - live)


def residual_paths() -> list[str]:
    """Chemins où de la masse peut RESTER après délestage complet : déclarés
    `KEEP` ou `RESIDUAL`, et qui ne sont pas SOUS une liste délestable (sous une
    liste délestable, la masse part avec les éléments).

    C'est la liste « ce qui n'est PAS garanti » de docs/DEPLOY-SECURITY.md §2.10
    — dérivée d'ici, pour qu'elle ne puisse plus omettre un champ."""
    out: list[str] = []

    def walk(cls: type[BaseModel], prefix: str, covered: bool) -> None:
        for field, info in cls.model_fields.items():
            decl = declaration(cls, field)
            variable = _variable_volume(info.annotation)
            path = f"{prefix}{field}"
            shed = decl is not None and decl.volume is Volume.SHED
            if variable and not covered and decl is not None \
                    and decl.volume in (Volume.KEEP, Volume.RESIDUAL):
                out.append(path)
            for sub in _nested_models(info.annotation):
                suffix = "[]." if get_origin(info.annotation) in (list, set, frozenset, tuple) else "."
                walk(sub, f"{path}{suffix}", covered or shed)

    walk(OcularResult, "", False)
    return sorted(set(out))


def _shed_plan(cls: type[BaseModel] = OcularResult,
               prefix: tuple[str, ...] = (),
               seen: tuple[type, ...] = ()) -> list[tuple[tuple[str, ...], str]]:
    """Chemin de CHAQUE liste délestable, dérivé du modèle une fois pour toutes.
    Un champ déclaré `SHED` demain entre ici sans que personne ne relise le
    délestage."""
    plan: list[tuple[tuple[str, ...], str]] = []
    for field, info in cls.model_fields.items():
        decl = declaration(cls, field)
        if decl is not None and decl.volume is Volume.SHED:
            plan.append((prefix + (field,), decl.counter))
        for sub in _nested_models(info.annotation):
            if sub not in seen:
                plan.extend(_shed_plan(sub, prefix + (field,), seen + (cls,)))
    return plan


SHED_PLAN: tuple[tuple[tuple[str, ...], str], ...] = ()


def _owners(node: Any, segments: tuple[str, ...]) -> list[BaseModel]:
    if not segments:
        return [node] if isinstance(node, BaseModel) else []
    value = getattr(node, segments[0], None)
    nodes = value if isinstance(value, list) else [value]
    out: list[BaseModel] = []
    for sub in nodes:
        if isinstance(sub, BaseModel):
            out.extend(_owners(sub, segments[1:]))
    return out


def shed_targets(result: BaseModel) -> list[tuple[BaseModel, str, str]]:
    """`(porteur, champ, compteur)` de chaque liste délestable PRÉSENTE dans ce
    résultat-là. Dérivé de `SHED_PLAN`, donc du modèle."""
    out: list[tuple[BaseModel, str, str]] = []
    for path, counter in SHED_PLAN:
        for owner in _owners(result, path[:-1]):
            if isinstance(getattr(owner, path[-1], None), list):
                out.append((owner, path[-1], counter))
    return out


def _check_declarations() -> None:
    missing, stale = undeclared_fields(), stale_declarations()
    if missing or stale:
        raise RuntimeError(
            "engine.result.FIELD_VOLUME ne décrit plus le modèle — champs de "
            f"volume variable non déclarés : {missing or 'aucun'} ; déclarations "
            f"sans champ correspondant : {stale or 'aucune'}. Un champ dicté par "
            "la page qui n'est ni délesté (SHED) ni coupé (CLIP) ni justifié "
            "(FIXED/KEEP/RESIDUAL) rend `OcularResult` non bornable : déclarez-le "
            "(cf. docs/DEPLOY-SECURITY.md §2.10)."
        )


_check_declarations()
SHED_PLAN = tuple(_shed_plan())
# Un compteur nommé dans une déclaration mais absent de `Truncation` ferait
# disparaître en silence ce qu'un délestage a retiré.
_orphelins = sorted({c for _, c in SHED_PLAN if c not in Truncation.model_fields})
if _orphelins:
    raise RuntimeError(
        f"compteurs de délestage inconnus de Truncation : {_orphelins} — "
        "des éléments seraient retirés sans qu'aucun compteur ne le dise."
    )
