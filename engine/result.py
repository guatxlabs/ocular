# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

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
# Le plafond d'EXPLOITATION, lui, est `OCULAR_MAX_POST_DATA_BYTES` (défaut 8192)
# et s'applique en OCTETS UTF-8 (cf. `engine.wrapper._max_post_data_bytes`) :
# c'est la seule unité qui borne réellement la mémoire, un caractère pouvant
# valoir jusqu'à 4 octets. Comme un plafond en octets borne aussi le nombre de
# caractères, `build()` ne peut jamais produire un `post_data` que ce modèle
# refuserait. Quelques Kio suffisent à établir un indice d'exfiltration (même
# esprit que `match[:200]` dans engine/static.py).
POST_DATA_MAX_CHARS = 65536


class NetworkEntry(BaseModel):
    url: str
    method: str
    status: Optional[int] = None
    headers: dict[str, str] = Field(default_factory=dict)
    post_data: Optional[str] = Field(default=None, max_length=POST_DATA_MAX_CHARS)
    # Marqueur par entrée : ce corps a été coupé, ce n'est pas celui qu'a émis
    # la page. Compté aussi dans `OcularResult.truncation`.
    post_data_truncated: bool = False
    resource_type: Optional[str] = None
    initiator: Optional[str] = None


class ConsoleEntry(BaseModel):
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


class DomInfo(BaseModel):
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
        compteur porte sur le nombre de CHAMPS coupés, pas d'entrées."""
    network_dropped: int = 0
    console_dropped: int = 0
    post_data_truncated: int = 0
    findings_dropped: int = 0
    text_truncated: int = 0


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
