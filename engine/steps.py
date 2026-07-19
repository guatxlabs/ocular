# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""DSL d'actions déclaratif borné pour le tier dynamique scripté (3c).
Partagé par le web (validation à la soumission) et le runner (re-validation
défensive avant exécution) — source unique, jamais deux implémentations.
Aucun JS arbitraire, aucun eval : verbes en allowlist stricte."""
import copy
import re
from engine.ssrf import validate_capture_url

MAX_STEPS = 50
MAX_SEL = 500
MAX_VALUE = 2000
MAX_WAIT_MS = 30000
MAX_SLEEP_S = 60     # `sleep` est exprimé en SECONDES (unité intuitive, cf. _one)
MAX_SCROLL_PX = 100000
MAX_LABEL = 64
ALLOWED_PRESS_KEYS = frozenset({
    "Enter", "Tab", "Escape", "Backspace", "Delete",
    "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "Home", "End", "PageUp", "PageDown", "Space",
})
_LABEL_RE = re.compile(r"[\w .:-]{1,%d}$" % MAX_LABEL)


class StepValidationError(ValueError):
    """Motif de rejet lisible (renvoyé tel quel au client / loggé)."""


def _bounded_repr(value, limit=100):
    """`repr()` borné d'une valeur utilisateur, pour toute interpolation dans
    un message d'erreur — quel que soit le type de `value` (str, list, dict,
    exception déjà stringifiée...). `web/app.py` renvoie `str(e)` tel quel en
    détail 422 : sans cette borne, une valeur géante/non-str (ex. arg `press`
    non-str, message d'exception SSRF) produirait une réponse 422 de taille
    arbitraire (amplification). Appliqué systématiquement à toute branche de
    `_one` qui réfléchit une valeur utilisateur (cf. audit 3c)."""
    return repr(value)[:limit]


def _sel(v):
    if not isinstance(v, str) or not (1 <= len(v) <= MAX_SEL):
        raise StepValidationError(f"sélecteur invalide (str, 1..{MAX_SEL})")
    return v


def _one(step):
    if not isinstance(step, dict) or len(step) != 1:
        raise StepValidationError("chaque step doit être un objet mono-clé")
    (verb, arg), = step.items()
    if verb == "goto":
        if not isinstance(arg, str) or len(arg) > 2048:
            raise StepValidationError("goto: url invalide ou trop longue")
        try:
            validate_capture_url(arg)
        except ValueError as e:
            # e vient de engine.ssrf (hors périmètre de ce correctif) : on ne
            # fait pas confiance à sa longueur, on la borne ici aussi.
            raise StepValidationError(f"goto SSRF/scheme: {_bounded_repr(str(e))}")
        return {"goto": arg}
    if verb == "fill":
        if not isinstance(arg, dict) or set(arg) != {"sel", "value"}:
            raise StepValidationError("fill: {sel, value} attendu")
        val = arg["value"]
        if not isinstance(val, str) or len(val) > MAX_VALUE:
            raise StepValidationError(f"fill.value invalide (str ≤ {MAX_VALUE})")
        return {"fill": {"sel": _sel(arg["sel"]), "value": val}}
    if verb == "click":
        return {"click": _sel(arg)}
    if verb == "wait":
        if isinstance(arg, bool):
            raise StepValidationError("wait invalide")
        if isinstance(arg, int):
            if not (0 <= arg <= MAX_WAIT_MS):
                raise StepValidationError(f"wait ms 0..{MAX_WAIT_MS}")
            return {"wait": arg}
        if isinstance(arg, dict) and set(arg) == {"selector"}:
            return {"wait": {"selector": _sel(arg["selector"])}}
        raise StepValidationError("wait: ms int ou {selector}")
    if verb == "press":
        if not isinstance(arg, str) or arg not in ALLOWED_PRESS_KEYS:
            # arg peut être n'importe quel JSON (liste, dict, str géante...) :
            # borner INCONDITIONNELLEMENT, indépendamment du type (cf. audit 3c).
            raise StepValidationError(f"press hors allowlist: {_bounded_repr(arg)}")
        return {"press": arg}
    if verb == "sleep":
        # Pause fixe exprimée en SECONDES (unité par défaut, intuitive ; convertie
        # en ms à l'exécution). Accepte un entier ou un flottant (ex. 0.5).
        # `bool` est un `int` en Python -> rejeté d'abord (pas de true/false).
        if isinstance(arg, bool) or not isinstance(arg, (int, float)) or not (0 <= arg <= MAX_SLEEP_S):
            raise StepValidationError(f"sleep: secondes 0..{MAX_SLEEP_S}")
        return {"sleep": arg}
    if verb == "hide":
        # Masque le(s) élément(s) correspondant au sélecteur (display:none) —
        # ex. bannières cookies/overlays avant une capture. Sélecteur borné par
        # `_sel` ; le JS exécuté côté runner est FIXE (jamais interpolé).
        return {"hide": _sel(arg)}
    if verb == "capture":
        # Forme simple : label str (capture du viewport). Forme étendue :
        # {label, selector?, full_page?} — `selector` capture une RÉGION (un
        # élément), `full_page` capture la PAGE ENTIÈRE. selector et full_page
        # sont mutuellement exclusifs (une région n'est jamais « full page »).
        if isinstance(arg, str):
            if not _LABEL_RE.fullmatch(arg):
                raise StepValidationError("capture: label [\\w .:-] ≤ 64")
            return {"capture": arg}
        if isinstance(arg, dict):
            extra = set(arg) - {"label", "selector", "full_page"}
            if extra:
                raise StepValidationError("capture: clés {label, selector?, full_page?}")
            label = arg.get("label", "capture")
            if not isinstance(label, str) or not _LABEL_RE.fullmatch(label):
                raise StepValidationError("capture.label [\\w .:-] ≤ 64")
            out = {"label": label}
            if "selector" in arg and "full_page" in arg:
                raise StepValidationError("capture: selector et full_page exclusifs")
            if "selector" in arg:
                out["selector"] = _sel(arg["selector"])
            if "full_page" in arg:
                if not isinstance(arg["full_page"], bool):
                    raise StepValidationError("capture.full_page: bool")
                out["full_page"] = arg["full_page"]
            return {"capture": out}
        raise StepValidationError("capture: label str ou {label, selector?, full_page?}")
    if verb == "scroll":
        if arg in ("top", "bottom"):
            return {"scroll": arg}
        if isinstance(arg, int) and not isinstance(arg, bool) and 0 <= arg <= MAX_SCROLL_PX:
            return {"scroll": arg}
        raise StepValidationError("scroll: 'top'|'bottom'|px")
    raise StepValidationError(f"verbe non autorisé: {verb[:64]!r}")


def validate_steps(raw):
    if not isinstance(raw, list):
        raise StepValidationError("steps doit être une liste")
    # La borne porte sur les steps utilisateur ; la capture finale auto
    # (ajoutée par une validation antérieure) est exemptée pour garantir
    # l'idempotence — le web normalise puis le runner re-valide la sortie.
    effective = raw[:-1] if (raw and isinstance(raw[-1], dict) and set(raw[-1]) == {"capture"}) else raw
    if len(effective) > MAX_STEPS:
        raise StepValidationError(f"trop de steps (max {MAX_STEPS})")
    out = [_one(s) for s in raw]
    # capture final implicite : garantit un screenshot d'état de fin,
    # sauf si le dernier step normalisé est déjà un `capture`.
    if not (out and set(out[-1]) == {"capture"}):
        out.append({"capture": "final"})
    return out


def redact_step(step):
    if set(step) == {"fill"}:
        return {"fill": {"sel": step["fill"]["sel"], "value": "***"}}
    return copy.deepcopy(step)
