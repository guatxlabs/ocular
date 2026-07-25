# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import re
from typing import NamedTuple, Optional

from engine.result import Severity, StaticFinding

# --- Budgets de balayage -------------------------------------------------------
# Le document balayé est HOSTILE par définition : sa TAILLE, sa FORME et la
# DENSITÉ de chaque amorce sont choisies par l'attaquant. Un moteur à
# rétro-action (le `re` de CPython) coûte, pour un motif donné :
#
#     (nombre de positions de départ) × (travail par position de départ)
#
# Un quantificateur NON BORNÉ (`*`, `+`, `{n,}`) rend le second facteur
# proportionnel à la taille du document : le moteur consomme jusqu'à la fin puis
# rétrograde depuis CHAQUE position de départ -> coût QUADRATIQUE. C'est ce qui
# était mesuré ici, forme `eval(` répétée, chemin complet (analyze_html +
# extract_forms + extract_mailtos), avant ce correctif :
#
#     16 Kio 332 ms · 32 Kio 1 392 ms · 64 Kio 5 648 ms · 128 Kio 27 295 ms
#
# soit ×4 par DOUBLEMENT de taille — et ZÉRO détection produite, donc rien à
# voir avec le nombre de matches. Forme `<input` répétée : 128 Kio = 52 608 ms.
#
# Les constantes ci-dessous bornent le travail par position de départ. Elles ne
# sont pas des « cas couverts » : `_compile_bounded` REFUSE À L'IMPORT tout motif
# de ce module qui contiendrait encore un quantificateur non borné (cf. plus
# bas), donc la propriété vaut pour les motifs présents ET futurs.
#
# Deux familles, et la différence est ce qui fixe le coût :
#
#   - Classe qui EXCLUT les caractères de sa propre amorce (`[^<>]` après
#     `<form`, `[^"']` après une quote ouvrante) : le balayage d'une position
#     s'arrête au caractère suivant qui pourrait ouvrir la position SUIVANTE.
#     Les intervalles balayés sont donc DISJOINTS, leur somme vaut le document
#     une fois, et le coût est linéaire QUELLE QUE SOIT la borne. C'est aussi la
#     classe CORRECTE : une zone d'attributs ne contient ni `<` ni `>`, une
#     valeur entre quotes ne contient pas sa quote. D'où des bornes larges.
#
#   - Classe qui n'exclut PAS son amorce (`[^)]` après `eval(`, `[^;]` après
#     `innerHTML=`) : les intervalles se recouvrent, le coût est
#     `borne / longueur_d_amorce` par caractère de document. Ces bornes-là sont
#     serrées et CALIBRÉES SUR UNE MESURE de contenu réel (1 437 fichiers
#     HTML/JS de cette machine dont 10 échantillons malveillants réels) :
#         `[^)]` : 111 occurrences, p50=5, p99=52, max=166   -> borne 200
#         `[^;]` : 321 occurrences, p50=31, p99=1006, max=1217 -> borne 4096
#     Aucune occurrence réelle mesurée n'est perdue à ces bornes (0/111, 0/321).
#     La borne 200 de `[^)]` a une seconde justification, structurelle :
#     `StaticFinding.match` vaut `m.group(0)[:200]`, donc un argument plus long
#     n'apparaissait DÉJÀ pas dans la sortie. Elle porte le motif le plus cher du
#     lot — mesuré à 67 % du coût total sur la forme `eval(` répétée.
#     `[^;]` n'a pas de caractère de fermeture à trouver, donc il apparie sans
#     rétrograder : sa borne est large sans coûter.
_WS = r"\s{0,32}"        # séparateur entre lexèmes (mesuré sur le corpus : run max = 1)
_WS1 = r"\s{1,32}"
_ATTR = r"[^<>]{0,262144}"        # zone d'attributs À L'INTÉRIEUR d'une balise
_AVAL = r"[^\"'<>]{1,262144}"     # valeur d'attribut À L'INTÉRIEUR d'une balise
_SVAL = r"[^\"']{1,262144}"       # littéral de chaîne JS (peut contenir `<`)
_SVAL0 = r"[^\"']{0,262144}"
_ARG = r"[^)]{1,200}"             # argument d'un appel JS   — calibré, cf. ci-dessus
_STMT = r"[^;]{1,4096}"           # membre droit d'affectation JS — idem

# (pattern, description, severity) — porté d'un détecteur interne antérieur.
PATTERNS: list[tuple[str, str, Severity]] = [
    # Malicious redirection: not explicitly listed in the Phase 3d-2j re-tier
    # table, but structurally identical to its siblings "Forced URL change" /
    # "Forced navigation" (also plain navigation signals) -> tiered "low" too.
    (rf"window\.location{_WS}[=.].{{0,80}}?[\"']({_SVAL})[\"']", "Malicious redirection", "low"),
    (rf"location\.href{_WS}={_WS}[\"']({_SVAL})[\"']", "Forced URL change", "low"),
    (rf"document\.location{_WS}={_WS}[\"']({_SVAL})[\"']", "Forced navigation", "low"),
    (rf"eval{_WS}\({_WS}({_ARG})\)", "Dynamic code evaluation", "high"),
    (rf"Function{_WS}\({_WS}[\"']({_SVAL0})[\"']", "Dynamic function creation", "high"),
    # setTimeout/setInterval avec une chaîne = exécution de code par chaîne
    # (équivalent d'un eval différé) -> signal fort "high", et membres de _OBF
    # côté verdict (cf. engine/verdict.py).
    (rf"setTimeout{_WS}\({_WS}[\"']({_SVAL})[\"']", "Delayed code execution", "high"),
    (rf"setInterval{_WS}\({_WS}[\"']({_SVAL})[\"']", "Repeated code execution", "high"),
    (rf"document\.write{_WS}\({_WS}({_ARG})\)", "Direct DOM write", "medium"),
    (rf"innerHTML{_WS}={_WS}({_STMT})", "HTML injection", "low"),
    (rf"outerHTML{_WS}={_WS}({_STMT})", "Complete HTML replacement", "low"),
    (rf"fetch{_WS}\({_WS}[\"']({_SVAL})[\"']", "Fetch request", "low"),
    (rf"XMLHttpRequest{_WS}\({_WS}\)", "AJAX request", "low"),
    (rf"\.submit{_WS}\({_WS}\)", "Form submission", "low"),
    (rf"<form{_ATTR}action{_WS}={_WS}[\"']({_AVAL})[\"']", "Form action URL", "low"),
    (rf"<form{_ATTR}action{_WS}={_WS}[\"']https?://{_AVAL}[\"']", "External form action", "medium"),
    (rf"<form{_ATTR}method{_WS}={_WS}[\"']post[\"']", "POST form detected", "low"),
    (rf"<img{_ATTR}src{_WS}={_WS}[\"']https?://({_AVAL})[\"']", "External image", "medium"),
    (rf"<script{_ATTR}src{_WS}={_WS}[\"']https?://({_AVAL})[\"']", "External script", "medium"),
    (r"document\.cookie", "Cookie access", "low"),
    (rf"localStorage\.getItem{_WS}\({_WS}[\"']({_SVAL})[\"']", "Local storage read", "low"),
    (rf"sessionStorage\.getItem{_WS}\({_WS}[\"']({_SVAL})[\"']", "Session storage read", "low"),
    (rf"localStorage\.setItem{_WS}\({_WS}[\"']({_SVAL})[\"']", "Local storage write", "low"),
    (r"navigator\.userAgent", "Browser detection", "low"),
    (r"navigator\.platform", "OS detection", "low"),
    (r"screen\.width|screen\.height", "Resolution detection", "low"),
    (r"navigator\.language", "Language detection", "low"),
    (rf"on(?:click|load|error|focus|blur|submit){_WS}={_WS}[\"']({_SVAL})[\"']", "Event handler", "low"),
    (rf"addEventListener{_WS}\({_WS}[\"']({_SVAL})[\"']", "Event listener", "low"),
    (rf"onsubmit{_WS}=", "Form submit handler", "low"),
    (rf"oncopy{_WS}={_WS}[\"']return{_WS1}false[\"']", "Copy disabled", "low"),
    (rf"onpaste{_WS}=", "Paste handler", "low"),
    # Iframe/object/embed restent "medium" (pas "high") : les embeds tiers
    # (YouTube, maps, widgets, pubs) sont extrêmement courants sur des pages
    # légitimes -> choix anti-faux-positif assumé.
    (rf"<iframe{_ATTR}src{_WS}={_WS}[\"']({_AVAL})[\"']", "Embedded iframe", "medium"),
    (rf"<object{_ATTR}data{_WS}={_WS}[\"']({_AVAL})[\"']", "Embedded object", "medium"),
    (rf"<embed{_ATTR}src{_WS}={_WS}[\"']({_AVAL})[\"']", "Embedded content", "medium"),
    (rf"atob{_WS}\({_WS}[\"']({_SVAL})[\"']", "Base64 decode", "medium"),
    (rf"atob{_WS}\(", "Base64 decoding function", "low"),
    (rf"btoa{_WS}\({_WS}({_ARG})\)", "Base64 encode", "low"),
    (rf"unescape{_WS}\({_WS}[\"']({_SVAL})[\"']", "URL decode", "medium"),
    (rf"String\.fromCharCode{_WS}\(({_ARG})\)", "String construction", "medium"),
    (rf"charCodeAt{_WS}\(", "Character code access", "low"),
    (rf"<input{_ATTR}type{_WS}={_WS}[\"']password[\"']", "Password input field", "low"),
    (rf"<input{_ATTR}name{_WS}={_WS}[\"']pass", "Password field (name)", "low"),
    (rf"<input{_ATTR}name{_WS}={_WS}[\"']email", "Email input field", "low"),
    (rf"<input{_ATTR}name{_WS}={_WS}[\"']user", "Username input field", "low"),
    # Langage d'urgence (phishing) — couverture EN + FR + ES + DE + PT. Tous les
    # patterns non-EN sont mappés sur les MÊMES `rule` names que l'anglais pour
    # rejoindre le cluster _URGENCY côté verdict (cf. engine/verdict.py).
    # Quantificateurs bornés `.{0,20}` (pas d'imbrication) -> ReDoS-safe.
    # Collocations mot-clé+proximité (pas de mot isolé trop courant type
    # compte/cuenta/konto/conta) -> anti-faux-positif.
    # Quantificateurs BORNÉS `.{0,20}` comme les variantes non-EN ci-dessous :
    # un `.*` glouton non borné ici est un ReDoS quadratique : l'ancien
    # `verify.*account` pinnait un cœur broker plusieurs dizaines de secondes.
    (r"verify.{0,20}account", "Account verification text", "medium"),
    (r"confirm.{0,20}identity", "Identity confirmation text", "medium"),
    (r"update.{0,20}payment", "Payment update text", "medium"),
    (r"suspended.{0,20}account", "Account suspended text", "medium"),
    (r"v[eé]rifi.{0,25}(compte|identit)", "Account verification text", "medium"),
    (r"confirm.{0,25}(identit|compte)", "Identity confirmation text", "medium"),
    (r"(mett|mise).{0,20}jour.{0,20}paiement", "Payment update text", "medium"),
    (r"compte.{0,20}(suspendu|bloqu[eé]|d[eé]sactiv)", "Account suspended text", "medium"),
    # ES — le radical "verific" ne couvre pas la forme "verifique" (c -> qu
    # devant e en espagnol) -> alternance des deux radicaux.
    (r"(?:verific|verifiqu).{0,25}cuenta", "Account verification text", "medium"),
    (r"confirm.{0,25}(identidad|cuenta)", "Identity confirmation text", "medium"),
    (r"actualiz.{0,25}pago", "Payment update text", "medium"),
    (r"cuenta.{0,20}(suspendid|bloquead|desactivad)", "Account suspended text", "medium"),
    # DE — l'allemand place souvent le verbe avant l'objet ("Bitte
    # verifizieren Sie Ihr Konto" / "Bestätigen Sie Ihre Identität") ->
    # alternance des deux ordres, toujours avec écarts bornés `.{0,20}`.
    (
        r"(?:konto|zugang).{0,20}(?:verifizier|best[aä]tig)\w{0,15}"
        r"|(?:verifizier|best[aä]tig).{0,25}(?:konto|zugang)",
        "Account verification text",
        "medium",
    ),
    (
        r"identit[aä]t.{0,20}best[aä]tig\w{0,15}|best[aä]tig.{0,25}identit[aä]t",
        "Identity confirmation text",
        "medium",
    ),
    (
        r"zahlung.{0,25}aktualisier\w{0,15}|aktualisier.{0,25}zahlung",
        "Payment update text",
        "medium",
    ),
    (r"konto.{0,20}(gesperrt|deaktiviert|suspendier)", "Account suspended text", "medium"),
    # PT — même remarque qu'en ES ("verifique" via c -> qu).
    (r"(?:verific|verifiqu).{0,25}conta", "Account verification text", "medium"),
    (r"confirm.{0,25}(identidade|conta)", "Identity confirmation text", "medium"),
    (r"atualiz.{0,25}pagamento", "Payment update text", "medium"),
    (r"conta.{0,20}(suspens|bloquead|desativ)", "Account suspended text", "medium"),
]

class UnboundedPatternError(ValueError):
    """Un motif de ce module contient un quantificateur non borné. Levée À
    L'IMPORT : le module ne peut pas se charger, donc aucun chemin d'exécution
    ne peut balayer du contenu hostile avec un motif à coût non borné."""


def quantifier_bounds(pattern: str) -> list[Optional[int]]:
    """Borne haute de CHAQUE quantificateur de `pattern`, dans l'ordre ; `None`
    pour un quantificateur NON BORNÉ (`*`, `+`, `{n,}`, y compris leurs formes
    paresseuse `*?` et possessive `*+`).

    Analyseur à la main plutôt qu'une regex sur la regex : il faut distinguer un
    `*` littéral d'un quantificateur, ce qui demande de suivre les échappements
    (`\\*`) et les classes de caractères (`[*+]`), qu'aucune expression régulière
    ne fait de façon fiable. Lève `UnboundedPatternError` si un groupe QUANTIFIÉ
    contient lui-même un quantificateur (imbrication) : c'est l'autre façon de
    faire exploser le travail par position de départ, et aucun motif de ce
    module n'en a besoin."""
    bounds: list[Optional[int]] = []
    stack: list[list[Optional[int]]] = [bounds]
    i, n = 0, len(pattern)

    def read_quant(j: int) -> Optional[tuple[Optional[int], int]]:
        """(borne_haute, position_suivante) si un quantificateur commence en `j`."""
        if j >= n:
            return None
        c = pattern[j]
        if c in "*+":
            j += 1
        elif c == "?":
            return 1, j + 1
        elif c == "{":
            m = re.match(r"\{(\d*)(,?)(\d*)\}", pattern[j:])
            if not m or not (m.group(1) or m.group(3)):
                return None                      # `{` littéral
            lo, comma, hi = m.groups()
            j += m.end()
            top = int(hi) if hi else (None if comma else int(lo))
            if j < n and pattern[j] in "?+":     # `{m,n}?` / `{m,n}+`
                j += 1
            return top, j
        else:
            return None
        if j < n and pattern[j] in "?+":         # `*?` / `*+` / `+?` / `++`
            j += 1
        return None, j

    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
        elif c == "[":
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":      # `]` en 1re position = littéral
                i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
        elif c == "(":
            stack.append([])
            i += 1
            if i < n and pattern[i] == "?":      # (?: (?= (?! (?<= (?P<n> ...
                i += 1
                while i < n and pattern[i] not in ":)":
                    i += 2 if pattern[i] == "\\" else 1
                if i < n and pattern[i] == ":":
                    i += 1
        elif c == ")":
            inner = stack.pop() if len(stack) > 1 else []
            i += 1
            q = read_quant(i)
            if q is not None:
                top, i = q
                if any(b is None or b > 1 for b in inner):
                    raise UnboundedPatternError(
                        f"quantificateur imbriqué dans un groupe quantifié : {pattern!r}"
                    )
                stack[-1].append(top)
            stack[-1].extend(inner)
        else:
            q = read_quant(i)
            if q is None:
                i += 1
            else:
                top, i = q
                stack[-1].append(top)
    return bounds


def _compile_bounded(pattern: str) -> re.Pattern[str]:
    """SEUL endroit de ce module où une expression régulière devient un
    apparieur. Toute regex qui balaye du contenu de page passe par ici — les 64
    motifs de `PATTERNS` comme les 4 extracteurs `_FORM_TAG_RE` / `_ACTION_RE` /
    `_METHOD_RE` / `_MAILTO_RE`, qui balayaient eux aussi le document entier
    (`<form\\b[^>]*>` était quadratique sur `<form` répété, exactement comme les
    motifs de détection).

    La garde n'énumère pas des cas à bloquer : elle REFUSE la propriété
    manquante. Un motif à quantificateur non borné fait échouer l'import du
    module — impossible d'en ajouter un plus tard sans que la suite le voie."""
    for position, bound in enumerate(quantifier_bounds(pattern)):
        if bound is None:
            raise UnboundedPatternError(
                f"quantificateur non borné n°{position + 1} dans {pattern!r} : "
                "le coût par position de départ deviendrait proportionnel à la "
                "taille du document analysé (donc quadratique, cf. en-tête de "
                "engine/static.py). Bornez-le (`{0,N}`)."
            )
    return re.compile(pattern, re.IGNORECASE)


_COMPILED = [(_compile_bounded(p), d, s) for p, d, s in PATTERNS]

# --- Fenêtre d'analyse ---------------------------------------------------------
# Deuxième borne, INDÉPENDANTE de la forme du contenu. Les motifs bornés ci-dessus
# rendent le coût LINÉAIRE en la taille du document ; celle-ci borne la TAILLE, et
# c'est la conjonction des deux qui donne un plafond de temps en millisecondes —
# le seul chiffre qu'un exploitant puisse utiliser.
#
# L'unité est le CARACTÈRE et non l'octet UTF-8, contrairement aux plafonds
# d'`engine.wrapper` : ce budget-ci borne un coût CPU (le moteur `re` balaye des
# caractères d'un `str` déjà en mémoire), pas une empreinte mémoire. Annoncer des
# octets ici serait annoncer la mauvaise grandeur.
_DEFAULT_MAX_ANALYZED_HTML_CHARS = 512 * 1024
_HARD_MAX_ANALYZED_HTML_CHARS = 16 * 1024 * 1024
_warned_env: set[str] = set()


def max_analyzed_html_chars() -> int:
    """`OCULAR_MAX_ANALYZED_HTML_CHARS`, défaut 2 097 152 caractères. Plancher 1,
    borne haute 16 777 216 : ce plafond se baisse, il ne se retire pas. Toute
    valeur illisible ou hors bornes est journalisée UNE FOIS par variable (le
    volume de journal ne doit pas être dicté par le trafic de la page)."""
    raw = os.environ.get("OCULAR_MAX_ANALYZED_HTML_CHARS")
    if raw is None:
        return _DEFAULT_MAX_ANALYZED_HTML_CHARS
    try:
        val = int(raw)
    except ValueError:
        _warn_once("OCULAR_MAX_ANALYZED_HTML_CHARS illisible=%r — défaut %d retenu",
                   raw, _DEFAULT_MAX_ANALYZED_HTML_CHARS)
        return _DEFAULT_MAX_ANALYZED_HTML_CHARS
    clamped = min(max(1, val), _HARD_MAX_ANALYZED_HTML_CHARS)
    if clamped != val:
        _warn_once("OCULAR_MAX_ANALYZED_HTML_CHARS=%d hors bornes [1, %d] — ramené à %d",
                   val, _HARD_MAX_ANALYZED_HTML_CHARS, clamped)
    return clamped


def _warn_once(fmt: str, *args: object) -> None:
    import logging
    key = fmt % args
    if key in _warned_env:
        return
    _warned_env.add(key)
    logging.getLogger("ocular.static").warning(fmt, *args)


def analysis_window(html: str) -> tuple[str, int]:
    """SEUL endroit où l'on décide COMBIEN de document est balayé. Rend
    `(fenêtre, caractères_écartés)`. Les trois fonctions de balayage de ce module
    (`scan_html`, `extract_forms`, `extract_mailtos`) commencent par cet appel :
    aucune d'elles ne peut voir plus que cette fenêtre."""
    cap = max_analyzed_html_chars()
    if len(html) <= cap:
        return html, 0
    return html[:cap], len(html) - cap


class HtmlScan(NamedTuple):
    """Résultat du balayage statique + ce qu'il n'a PAS regardé.
    `chars_dropped` > 0 = le document a été tronqué AVANT analyse : les
    détections qui vivaient au-delà n'existent pas dans ce résultat. Jamais
    tu — cf. `OcularResult.truncation.html_chars_dropped`."""
    findings: list[StaticFinding]
    chars_dropped: int


def scan_html(html: str) -> HtmlScan:
    """SEUL balayage statique du module. Le contenu est HOSTILE par définition :
    sa taille, sa forme et la densité de chaque amorce sont choisies par
    l'attaquant. Deux bornes, indépendantes l'une de l'autre :

    1. `analysis_window` borne la TAILLE réellement balayée et DIT ce qu'elle a
       écarté (`HtmlScan.chars_dropped`) ;
    2. `_compile_bounded` garantit qu'aucun motif n'a de quantificateur non
       borné, donc que le travail par position de départ ne dépend PAS de la
       taille du document.

    Ce qui est MESURÉ après ces deux bornes est dans l'en-tête du module et dans
    tests/test_static_linear.py — pas d'affirmation ici que la mesure ne porte.

    Le numéro de ligne, lui, était recalculé depuis le début pour CHAQUE match
    (`html.count("\\n", 0, m.start())`), soit O(n) par match. `finditer` rend les
    matches par position croissante : on compte donc les sauts de ligne PAR
    INTERVALLE DISJOINT depuis le match précédent. La somme des intervalles d'une
    passe vaut la fenêtre une seule fois, à résultat identique (vérifié contre le
    recomptage naïf dans tests/test_static_linear.py)."""
    html, dropped = analysis_window(html)
    findings: list[StaticFinding] = []
    for rx, description, severity in _COMPILED:
        cursor = 0     # fin de l'intervalle déjà compté pour ce motif
        line = 1       # numéro de ligne à la position `cursor`
        for m in rx.finditer(html):
            line += html.count("\n", cursor, m.start())
            cursor = m.start()
            start = max(0, m.start() - 30)
            findings.append(
                StaticFinding(
                    rule=description,
                    severity=severity,
                    match=m.group(0)[:200],
                    line=line,
                    context=html[start : m.end() + 30].replace("\n", " ")[:200],
                )
            )
    return HtmlScan(findings, dropped)


def analyze_html(html: str) -> list[StaticFinding]:
    """Vue « détections seules » de `scan_html`, pour les appelants qui n'ont pas
    de marqueur de troncature à porter. Ce n'est PAS un second chemin de
    balayage : la fenêtre et les motifs bornés s'appliquent à l'identique, parce
    que tout passe par `scan_html`."""
    return scan_html(html).findings


# --- extraction structurée formulaires + mailto (Phase 3j) ---------------------
# Où atterrit la saisie utilisateur d'une page : c'est l'indicateur d'exfiltration
# le plus direct d'un kit de phishing. On expose, pour l'analyste, l'action de
# CHAQUE formulaire (méthode + destination — un POST vers un domaine tiers ou un
# mailto trahit un harvester) et TOUTES les cibles mailto de la page. Tout est
# borné (anti-DoS) et purement regex (pas de dépendance parseur ; même style que
# le reste du module). Partagé par les 4 tiers (analyse HTML, capture, scripté,
# interactif) via le remplissage de `DomInfo.forms` / `DomInfo.mailtos`.
_MAX_FORMS = 100
_MAX_MAILTOS = 100
# Mêmes garde et même fenêtre que les motifs de détection : ces quatre-là
# balayent le MÊME document hostile, et `<form\b[^>]*>` était quadratique sur
# `<form` répété pour exactement la même raison.
_FORM_TAG_RE = _compile_bounded(rf"<form\b{_ATTR}>")
_ACTION_RE = _compile_bounded(rf"\baction{_WS}={_WS}[\"']({_AVAL}|)[\"']")
_METHOD_RE = _compile_bounded(rf"\bmethod{_WS}={_WS}[\"']({_AVAL}|)[\"']")
_MAILTO_RE = _compile_bounded(
    rf"(?:href|action){_WS}={_WS}[\"']{_WS}(mailto:{_SVAL})[\"']"
)


def extract_forms(html: str) -> list[dict]:
    """Liste `[{action, method}]` des formulaires (méthode en MAJUSCULES, GET par
    défaut ; action vide = soumission vers l'URL courante = auto-post). Borné."""
    html, _ = analysis_window(html)
    forms: list[dict] = []
    for m in _FORM_TAG_RE.finditer(html):
        tag = m.group(0)
        am = _ACTION_RE.search(tag)
        mm = _METHOD_RE.search(tag)
        action = (am.group(1).strip() if am else "")[:500]
        method = (mm.group(1).strip().upper() if mm and mm.group(1).strip() else "GET")[:16]
        forms.append({"action": action, "method": method})
        if len(forms) >= _MAX_FORMS:
            break
    return forms


def extract_mailtos(html: str) -> list[str]:
    """Cibles `mailto:` uniques (liens ET actions de formulaire), ordre stable, bornées."""
    html, _ = analysis_window(html)
    seen: list[str] = []
    for m in _MAILTO_RE.finditer(html):
        val = m.group(1).strip()[:320]
        if val not in seen:
            seen.append(val)
            if len(seen) >= _MAX_MAILTOS:
                break
    return seen
