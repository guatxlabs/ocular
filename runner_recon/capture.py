from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
import time
from typing import Any, AsyncIterator, Optional
from urllib.parse import urlsplit, urlunsplit

from ocular_logging import get_logger

# CRITIQUE : comme runner_analysis/render.py — stdout = wrapper JSON pur consommé
# par broker/launcher.py. Tous les logs partent sur stderr.
#
# DOIT s'exécuter AVANT tout import qui déclenche, indirectement, un premier
# appel à `ocular_logging.get_logger(...)` SANS préciser `stream` — notamment
# `engine.egress_guard` (plan 3g Task G2), qui fait `logger = get_logger(
# "egress_guard")` À SON IMPORT. `get_logger` configure un handler UNIQUE,
# partagé par tout le process (`ocular_logging._CONFIGURED`, cf. docstring
# du module) : le PREMIER appelant gagne le `stream` pour TOUS les loggers
# "ocular.*" ultérieurs, y compris celui-ci. Sans cet ordre, les logs du
# garde (ex. "egress blocked host=...") atterriraient sur stdout et
# corrompraient le JSON du wrapper que lit `broker/launcher.py` — régression
# réelle observée empiriquement en intégration avant ce fix (cf.
# tests/test_egress_integration.py, échec `JSONDecodeError: Extra data`).
log = get_logger("runner-recon", stream=sys.stderr)

from engine.browser_js import CF_INDICATOR_JS, SCROLL_TO_LOAD_JS  # noqa: E402
from engine.egress_policy import hardened_launch_kwargs, maybe_start_egress_guard  # noqa: E402
from engine.result import DomInfo, DynamicStep, OcularResult, StealthInfo  # noqa: E402
from engine.static import analyze_html, extract_forms, extract_mailtos  # noqa: E402
from engine.steps import validate_steps  # noqa: E402
from engine.urlnorm import url_input_hash  # noqa: E402
from engine.verdict import compute_verdict  # noqa: E402
from engine.wrapper import NetworkCapture, ResultBuilder, emit_wrapper  # noqa: E402
from runner_recon.steps_exec import run_steps  # noqa: E402

# Budget wall-clock TOTAL de l'exécution des steps scriptés (3c Global
# Constraint : « timeout d'exécution total 120s -> arrêt + résultat partiel »).
# Séparé du timeout conteneur broker (`broker/launcher.py:_SCRIPTED_TIMEOUT`,
# 180s) : ce budget est appliqué PAR le runner (via `run_steps(deadline=...)`)
# pour émettre un résultat partiel AVANT que le broker ne `docker kill` le
# conteneur — la marge de 60s couvre le démarrage Camoufox + l'extraction DOM
# finale après l'arrêt du budget.
SCRIPTED_EXEC_TIMEOUT_S = 120


def _scripted_deadline() -> float:
    """Instant absolu `time.monotonic()` au-delà duquel le budget wall-clock
    total de la séquence de steps est épuisé. Fonction pure, isolée pour être
    testable sans navigateur (cf. tests/test_capture_scripted_logic.py)."""
    return time.monotonic() + SCRIPTED_EXEC_TIMEOUT_S


def _analyze(dom_html: bytes) -> list:
    """Factorisé entre le chemin 3a (`build_result`) et le chemin scripté 3c
    (`capture_scripted`) — même calcul de findings statiques à partir du DOM
    capturé, une seule implémentation."""
    return analyze_html(dom_html.decode("utf-8", "replace")) if dom_html else []


# Snippet partagé (source unique engine/browser_js) — parcours pas-à-pas pour
# déclencher le lazy-load avant une capture full-page.
_SCROLL_TO_LOAD_JS = SCROLL_TO_LOAD_JS


async def _scroll_to_load(page: Any) -> None:
    """Parcourt la page (pas à pas) pour déclencher le lazy-loading AVANT une
    capture full-page, puis attend que le réseau se calme (contenus déclenchés
    par le scroll effectivement chargés) — la capture ne part QU'APRÈS. Tout est
    best-effort et borné : une page hostile/instable ne fait jamais échouer la
    capture ni dépasser le budget."""
    with contextlib.suppress(Exception):
        await page.evaluate(_SCROLL_TO_LOAD_JS)          # attend la FIN du parcours
    with contextlib.suppress(Exception):
        await page.wait_for_load_state("networkidle", timeout=5000)  # réseau calmé


def _dom_info(dom_html: bytes, title: str, final_url: str) -> DomInfo:
    """DomInfo enrichi des formulaires (action+méthode) et cibles mailto extraits
    du DOM (indicateurs d'exfiltration ; cf. static.extract_forms/extract_mailtos).
    Factorisé entre les deux chemins de capture (3a et scripté)."""
    dom_str = dom_html.decode("utf-8", "replace") if dom_html else ""
    return DomInfo(
        title=title, final_url=final_url,
        forms=extract_forms(dom_str), mailtos=extract_mailtos(dom_str),
    )


def journal_to_dynamic_steps(
    journal: list[dict[str, Any]], capture_refs: list[str]
) -> list[DynamicStep]:
    """Traduit le journal `run_steps` (déjà redigé — chaque entrée porte
    `step` passé par `engine.steps.redact_step`, jamais de valeur `fill` en
    clair) en `list[DynamicStep]` — le schéma EXISTANT de `OcularResult`
    (pas de nouveau champ `actions`, cf. plan 3c). Fonction pure, testable
    sans navigateur.

    `action` : libellé lisible du step (JSON compact du step redigé).
    `screenshot_ref` : renseigné UNIQUEMENT pour un step `capture`, associé
    PAR ORDRE (Nième `capture` du journal <-> Nième ref) et NON par label —
    `screenshot_cb` est appelé une fois par `capture` dans l'ordre et empile
    les refs dans une liste ordonnée (cf. `capture_scripted`). Associer par
    label écraserait la clé pour deux captures homonymes -> les deux
    `DynamicStep` pointeraient le même (dernier) screenshot : preuve
    forensique mal associée. Un `capture` en échec (ex. screenshot qui lève,
    toujours le dernier step puisque l'échec arrête la séquence) n'a produit
    aucune ref -> `screenshot_ref=None`.
    `ok`/`duration_ms`/`error` : issus tels quels du journal.
    """
    refs_iter = iter(capture_refs)
    out: list[DynamicStep] = []
    for entry in journal:
        step = entry["step"]
        verb = next(iter(step))
        ref = next(refs_iter, None) if verb == "capture" else None
        out.append(
            DynamicStep(
                action=json.dumps(step, sort_keys=True, ensure_ascii=False),
                screenshot_ref=ref,
                ok=entry["ok"],
                duration_ms=entry.get("ms"),
                error=entry.get("error"),
            )
        )
    return out


def build_result(
    url: str,
    screenshots: list[tuple[int, str, bytes]],
    network: list[dict],
    console: list[dict],
    dom_html: bytes,
    title: str,
    final_url: str,
    turnstile_solved: bool,
) -> tuple[OcularResult, dict[str, bytes]]:
    """Logique pure (aucune dépendance navigateur) : compose l'`OcularResult`
    profil `capture` à partir de données déjà capturées. Testable directement
    sans Camoufox — c'est `capture_url` qui pilote le navigateur et lui fournit
    ces données."""
    builder = ResultBuilder()
    for step, phase, png in screenshots:
        builder.add_screenshot(step, phase, png)
    builder.set_dom(dom_html)

    findings = _analyze(dom_html)

    return builder.build(
        job_id="",
        profile="capture",
        target=url,
        input_hash=url_input_hash(url),
        verdict=compute_verdict(findings),
        dom_info=_dom_info(dom_html, title, final_url),
        stealth=StealthInfo(engine="camoufox", turnstile_solved=turnstile_solved),
        static_findings=findings,
        network=network,
        console=console,
    )


# Boucle de détection Turnstile : ~6 tentatives x 0.8s (5 pauses) = 4s de
# budget total avant d'abandonner (pas de Turnstile sur cette page -> chemin
# 3a inchangé, cf. solve_turnstile). Attente post-clic séparée (le widget met
# un instant à se mettre à jour après le clic avant de re-vérifier).
_TURNSTILE_RETRY_ATTEMPTS = 6
_TURNSTILE_RETRY_INTERVAL_S = 0.8
_TURNSTILE_POST_CLICK_WAIT_S = 4

# Gating (phase3f-F1a) : indicateur DOM booléen, PELÉ au tout début de
# `solve_turnstile`, AVANT tout screenshot/detect/clic. Le div `[data-sitekey]`/
# `.cf-turnstile` et le `<script>`/`<iframe>` `challenges.cloudflare.com`
# marquent la présence d'un challenge Cloudflare.
#
# ATTENTION (régression corrigée) : ces éléments NE sont PAS forcément
# présents dès `goto` — guatx.com les injecte de façon ASYNCHRONE (script CF
# chargé puis DOM muté après coup). Un check one-shot juste après `goto`
# manquait donc l'indicateur et sautait la résolution à tort. On POLL donc
# l'indicateur sur une courte fenêtre bornée (`_CF_INDICATOR_POLL_ATTEMPTS` x
# `_CF_INDICATOR_POLL_INTERVAL_S` ~ 3.6s) : l'injection async a le temps
# d'apparaître. Absent après toute la fenêtre -> pas de Turnstile sur cette
# page -> `return False` (aucune tentative de clic ; latence bornée par des
# `evaluate` légers, moins chers que les anciens screenshots+opencv). Présent
# (même tardivement) -> la boucle de retry vision + solve EXISTANTE s'exécute
# inchangée.
# Indicateur CF partagé (source unique engine/browser_js).
_CF_INDICATOR_JS = CF_INDICATOR_JS
_CF_INDICATOR_POLL_ATTEMPTS = 6
_CF_INDICATOR_POLL_INTERVAL_S = 0.6


async def solve_turnstile(
    page: Any,
    screenshots: list[tuple[int, str, bytes]],
    console: list[dict],
    vision_mod: Any,
    next_index: int = 1,
) -> "bool | None":
    """Détecte + résout un challenge Turnstile Cloudflare sur `page` (vision
    template matching + clic OS xdotool), appelée après le screenshot initial
    de `capture_url`. `vision_mod` est injecté (jamais un `import vision`
    local ici) : garde cette fonction testable avec un module mocké, sans
    navigateur ni dépendance opencv/numpy réelle (cf. tests/test_capture_logic.py).

    Corrige 2 causes racines (plan phase3d-2b) :
    - **timing** : le widget Turnstile se charge dans une iframe async, donc
      souvent absent du tout premier screenshot -> re-screenshot + re-détecte
      jusqu'à `_TURNSTILE_RETRY_ATTEMPTS` fois (~4s au total). Aucun match
      après toutes les tentatives -> pas de Turnstile sur cette page,
      comportement 3a inchangé (retourne `False` sans jamais cliquer).
    - **mapping** : `vision_mod.detect()` renvoie des px IMAGE (viewport du
      screenshot) alors que `human_click_xdotool` clique en px ÉCRAN -> offset
      via `window.mozInnerScreenX/Y` + `devicePixelRatio`
      (`vision_mod.image_to_screen`).

    Après le clic, attend `_TURNSTILE_POST_CLICK_WAIT_S` puis re-vérifie : la
    case a disparu du nouveau screenshot -> résolu (`True`) ; toujours
    présente -> pas résolu (`False`, logué en warning dans `console`).
    `turnstile_solved` reflète donc la réalité, jamais un optimiste `True` non
    vérifié (3e cause corrigée par le plan).

    Ne journalise jamais d'URL/secret : uniquement des coordonnées px et un
    booléen.

    **Gating (phase3f-F1a)** : avant tout screenshot/detect/clic, POLL
    l'indicateur DOM `_CF_INDICATOR_JS` (booléen, `page.evaluate`) sur une
    courte fenêtre bornée — l'injection Cloudflare est ASYNCHRONE (guatx.com),
    donc un check one-shot juste après `goto` la manquerait. Absent après
    toute la fenêtre -> `return False` (0 screenshot, 0 detect, 0 clic) : une
    page sans Turnstile ne paie plus les ~4s de screenshots+opencv de la
    boucle de retry, juste des `evaluate` légers. Présent (même tardivement)
    -> la boucle de retry vision + solve ci-dessous s'exécute exactement comme
    avant."""
    indicator = False
    for _ in range(_CF_INDICATOR_POLL_ATTEMPTS):
        if await page.evaluate(_CF_INDICATOR_JS):
            indicator = True
            break
        await asyncio.sleep(_CF_INDICATOR_POLL_INTERVAL_S)
    if not indicator:
        return None  # AUCUN challenge CF -> tri-état N.A. (pas un « non passé »)

    det = None
    for attempt in range(_TURNSTILE_RETRY_ATTEMPTS):
        png = await page.screenshot(full_page=False)
        det = vision_mod.detect(vision_mod.png_to_bgr(png), strategy="turnstile")
        if det is not None:
            break
        if attempt < _TURNSTILE_RETRY_ATTEMPTS - 1:
            await asyncio.sleep(_TURNSTILE_RETRY_INTERVAL_S)

    if det is None:
        # Indicateur CF présent mais widget non localisé par la vision : il Y A
        # un challenge, non résolu -> False (« non passé » honnête), pas None.
        return False

    off = await page.evaluate(
        "() => ({x: window.mozInnerScreenX, y: window.mozInnerScreenY, "
        "d: window.devicePixelRatio || 1})"
    )
    sx, sy = vision_mod.image_to_screen((det[0], det[1]), off["x"], off["y"], off["d"])
    log.info("turnstile detected img=(%d,%d) screen=(%d,%d)", det[0], det[1], sx, sy)
    await vision_mod.human_click_xdotool(sx, sy)

    await asyncio.sleep(_TURNSTILE_POST_CLICK_WAIT_S)
    png1 = await page.screenshot(full_page=False)
    screenshots.append((next_index, "post-turnstile", png1))

    still_there = vision_mod.detect(vision_mod.png_to_bgr(png1), strategy="turnstile") is not None
    solved = not still_there
    log.info("turnstile solved=%s", solved)
    if not solved:
        console.append({"level": "warning", "text": "turnstile: non résolu"})
    return solved


async def _goto_with_fallback(page: Any, url: str, timeout_ms: int, console: list[dict]) -> None:
    """Navigue `page` vers `url` ; si CETTE PREMIÈRE tentative lève ET que le
    schéma est `https`, retente UNE SEULE fois avec le même hôte/chemin/query
    en `http://` (jamais de boucle : au plus un fallback). Journalise l'échec
    initial (`console` "error", comme avant — inchangé) puis, si le fallback
    réussit, un `console` "warning" `scheme-fallback https->http` (jamais
    l'URL en clair). Un `goto` déjà en `http` qui échoue n'a PAS de fallback
    (il n'y a pas de schéma plus permissif à essayer).

    Factorisé entre `capture_url` (chemin 3a) et `capture_scripted` (chemin
    3c) : même politique de résilience réseau, une seule implémentation.
    Pas de valeur de retour : `page` porte déjà l'état de navigation (succès
    ou dernier échec) que les appelants lisent ensuite via `page.url` /
    `page.content()` / `page.title()`, exactement comme avant l'introduction
    du fallback."""
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        return
    except Exception as exc:
        console.append({"level": "error", "text": f"goto: {type(exc).__name__}"})

    scheme = urlsplit(url).scheme.lower()
    if scheme != "https":
        return

    parts = urlsplit(url)
    fallback_url = urlunsplit(("http", parts.netloc, parts.path, parts.query, parts.fragment))

    try:
        await page.goto(fallback_url, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception as exc:
        console.append({"level": "error", "text": f"goto: {type(exc).__name__}"})
        return

    console.append({"level": "warning", "text": "scheme-fallback https->http"})


# Budget de finalisation DOM (phase3f-F1c) : appliqué UNIQUEMENT au chemin
# scripté (`capture_scripted`), dont `page` peut être dans un état dégradé
# après un `run_steps` bancal (cf. commentaire au point d'appel). Court
# (15s) car résiduel : il mord sur la marge broker/launcher.py, pas sur le
# budget `SCRIPTED_EXEC_TIMEOUT_S` (déjà épuisé à ce stade dans le cas visé).
_DOM_FINALIZE_TIMEOUT_S = 15


async def _capture_dom(page: Any, url: str) -> tuple[bytes, str, str]:
    """Extraction DOM finale — factorisée entre `capture_url` (3a) et
    `capture_scripted` (3c) : avant (phase3f-F1), ces deux fonctions
    dupliquaient ~5 lignes identiques (`page.content()`/`title()`/`url` sous
    try/except), relevé par 2 audits comme risque de dérive. Une seule
    implémentation désormais.

    Ne lève JAMAIS : toute exception (driver Camoufox mort, page hostile) est
    absorbée ici, loguée (avec le contexte `url` forensique), et remplacée par
    dom/title vides — même politique d'erreur qu'avant le factoring (résultat
    partiel plutôt qu'un crash qui priverait le broker de tout résultat).
    `final_url` retombe sur `url` (l'URL cible), PAS sur `""` : avant le
    refactor les appelants prédéclaraient `final_url = url` et ne l'écrasaient
    qu'en cas de succès -> même comportement ici, cohérent avec
    `_error_wrapper` (qui restaure aussi `final_url=url`)."""
    try:
        dom_html = (await page.content()).encode()
        title = await page.title()
        final_url = page.url
        return dom_html, title, final_url
    except Exception as exc:
        log.warning("url=%s dom capture failed err=%s", url, type(exc).__name__)
        return b"", "", url


# Options de lancement communes Camoufox (3a et 3c) : navigateur headed
# (Xvfb), anti-detect, curseur humanisé. Factorisées ici (une seule fois),
# le `proxy` egress guard y est mergé conditionnellement par
# `_camoufox_session` ci-dessous.
#
# WebRTC OFF (audit 3g C1) : le garde egress est un proxy TCP HTTP/CONNECT ;
# le moteur ICE/STUN de Firefox (WebRTC) sort en UDP DIRECT, HORS proxy — une
# page hostile pourrait donc joindre une IP interne via
# `new RTCPeerConnection({iceServers:[{urls:"stun:169.254.169.254:3478"}]})`,
# contournant totalement le garde. On désactive WebRTC via la préférence
# Firefox `media.peerconnection.enabled=false` (passée en `firefox_user_prefs`,
# que Camoufox merge tel quel dans `playwright.firefox.launch`, cf.
# camoufox.utils.launch_options) : `RTCPeerConnection` devient alors
# indisponible dans la page -> vecteur UDP fermé. (Équivaut au paramètre
# `block_webrtc=True` de Camoufox, qui pose exactement cette même pref ; on
# passe la pref explicitement pour rendre l'intention et le test unitaire
# lisibles.) Vérifié empiriquement : Turnstile (guatx.com) reste résolu et
# `typeof RTCPeerConnection === "undefined"` dans le DOM capturé (cf.
# tests/test_egress_integration.py).
# Kwargs de lancement Camoufox : factorisés dans engine.egress_policy (source
# unique, partagée avec le tier interactif). Conservé comme constante module pour
# compat (tests + lisibilité) ; le `proxy` egress est mergé par `_camoufox_session`.
_CAMOUFOX_LAUNCH_KWARGS: dict[str, Any] = hardened_launch_kwargs()


@contextlib.asynccontextmanager
async def _camoufox_session() -> AsyncIterator[Any]:
    """Lance Camoufox (headed, anti-detect) routé — quand
    `ocular_settings.egress_guard_enabled()` est vrai (défaut) — à travers
    un `engine.egress_guard.EgressGuard` local, factorisé entre `capture_url`
    (3a) et `capture_scripted` (3c) : même pilotage réseau, une seule
    implémentation (DRY, cf. plan 3g Task G2).

    **Voie proxy retenue (vérifiée empiriquement)** : `AsyncCamoufox` déroule
    ses `**launch_options` directement dans `playwright.firefox.launch(...)`
    (cf. camoufox.utils.launch_options / camoufox.async_api.AsyncNewBrowser)
    — le paramètre `proxy` est donc le `ProxySettings` STANDARD de Playwright
    (`{"server": "http://host:port"}`), pas un hack `firefox_user_prefs`.
    C'est la voie utilisée ici : `proxy={"server": f"http://127.0.0.1:{port}"}`.

    **Fail-safe (décision tranchée)** : si le garde ne démarre pas
    (`guard.start()` lève), l'exception REMONTE — on ne bascule JAMAIS sur un
    lancement Camoufox sans proxy (ce serait un fetch direct non filtré,
    silencieusement moins sûr que ce que `egress_guard_enabled()` a demandé).
    Les appelants (`capture_url`/`capture_scripted`, via `main()`) traitent
    déjà toute exception de ce type comme un échec propre (`_error_wrapper`,
    wrapper `OcularResult` valide sur stdout) — pas de crash silencieux, pas
    de bypass silencieux.

    Le garde est arrêté en `finally`, que la session Camoufox se termine
    normalement ou lève."""
    # Politique egress (garde / strict / warning) factorisée dans engine
    # (source unique, cf. audit 3m). Décidée AVANT l'import Camoufox pour que le
    # refus fail-closed soit immédiat.
    launch_kwargs = hardened_launch_kwargs()
    guard, proxy_kwargs = await maybe_start_egress_guard()
    launch_kwargs.update(proxy_kwargs)

    try:
        # import DANS le try : s'il lève (camoufox absent/cassé), le `finally`
        # stoppe quand même le garde déjà démarré (pas de socket fuité).
        from camoufox.async_api import AsyncCamoufox
        async with AsyncCamoufox(**launch_kwargs) as ctx:
            yield ctx
    finally:
        if guard is not None:
            await guard.stop()


async def capture_url(url: str, timeout_ms: int = 45000) -> tuple[OcularResult, dict[str, bytes]]:
    """Pilote Camoufox (anti-detect Firefox headed, Xvfb) : navigue vers `url`,
    tente de résoudre un Turnstile interactif via la vision (template matching)
    + clic OS xdotool (cf. runner_recon/vision.py, porté depuis
    YesWeHack/toolkit/browser-automation), capture screenshots/réseau/DOM, puis
    délègue l'assemblage du résultat à `build_result`."""
    import vision  # copié dans runner_recon/, sur le PYTHONPATH du conteneur

    capture = NetworkCapture()
    screenshots: list[tuple[int, str, bytes]] = []
    turnstile_solved = None   # tri-état : None = aucun challenge (défaut), True/False sinon
    # (dom_html/title/final_url ne sont plus prédéclarés ici : `_capture_dom`
    # ne lève jamais, donc la seule affectation qui compte est celle après le
    # `async with` ci-dessous — cf. `_capture_dom`.)

    async with _camoufox_session() as ctx:
        page = await ctx.new_page()
        capture.attach(page)

        await _goto_with_fallback(page, url, timeout_ms, capture.console)

        png0 = await page.screenshot(full_page=False)
        screenshots.append((0, "initial", png0))

        # Turnstile : détection vision (template matching, retry le temps du
        # rendu async du widget) + mapping viewport->écran + clic OS xdotool +
        # vérif post-clic (cf. solve_turnstile, cause racine détaillée là-bas).
        try:
            turnstile_solved = await solve_turnstile(
                page, screenshots, capture.console, vision, next_index=len(screenshots)
            )
        except Exception as exc:
            capture.console.append({"level": "warning", "text": f"turnstile: {type(exc).__name__}"})

        dom_html, title, final_url = await _capture_dom(page, url)

    return build_result(
        url, screenshots, capture.network, capture.console, dom_html, title,
        final_url, turnstile_solved,
    )


async def capture_scripted(
    url: str, steps: list, timeout_ms: int = 45000
) -> tuple[OcularResult, dict[str, bytes]]:
    """Mode scripté (3c) : rejoue `steps` sur `url` (même pilotage Camoufox
    headed que `capture_url`, NetworkCapture armé de la même façon) pour
    révéler les appels réseau post-interaction (ex. un `fetch` déclenché par
    un clic). Assemble l'`OcularResult` via `ResultBuilder`/`DynamicStep`
    déjà existants — aucune nouvelle structure de résultat.

    DÉCISION D'ARCHI (tranchée) : `url` (top-level) N'EST PAS re-SSRF-validée
    ici. Source unique de validation SSRF pour l'URL de soumission :
    `engine.ssrf.validate_capture_url`, appelée côté web à la soumission du
    job (Task 5 du plan 3c) — ce runner ne reçoit `url` QUE via le broker de
    confiance (jamais d'entrée utilisateur directe sur ce process). En
    revanche `validate_steps(steps)` ci-dessous SSRF-valide bien CHAQUE step
    `goto` (la seule navigation réellement pilotée par l'utilisateur dans le
    DSL) — défense en profondeur, pas duplication de la validation `url`. Ce
    choix est aussi ce qui permet à la fixture d'intégration privée (réseau
    docker dédié, IP non routable publiquement) de fonctionner : re-valider
    `url` la rejetterait à tort alors qu'elle vient déjà d'une source de
    confiance.
    """
    # défense en profondeur AVANT tout lancement navigateur : des steps
    # invalides (verbe hors allowlist, `goto` SSRF, bornes) lèvent ici, sans
    # payer le coût d'un démarrage Camoufox — et l'exception remonte à `main()`
    # qui émet quand même un wrapper valide (chemin résilient).
    validated_steps = validate_steps(steps)  # cf. docstring (SSRF des `goto`)
    # Budget wall-clock TOTAL démarré ICI (avant le lancement Camoufox, qui a
    # lui-même un coût non négligeable) -> `run_steps` reçoit un `deadline`
    # absolu et coupe la séquence net (résultat partiel) avant que le broker
    # ne tue le conteneur (cf. SCRIPTED_EXEC_TIMEOUT_S ci-dessus).
    deadline = _scripted_deadline()

    capture = NetworkCapture()
    builder = ResultBuilder()
    # refs des screenshots `capture` empilées DANS L'ORDRE des appels (une par
    # step `capture`) — association par ordre, pas par label (cf.
    # journal_to_dynamic_steps).
    capture_refs: list[str] = []
    shot_idx = 0
    turnstile_solved = None   # tri-état : None = aucun challenge (défaut), True/False sinon
    page = None  # affecté dans le `async with` ci-dessous, capturé par le closure

    async def screenshot_cb(label: str, *, selector: str | None = None, full_page: bool = False) -> None:
        nonlocal shot_idx
        # `selector` -> capture de RÉGION (élément) ; `full_page` -> page entière ;
        # sinon viewport visible (défaut). selector/full_page validés+exclusifs
        # côté engine.steps ; ici on exécute simplement le mode demandé.
        if selector:
            png = await page.locator(selector).first.screenshot()
        else:
            if full_page:
                # Déclenche le lazy-loading (images/div/scripts liés au scroll,
                # IntersectionObserver…) : sans ce parcours, une capture full-page
                # rate les éléments jamais entrés dans le viewport. JS FIXE.
                await _scroll_to_load(page)
            png = await page.screenshot(full_page=full_page)
        ref = builder.add_screenshot(shot_idx, label, png)
        capture_refs.append(ref)
        shot_idx += 1

    async with _camoufox_session() as ctx:
        page = await ctx.new_page()
        capture.attach(page)

        await _goto_with_fallback(page, url, timeout_ms, capture.console)

        # Turnstile AVANT de rejouer les steps : sinon le script (sleep/click/
        # full_page/selecteur…) s'exécute sur la page de CHALLENGE Cloudflare et
        # non sur le contenu réel -> capture « turnstile non passé ». Même
        # mécanique que capture_url (gating indicateur CF + vision + clic OS).
        #
        # IMPORTANT : en mode scripté, l'analyste contrôle EXACTEMENT les captures
        # via le DSL (`capture` full_page / région / après-clic). On NE conserve
        # donc PAS le screenshot post-turnstile dans le résultat — seules les
        # captures explicitement demandées apparaissent (pas de capture auto
        # parasite). `ts_shots` est jeté (solve_turnstile exige une liste ; le
        # Turnstile est bien résolu, juste sans screenshot ajouté au résultat).
        ts_shots: list[tuple[int, str, bytes]] = []
        try:
            import vision  # copié dans runner_recon/, sur le PYTHONPATH du conteneur
            turnstile_solved = await solve_turnstile(
                page, ts_shots, capture.console, vision, next_index=0
            )
        except Exception as exc:  # noqa: BLE001 - la résolution ne doit jamais casser le scripté
            capture.console.append({"level": "warning", "text": f"turnstile: {type(exc).__name__}"})

        journal = await run_steps(
            page, validated_steps, screenshot_cb=screenshot_cb, deadline=deadline
        )
        if journal and journal[-1].get("error") == "timeout budget":
            # Note console (pas une exception) : le résultat partiel (journal +
            # screenshots déjà pris) est quand même émis ci-dessous — jamais de
            # stdout vide sur dépassement de budget.
            capture.console.append({
                "level": "warning",
                "text": f"scripted execution: budget de {SCRIPTED_EXEC_TIMEOUT_S}s atteint, steps restants abandonnés",
            })

        # Finalisation sous timeout (phase3f-F1c) : après un `run_steps`
        # bancal (ex. step qui a lui-même timeout), `page` peut être dans un
        # état dégradé où `page.content()/title()` PEND indéfiniment (pas
        # d'exception, juste un blocage) — sans budget propre ici, ça peut
        # dépasser la marge broker et priver le broker de tout résultat
        # (stdout vide). `_capture_dom` a son propre budget court
        # (`_DOM_FINALIZE_TIMEOUT_S`) : sur dépassement, dom vide + warning
        # console, mais on continue jusqu'à `emit_wrapper` (résultat partiel
        # garanti, jamais de stdout vide).
        try:
            dom_html, title, final_url = await asyncio.wait_for(
                _capture_dom(page, url), timeout=_DOM_FINALIZE_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            dom_html, title, final_url = b"", "", url
            log.warning("url=%s scripted dom capture timed out after %ss", url, _DOM_FINALIZE_TIMEOUT_S)
            capture.console.append({
                "level": "warning",
                "text": f"scripted dom capture: timeout après {_DOM_FINALIZE_TIMEOUT_S}s",
            })

    builder.set_dom(dom_html)
    findings = _analyze(dom_html)

    return builder.build(
        job_id="",
        profile="capture",
        target=url,
        input_hash=url_input_hash(url),
        verdict=compute_verdict(findings),
        dom_info=_dom_info(dom_html, title, final_url),
        stealth=StealthInfo(engine="camoufox", turnstile_solved=turnstile_solved),
        static_findings=findings,
        network=capture.network,
        console=capture.console,
        dynamic_steps=journal_to_dynamic_steps(journal, capture_refs),
    )


def _read_stdin_payload() -> Optional[dict[str, Any]]:
    """Lit un éventuel job scripté JSON `{"url":..., "steps":[...]}` sur
    stdin. Retourne `None` si stdin est vide/absente/non-scripté — dans ce cas
    le chemin 3a (`--url`) prend le relais, STRICTEMENT inchangé (aucun step).

    `sys.stdin.isatty()` : en CLI interactive (terminal), `sys.stdin.read()`
    bloquerait sur EOF ; on saute donc la lecture et on bascule sur le chemin
    3a argparse. Le chemin de production (broker sans `-i`, stdin fermé) n'est
    pas un TTY -> lecture normale. La lecture reste protégée par `try/except`
    (isatty ET read) : certains contextes n'ont aucun stdin exploitable (ex.
    la capture par défaut de pytest hors `-s`) — ce n'est pas une erreur de
    payload, juste l'absence de stdin.

    LÈVE `ValueError` (anti double-fault) quand stdin porte CLAIREMENT un job
    scripté (dict avec les clés `url` ET `steps`) mais avec des TYPES
    invalides (`url` non-str, `steps` non-list). Garantit ainsi que si cette
    fonction RETOURNE un payload, `url` est TOUJOURS un str et `steps` une
    list — le fallback résilient de `main()` (`build_result(url=...)`) ne peut
    donc plus re-crasher sur un `url` None (double-fault -> zéro octet stdout,
    interdit par le contrat runner). `main()` traite ce `ValueError` comme un
    payload scripté invalide et émet quand même un wrapper valide."""
    try:
        if sys.stdin.isatty():
            return None
        raw = sys.stdin.read()
    except Exception:
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or "url" not in payload or "steps" not in payload:
        return None
    # Dès ici stdin contient clairement un job scripté : valider les types
    # (voir docstring — garantie "url toujours str dans le chemin scripté").
    if not isinstance(payload["url"], str):
        raise ValueError("scripted payload: 'url' doit être une chaîne")
    if not isinstance(payload["steps"], list):
        raise ValueError("scripted payload: 'steps' doit être une liste")
    return payload


def _error_wrapper(url: str, text: str) -> tuple[OcularResult, dict[str, bytes]]:
    """Wrapper `OcularResult` minimal mais VALIDE, émis quand la capture ne
    peut pas produire de résultat exploitable (page hostile, driver Camoufox
    mort, payload scripté malformé, steps invalides). Contrat runner : stdout
    ne doit JAMAIS être vide, sinon broker/launcher.py perd tout résultat.
    `url` DOIT être un str (garanti par les appelants ; `""` si inconnu)."""
    return build_result(
        url=url,
        screenshots=[],
        network=[],
        console=[{"level": "error", "text": text}],
        dom_html=b"",
        title="",
        final_url=url,
        turnstile_solved=False,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    # --url reste l'entrée du chemin 3a (one-shot classique). En mode
    # scripté (3c) l'URL vient du JSON stdin {"url","steps"} (jamais d'un
    # argument CLI/env — pas de fuite dans `docker inspect`) : optionnel ici,
    # re-imposé plus bas seulement si aucun job scripté n'est reçu.
    ap.add_argument("--url", required=False, default=None)
    args = ap.parse_args()

    try:
        payload = _read_stdin_payload()
    except ValueError as exc:
        # stdin porte un job scripté mais malformé (types url/steps invalides).
        # Résilience : émettre quand même un wrapper valide (jamais zéro octet,
        # jamais de bascule à tort sur le chemin 3a). `url` inconnu -> "".
        log.warning("scripted payload invalide err=%s", exc)
        emit_wrapper(*_error_wrapper("", f"scripted payload invalide: {exc}"))
        return

    if payload is not None:
        # `url` garanti str, `steps` garanti list par `_read_stdin_payload`.
        url = payload["url"]
        steps = payload["steps"]
        # CRITIQUE (résilience, même contrat que le chemin 3a ci-dessous) :
        # toute exception (page hostile, driver Camoufox mort en cours de
        # route, steps invalides détectés par validate_steps en défense en
        # profondeur, ...) doit quand même produire un wrapper `OcularResult`
        # valide sur stdout.
        try:
            result, blobs = asyncio.run(capture_scripted(url, steps))
        except Exception as exc:
            log.warning("url=%s scripted capture failed err=%s", url, type(exc).__name__)
            result, blobs = _error_wrapper(url, f"capture failed: {type(exc).__name__}")
        emit_wrapper(result, blobs)
        return

    # Chemin 3a strictement inchangé : sans job scripté valide sur stdin,
    # --url reste requis (comme avant l'introduction du mode scripté).
    if args.url is None:
        ap.error("--url requis (aucun job scripté valide reçu sur stdin)")

    # CRITIQUE (résilience) : les pages visitées sont hostiles (Cloudflare/Auth0)
    # et peuvent faire mourir le driver/navigateur Camoufox en cours de capture
    # (ex. "Connection closed"). On n'a plus de patch driver pour absorber ça
    # (cf. Dockerfile) : toute exception non catchée par `capture_url` doit
    # quand même produire un wrapper `OcularResult` valide sur stdout, sinon le
    # broker/launcher.py qui lit stdout reste sans résultat exploitable.
    try:
        result, blobs = asyncio.run(capture_url(args.url))
    except Exception as exc:
        log.warning("url=%s capture failed err=%s", args.url, type(exc).__name__)
        result, blobs = _error_wrapper(args.url, f"capture failed: {type(exc).__name__}")
    emit_wrapper(result, blobs)


if __name__ == "__main__":
    main()
