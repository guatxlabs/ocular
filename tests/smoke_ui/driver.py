# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pilote du smoke e2e de l'UI — s'exécute DANS le conteneur `ocular-runner-recon`.

Ce fichier n'est PAS un test pytest (il n'est jamais collecté : le nom ne
correspond à aucun motif `test_*`). Il est monté en lecture seule dans un
conteneur jetable par `tests/test_ui_smoke_e2e.py`, qui lit son verdict sur
stdout. Le voir tourner seul :

    docker run --rm -i --network container:<gateway> --entrypoint python3 \\
        -e PYTHONPATH=/app -v "$PWD/tests/smoke_ui/driver.py:/smoke/driver.py:ro" \\
        ocular-runner-recon:latest /smoke/driver.py --base-url http://127.0.0.1:8000 \\
        --token-stdin <<< "$OCULAR_TOKEN"

POURQUOI DANS CE CONTENEUR — l'image runner embarque déjà Camoufox et le
`playwright==1.49.1` qui sait lui parler (le couple est ÉPINGLÉ, cf.
`runner_recon/Dockerfile` : une autre version du driver Juggler bloque le
lancement du navigateur pendant 180 s sans message). Réinstaller un navigateur
sur l'hôte dupliquerait ce couple et le ferait dériver ; l'image est la source
unique.

POURQUOI SANS GARDE EGRESS — `runner_recon/capture.py` fait passer le
navigateur par `engine.egress_guard`, qui REFUSE les IP non publiques : c'est
exactement la protection SSRF qui existe pour empêcher un site analysé de
pivoter vers le réseau interne. Or le smoke vise DÉLIBÉRÉMENT une cible
interne — l'UI d'Ocular elle-même, à travers la pile de test. Le garde n'est
donc pas démarré ici. Conséquence à ne jamais perdre de vue : ce pilote ne doit
recevoir que l'URL de la pile Ocular sous test, JAMAIS une cible tierce.

STDOUT — la dernière ligne préfixée `OCULAR_SMOKE_JSON:` porte le verdict JSON.
Le préfixe existe parce que ni Camoufox ni le driver Playwright ne garantissent
un stdout silencieux : chercher « le stdout est du JSON » (convention des
runners, cf. `engine/wrapper.py`) casserait au premier message parasite d'une
dépendance tierce. Tout le reste — journal de progression — part sur stderr.

AUCUNE ÉVALUATION DE CODE DANS LA PAGE — ni `page.evaluate`, ni
`page.wait_for_function`. MESURÉ sur cette pile : la CSP de l'app shell
(`web/app.py`, `script-src 'self'` sans `'unsafe-eval'`) fait que Firefox
refuse l'évaluation injectée par Playwright. Deux dégâts, tous deux
silencieux et trompeurs :
  1. un `pageerror` « call to eval() blocked by CSP » **imputable à
     l'outillage**, qui ferait échouer l'assertion « zéro pageerror » sur une
     UI parfaitement saine ;
  2. une attente qui n'aboutit JAMAIS alors que la condition est vraie —
     observé tel quel : « le jeton n'a pas été accepté (pas de bascule vers
     #/jobs) — hash resté '#/jobs' », c'est-à-dire un échec annoncé sur une
     condition littéralement satisfaite.
Tout ce qui aurait demandé du JS passe donc par le côté Python : `page.url`
pour le fragment, `page.text_content` pour un libellé, `page.request` pour un
appel HTTP authentifié. Les sélecteurs (`wait_for_selector`, `fill`, `click`)
n'utilisent PAS `eval` et fonctionnent normalement — désactiver la CSP pour
faire marcher l'outillage aurait été tester une autre application que celle
qu'on déploie.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from typing import Any, Optional

# Préfixe de la ligne de verdict (cf. docstring). Lu par
# `tests/test_ui_smoke_e2e.py::_verdict`.
JSON_PREFIX = "OCULAR_SMOKE_JSON:"

# --- marqueurs stables attendus, vue par vue --------------------------------
# Chacun est relevé DANS le code de la vue, jamais inventé : un marqueur
# inventé passerait au vert sur une page à moitié rendue.
#
#   login        web/ui/views/login.js:43        el('h2', {}, 'Connexion')
#   jobs         web/ui/views/jobs.js:13         el('h2', {}, 'Mes analyses')
#   submit       web/ui/views/submit.js:258      el('h2', {}, 'Analyser une page')
#   interactif   web/ui/views/interactive.js:357 el('h2', {}, 'Session interactive')
#   détail       web/ui/views/detail.js:143-144  div.verdict-hero > span.verdict-badge
#   noVNC        web/ui/views/interactive.js:559 div.vncframe (cible RFB -> <canvas>)
#
# Les libellés sont en FRANÇAIS parce que le contexte navigateur est neuf :
# `state.js` lit `localStorage.ocular_lang`, absent -> 'fr' (défaut), et
# `i18n.js` ne traduit QUE si LANG === 'en'. Le smoke ne pose jamais cette clé.
H2_LOGIN = "Connexion"
H2_JOBS = "Mes analyses"
H2_SUBMIT = "Analyser une page"
H2_INTERACTIVE = "Session interactive"

# Budgets. Larges à dessein : ce smoke répond « l'UI se charge-t-elle ? », pas
# « en combien de temps ? ». Un budget serré transformerait une machine chargée
# en fausse régression.
NAV_TIMEOUT_MS = 30_000
VIEW_TIMEOUT_MS = 20_000
# Le job d'analyse traverse la file redis, le broker, puis un conteneur runner ;
# la vue détail re-sonde toutes les 3 s (detail.js). 180 s couvre un premier
# lancement à froid.
VERDICT_TIMEOUT_MS = 180_000
# Une session interactive démarre un conteneur + Camoufox : ~7-9 s annoncés
# (cf. docs/ROADMAP.md « disponibilité ≠ vivacité »), 180 s de marge.
SESSION_TIMEOUT_MS = 180_000


def log(msg: str) -> None:
    """Journal de progression — sur stderr, TOUJOURS (cf. docstring stdout)."""
    print(f"[smoke-ui] {msg}", file=sys.stderr, flush=True)


class SmokeFailure(RuntimeError):
    """Échec fonctionnel du smoke : marqueur absent, verdict jamais rendu, hash
    qui ne bascule pas. Distinct d'une panne d'OUTILLAGE (navigateur qui meurt,
    protocole Playwright cassé) : les deux font échouer le test, mais le verdict
    les étiquette différemment (`kind`) — un opérateur ne cherche pas au même
    endroit selon le cas."""


# --- pilotage de la page -----------------------------------------------------


class Smoke:
    def __init__(self, page: Any, base_url: str, token: str) -> None:
        self.page = page
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.phase = "boot"
        self.page_errors: list[dict[str, str]] = []
        self.console_errors: list[dict[str, str]] = []
        self.steps: list[dict[str, Any]] = []
        self.session_id: Optional[str] = None
        self.job_id: Optional[str] = None

    # -- collecte des erreurs -------------------------------------------------
    def attach_listeners(self) -> None:
        """`pageerror` = exception JS NON RATTRAPÉE dans la page. C'est
        l'assertion dure du smoke : une seule suffit à faire échouer. Les
        erreurs console sont collectées à côté, à titre de DIAGNOSTIC — elles
        recouvrent aussi du bruit légitime (404 d'icône, avertissement d'une
        dépendance) et n'ont donc pas valeur de verdict."""
        self.page.on("pageerror", self._on_page_error)
        self.page.on("console", self._on_console)

    def _on_page_error(self, exc: Any) -> None:
        # `phase` est celle EN COURS À L'ARRIVÉE de l'erreur, pas celle de la
        # vue fautive : une vue qui lève au rendu le fait pendant le
        # `hashchange` déclenché par la phase PRÉCÉDENTE (mesuré : une
        # régression posée dans `views/jobs.js` remonte étiquetée `login`).
        # C'est un repère de séquence, jamais un diagnostic — le diagnostic est
        # le message JS lui-même.
        entry = {"phase": self.phase, "message": str(exc)}
        self.page_errors.append(entry)
        log(f"PAGEERROR [{self.phase}] {entry['message']}")

    def _on_console(self, msg: Any) -> None:
        try:
            if msg.type != "error":
                return
            self.console_errors.append({"phase": self.phase, "message": msg.text})
        except Exception:  # noqa: BLE001 — le diagnostic ne doit jamais casser le smoke
            pass

    # -- primitives -----------------------------------------------------------
    def step(self, name: str, detail: str = "") -> None:
        self.steps.append({"phase": self.phase, "step": name, "detail": detail})
        log(f"{self.phase}: {name}{(' — ' + detail) if detail else ''}")

    async def open_route(self, route: str) -> None:
        """Charge une route en LIEN PROFOND (chargement complet du document).

        `page.goto` vers une URL qui ne diffère que par le fragment est une
        navigation MÊME DOCUMENT : le routeur ne repasse pas par `boot()`. Le
        `reload` qui suit force donc le vrai chemin d'un lien profond —
        `boot()` -> `whoami()` -> premier routage — celui qu'un opérateur
        emprunte en collant une URL, et le seul qui prouve que le jeton posé
        en `localStorage` survit à un rechargement."""
        await self.page.goto(f"{self.base_url}/{route}", wait_until="domcontentloaded",
                             timeout=NAV_TIMEOUT_MS)
        await self.page.reload(wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)

    async def expect_h2(self, expected: str) -> None:
        """Le marqueur de vue : le `h2` rendu DANS `#app` (le `h1` du header,
        lui, est présent sur toutes les vues — il ne prouverait rien)."""
        try:
            await self.page.wait_for_selector("#app h2", state="visible",
                                              timeout=VIEW_TIMEOUT_MS)
            seen = (await self.page.text_content("#app h2") or "").strip()
        except Exception as exc:  # noqa: BLE001
            raise SmokeFailure(f"aucun `#app h2` visible (attendu {expected!r}) : {exc}") from exc
        if seen != expected:
            raise SmokeFailure(f"marqueur de vue inattendu : vu {seen!r}, attendu {expected!r}")
        self.step("marqueur h2", seen)

    async def expect_selector(self, selector: str, what: str,
                              timeout_ms: int = VIEW_TIMEOUT_MS) -> None:
        """Attend un marqueur et NOMME ce qui manque s'il n'arrive pas.

        Le `TimeoutError` brut de Playwright dit « selector timed out » et fait
        classer l'échec en panne d'OUTILLAGE alors que c'est un défaut de l'UI.
        La traduction en `SmokeFailure` remet le diagnostic à l'endroit."""
        try:
            await self.page.wait_for_selector(selector, state="visible", timeout=timeout_ms)
        except Exception as exc:  # noqa: BLE001
            raise SmokeFailure(f"{what} — `{selector}` jamais visible") from exc
        self.step(what, selector)

    def current_hash(self) -> str:
        """Fragment courant, lu côté Playwright (`page.url` suit les navigations
        MÊME DOCUMENT, donc un `location.hash = …` du routeur). Aucune
        évaluation dans la page — cf. la docstring du module."""
        url = self.page.url
        return "#" + url.split("#", 1)[1] if "#" in url else ""

    async def wait_hash(self, want: str, timeout_ms: int, what: str,
                        prefix: bool = False) -> None:
        deadline = time.monotonic() + timeout_ms / 1000.0
        seen = ""
        while time.monotonic() < deadline:
            seen = self.current_hash()
            if seen.startswith(want) if prefix else seen == want:
                return
            await asyncio.sleep(0.2)
        raise SmokeFailure(f"{what} — hash resté {seen!r}")

    async def wait_text(self, selector: str, expected: str, timeout_ms: int,
                        what: str) -> None:
        """Attend qu'un élément porte EXACTEMENT ce texte (détouré). L'égalité
        stricte n'est pas du zèle : le statut de session passe par `déconnecté`,
        qui CONTIENT `connecté` — un `in` conclurait au succès sur l'échec."""
        deadline = time.monotonic() + timeout_ms / 1000.0
        seen = None
        while time.monotonic() < deadline:
            try:
                raw = await self.page.text_content(selector, timeout=1_000)
            except Exception:  # noqa: BLE001 — élément pas encore rendu
                raw = None
            seen = (raw or "").strip()
            if seen == expected:
                return
            await asyncio.sleep(0.25)
        raise SmokeFailure(f"{what} — {selector} affiche {seen!r}, attendu {expected!r}")

    # -- scénarios ------------------------------------------------------------
    async def scenario_login(self) -> None:
        """Vue login + POSE DU JETON. Le jeton passe par le FORMULAIRE, pas par
        un `localStorage.setItem` injecté : la vue vérifie le jeton contre le
        serveur (`checkToken`) avant de router, donc ce chemin prouve à la fois
        le rendu de la vue, l'appel authentifié et la redirection."""
        self.phase = "login"
        await self.page.goto(f"{self.base_url}/", wait_until="domcontentloaded",
                             timeout=NAV_TIMEOUT_MS)
        # Non authentifié : le routeur redirige vers #/login (core.js::route).
        await self.wait_hash("#/login", VIEW_TIMEOUT_MS, "pas de redirection vers #/login")
        await self.expect_h2(H2_LOGIN)
        await self.page.fill("#tok", self.token)
        await self.page.click(".login-card button.btn-primary")
        await self.wait_hash("#/jobs", VIEW_TIMEOUT_MS,
                             "le jeton n'a pas été accepté (pas de bascule vers #/jobs)")
        self.step("jeton accepté")

    async def scenario_jobs_empty(self) -> None:
        """Vue jobs sur un navigateur neuf : la liste vient de `localStorage`,
        donc l'état vide est le seul état déterministe au premier passage."""
        self.phase = "jobs"
        await self.expect_h2(H2_JOBS)
        await self.expect_selector("#app .emptyview", "état vide rendu")

    async def scenario_submit_and_verdict(self) -> None:
        """Vue submit -> soumission d'un job `analysis` -> vue détail/verdict.

        Le HTML porte un NONCE : `submit.js` interroge `/saved/{sha256}` avant
        de soumettre et ouvre une modale de déduplication si l'analyse existe
        déjà. Un HTML fixe ferait donc dérailler le smoke au deuxième passage
        sur une pile où quelqu'un a sauvegardé le résultat."""
        self.phase = "submit"
        await self.open_route("#/submit")
        await self.expect_h2(H2_SUBMIT)

        # Le profil par défaut est « URL » (capture live) : on bascule sur
        # « HTML » (analysis), qui n'exige AUCUN egress externe — le smoke
        # reste sur le réseau interne. Le clic vise le `label.seg` : la radio
        # elle-même est `opacity:0;width:0;height:0;pointer-events:none`
        # (style.css:1064), donc incliquable ; c'est le label qui la coche,
        # nativement. Sélecteur STRUCTUREL (`:has(input[value=…])`) et non
        # textuel : il survit à une traduction du libellé.
        await self.page.click('.profile-toggle label.seg:has(input[name="profile"][value="analysis"])')
        await self.expect_selector("#html", "champ HTML affiché")

        nonce = uuid.uuid4().hex
        # Le `eval(atob(...))` est la CHARGE À ANALYSER, pas du code de ce
        # pilote : c'est le motif que `engine/static.py` classe en « Dynamic
        # code evaluation », donc ce qui garantit un verdict non trivial plutôt
        # qu'un `benign` par défaut. Même fixture que `tests/test_e2e.py`. Elle
        # ne s'exécute que dans le conteneur runner jetable — c'est précisément
        # le métier du produit.
        html = (f"<html><body><h1>ocular smoke {nonce}</h1>"
                f"<script>eval(atob('c21va2U='))</script></body></html>")
        await self.page.fill("#html", html)
        await self.page.click('#app form button.btn-primary[type="submit"]')

        self.phase = "detail"
        await self.wait_hash("#/job/", VIEW_TIMEOUT_MS,
                             "la soumission n'a pas mené à la vue détail", prefix=True)
        self.job_id = self.current_hash().split("/")[-1]
        self.step("job soumis", self.job_id or "")

        # Marqueur de la vue détail : le HÉROS de verdict. Il n'apparaît qu'une
        # fois le résultat réellement rendu — l'état « en attente » affiche une
        # `.pending-pill`, pas un `.verdict-badge`. Attendre le badge, c'est
        # donc attendre la chaîne complète web -> redis -> broker -> runner.
        try:
            await self.page.wait_for_selector(".verdict-hero .verdict-badge", state="visible",
                                              timeout=VERDICT_TIMEOUT_MS)
        except Exception as exc:  # noqa: BLE001
            body = (await self.page.text_content("#app") or "")[:400]
            raise SmokeFailure(f"aucun verdict rendu pour {self.job_id} ; vue : {body!r}") from exc
        verdict = (await self.page.text_content(".verdict-hero .verdict-badge") or "").strip()
        if not verdict:
            raise SmokeFailure("badge de verdict rendu mais VIDE")
        self.step("verdict rendu", verdict)

    async def scenario_jobs_listed(self) -> None:
        """Retour sur la vue jobs APRÈS soumission : la ligne doit y être. Ce
        second passage est ce qui prouve que le jeton ET la liste locale ont
        survécu au rechargement complet de `open_route`."""
        self.phase = "jobs-après-soumission"
        await self.open_route("#/jobs")
        await self.expect_h2(H2_JOBS)
        await self.expect_selector("#app .joblist .jobrow", "ligne de job présente")
        rows = await self.page.locator("#app .joblist .jobrow").count()
        self.step("lignes de jobs", str(rows))

    async def scenario_interactive_view(self) -> None:
        """Vue interactive SANS ouvrir de session : formulaire + avertissement.
        Volontairement séparé de l'ouverture réelle (scénario `session`), qui
        coûte un conteneur de ~4 Go."""
        self.phase = "interactive"
        await self.open_route("#/interactive")
        await self.expect_h2(H2_INTERACTIVE)
        await self.expect_selector("#app .livewarn", "bandeau « IP exposée » rendu")
        await self.expect_selector("#live-url", "formulaire d'ouverture rendu")

    async def scenario_interactive_session(self) -> None:
        """Ouvre une VRAIE session interactive et attend le canvas noVNC.

        Mode HTML et non URL : une session `url` ferait sortir le conteneur de
        session sur Internet, ce qui rendrait le smoke dépendant d'un tiers.
        L'HTML inline reste entièrement sur le réseau interne.

        Deux marqueurs, pas un : le `<canvas>` est créé par le constructeur
        `RFB` AVANT toute connexion — seul, il ne prouverait que l'exécution
        d'un `new`. Le statut « connecté » n'arrive, lui, qu'après la poignée
        de main WebSocket à travers le proxy web jusqu'au conteneur de session.
        """
        self.phase = "interactive-session"
        await self.open_route("#/interactive")
        await self.expect_h2(H2_INTERACTIVE)
        await self.page.click('.profile-toggle label.seg:has(input[name="live-mode"][value="html"])')
        await self.expect_selector("#live-html", "champ HTML de session affiché")
        await self.page.fill("#live-html", "<html><body><h1>ocular smoke live</h1></body></html>")
        await self.page.click('#app form button.btn-primary[type="submit"]')

        try:
            await self.expect_selector(".livestage .vncframe canvas", "scène live ouverte",
                                       timeout_ms=SESSION_TIMEOUT_MS)
            self.session_id = (await self.page.text_content(".livebar .livemeta") or "").strip() or None
            self.step("canvas noVNC présent", self.session_id or "")
            await self.wait_text(".livebar .livestat", "connecté", SESSION_TIMEOUT_MS,
                                 "le flux VNC ne s'est jamais connecté")
            self.step("flux VNC connecté", self.session_id or "")
        finally:
            await self._close_session()

    async def _close_session(self) -> None:
        """Ferme la session PAR L'UI (bouton « Fermer » -> DELETE /sessions/{id}),
        puis, en dernier recours, par un DELETE direct. Aucun chemin de sortie —
        y compris un échec du scénario — ne doit laisser vivre un conteneur de
        ~4 Go et un réseau docker jusqu'au TTL."""
        try:
            btn = self.page.locator(".livebar-act button.btn-danger")
            if await btn.count():
                await btn.first.click()
                await self.page.wait_for_selector(".livestage", state="hidden", timeout=60_000)
                self.step("session fermée par l'UI", self.session_id or "")
                return
        except Exception as exc:  # noqa: BLE001
            log(f"fermeture par l'UI impossible ({exc}) — bascule sur DELETE direct")
        if not self.session_id:
            return
        try:
            # `page.request` émet la requête depuis le contexte du navigateur
            # SANS exécuter de JS dans la page (la CSP interdit `eval`, cf.
            # docstring du module). Le jeton vient du côté Python, pas du
            # `localStorage`.
            await self.page.request.delete(
                f"{self.base_url}/sessions/{self.session_id}",
                headers={"Authorization": f"Bearer {self.token}"},
            )
            self.step("session fermée par DELETE direct", self.session_id)
        except Exception as exc:  # noqa: BLE001
            log(f"DELETE direct en échec ({exc}) — l'hôte balaiera le résidu")


# --- orchestration -----------------------------------------------------------


async def run(base_url: str, token: str, with_session: bool) -> dict[str, Any]:
    # Import tardif : si camoufox manque, le message d'erreur doit désigner
    # l'image, pas une ligne d'import perdue en tête de fichier.
    from camoufox.async_api import AsyncCamoufox

    try:
        from engine.browser_prefs import HARDENED_FIREFOX_PREFS  # PYTHONPATH=/app
        prefs = dict(HARDENED_FIREFOX_PREFS)
    except ImportError:  # pragma: no cover — l'image copie toujours engine/
        log("engine.browser_prefs introuvable — prefs par défaut")
        prefs = {}

    t0 = time.monotonic()
    # `headless=True` : borne posée par la feuille de route. Le tier capture
    # tourne en HEADED sous Xvfb (posture anti-detect face à un site hostile) ;
    # ici la cible est notre propre UI, aucun anti-bot à franchir, et le
    # headless supprime la dépendance à un serveur X dans le conteneur.
    async with AsyncCamoufox(headless=True, os="linux", i_know_what_im_doing=True,
                             firefox_user_prefs=prefs) as browser:
        page = await browser.new_page()
        smoke = Smoke(page, base_url, token)
        smoke.attach_listeners()
        page.set_default_timeout(VIEW_TIMEOUT_MS)

        error: Optional[str] = None
        kind: Optional[str] = None
        # LE VERDICT EST CONSTRUIT DANS TOUS LES CAS, échec compris. Une version
        # antérieure laissait l'exception remonter jusqu'à `main()`, qui
        # fabriquait alors un verdict MINIMAL, sans `page_errors` : MESURÉ en
        # cassant volontairement `views/jobs.js`, le test rapportait « timeout
        # en attendant .emptyview » et TAISAIT l'exception JS qui en était la
        # cause, pourtant déjà capturée. Un smoke qui perd la cause racine au
        # moment précis où elle existe ne vaut pas grand-chose.
        try:
            await smoke.scenario_login()
            await smoke.scenario_jobs_empty()
            await smoke.scenario_submit_and_verdict()
            await smoke.scenario_jobs_listed()
            await smoke.scenario_interactive_view()
            if with_session:
                await smoke.scenario_interactive_session()
        except SmokeFailure as exc:
            error, kind = str(exc), "smoke"
            log(f"ÉCHEC [{smoke.phase}] {error}")
        except Exception as exc:  # noqa: BLE001 — un échec doit rendre un verdict lisible
            error, kind = f"{type(exc).__name__}: {exc}", "outillage"
            log(f"ÉCHEC OUTILLAGE [{smoke.phase}] {error}")

        # Contexte fermé par le `async with` : le profil Camoufox vit dans
        # $TMPDIR=/work, un tmpfs du conteneur jetable — aucun résidu hôte.
        return {
            "ok": error is None and not smoke.page_errors,
            "error": error,
            "kind": kind,
            "phase": smoke.phase,
            "elapsed_s": round(time.monotonic() - t0, 1),
            "steps": smoke.steps,
            "page_errors": smoke.page_errors,
            "console_errors": smoke.console_errors,
            "job_id": smoke.job_id,
            "session_id": smoke.session_id,
        }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Smoke e2e de l'UI Ocular (Camoufox headless, dans le conteneur runner).",
    )
    ap.add_argument("--base-url", default="http://127.0.0.1:8000",
                    help="racine de l'UI sous test (défaut : http://127.0.0.1:8000)")
    ap.add_argument("--token-stdin", action="store_true",
                    help="lit le jeton Bearer sur stdin (1 ligne). Jamais en argv : "
                         "argv est visible dans `ps` sur l'hôte et dans `docker inspect`.")
    ap.add_argument("--with-session", action="store_true",
                    help="ouvre une VRAIE session interactive (conteneur ~4 Go) et "
                         "attend le canvas noVNC, puis la referme.")
    args = ap.parse_args(argv)

    token = sys.stdin.readline().strip() if args.token_stdin else ""
    if not token:
        log("aucun jeton reçu (--token-stdin attendu)")
        print(JSON_PREFIX + json.dumps({"ok": False, "error": "jeton manquant"}), flush=True)
        return 2

    # `run()` assume ses propres échecs de scénario (verdict complet, avec les
    # `page_errors`). Ce filet-ci ne couvre plus que ce qui casse AVANT d'avoir
    # un navigateur : camoufox absent de l'image, lancement impossible.
    try:
        out = asyncio.run(run(args.base_url, token, args.with_session))
    except Exception as exc:  # noqa: BLE001 — tout échec doit rendre un verdict lisible
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "kind": "amorçage"}

    print(JSON_PREFIX + json.dumps(out, ensure_ascii=False), flush=True)
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
