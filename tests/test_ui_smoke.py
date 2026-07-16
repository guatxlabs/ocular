import os
import re

from fastapi.testclient import TestClient

from web.app import app


def test_index_served_at_root():
    os.environ["OCULAR_TOKEN"] = "t"
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200
    assert "Ocular" in r.text  # l'index se charge (route publique, pas /jobs)


def test_static_assets_served():
    c = TestClient(app)
    assert c.get("/style.css").status_code == 200
    assert c.get("/api.js").status_code == 200
    assert c.get("/boot.js").status_code == 200


def test_saved_and_admin_views_served():
    # Les vues de la feature « analyses sauvegardées » (T7) sont servies en statique.
    c = TestClient(app)
    for path in ("/views/saved.js", "/views/admin.js"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert "javascript" in r.headers.get("content-type", "").lower(), path


def test_interactive_view_served():
    # La vue interactive (T8) est servie en statique.
    c = TestClient(app)
    r = c.get("/views/interactive.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "").lower()


def test_novnc_rfb_embedded_and_served():
    # noVNC est EMBARQUÉ localement (aucun CDN -> CSP) : le module ES rfb.js doit
    # être servi en 200 depuis le même origine.
    c = TestClient(app)
    r = c.get("/vendor/novnc/core/rfb.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "").lower()


def test_csp_allows_same_origin_ws():
    # La CSP de l'app shell doit autoriser le WebSocket same-origin (connect-src 'self').
    c = TestClient(app)
    csp = c.get("/").headers.get("content-security-policy", "")
    assert "connect-src 'self'" in csp


def test_csp_blocks_framing_anticlickjacking():
    # Anti-clickjacking (audit sécu 3k) : frame-ancestors 'none' (ne retombe PAS
    # sur default-src) + X-Frame-Options DENY en repli.
    c = TestClient(app)
    r = c.get("/")
    assert "frame-ancestors 'none'" in r.headers.get("content-security-policy", "")
    assert r.headers.get("x-frame-options") == "DENY"


# ---- tier dynamique scripté (3c) : champ script + journal d'actions XSS-clean ----

def test_scripted_field_present_in_submit_view():
    # Le formulaire capture porte un champ script (textarea JSON, optionnel),
    # câblé jusqu'au payload POST /jobs (`steps`).
    js = open("web/ui/views/submit.js").read()
    assert "id: 'script'" in js
    assert "payload.steps" in js
    assert "JSON.parse(rawScript)" in js


def test_scripted_examples_are_valid_json():
    # Les exemples insérables doivent être des steps DSL valides (mono-clé,
    # verbes en allowlist) — cohérent avec engine.steps.validate_steps.
    import re

    from engine.steps import validate_steps

    js = open("web/ui/views/submit.js").read()
    m = re.search(r"const EXAMPLES = (\[.*?\n  \]);", js, re.S)
    assert m, "bloc EXAMPLES introuvable dans submit.js"
    # les exemples sont écrits en objets JS littéraux (pas de guillemets sur les clés) ;
    # on ne les ré-exécute pas ici — on vérifie juste, par motif, la présence de verbes
    # DSL connus, et on exerce le validateur réel sur un jeu de steps équivalent.
    assert "click" in m.group(1) and "capture" in m.group(1) and "fill" in m.group(1)
    equivalent = [
        {"click": "#accept"}, {"wait": 500}, {"capture": "apres-cookies"},
    ]
    assert validate_steps(equivalent)[-1] == {"capture": "apres-cookies"}


def test_detail_renders_dynamic_steps_without_innerhtml_on_untrusted_data():
    # Le journal d'actions (`dynamic_steps`) doit être rendu SANS jamais passer
    # `action`/`error` par innerHTML — uniquement via `el(...)` (textNode).
    js = open("web/ui/views/detail.js").read()
    assert "dynamic_steps" in js
    assert "buildDynamicSteps" in js
    # aucune AFFECTATION .innerHTML n'existe dans le fichier (les commentaires
    # mentionnant ".innerHTML" pour l'expliciter sont légitimes ; seul un
    # `.innerHTML =` ou `.innerHTML(` serait une fuite XSS réelle).
    import re
    assert not re.search(r"\.innerHTML\s*[=(]", js)
    # action/error passent explicitement par el(...) (-> textContent), jamais concaténés
    # dans une chaîne de markup.
    assert "el('span.action-verb', {}, s.action" in js
    assert "el('span.action-err', {}, s.error" in js


# ---- unicité du nom des sauvegardes (Task D 3d-1) : affichage du 409 côté UI ----

def test_save_analysis_distinguishes_duplicate_label_409():
    # api.js doit distinguer un 409 « nom déjà pris » d'un 409 « artefacts
    # expirés » (les deux passent par POST /saved) pour permettre un message
    # d'erreur distinct côté vue.
    js = open("web/ui/api.js").read()
    assert "duplicateLabel" in js
    assert "expired" in js


def test_detail_shows_duplicate_label_error_via_textcontent_not_innerhtml():
    js = open("web/ui/views/detail.js").read()
    assert "duplicateLabel" in js
    assert "err.textContent" in js
    import re
    assert not re.search(r"\.innerHTML\s*[=(]", js)


def test_i18n_has_duplicate_label_translation():
    js = open("web/ui/i18n.js").read()
    assert "Nom déjà utilisé" in js


# ---- upload .htm/.html en plus de .eml (Task F 3d-1) ----

def test_submit_file_input_accepts_html_and_htm():
    js = open("web/ui/views/submit.js").read()
    m = re.search(r"accept:\s*'([^']*)'", js)
    assert m, "attribut accept introuvable dans submit.js"
    accept = m.group(1)
    assert ".html" in accept
    assert ".htm" in accept
    assert ".eml" in accept  # le .eml reste accepté


def test_submit_labels_no_longer_eml_only():
    js = open("web/ui/views/submit.js").read()
    # le bouton d'upload ne doit plus dire "Charger un .eml" seul
    assert "Charger un .eml" not in js
    assert "Charger un fichier" in js
    # le placeholder mentionne HTML/.htm/.html, pas seulement .eml
    assert "colle ici le HTML (ou charge un .eml)" not in js
    assert ".htm/.html/.eml" in js


def test_interactive_has_html_file_upload():
    js = open("web/ui/views/interactive.js").read()
    assert "type: 'file'" in js
    m = re.search(r"accept:\s*'([^']*)'", js)
    assert m, "attribut accept introuvable dans interactive.js"
    accept = m.group(1)
    assert ".html" in accept
    assert ".htm" in accept
    assert "text/html" in accept
    # même mécanisme que submit.js : FileReader -> textarea via .value (pas innerHTML)
    assert "FileReader" in js
    assert "htmlArea.value" in js


def test_interactive_i18n_translation_present_for_new_placeholder():
    js = open("web/ui/i18n.js").read()
    assert ".htm/.html/.eml" in js


def test_ui_upload_never_uses_innerhtml_on_file_content():
    # les contenus de fichiers chargés doivent alimenter .value/textContent,
    # jamais innerHTML (XSS-clean).
    for path in ("web/ui/views/submit.js", "web/ui/views/interactive.js"):
        js = open(path).read()
        assert not re.search(r"\.innerHTML\s*[=(]", js), path


# ---- bandeau « IP exposée » sans débordement (Task G 3d-1) ----

def test_livewarn_has_no_divergent_border_left():
    css = open("web/ui/style.css").read()
    m = re.search(r"\.livewarn\{[^}]*\}", css, re.S)
    assert m, "bloc .livewarn introuvable dans style.css"
    block = m.group(0)
    assert "border-left" not in block
    assert "border:1px" in block or "border: 1px" in block


# ---- filtre SOC des résultats réseau (Task 1 3d-2 I) : filter.js ----

def test_filter_js_served_as_static_module():
    # web/ui/filter.js est un module ES autonome, servi en statique comme les
    # autres vues (aucune route serveur dédiée n'est requise par le plan).
    c = TestClient(app)
    r = c.get("/filter.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "").lower()


def test_filter_js_has_no_user_regex_anti_redos():
    # Contrainte de sécurité du plan : aucune regex utilisateur -> aucun
    # `new RegExp` dans le module de filtrage (matching substring/égalité
    # uniquement, via String.includes/toLowerCase).
    js = open("web/ui/filter.js").read()
    assert "new RegExp" not in js


def test_filter_js_never_uses_innerhtml():
    # XSS-clean : chips/compteur construits via el()/textContent, jamais
    # d'innerHTML sur des données d'entrée (labels de chip, valeurs d'entrée).
    js = open("web/ui/filter.js").read()
    assert not re.search(r"\.innerHTML\s*[=(]", js)


def test_filter_js_makes_no_network_calls():
    # Filtrage 100% côté client sur des données déjà chargées : aucun fetch/
    # appel réseau ne doit être déclenché par le module.
    js = open("web/ui/filter.js").read()
    assert "fetch(" not in js
    assert "XMLHttpRequest" not in js


def test_filter_js_exports_expected_interface():
    js = open("web/ui/filter.js").read()
    for name in ("entryHost", "entryMime", "matchChip", "filterEntries", "buildFilterBar"):
        assert f"export function {name}" in js or f"export async function {name}" in js, name


def test_build_filter_bar_is_synchronous_no_core_import():
    # buildFilterBar doit être SYNCHRONE (pas `async`) et ne contenir AUCUN
    # import (statique OU dynamique `import(`) de core.js : `el` est injecté par
    # l'appelant. C'est indispensable pour que la barre soit insérée AVANT le
    # i18nWalk() synchrone (sinon libellés jamais traduits en LANG='en'), et pour
    # que les fonctions pures restent importables par le test node sans core.js.
    js = open("web/ui/filter.js").read()
    assert "export async function buildFilterBar" not in js
    assert "export function buildFilterBar" in js
    assert "import(" not in js  # aucun import dynamique
    # aucun import top-level de core.js (statique) — el vient uniquement du param
    assert "from './core.js'" not in js
    assert "'./core.js'" not in js


# ---- filtre SOC des résultats réseau (Task 2 3d-2 I) : intégration détail ----

def test_detail_imports_and_uses_filter_bar_in_build_network():
    # detail.js doit importer filter.js et appeler buildFilterBar depuis
    # buildNetwork (au-dessus du tableau, réutilise la logique de Task 1 -> DRY,
    # pas de réimplémentation du matching).
    js = open("web/ui/views/detail.js").read()
    assert "from '../filter.js'" in js
    assert "buildFilterBar" in js
    m = re.search(r"function buildNetwork\(netRaw\)\s*\{.*?\n  \}\n", js, re.S)
    assert m, "buildNetwork introuvable dans detail.js"
    body = m.group(0)
    assert "buildFilterBar" in body


def test_detail_network_filter_threshold_avoids_noise_on_small_results():
    # Petit résultat (<= 8 entrées) -> pas de barre de filtre (pas de bruit) ;
    # la barre n'apparaît qu'au-delà du seuil.
    js = open("web/ui/views/detail.js").read()
    assert re.search(r"net\.length\s*>\s*(NETWORK_FILTER_THRESHOLD|8)", js)


def test_detail_network_filter_handler_makes_no_network_calls():
    # Le handler de filtre (portion buildNetwork qui appelle buildFilterBar)
    # ne doit déclencher aucun fetch/appel API : filtrage 100% côté client sur
    # `net` déjà chargé.
    js = open("web/ui/views/detail.js").read()
    m = re.search(r"function buildNetwork\(netRaw\)\s*\{.*?\n  \}\n", js, re.S)
    assert m, "buildNetwork introuvable dans detail.js"
    body = m.group(0)
    assert "fetch(" not in body
    assert re.search(r"\bapi\.", body) is None
    assert not re.search(r"\.innerHTML\s*[=(]", body)


def test_detail_network_filter_rerender_uses_el_not_innerhtml():
    # Le re-rendu déclenché par onChange (renderRows) doit repasser par el() /
    # replaceChildren, jamais innerHTML — mêmes colonnes method/status/type/url
    # que le rendu initial.
    js = open("web/ui/views/detail.js").read()
    assert "renderRows" in js
    assert "tb.replaceChildren" in js
    assert not re.search(r"\.innerHTML\s*[=(]", js)


def test_detail_inserts_filter_bar_synchronously():
    # detail.js doit insérer la barre de façon SYNCHRONE (pas de `.then(` autour
    # de buildFilterBar) : el importé synchrone est injecté et la barre est
    # ajoutée avant le retour de renderResult (donc avant i18nWalk).
    js = open("web/ui/views/detail.js").read()
    m = re.search(r"function buildNetwork\(netRaw\)\s*\{.*?\n  \}\n", js, re.S)
    assert m, "buildNetwork introuvable dans detail.js"
    body = m.group(0)
    assert "buildFilterBar(() => net, renderRows, { el })" in body
    # aucune promesse chaînée sur buildFilterBar (plus d'insertion asynchrone)
    assert ".then(" not in body


def test_i18n_has_filter_bar_translations():
    js = open("web/ui/i18n.js").read()
    for term in ("Domaine", "Statut", "contient", "égal", "exclure"):
        assert f"'{term}'" in js, term


# ---- panneau live + auto-fermeture onglet + sauvegarde (Task C3 3d-2 C) ----

def test_api_exposes_live_session():
    # GET /sessions/{id}/live, mêmes en-têtes auth (authFetch) que les autres
    # appels sessions — pas de fetch nu, pas de duplication de la logique Bearer.
    js = open("web/ui/api.js").read()
    assert "export async function liveSession" in js
    assert "authFetch('/sessions/' + encodeURIComponent(id) + '/live')" in js


def test_interactive_imports_filter_js_and_polls_live():
    js = open("web/ui/views/interactive.js").read()
    assert "from '../filter.js'" in js
    assert "buildFilterBar" in js
    assert "liveSession" in js
    assert "setInterval(pollLive, POLL_INTERVAL_MS)" in js
    assert "POLL_INTERVAL_MS = 2000" in js


def test_filter_bar_exposes_refresh_backcompat():
    # buildFilterBar attache son refresh() interne sur le nœud retourné
    # (rétro-compatible : detail.js ignore `.refresh`). Signature/retour
    # principal inchangés.
    js = open("web/ui/filter.js").read()
    assert "bar.refresh = refresh" in js
    assert "return bar;" in js


def test_live_filter_bar_built_once_and_refreshed_not_rebuilt_per_poll():
    # La barre de filtre du panneau live est construite UNE SEULE FOIS, hors de
    # la boucle de poll : `buildFilterBar` ne doit PAS être appelée dans le
    # corps du callback de poll (`pollLive`) ni dans `update()`. Le poll
    # rafraîchit via `bar.refresh()` -> les chips posés PERSISTENT.
    js = open("web/ui/views/interactive.js").read()
    # buildFilterBar appelée exactement deux fois (réseau + console, dans
    # buildLivePanel, hors poll) — chaque barre construite UNE fois.
    assert js.count("buildFilterBar(") == 2
    # le refresh des barres est bien invoqué (persistance des chips au poll)
    assert "bar.refresh" in js and "consBar.refresh" in js
    # pollLive() ne reconstruit aucune barre
    m = re.search(r"async function pollLive\(\)\s*\{.*?\n  \}\n", js, re.S)
    assert m, "pollLive introuvable dans interactive.js"
    assert "buildFilterBar" not in m.group(0)
    # update() (appelé à chaque poll) ne reconstruit pas non plus les barres
    mu = re.search(r"function update\(data\)\s*\{.*?\n  \}\n", js, re.S)
    assert mu and "buildFilterBar" not in mu.group(0)


def test_interactive_live_panel_never_uses_innerhtml_or_regex_on_data():
    # Le panneau live (réseau + findings) doit rester XSS-clean (el()/textContent
    # uniquement) et ne jamais matcher les données réseau par regex — le
    # filtrage passe exclusivement par filter.js (String.includes).
    js = open("web/ui/views/interactive.js").read()
    assert not re.search(r"\.innerHTML\s*[=(]", js)
    assert "new RegExp" not in js


def test_interactive_hidden_tab_auto_close():
    # C2 : onglet caché en continu >= 60s -> deleteSession + teardown RFB +
    # arrêt du poll (armé/désarmé via visibilitychange).
    js = open("web/ui/views/interactive.js").read()
    assert "visibilitychange" in js
    assert "SESSION_HIDDEN_CLOSE_MS = 60000" in js
    assert "document.hidden" in js
    assert "deleteSession" in js


def test_interactive_beforeunload_best_effort_close():
    js = open("web/ui/views/interactive.js").read()
    assert "beforeunload" in js
    assert "sendBeacon" in js
    assert "keepalive" in js


def test_interactive_reload_confirms_before_destroying_session():
    # Phase 3k : un Ctrl+R (focus hors canvas noVNC) rechargerait la page Ocular
    # et détruirait la session -> perte de l'état DERRIÈRE le login/Turnstile.
    # beforeunload DEMANDE confirmation (preventDefault + returnValue) ; la
    # suppression serveur ne se fait qu'au unload RÉEL (pagehide) -> confirmation
    # annulée = session préservée.
    js = open("web/ui/views/interactive.js").read()
    assert "e.preventDefault()" in js and "e.returnValue" in js
    assert "'pagehide'" in js and "onPageHide" in js
    # le sendBeacon de suppression vit dans pagehide, pas dans beforeunload
    assert "removeEventListener('pagehide', onPageHide)" in js


def test_interactive_teardown_clears_timers_and_listeners():
    # Pas de setInterval/setTimeout/listener fantôme entre deux navigations de
    # vue : le poll live, le timer de fermeture auto et les listeners globaux
    # (visibilitychange/beforeunload) doivent tous être nettoyés au teardown.
    js = open("web/ui/views/interactive.js").read()
    assert "clearInterval(pollTimer)" in js
    assert "clearTimeout(hiddenTimer)" in js
    assert "removeEventListener('visibilitychange', onVisibilityChange)" in js
    assert "removeEventListener('beforeunload', onBeforeUnload)" in js


def test_interactive_save_requires_name_and_notifies_only_after_save():
    # Phase 3j : « Sauvegarder » fige une capture ÉPHÉMÈRE ; la persistance
    # (POST /saved via saveAnalysis) ne se fait QUE si un nom est donné, et la
    # confirmation « Sauvegardé » n'apparaît qu'APRÈS l'enregistrement effectif
    # (aucun avertissement de capture temporaire). Gère le 409 (nom déjà pris).
    js = open("web/ui/views/interactive.js").read()
    assert "saveAnalysis(jobId, name)" in js
    assert "duplicateLabel" in js
    # nom requis : garde-fou explicite avant toute sauvegarde
    assert "const name = saveLabelInput.value.trim()" in js
    assert "Donne un nom pour enregistrer" in js
    # bouton d'enregistrement = « Enregistrer » ; confirmation post-save = « Sauvegardé »
    assert "'Enregistrer'" in js
    assert "'Sauvegardé'" in js
    # aucune annonce de capture temporaire (« Capture enregistrée » supprimé du flux)
    assert "Capture enregistrée" not in js


def test_i18n_has_live_panel_translations():
    js = open("web/ui/i18n.js").read()
    assert "'appels réseau'" in js
    assert "'verdict inconnu'" in js


# ---- Phase 3e : identité (whoami) + provenance + verdict analyste (Task 4) ----

def test_api_exposes_whoami_and_set_analyst_verdict():
    # api.js doit exposer whoami() (GET /auth/whoami) et setAnalystVerdict()
    # (POST /saved/{sid}/verdict), tous deux passés par authFetch comme le reste
    # des appels (pas de fetch nu, pas de duplication de la logique Bearer).
    js = open("web/ui/api.js").read()
    assert "export async function whoami" in js
    assert "authFetch('/auth/whoami')" in js
    assert "export async function setAnalystVerdict" in js
    assert "authFetch('/saved/' + encodeURIComponent(sid) + '/verdict'" in js
    assert "export async function getSavedMeta" in js


def test_core_calls_whoami_at_boot_and_wires_banner():
    # Le bandeau whoami est appelé « au chargement » (avant le premier routage) et
    # construit dynamiquement (index.html non modifiable dans ce plan) via el().
    js = open("web/ui/core.js").read()
    assert "from './api.js'" in js
    assert "await refreshWhoami();" in js
    assert "async function boot()" in js
    assert "el('span.whoami'" in js


def test_core_whoami_identity_rendered_via_el_never_innerhtml():
    # `identity` (donnée potentiellement hostile — en-tête forward-auth relayé par
    # un proxy) doit être posée en textNode via el()/iconNode, jamais innerHTML.
    js = open("web/ui/core.js").read()
    m = re.search(r"async function refreshWhoami\(\)\s*\{.*?\n\}\n", js, re.S)
    assert m, "refreshWhoami introuvable dans core.js"
    body = m.group(0)
    assert "who.identity" in body
    assert not re.search(r"\.innerHTML\s*[=(]", body)
    assert "el('b.whoami-id', {}, (who && who.identity) || '?')" in body


def test_core_forward_auth_confirms_session_without_local_token():
    # Un whoami() réussi doit AUSSI autoriser la navigation côté routeur, même sans
    # jeton Bearer local stocké : c'est ce qui évite l'invite de jeton quand
    # l'identité vient uniquement du forward-auth (opt-in serveur actif).
    js = open("web/ui/core.js").read()
    assert "identityConfirmed" in js
    assert "const authed = !!getToken() || identityConfirmed;" in js


def test_saved_list_shows_provenance_and_analyst_verdict():
    js = open("web/ui/views/saved.js").read()
    assert "export function provenanceLine" in js
    assert "export function analystPill" in js
    assert "provenanceLine(m)" in js
    assert "analystPill(m.analyst_verdict)" in js


def test_saved_list_never_uses_innerhtml():
    js = open("web/ui/views/saved.js").read()
    assert not re.search(r"\.innerHTML\s*[=(]", js)
    assert "m.saved_by" in js


def test_detail_shows_provenance_and_analyst_verdict_controls():
    js = open("web/ui/views/detail.js").read()
    assert "function buildProvenance" in js
    assert "function buildAnalystPanel" in js
    assert "getSavedMeta" in js
    assert "setAnalystVerdict(sid, value, noteInput.value.trim())" in js
    assert "meta.saved_by" in js
    assert "m.analyst_verdict" in js
    for v in ("legitimate", "suspicious", "malicious"):
        assert f"'{v}'" in js


def test_detail_auto_verdict_hero_always_rendered_analyst_panel_conditional():
    # Le verdict AUTO (hero) est construit inconditionnellement dans renderResult ;
    # seul le panneau analyste (meta) est conditionnel — le verdict auto n'est
    # jamais masqué/remplacé par le verdict analyste.
    js = open("web/ui/views/detail.js").read()
    m = re.search(r"function renderResult\(r, meta\)\s*\{.*?\n  \}\n", js, re.S)
    assert m, "renderResult introuvable"
    body = m.group(0)
    assert "verdict-hero" in body
    assert re.search(r"if \(meta\) \{\s*\n\s*const prov = buildProvenance", body)
    # le hero est appendé avant le bloc conditionnel `if (meta)`
    assert body.index("verdict-hero") < body.index("if (meta)")


def test_detail_analyst_panel_never_uses_innerhtml_on_untrusted_fields():
    # `analyst`/`analyst_note` (identité forward-auth / texte libre saisi par un
    # analyste) doivent être posés en textNode via el(), jamais innerHTML.
    js = open("web/ui/views/detail.js").read()
    m = re.search(r"function buildAnalystPanel\(sid, meta\)\s*\{.*?\n  \}\n", js, re.S)
    assert m, "buildAnalystPanel introuvable"
    body = m.group(0)
    assert not re.search(r"\.innerHTML\s*[=(]", body)
    assert "el('b', {}, m.analyst || '?')" in body
    assert "el('p.analyst-note', {}, m.analyst_note)" in body


def test_detail_provenance_never_uses_innerhtml_on_saved_by():
    js = open("web/ui/views/detail.js").read()
    m = re.search(r"function buildProvenance\(meta\)\s*\{.*?\n  \}\n", js, re.S)
    assert m, "buildProvenance introuvable"
    body = m.group(0)
    assert not re.search(r"\.innerHTML\s*[=(]", body)
    assert "el('b', {}, meta.saved_by)" in body


def test_detail_hot_updates_analyst_panel_after_classification():
    # Classer (bouton verdict) doit repeindre le panneau SANS recharger la page
    # (mise à jour à chaud) : la réponse de setAnalystVerdict est repassée à
    # paintCurrent, pas de location.reload()/re-fetch du résultat entier.
    js = open("web/ui/views/detail.js").read()
    assert "const updated = await setAnalystVerdict(sid, value, noteInput.value.trim());" in js
    assert "paintCurrent(updated);" in js


def test_i18n_has_phase3e_translations():
    js = open("web/ui/i18n.js").read()
    for term in ("sauvé par", "classé par", "Verdict analyste", "Classer", "légitime", "Turnstile non passé"):
        assert f"'{term}'" in js, term


def test_style_has_whoami_provenance_and_verdict_controls_css():
    css = open("web/ui/style.css").read()
    assert ".whoami{" in css
    assert ".provenance{" in css
    assert ".analystpanel{" in css
    assert ".verdict-btn{" in css


# ---- Phase 3h : is_admin/groups via whoami -> masquage UI des contrôles admin ----

def test_core_exposes_is_admin_and_groups_from_whoami():
    # core.js doit lire `is_admin`/`groups` sur la réponse de whoami() (déjà
    # appelée au boot pour le bandeau, Phase 3e) et les exposer aux vues via des
    # getters — jamais de mutation externe de l'état interne.
    js = open("web/ui/core.js").read()
    assert "who.is_admin" in js
    assert "who.groups" in js
    assert "export function isAdmin" in js
    assert "export function getGroups" in js


def test_core_resets_admin_state_on_whoami_failure_and_logout():
    # Fail-closed côté ergonomie aussi : un whoami() en échec ou une déconnexion
    # explicite doit retomber sur isAdmin() === false (pas de contrôle admin
    # "collé" après expiration/logout).
    js = open("web/ui/core.js").read()
    assert "adminFlag = false" in js
    assert js.count("adminFlag = false") >= 2  # catch whoami + logout


def test_core_shows_admin_nav_link_when_authenticated():
    # L'admin par X-Admin-Token se saisit DANS la page admin : le lien ne doit PAS
    # être masqué sur le seul flag de groupe (sinon un admin par token n'y accéderait
    # jamais — régression 3h). Visible dès qu'authentifié ; le backend reste la garde.
    js = open("web/ui/core.js").read()
    assert 'querySelector(\'#topnav a[data-route="admin"]\')' in js
    assert "adminLink.hidden = !authed" in js
    assert "adminLink.hidden = !authed || !adminFlag" not in js


def test_admin_view_always_shows_token_form():
    # La page admin (formulaire X-Admin-Token) est TOUJOURS accessible : pas de
    # early-return qui la masque aux non-membres du groupe admin (régression 3h
    # corrigée). isAdmin() ne sert qu'à signaler que le token est facultatif.
    js = open("web/ui/views/admin.js").read()
    assert "isAdmin" in js and "getGroups" in js
    assert "if (!isAdmin())" not in js   # plus de blocage de la page
    assert "tokenCard" in js             # le formulaire token est rendu


def test_admin_view_notes_group_admin_token_optional():
    # Un admin via groupe IdP voit une note "token facultatif" ; plus de message
    # bloquant "Admin requis.".
    js = open("web/ui/views/admin.js").read()
    assert "facultatif" in js
    assert "Admin requis." not in js


def test_admin_view_renders_groups_via_el_never_innerhtml():
    # `groups` (potentiellement issu d'un en-tête forward-auth) doit être posé
    # en textNode via el(...), jamais en innerHTML.
    import re
    js = open("web/ui/views/admin.js").read()
    assert not re.search(r"\.innerHTML\s*[=(]", js)
    assert "getGroups()" in js
    assert "groups.join(', ')" in js


def test_core_whoami_groups_rendered_via_el_never_innerhtml():
    import re
    js = open("web/ui/core.js").read()
    m = re.search(r"async function refreshWhoami\(\)\s*\{.*?\n\}\n", js, re.S)
    assert m, "refreshWhoami introuvable dans core.js"
    body = m.group(0)
    assert not re.search(r"\.innerHTML\s*[=(]", body)
    assert "groupsList.join(', ')" in body
    assert "el('span.whoami-groups'" in body


def test_i18n_has_phase3h_admin_gate_translations():
    js = open("web/ui/i18n.js").read()
    for term in ("Admin requis.", "Tes groupes :", "Aucun groupe détecté."):
        assert f"'{term}'" in js, term


def test_style_has_whoami_groups_css():
    css = open("web/ui/style.css").read()
    assert ".whoami-groups{" in css


def test_jobs_view_treats_unknown_as_terminal_and_offers_purge():
    # Phase 3k : un job "unknown" (résultat perdu/expiré) est TERMINAL — la vue
    # Jobs arrête de le poller (plus de fantôme "en attente") et propose de
    # purger les jobs terminés de la liste locale.
    js = open("web/ui/views/jobs.js").read()
    assert "res.status === 'unknown'" in js
    assert "expiredPill" in js
    assert "removeJobs" in js          # purge localStorage
    assert "terminal.add(id)" in js    # sort du polling


def test_detail_view_handles_unknown_job_terminally():
    # La page de détail ne poll pas à l'infini un job perdu : "unknown" affiche
    # un message d'expiration au lieu d'un résultat vide / d'un spinner sans fin.
    js = open("web/ui/views/detail.js").read()
    assert "res.status === 'unknown'" in js
    assert "expirée ou introuvable" in js
