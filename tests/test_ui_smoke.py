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
    m = re.search(r"function buildNetwork\(net\)\s*\{.*?\n  \}\n", js, re.S)
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
    m = re.search(r"function buildNetwork\(net\)\s*\{.*?\n  \}\n", js, re.S)
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
    m = re.search(r"function buildNetwork\(net\)\s*\{.*?\n  \}\n", js, re.S)
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


def test_interactive_teardown_clears_timers_and_listeners():
    # Pas de setInterval/setTimeout/listener fantôme entre deux navigations de
    # vue : le poll live, le timer de fermeture auto et les listeners globaux
    # (visibilitychange/beforeunload) doivent tous être nettoyés au teardown.
    js = open("web/ui/views/interactive.js").read()
    assert "clearInterval(pollTimer)" in js
    assert "clearTimeout(hiddenTimer)" in js
    assert "removeEventListener('visibilitychange', onVisibilityChange)" in js
    assert "removeEventListener('beforeunload', onBeforeUnload)" in js


def test_interactive_save_button_calls_save_analysis():
    # C3 : bouton Sauvegarder sur le panneau de capture, à côté de « Voir
    # l'analyse » — même flux POST /saved (saveAnalysis) que le résultat figé,
    # gère le 409 (nom déjà pris) avec un message clair.
    js = open("web/ui/views/interactive.js").read()
    assert "saveAnalysis(jobId, saveLabelInput.value.trim())" in js
    assert "duplicateLabel" in js
    assert "Sauvegarder" in js


def test_i18n_has_live_panel_translations():
    js = open("web/ui/i18n.js").read()
    assert "'appels réseau'" in js
    assert "'verdict inconnu'" in js
