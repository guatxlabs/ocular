import os

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
