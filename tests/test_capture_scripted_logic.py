"""Logique pure du mode scripté (3c) de runner_recon/capture.py — aucun
navigateur requis, comme test_capture_logic.py pour `build_result`.

Couvre :
  - `journal_to_dynamic_steps` : traduction du journal `run_steps` en
    `list[DynamicStep]` (schéma existant, pas de nouveau champ `actions`) —
    ok/duration_ms/error portés, screenshot_ref des `capture` associé PAR
    ORDRE (pas par label : deux captures de même label doivent avoir des refs
    distincts), et surtout la valeur `fill` jamais en clair.
  - le dispatch stdin de `main()` : JSON scripté non vide -> `capture_scripted`
    (mocké) ; stdin vide/absent -> chemin 3a (`--url`) strictement inchangé ;
    payload scripté malformé (url/steps mauvais type) ou steps invalides
    (allowlist/SSRF) -> wrapper OcularResult VALIDE quand même (jamais zéro
    octet stdout — anti double-fault).
"""
import io
import json

import pytest

import runner_recon.capture as cap
from engine.result import DynamicStep
from runner_recon.capture import _read_stdin_payload, _scripted_deadline, journal_to_dynamic_steps
from runner_recon.steps_exec import run_steps


# --- budget wall-clock total (deadline passé à run_steps par capture_scripted) ---
#
# Couvre la spec 3c Global Constraint « timeout d'exécution total 120s -> arrêt
# + résultat partiel ». `_scripted_deadline` est une fonction pure (aucun
# navigateur requis) extraite de `capture_scripted` précisément pour rester
# testable ici (capture_scripted importe camoufox, absent de ce venv de test).


def test_scripted_exec_timeout_constant_is_120s():
    assert cap.SCRIPTED_EXEC_TIMEOUT_S == 120


def test_scripted_deadline_is_now_plus_budget(monkeypatch):
    monkeypatch.setattr(cap.time, "monotonic", lambda: 1000.0)
    assert _scripted_deadline() == 1000.0 + cap.SCRIPTED_EXEC_TIMEOUT_S


@pytest.mark.asyncio
async def test_capture_scripted_passes_deadline_to_run_steps(monkeypatch):
    # Vérifie le câblage réel de capture_scripted (navigateur entièrement
    # mocké via un faux module `camoufox.async_api`) : `run_steps` doit bien
    # recevoir un `deadline` ~ now + SCRIPTED_EXEC_TIMEOUT_S, pas None.
    import sys
    import types

    class FakePage:
        def __init__(self):
            self.url = "https://example.com/"

        async def goto(self, url, **k):
            pass

        async def content(self):
            return "<html></html>"

        async def title(self):
            return "t"

        async def screenshot(self, **k):
            return b"PNG"

        def on(self, event, handler):
            pass

    class FakeCtx:
        async def new_page(self):
            return FakePage()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class FakeAsyncCamoufox:
        def __init__(self, **k):
            pass

        async def __aenter__(self):
            return FakeCtx()

        async def __aexit__(self, *a):
            return False

    fake_async_api = types.ModuleType("camoufox.async_api")
    fake_async_api.AsyncCamoufox = FakeAsyncCamoufox
    fake_camoufox = types.ModuleType("camoufox")
    fake_camoufox.async_api = fake_async_api
    monkeypatch.setitem(sys.modules, "camoufox", fake_camoufox)
    monkeypatch.setitem(sys.modules, "camoufox.async_api", fake_async_api)

    captured = {}
    real_run_steps = run_steps

    async def spy_run_steps(page, steps, *, screenshot_cb, deadline=None):
        captured["deadline"] = deadline
        return await real_run_steps(page, steps, screenshot_cb=screenshot_cb, deadline=deadline)

    monkeypatch.setattr(cap, "run_steps", spy_run_steps)
    monkeypatch.setattr(cap.time, "monotonic", lambda: 5000.0)

    await cap.capture_scripted("https://example.com/", [])

    assert captured["deadline"] == 5000.0 + cap.SCRIPTED_EXEC_TIMEOUT_S


@pytest.mark.asyncio
async def test_capture_scripted_solves_turnstile_before_steps(monkeypatch):
    # Phase 3k : le scripté doit résoudre le Turnstile AVANT de rejouer les steps
    # (sinon le script tourne sur la page de challenge -> « turnstile non passé »),
    # et propager turnstile_solved au résultat.
    import sys
    import types

    class FakePage:
        def __init__(self):
            self.url = "https://example.com/"
        async def goto(self, url, **k):
            pass
        async def content(self):
            return "<html></html>"
        async def title(self):
            return "t"
        async def screenshot(self, **k):
            return b"PNG"
        def on(self, event, handler):
            pass

    class FakeCtx:
        async def new_page(self):
            return FakePage()
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False

    class FakeAsyncCamoufox:
        def __init__(self, **k):
            pass
        async def __aenter__(self):
            return FakeCtx()
        async def __aexit__(self, *a):
            return False

    fake_async_api = types.ModuleType("camoufox.async_api")
    fake_async_api.AsyncCamoufox = FakeAsyncCamoufox
    fake_camoufox = types.ModuleType("camoufox")
    fake_camoufox.async_api = fake_async_api
    monkeypatch.setitem(sys.modules, "camoufox", fake_camoufox)
    monkeypatch.setitem(sys.modules, "camoufox.async_api", fake_async_api)
    monkeypatch.setitem(sys.modules, "vision", types.ModuleType("vision"))

    order = []

    async def spy_solve(page, shots, console, vision_mod, next_index=1):
        order.append("turnstile")
        return True

    async def spy_run_steps(page, steps, *, screenshot_cb, deadline=None):
        order.append("steps")
        return []

    monkeypatch.setattr(cap, "solve_turnstile", spy_solve)
    monkeypatch.setattr(cap, "run_steps", spy_run_steps)

    result, _ = await cap.capture_scripted("https://example.com/", [])

    assert order == ["turnstile", "steps"]          # Turnstile AVANT les steps
    assert result.stealth.turnstile_solved is True  # propagé au résultat


def test_journal_to_dynamic_steps_maps_ok_duration_error_and_screenshot_ref():
    journal = [
        {"index": 0, "verb": "click", "ok": True, "ms": 12, "step": {"click": "#go"}},
        {
            "index": 1,
            "verb": "fill",
            "ok": True,
            "ms": 5,
            "step": {"fill": {"sel": "#i", "value": "***"}},  # déjà redigé par run_steps
        },
        {
            "index": 2,
            "verb": "click",
            "ok": False,
            "ms": 30,
            "error": "no element",
            "step": {"click": "#missing"},
        },
        {"index": 3, "verb": "capture", "ok": True, "ms": 2, "step": {"capture": "apres"}},
    ]
    # un seul step `capture` -> une seule ref, associée par ORDRE
    capture_refs = ["sha256:deadbeef"]

    out = journal_to_dynamic_steps(journal, capture_refs)

    assert len(out) == 4
    assert all(isinstance(d, DynamicStep) for d in out)

    click_ok = out[0]
    assert click_ok.ok is True and click_ok.duration_ms == 12 and click_ok.error is None
    assert click_ok.screenshot_ref is None  # pas un `capture`

    fill_step = out[1]
    # valeur `fill` jamais en clair dans le résultat émis
    assert "value" not in fill_step.action or "secret" not in fill_step.action
    assert "***" in fill_step.action

    click_fail = out[2]
    assert click_fail.ok is False
    assert click_fail.duration_ms == 30
    assert click_fail.error == "no element"
    assert click_fail.screenshot_ref is None

    capture_step = out[3]
    assert capture_step.ok is True
    assert capture_step.screenshot_ref == "sha256:deadbeef"


def test_journal_to_dynamic_steps_capture_without_matching_ref_is_none():
    journal = [{"index": 0, "verb": "capture", "ok": True, "ms": 1, "step": {"capture": "x"}}]
    out = journal_to_dynamic_steps(journal, [])  # aucune ref produite (capture échouée)
    assert out[0].screenshot_ref is None


def test_journal_to_dynamic_steps_duplicate_labels_get_distinct_refs():
    # Deux `capture` de MÊME label ne doivent PAS partager le screenshot_ref :
    # l'association se fait par ORDRE (Nième capture <-> Nième ref), pas par
    # label (un dict keyed par label écraserait la 1re ref -> preuve forensique
    # mal associée).
    journal = [
        {"index": 0, "verb": "capture", "ok": True, "ms": 1, "step": {"capture": "x"}},
        {"index": 1, "verb": "click", "ok": True, "ms": 2, "step": {"click": "#a"}},
        {"index": 2, "verb": "capture", "ok": True, "ms": 1, "step": {"capture": "x"}},
    ]
    capture_refs = ["sha256:first", "sha256:second"]
    out = journal_to_dynamic_steps(journal, capture_refs)

    captures = [d for d in out if d.action == '{"capture": "x"}']
    assert len(captures) == 2
    assert captures[0].screenshot_ref == "sha256:first"
    assert captures[1].screenshot_ref == "sha256:second"
    assert captures[0].screenshot_ref != captures[1].screenshot_ref
    # le `click` intercalé ne consomme pas de ref
    assert out[1].screenshot_ref is None


@pytest.mark.asyncio
async def test_journal_to_dynamic_steps_end_to_end_with_run_steps():
    """Intègre le vrai `run_steps` (page mockée, comme test_steps_exec.py) pour
    vérifier que le format de journal produit par l'exécuteur réel est bien
    consommé par le mapping — pas seulement un journal fabriqué à la main."""

    class FakePage:
        def __init__(self):
            self.calls = []
            self.keyboard = self

        async def click(self, sel, **k):
            self.calls.append(("click", sel))

        async def fill(self, sel, val, **k):
            self.calls.append(("fill", sel, val))

        async def screenshot(self, **k):
            return b"PNG"

    page = FakePage()
    capture_refs = []
    shot_idx = 0

    async def cb(label):
        nonlocal shot_idx
        png = await page.screenshot()
        capture_refs.append(f"sha256:{label}-{shot_idx}-{len(png)}")
        shot_idx += 1

    steps = [
        {"click": "#go"},
        {"fill": {"sel": "#i", "value": "hunter2"}},
        {"capture": "apres"},
    ]
    journal = await run_steps(page, steps, screenshot_cb=cb)
    out = journal_to_dynamic_steps(journal, capture_refs)

    assert [d.ok for d in out] == [True, True, True]
    assert out[-1].screenshot_ref == capture_refs[0]
    # la valeur `fill` ne fuit jamais dans les DynamicStep produits
    assert "hunter2" not in " ".join(d.action for d in out)


# --- dispatch stdin de main() : scripté vs 3a inchangé ---


def test_read_stdin_payload_valid_json_returns_dict(monkeypatch):
    monkeypatch.setattr(cap.sys, "stdin", io.StringIO(json.dumps({"url": "https://x", "steps": []})))
    assert _read_stdin_payload() == {"url": "https://x", "steps": []}


def test_read_stdin_payload_empty_returns_none(monkeypatch):
    monkeypatch.setattr(cap.sys, "stdin", io.StringIO(""))
    assert _read_stdin_payload() is None


def test_read_stdin_payload_invalid_json_returns_none(monkeypatch):
    monkeypatch.setattr(cap.sys, "stdin", io.StringIO("not json"))
    assert _read_stdin_payload() is None


def test_read_stdin_payload_missing_keys_returns_none(monkeypatch):
    monkeypatch.setattr(cap.sys, "stdin", io.StringIO(json.dumps({"url": "https://x"})))
    assert _read_stdin_payload() is None


def test_read_stdin_payload_read_raising_returns_none(monkeypatch):
    class Boom:
        def read(self):
            raise OSError("reading from stdin while output is captured!")

    monkeypatch.setattr(cap.sys, "stdin", Boom())
    assert _read_stdin_payload() is None


def test_read_stdin_payload_isatty_returns_none(monkeypatch):
    # Terminal interactif : ne PAS bloquer sur `sys.stdin.read()` (pend sur EOF).
    # Même s'il y aurait du contenu lisible, un TTY -> None -> chemin 3a argparse.
    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(
        cap.sys, "stdin", Tty(json.dumps({"url": "https://x", "steps": []}))
    )
    assert _read_stdin_payload() is None


def test_read_stdin_payload_null_url_raises(monkeypatch):
    # Payload clairement scripté (clés url+steps) mais `url` du mauvais type :
    # DOIT lever (traité comme scripté invalide), pas retourner un dict avec
    # url=None qui ferait re-crasher le fallback résilient (double-fault).
    monkeypatch.setattr(
        cap.sys, "stdin", io.StringIO(json.dumps({"url": None, "steps": []}))
    )
    with pytest.raises(ValueError):
        _read_stdin_payload()


def test_read_stdin_payload_int_url_raises(monkeypatch):
    monkeypatch.setattr(
        cap.sys, "stdin", io.StringIO(json.dumps({"url": 123, "steps": []}))
    )
    with pytest.raises(ValueError):
        _read_stdin_payload()


def test_read_stdin_payload_non_list_steps_raises(monkeypatch):
    monkeypatch.setattr(
        cap.sys, "stdin", io.StringIO(json.dumps({"url": "https://x", "steps": "nope"}))
    )
    with pytest.raises(ValueError):
        _read_stdin_payload()


def test_main_dispatches_to_capture_scripted_when_stdin_has_job(monkeypatch, capsys):
    calls = {}

    async def fake_capture_scripted(url, steps):
        calls["url"] = url
        calls["steps"] = steps
        from engine.result import DomInfo, StealthInfo
        from engine.wrapper import ResultBuilder

        b = ResultBuilder()
        return b.build(
            job_id="", profile="capture", target=url, input_hash=None, verdict="benign",
            dom_info=DomInfo(), stealth=StealthInfo(engine="camoufox"),
        )

    monkeypatch.setattr(cap, "capture_scripted", fake_capture_scripted)
    monkeypatch.setattr(
        cap.sys, "stdin",
        io.StringIO(json.dumps({"url": "https://x/", "steps": [{"click": "#a"}]})),
    )
    monkeypatch.setattr("sys.argv", ["capture"])  # pas de --url : vient du JSON stdin

    cap.main()

    assert calls["url"] == "https://x/"
    assert calls["steps"] == [{"click": "#a"}]
    out = capsys.readouterr().out
    d = json.loads(out)
    assert d["result"]["target"] == "https://x/"


def test_main_scripted_failure_still_emits_valid_wrapper(monkeypatch, capsys):
    async def boom(url, steps):
        raise RuntimeError("Connection closed")

    monkeypatch.setattr(cap, "capture_scripted", boom)
    monkeypatch.setattr(
        cap.sys, "stdin",
        io.StringIO(json.dumps({"url": "https://x/", "steps": [{"click": "#a"}]})),
    )
    monkeypatch.setattr("sys.argv", ["capture"])

    cap.main()

    out = capsys.readouterr().out
    d = json.loads(out)
    assert d["result"]["profile"] == "capture"
    assert d["result"]["target"] == "https://x/"
    assert any("capture failed" in c["text"] for c in d["result"]["console"])


def test_main_empty_stdin_falls_back_to_3a_url_path_unchanged(monkeypatch, capsys):
    """Chemin 3a strictement inchangé : sans job scripté sur stdin, `--url`
    déclenche toujours `capture_url` (jamais `capture_scripted`)."""
    called = {"scripted": False, "url_path": False}

    async def fake_capture_url(url, timeout_ms=45000):
        called["url_path"] = True
        from engine.result import DomInfo, StealthInfo
        from engine.wrapper import ResultBuilder

        b = ResultBuilder()
        return b.build(
            job_id="", profile="capture", target=url, input_hash=None, verdict="benign",
            dom_info=DomInfo(), stealth=StealthInfo(engine="camoufox"),
        )

    async def fake_capture_scripted(url, steps):
        called["scripted"] = True
        raise AssertionError("ne doit pas être appelé : pas de job scripté sur stdin")

    monkeypatch.setattr(cap, "capture_url", fake_capture_url)
    monkeypatch.setattr(cap, "capture_scripted", fake_capture_scripted)
    monkeypatch.setattr(cap.sys, "stdin", io.StringIO(""))  # rien sur stdin
    monkeypatch.setattr("sys.argv", ["capture", "--url", "https://example.com"])

    cap.main()

    assert called["url_path"] is True
    assert called["scripted"] is False
    out = capsys.readouterr().out
    d = json.loads(out)
    assert d["result"]["target"] == "https://example.com"


# --- anti double-fault : payload scripté malformé -> wrapper valide, jamais 0 octet ---


@pytest.mark.parametrize("bad_url", [None, 123, ["x"], {"a": 1}])
def test_main_scripted_malformed_url_emits_valid_wrapper(monkeypatch, capsys, bad_url):
    # Régression : `{"url": null/123/..., "steps": []}` faisait crasher le
    # fallback résilient (`url_input_hash(None)` -> AttributeError) => zéro
    # octet stdout, le broker perdait tout résultat. Doit émettre un wrapper
    # OcularResult VALIDE sur stdout.
    monkeypatch.setattr(
        cap.sys, "stdin", io.StringIO(json.dumps({"url": bad_url, "steps": []}))
    )
    monkeypatch.setattr("sys.argv", ["capture"])

    cap.main()

    out = capsys.readouterr().out
    assert out.strip(), "stdout ne doit JAMAIS être vide (contrat runner)"
    d = json.loads(out)
    assert d["result"]["profile"] == "capture"
    assert d["result"]["schema_version"] == "1.0"


def test_main_scripted_non_list_steps_emits_valid_wrapper(monkeypatch, capsys):
    monkeypatch.setattr(
        cap.sys, "stdin", io.StringIO(json.dumps({"url": "https://x/", "steps": "nope"}))
    )
    monkeypatch.setattr("sys.argv", ["capture"])

    cap.main()

    out = capsys.readouterr().out
    assert out.strip()
    d = json.loads(out)
    assert d["result"]["profile"] == "capture"


def test_main_scripted_invalid_step_emits_valid_wrapper(monkeypatch, capsys):
    # Défense en profondeur : un verbe hors allowlist doit être capturé par
    # `capture_scripted` (via validate_steps) et produire un wrapper valide,
    # jamais un crash. (camoufox n'est pas installé dans le venv de test :
    # validate_steps DOIT donc s'exécuter AVANT tout import/lancement du
    # navigateur pour que ce chemin soit atteint sans navigateur.)
    monkeypatch.setattr(
        cap.sys, "stdin",
        io.StringIO(json.dumps({"url": "https://example.com/", "steps": [{"evil": "x"}]})),
    )
    monkeypatch.setattr("sys.argv", ["capture"])

    cap.main()

    out = capsys.readouterr().out
    assert out.strip()
    d = json.loads(out)
    assert d["result"]["profile"] == "capture"
    assert d["result"]["target"] == "https://example.com/"
    assert any("capture failed" in c["text"] for c in d["result"]["console"])


def test_main_scripted_ssrf_goto_emits_valid_wrapper(monkeypatch, capsys):
    # Défense en profondeur SSRF : un `goto` interne (validate_steps le rejette)
    # ne doit pas crasher le runner — wrapper valide émis.
    monkeypatch.setattr(
        cap.sys, "stdin",
        io.StringIO(json.dumps(
            {"url": "https://example.com/", "steps": [{"goto": "http://127.0.0.1/"}]}
        )),
    )
    monkeypatch.setattr("sys.argv", ["capture"])

    cap.main()

    out = capsys.readouterr().out
    assert out.strip()
    d = json.loads(out)
    assert d["result"]["profile"] == "capture"
    assert d["result"]["target"] == "https://example.com/"


@pytest.mark.asyncio
async def test_camoufox_session_strict_refuses_when_guard_off(monkeypatch):
    # Durcissement (réseau sensible) : garde egress désactivé + mode strict ->
    # _camoufox_session REFUSE (fail-closed) AVANT tout lancement navigateur
    # (le refus précède même l'import Camoufox, donc testable sans navigateur).
    monkeypatch.setenv("OCULAR_EGRESS_GUARD", "0")
    monkeypatch.setenv("OCULAR_REQUIRE_EGRESS_GUARD", "1")
    with pytest.raises(RuntimeError, match="fail-closed"):
        async with cap._camoufox_session():
            pass
