"""Logique pure du mode scripté (3c) de runner_recon/capture.py — aucun
navigateur requis, comme test_capture_logic.py pour `build_result`.

Couvre :
  - `journal_to_dynamic_steps` : traduction du journal `run_steps` en
    `list[DynamicStep]` (schéma existant, pas de nouveau champ `actions`) —
    ok/duration_ms/error portés, screenshot_ref uniquement sur un `capture`,
    et surtout la valeur `fill` jamais en clair dans le résultat émis.
  - le dispatch stdin de `main()` : JSON scripté non vide -> `capture_scripted`
    (mocké) ; stdin vide/absent -> chemin 3a (`--url`) strictement inchangé.
"""
import io
import json

import pytest

import runner_recon.capture as cap
from engine.result import DynamicStep
from runner_recon.capture import _read_stdin_payload, journal_to_dynamic_steps
from runner_recon.steps_exec import run_steps


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
    refs_by_label = {"apres": "sha256:deadbeef"}

    out = journal_to_dynamic_steps(journal, refs_by_label)

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
    out = journal_to_dynamic_steps(journal, {})  # aucun ref enregistré pour "x"
    assert out[0].screenshot_ref is None


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
    refs_by_label = {}
    shot_idx = 0

    async def cb(label):
        nonlocal shot_idx
        png = await page.screenshot()
        refs_by_label[label] = f"sha256:{label}-{len(png)}"
        shot_idx += 1

    steps = [
        {"click": "#go"},
        {"fill": {"sel": "#i", "value": "hunter2"}},
        {"capture": "apres"},
    ]
    journal = await run_steps(page, steps, screenshot_cb=cb)
    out = journal_to_dynamic_steps(journal, refs_by_label)

    assert [d.ok for d in out] == [True, True, True]
    assert out[-1].screenshot_ref == refs_by_label["apres"]
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
