import pytest
from engine.steps import (
    validate_steps,
    StepValidationError,
    redact_step,
    MAX_STEPS,
    MAX_SEL,
    MAX_WAIT_MS,
    MAX_SLEEP_S,
    MAX_SCROLL_PX,
    MAX_LABEL,
)

def test_valid_sequence_normalized_with_final_capture():
    raw = [{"click": "#a"}, {"fill": {"sel": "input", "value": "x"}}, {"wait": 1000}]
    out = validate_steps(raw)
    assert out[:3] == raw
    assert out[-1] == {"capture": "final"}  # capture final implicite ajouté

def test_explicit_final_capture_not_duplicated():
    raw = [{"click": "#a"}, {"capture": "fin"}]
    out = validate_steps(raw)
    assert out.count({"capture": "fin"}) == 1 and out[-1] == {"capture": "fin"}

def test_unknown_verb_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"evil": "alert(1)"}])

def test_multikey_step_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"click": "#a", "fill": {"sel": "i", "value": "v"}}])

def test_not_a_list_rejected():
    with pytest.raises(StepValidationError):
        validate_steps({"click": "#a"})

def test_too_many_steps_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"click": "#a"}] * (MAX_STEPS + 1))

def test_selector_too_long_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"click": "a" * 501}])

def test_wait_too_long_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"wait": 30001}])

def test_wait_selector_form_ok():
    assert validate_steps([{"wait": {"selector": ".x"}}])[0] == {"wait": {"selector": ".x"}}

def test_press_not_in_allowlist_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"press": "F1"}])

def test_goto_ssrf_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"goto": "http://169.254.169.254/"}])

def test_goto_public_ok():
    assert validate_steps([{"goto": "https://example.com/"}])[0]["goto"] == "https://example.com/"

def test_fill_value_redacted():
    assert redact_step({"fill": {"sel": "i", "value": "secret"}}) == {"fill": {"sel": "i", "value": "***"}}
    assert redact_step({"click": "#a"}) == {"click": "#a"}

def test_label_charset_enforced():
    with pytest.raises(StepValidationError):
        validate_steps([{"capture": "bad<label>"}])

# --- Important 1: idempotence / borne MAX_STEPS ---

def test_validate_steps_idempotent():
    # 50 clicks -> 51 (capture finale ajoutée) ; re-valider ne doit PAS lever
    x = [{"click": "#a"}] * MAX_STEPS
    once = validate_steps(x)
    assert len(once) == MAX_STEPS + 1
    assert validate_steps(once) == once
    # 50 clicks + capture explicite : idempotent aussi
    y = [{"click": "#a"}] * MAX_STEPS + [{"capture": "fin"}]
    once_y = validate_steps(y)
    assert validate_steps(once_y) == once_y
    # 51 clicks (steps utilisateur > MAX_STEPS) : rejet
    with pytest.raises(StepValidationError):
        validate_steps([{"click": "#a"}] * (MAX_STEPS + 1))

# --- Important 2: press non-string ne doit pas crasher (TypeError) ---

def test_press_non_string_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"press": ["Enter"]}])
    with pytest.raises(StepValidationError):
        validate_steps([{"press": {}}])

# --- Minor 1: redact_step ne partage/ne mute pas les sous-dicts non-fill ---

def test_redact_step_no_mutation_wait():
    step = {"wait": {"selector": ".x"}}
    out = redact_step(step)
    assert out == step
    out["wait"]["selector"] = ".mutated"
    assert step["wait"]["selector"] == ".x"  # entrée intacte

# --- Minor 2: bool != int, fill clé surnuméraire ---

def test_wait_bool_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"wait": True}])

def test_scroll_bool_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"scroll": True}])

def test_fill_extra_key_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"fill": {"sel": "i", "value": "v", "extra": 1}}])

# --- Minor 2: acceptation aux bornes exactes ---

def test_boundary_values_accepted():
    assert validate_steps([{"click": "a" * MAX_SEL}])[0] == {"click": "a" * MAX_SEL}
    assert validate_steps([{"wait": MAX_WAIT_MS}])[0] == {"wait": MAX_WAIT_MS}
    assert validate_steps([{"scroll": MAX_SCROLL_PX}])[0] == {"scroll": MAX_SCROLL_PX}
    assert validate_steps([{"capture": "a" * MAX_LABEL}])[0] == {"capture": "a" * MAX_LABEL}
    assert len(validate_steps([{"click": "#a"}] * MAX_STEPS)) == MAX_STEPS + 1

# --- Important (3c review): 422 réfléchi borné (anti-amplification) ---

def test_giant_verb_error_bounded():
    giant = "A" * 100000
    with pytest.raises(StepValidationError) as exc:
        validate_steps([{giant: "x"}])
    assert len(str(exc.value)) < 200  # texte attaquant tronqué, pas réfléchi en entier

def test_goto_url_too_long_rejected():
    giant = "https://example.com/" + "a" * 100000
    with pytest.raises(StepValidationError) as exc:
        validate_steps([{"goto": giant}])
    assert len(str(exc.value)) < 200  # url géante rejetée avant réflexion non bornée


def test_press_giant_non_string_error_bounded():
    with pytest.raises(StepValidationError) as exc:
        validate_steps([{"press": ["A" * 200000]}])
    assert len(str(exc.value)) < 200  # arg non-str géant : réflexion bornée, pas de 422 ~200KB


# --- Minor 3: invariant liste vide (dont dépend le broker) ---

def test_validate_steps_empty_list_gets_final_capture():
    assert validate_steps([]) == [{"capture": "final"}]


# --- Phase 3j : nouveaux verbes DSL (sleep / hide / capture région|full_page) ---

def test_sleep_valid_and_bounded():
    # sleep en SECONDES (Phase 3k) : entier ou flottant, borné 0..MAX_SLEEP_S
    assert validate_steps([{"sleep": 5}])[0] == {"sleep": 5}
    assert validate_steps([{"sleep": MAX_SLEEP_S}])[0] == {"sleep": MAX_SLEEP_S}
    assert validate_steps([{"sleep": 0.5}])[0] == {"sleep": 0.5}


def test_sleep_rejects_bool_and_out_of_range():
    with pytest.raises(StepValidationError):
        validate_steps([{"sleep": True}])
    with pytest.raises(StepValidationError):
        validate_steps([{"sleep": MAX_SLEEP_S + 1}])   # > 60 s rejeté
    with pytest.raises(StepValidationError):
        validate_steps([{"sleep": "5"}])


def test_hide_requires_valid_selector():
    assert validate_steps([{"hide": ".cookie"}])[0] == {"hide": ".cookie"}
    with pytest.raises(StepValidationError):
        validate_steps([{"hide": 123}])
    with pytest.raises(StepValidationError):
        validate_steps([{"hide": "a" * (MAX_SEL + 1)}])


def test_capture_fullpage_form():
    out = validate_steps([{"capture": {"label": "p", "full_page": True}}])
    assert out[0] == {"capture": {"label": "p", "full_page": True}}


def test_capture_region_form():
    out = validate_steps([{"capture": {"label": "z", "selector": "#login"}}])
    assert out[0] == {"capture": {"label": "z", "selector": "#login"}}


def test_capture_selector_and_fullpage_mutually_exclusive():
    with pytest.raises(StepValidationError):
        validate_steps([{"capture": {"label": "x", "selector": "#a", "full_page": True}}])


def test_capture_dict_rejects_unknown_keys_and_bad_types():
    with pytest.raises(StepValidationError):
        validate_steps([{"capture": {"label": "x", "bogus": 1}}])
    with pytest.raises(StepValidationError):
        validate_steps([{"capture": {"label": "bad<x>"}}])
    with pytest.raises(StepValidationError):
        validate_steps([{"capture": {"label": "x", "full_page": "yes"}}])


def test_capture_dict_form_is_final_capture_not_duplicated():
    # un capture étendu en dernier step ne déclenche PAS l'ajout d'un capture auto
    raw = [{"click": "#a"}, {"capture": {"label": "fin", "full_page": True}}]
    out = validate_steps(raw)
    assert out[-1] == {"capture": {"label": "fin", "full_page": True}}
    assert sum(1 for s in out if "capture" in s) == 1
