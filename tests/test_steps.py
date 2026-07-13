import pytest
from engine.steps import validate_steps, StepValidationError, redact_step, MAX_STEPS

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
