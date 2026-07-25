# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Le marqueur `OcularResult.truncation` doit ATTEINDRE quelqu'un.

`engine.result.Truncation` énonce l'angle mort qu'il ferme : « l'analyste
croirait voir tout le trafic d'une page qui en a émis cent fois plus ». Le champ
était bien écrit — mais personne ne le lisait :

  - `grep truncation web/` = 0 occurrence hors commentaires ; la vue détail ne
    l'affichait pas ;
  - le WARNING « résultat tronqué … » du runner part sur STDERR, que
    `broker/launcher.py` capture (`capture_output=True`) puis JETTE quand
    `returncode == 0` — stderr n'est lu qu'en cas d'échec.

Pour les deux profils batch, le seul canal restant était donc un champ JSON que
rien ne lisait : le champ est écrit, la garantie n'est pas livrée.

Deux canaux, testés ici : le journal du broker (côté serveur, pour l'exploitant)
et un helper de présentation pur consommé par l'UI (côté analyste ; le rendu est
verrouillé par tests/filter_test.mjs).
"""
import json
import logging

import pytest

from broker.launcher import _parse_and_store


def _wrapper(truncation: dict) -> str:
    return json.dumps({
        "result": {
            "schema_version": "1.0", "job_id": "job-1", "profile": "capture",
            "target": "https://x.test/", "timestamp": "2026-07-25T10:00:00Z",
            "verdict": "suspicious", "truncation": truncation,
        },
        "blobs": {},
    })


@pytest.fixture
def broker_warnings():
    """Capture ciblée sur le logger du broker — `caplog` dépend de la
    propagation jusqu'à la racine, et `tests/test_logging.py` laisse le logger
    « ocular » à CRITICAL (état de module non restauré par monkeypatch)."""
    logger = logging.getLogger("ocular.broker.launcher")
    records: list[str] = []

    class _Sink(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    sink = _Sink(logging.WARNING)
    logger.addHandler(sink)
    previous = logger.level
    logger.setLevel(logging.WARNING)
    yield records
    logger.removeHandler(sink)
    logger.setLevel(previous)


def test_broker_logs_a_truncated_result(tmp_path, broker_warnings):
    """Le canal stderr du runner est jeté quand le job réussit : c'est ici, à la
    RÉCEPTION du résultat, que l'exploitant peut encore l'apprendre."""
    _parse_and_store(_wrapper({"network_dropped": 1200, "console_dropped": 0,
                               "post_data_truncated": 3, "findings_dropped": 0,
                               "text_truncated": 7}), str(tmp_path))
    assert any("tronqué" in m for m in broker_warnings), (
        "un résultat amputé traverse le broker sans laisser la moindre trace"
    )
    joined = " ".join(broker_warnings)
    assert "1200" in joined and "job-1" in joined


def test_broker_stays_quiet_on_a_complete_result(tmp_path, broker_warnings):
    """Non-régression : un résultat complet ne doit produire aucun bruit."""
    _parse_and_store(_wrapper({"network_dropped": 0, "console_dropped": 0,
                               "post_data_truncated": 0, "findings_dropped": 0,
                               "text_truncated": 0}), str(tmp_path))
    assert not [m for m in broker_warnings if "tronqué" in m]


def test_broker_tolerates_a_result_without_the_field(tmp_path, broker_warnings):
    """Rétro-compatibilité : un payload 1.0 antérieur n'a pas de `truncation`."""
    payload = json.dumps({
        "result": {"schema_version": "1.0", "job_id": "job-2", "profile": "capture",
                   "target": "https://x.test/", "timestamp": "2026-07-25T10:00:00Z",
                   "verdict": "benign"},
        "blobs": {},
    })
    stored = _parse_and_store(payload, str(tmp_path))
    assert json.loads(stored)["job_id"] == "job-2"
    assert not [m for m in broker_warnings if "tronqué" in m]


def test_the_ui_has_a_consumer_for_the_marker():
    """Garde anti-régression du finding : le marqueur doit être LU côté UI, pas
    seulement écrit côté moteur. Le comportement du helper est verrouillé par
    tests/filter_test.mjs ; ce test-ci vérifie qu'il est bien câblé dans les deux
    surfaces qui affichent un résultat."""
    import pathlib
    filter_js = pathlib.Path("web/ui/filter.js").read_text()
    assert "export function truncationNotice" in filter_js

    for view in ("web/ui/views/detail.js", "web/ui/views/interactive.js"):
        text = pathlib.Path(view).read_text()
        assert "truncationNotice" in text, f"{view} n'affiche pas le marqueur de troncature"
