# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixtures partagées. Les tests web surchargent `web.app.app.dependency_overrides`
(le singleton FastAPI global) ; sans reset entre tests, un override laissé en
place fuit sur les tests suivants selon l'ordre d'exécution (bug latent d'ordre —
audit qualité 3k). Ce nettoyage autouse le supprime après chaque test."""
import pytest


@pytest.fixture(autouse=True)
def _clear_dependency_overrides():
    yield
    try:
        from web.app import app
        app.dependency_overrides.clear()
    except Exception:  # noqa: BLE001 - un test sans FastAPI ne doit pas échouer ici
        pass
