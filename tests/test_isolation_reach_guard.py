# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Garde-fou du classificateur de `_can_reach` (preuve d'isolation réseau).

`tests/test_session_isolation_integration.py` porte la preuve de sécurité de
toute la phase « isolation réseau par session » : ses assertions négatives
(`assert not _can_reach(...)`) ne valent QUE si un `False` signifie vraiment
« injoignable » et non « l'outillage a cassé ». Ces tests-ci verrouillent cette
distinction SANS démon Docker (d'où l'absence de marqueur `integration`) :
c'est le classificateur qui est testé, pas le réseau.
"""
import pytest

from test_session_isolation_integration import ReachToolingError, _classify_reach


# --- Codes RÉSEAU de curl : vraie preuve d'injoignabilité --------------------

@pytest.mark.parametrize("rc", [6, 7, 28])
def test_curl_network_codes_mean_unreachable(rc):
    # 6=DNS introuvable, 7=connexion refusée, 28=timeout.
    assert _classify_reach(rc, "") is False


def test_returncode_zero_means_reachable():
    assert _classify_reach(0, "") is True


# --- Codes d'OUTILLAGE : le test ne prouve rien -> il doit hurler ------------

@pytest.mark.parametrize("rc", [125, 126, 127])
def test_docker_exec_tooling_codes_raise(rc):
    # 125=échec du démon, 126=commande non exécutable, 127=commande introuvable
    # (ex. `curl` absent de l'image) -> aucune conclusion possible sur le réseau.
    with pytest.raises(ReachToolingError):
        _classify_reach(rc, "OCI runtime exec failed: ...")


def test_stopped_container_returncode_one_raises():
    # Constaté empiriquement : `docker exec` sur un conteneur ARRÊTÉ ou ABSENT
    # renvoie 1 (« Error response from daemon: ... is not running »), PAS 125.
    # Une liste noire {125,126,127} laisserait donc passer ce cas en « isolé ».
    with pytest.raises(ReachToolingError):
        _classify_reach(1, "Error response from daemon: container ... is not running")


def test_unknown_returncode_raises_rather_than_concluding_isolated():
    # Liste BLANCHE : tout code hors {0, 6, 7, 28} est traité comme outillage.
    # Ex. curl 52 (« empty reply ») signifie que le TCP a ABOUTI — le rendre
    # `False` fabriquerait une fausse preuve d'isolation.
    with pytest.raises(ReachToolingError):
        _classify_reach(52, "")


def test_tooling_error_message_carries_returncode_and_stderr():
    with pytest.raises(ReachToolingError) as excinfo:
        _classify_reach(127, "exec: \"curl\": executable file not found in $PATH")
    msg = str(excinfo.value)
    assert "127" in msg, "le returncode doit figurer dans le message"
    assert "executable file not found" in msg, "le stderr doit figurer dans le message"
