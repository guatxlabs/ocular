# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""LA COMPTABILITÉ DU TAMPON DE SESSION DOIT ÊTRE VRAIE, PAS SEULEMENT RAPIDE.

Le budget cumulé (`OCULAR_MAX_CAPTURE_BUFFER_BYTES`) borne ce qu'une page retient
pendant TOUTE une session interactive. Il est appliqué à l'insertion, sur une
comptabilité INCRÉMENTALE — c'est ce qui la rend O(1) — et re-dérivé quand la
liste a bougé ailleurs. Le déclencheur de cette re-dérivation était la LONGUEUR.

CE QUE ÇA LAISSAIT PASSER, mesuré sur 5d37457 avec
`OCULAR_MAX_CAPTURE_BUFFER_BYTES=65536` : remplacer une entrée par une plus
lourde SANS changer la longueur de la liste laissait la comptabilité annoncer
l'ancien coût —

    avant remplacement : retenu annoncé =      1 012
    après remplacement : retenu annoncé =      1 012  |  réel = 10 000 012

Deux fermetures, et il faut les deux :

  1. la LECTURE (`retained_bytes`) re-dérive du contenu, toujours : un budget
     qu'on lit faux ne borne rien, et la valeur re-dérivée est réinjectée, donc
     l'insertion suivante borne sur le bon chiffre ;
  2. une garde STATIQUE dérivée des tampons EUX-MÊMES interdit à tout autre
     module de remplacer une entrée en place. Les mutations qui restent —
     `append`, `extend`, `pop`, `del` — changent la longueur, donc sont vues.
"""
import ast
import pathlib

import pytest

from engine.wrapper import NetworkCapture

RACINE = pathlib.Path(__file__).resolve().parent.parent
# Le module qui DÉFINIT la classe a le droit de toucher ses propres entrées
# (`_on_response` y pose le statut HTTP) : c'est lui qui tient l'invariant.
PROPRIETAIRE = RACINE / "engine" / "wrapper.py"


def _buffers() -> list[str]:
    """Noms des tampons, DÉRIVÉS de la classe : ce sont exactement les familles
    dont elle tient la comptabilité. Un troisième tampon ajouté demain est gardé
    sans que personne ne relise ce fichier."""
    return sorted(NetworkCapture()._costs)


def _sources() -> list[pathlib.Path]:
    return sorted(p for p in RACINE.rglob("*.py")
                  if ".venv" not in p.parts and "__pycache__" not in p.parts
                  and p != PROPRIETAIRE and p.resolve() != pathlib.Path(__file__).resolve())


def _touche_un_tampon(node: ast.AST, buffers: list[str]) -> bool:
    """`<quoi que ce soit>.<tampon>[...]` — l'accès qui remplace une entrée sans
    changer la longueur de la liste."""
    return (isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr in buffers)


def test_the_buffers_are_derived_and_not_empty():
    assert _buffers() == ["console", "network"], (
        "les tampons ne sont plus ceux que la comptabilité connaît"
    )


def _verifie(source: pathlib.Path, etiquette: str) -> None:
    """Corps UNIQUE de la garde : un remplacement d'entrée en place, sous
    n'importe quelle forme d'affectation ou de mutation."""
    buffers = _buffers()
    arbre = ast.parse(source.read_text(encoding="utf-8"))
    for node in ast.walk(arbre):
        cibles: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            cibles = list(node.targets)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            cibles = [node.target]
        for cible in cibles:
            assert not _touche_un_tampon(cible, buffers), (
                f"{etiquette}:{node.lineno} remplace une entrée de tampon en "
                f"place : la comptabilité du budget cumulé annoncerait l'ancien "
                f"coût (utilisez append/pop, qui changent la longueur)"
            )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert not _touche_un_tampon(node.func.value, buffers), (
                f"{etiquette}:{node.lineno} mute une entrée de tampon en place "
                f"(`.{node.func.attr}()`) : son coût changerait sans que la "
                f"comptabilité le voie"
            )


@pytest.mark.parametrize("source", _sources(), ids=lambda p: str(p.relative_to(RACINE)))
def test_no_module_replaces_a_buffer_entry_in_place(source):
    """Un remplacement en place échappe au déclencheur de longueur : la
    comptabilité annoncerait l'ancien coût jusqu'à la prochaine observation."""
    _verifie(source, str(source.relative_to(RACINE)))


def test_the_static_guard_actually_catches_a_replacement(tmp_path):
    """La garde de la garde : jouée sur une source qui commet la faute, elle doit
    la voir. Une garde qu'on ne met jamais en défaut ne prouve rien."""
    faute = tmp_path / "fautif.py"
    faute.write_text(
        "def f(cap):\n"
        "    cap.console[0] = {'level': 'log', 'text': 'x' * 10_000_000}\n",
        encoding="utf-8")
    with pytest.raises(AssertionError, match="remplace une entrée"):
        _verifie(faute, "fautif.py")

    mutation = tmp_path / "mutant.py"
    mutation.write_text("def f(cap):\n    cap.network[3].update({'url': 'x' * 9000})\n",
                        encoding="utf-8")
    with pytest.raises(AssertionError, match="mute une entrée"):
        _verifie(mutation, "mutant.py")


def test_reading_the_budget_re_derives_it_from_the_content(monkeypatch):
    """La mesure de la revue, à l'identique : une entrée remplacée par une plus
    lourde, à longueur constante. La LECTURE doit rendre le coût RÉEL, et le
    réinjecter — sinon l'insertion suivante borne sur un chiffre faux."""
    monkeypatch.setenv("OCULAR_MAX_CAPTURE_BUFFER_BYTES", "65536")
    cap = NetworkCapture(keep="last")
    hooks: dict = {}

    class _Page:
        def on(self, event, fn):
            hooks[event] = fn

    cap.attach(_Page())

    class _Msg:
        def __init__(self, text):
            self.type, self.text = "log", text

    hooks["console"](_Msg("c" * 1000))
    assert cap.retained_bytes("console") == 1012

    cap.console[0] = {"level": "log", "text": "x" * 10_000_000}
    assert cap.retained_bytes("console") == 10_000_012, (
        "la comptabilité annonce l'ancien coût : un budget qui compte faux ne "
        "borne rien"
    )

    # ... et la valeur re-dérivée est REPRISE par l'insertion suivante, qui
    # évince donc pour de bon.
    hooks["console"](_Msg("d" * 1000))
    assert cap.retained_bytes("console") <= 65536
    assert cap.dropped_console >= 1
