#!/usr/bin/env python3
"""Rassemble TOUTES les surfaces de dépendances Python du dépôt, pour qu'un audit de
vulnérabilité les couvre sans en oublier une.

POURQUOI CE SCRIPT EXISTE (mesuré le 2026-08-02, pas supposé). Le dépôt n'avait AUCUN audit de
vulnérabilité de dépendances — vérifié sous tous les noms (`pip-audit`, `safety`, `osv-scanner`,
`snyk`, `trivy`, `grype`), zéro correspondance en CI. Il en avait pourtant l'INTENTION écrite :
`docs/superpowers/specs/2026-07-12-ocular-moteur-unifie-design.md` annonçait « scan deps
(pip-audit) ». Une capacité affirmée et absente est pire qu'une capacité absente.

POURQUOI CE N'EST PAS `pip-audit pyproject.toml` ET RIEN D'AUTRE. Mesuré : `pyproject.toml`
n'est PAS la seule surface. Les images des runners installent, en plus et hors manifeste,
`camoufox[geoip]`, `opencv-python-headless`, `numpy`, et ÉPINGLENT playwright à des versions
différentes de celle qu'un `pip install` du projet résoudrait (`==1.41.0` dans
`runner_analysis`, `==1.49.1` dans `runner_recon`, contre `>=1.41` au manifeste). Un audit qui
ne lirait que le manifeste rendrait « 0 vulnérabilité » en ignorant les paquets réellement
livrés dans les conteneurs qui, eux, ouvrent du contenu hostile. C'est exactement le défaut
qu'on ferme : un contrôle qui connaît son incomplétude et présente son résultat comme complet.

LA COLLECTE EST DÉRIVÉE, PAS ÉNUMÉRÉE. On ne nomme aucun Dockerfile ni aucun paquet :

  1. le manifeste — `project.dependencies` PLUS la valeur de CHAQUE clé de
     `project.optional-dependencies` (la table est parcourue, jamais la clé `dev` nommée : un
     extra ajouté demain est couvert par construction) ;
  2. les images — tout fichier SUIVI dont le nom contient « Dockerfile », dont on extrait les
     arguments de chaque `pip install`. Un Dockerfile ajouté demain est couvert de même.

Chaque surface donne UN fichier de requirements distinct, et non un seul fichier commun : les
images épinglent des versions CONTRADICTOIRES (playwright 1.41.0 et 1.49.1), qu'aucun résolveur
ne peut satisfaire ensemble. Fusionner les surfaces ferait échouer la résolution — ou pire, la
ferait réussir sur un compromis que personne ne déploie.

ANTI-MUETTE. Un collecteur qui ne trouve rien rend « 0 vulnérabilité » aussi tranquillement
qu'un arbre sain. Quatre conditions font donc ÉCHOUER la collecte plutôt que la laisser
silencieuse : aucune dépendance au manifeste ; aucun Dockerfile suivi ; un Dockerfile qui
contient `pip install` mais dont on n'extrait aucun paquet ; un drapeau inconnu dans une ligne
`pip install` (le script ne peut alors pas affirmer qu'il a compris la ligne).

PÉRIMÈTRE, ET SA GARDE. Tout fichier suivi contenant `pip install` doit être soit un Dockerfile
(analysé ci-dessus), soit sous `docs/` (de la prose : elle n'installe rien au build), soit
porter une exemption ÉCRITE et DATÉE ci-dessous. Un script shell qui installerait des paquets
demain fait donc ÉCHOUER la collecte au lieu d'ouvrir un angle mort silencieux.

Usage :  python3 .github/scripts/collect_python_requirements.py --repo . --out DIR
Sortie :  0 = collecte complète (DIR contient un .txt par surface, plus python-floor.txt) ;
          1 = collecte incomplète ou incomprise (message nommant la cause).
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path

# Fichiers qui contiennent `pip install` sans porter de surface de dépendances PROPRE.
# SCOPÉ AU FICHIER, avec la raison écrite et la date — jamais un répertoire en bloc, jamais
# « au cas où ». Toute autre occurrence hors `docs/` fait échouer la collecte.
_SANS_SURFACE_PROPRE = {
    ".github/workflows/ci.yml": (
        "installe `-e \".[dev]\"`, c'est-à-dire EXACTEMENT le manifeste, déjà collecté "
        "comme surface 1 — l'auditer une seconde fois n'ajouterait rien (2026-08-03)"
    ),
    "pyproject.toml": (
        "les occurrences y sont en COMMENTAIRE (note d'épinglage par hashes), pas des "
        "installations ; les dépendances du fichier sont lues par la surface 1 (2026-08-03)"
    ),
    ".github/scripts/collect_python_requirements.py": (
        "ce script-ci : les occurrences sont dans sa documentation et dans ses messages "
        "d'erreur, qui CITENT la commande qu'il analyse. Il n'installe rien et n'entre dans "
        "aucune image. Constaté par la mutation qui a fait rougir la garde sur elle-même "
        "(2026-08-03)"
    ),
}

# Drapeaux de `pip install` sans argument : ils ne nomment pas de paquet, on les saute.
_DRAPEAUX_SANS_ARGUMENT = {
    "--no-cache-dir", "--upgrade", "-U", "--no-deps", "--quiet", "-q", "--verbose", "-v",
    "--user", "--pre", "--force-reinstall", "--no-compile", "--compile", "--no-build-isolation",
    "--disable-pip-version-check", "--no-warn-script-location", "--no-warn-conflicts",
    "--ignore-installed", "--prefer-binary", "--no-input",
}

# Drapeaux de `pip install` qui CONSOMMENT l'argument suivant : on saute les deux. Aucun ne
# nomme un paquet à auditer (`-r` est traité à part, plus bas, parce qu'il en nomme, lui).
_DRAPEAUX_AVEC_ARGUMENT = {
    "--index-url", "-i", "--extra-index-url", "--find-links", "-f", "--constraint", "-c",
    "--target", "-t", "--platform", "--python-version", "--implementation", "--abi",
    "--prefix", "--root", "--src", "--only-binary", "--no-binary", "--progress-bar",
    "--timeout", "--retries", "--proxy", "--cert", "--client-cert", "--root-user-action",
}

_PIP_INSTALL = re.compile(
    r"(?:python[0-9.]*\s+-m\s+)?\bpip[0-9]*\s+install\b(?P<reste>.*)"
)


def _fichiers_suivis(repo: Path) -> list[str]:
    """Les chemins suivis par git, découpés sur NUL pour survivre aux noms exotiques."""
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def _lire(repo: Path, rel: str) -> str | None:
    try:
        return (repo / rel).read_text("utf-8", "surrogateescape")
    except (IsADirectoryError, FileNotFoundError, PermissionError, UnicodeDecodeError):
        return None


def _lignes_jointes(texte: str) -> list[str]:
    """Les lignes d'instruction d'un Dockerfile, commentaires retirés et continuations recollées.

    Les COMMENTAIRES sont retirés d'abord, et c'est nécessaire, pas cosmétique : mesuré sur ce
    dépôt, trois Dockerfiles commentent le choix d'une version en citant `pip install` en prose.
    Les lire comme des installations produisait des « paquets » tels que `sans`, `version`, `la`
    — et un backtick non apparié y cassait l'analyse de la ligne RÉELLE du même fichier. Docker
    ignore ces lignes ; le collecteur doit les ignorer aussi, sinon il audite de la prose et
    manque le vrai `pip install`.

    Les continuations `\\` sont ensuite recollées, sinon un `pip install` multiligne est lu
    tronqué — et un paquet déclaré sur la deuxième ligne ne serait jamais audité.
    """
    lignes: list[str] = []
    tampon = ""
    for ligne in texte.splitlines():
        if re.match(r"\s*#", ligne):
            continue
        depouillee = ligne.rstrip()
        if depouillee.endswith("\\"):
            tampon += depouillee[:-1] + " "
            continue
        lignes.append(tampon + depouillee)
        tampon = ""
    if tampon:
        lignes.append(tampon)
    return lignes


def _specs_dune_ligne(reste: str, rel: str, erreurs: list[str]) -> list[str]:
    """Les spécificateurs de paquets d'un `pip install`, en signalant toute incompréhension.

    Un jeton commençant par `-` que le script ne connaît pas fait ÉCHOUER la collecte : ne pas
    comprendre une ligne d'installation et continuer, c'est produire un « 0 vulnérabilité » sur
    une surface qu'on n'a pas lue.
    """
    # On s'arrête au premier séparateur shell : ce qui suit n'appartient plus à `pip install`.
    reste = re.split(r"&&|\|\||;|\|", reste)[0]
    try:
        jetons = shlex.split(reste, posix=True)
    except ValueError as exc:
        erreurs.append(f"{rel} : ligne `pip install` non analysable ({exc})")
        return []

    specs: list[str] = []
    i = 0
    while i < len(jetons):
        jeton = jetons[i]
        if jeton in _DRAPEAUX_SANS_ARGUMENT or jeton.split("=", 1)[0] in _DRAPEAUX_SANS_ARGUMENT:
            i += 1
        elif jeton in _DRAPEAUX_AVEC_ARGUMENT:
            i += 2
        elif jeton.split("=", 1)[0] in _DRAPEAUX_AVEC_ARGUMENT and "=" in jeton:
            i += 1
        elif jeton in ("-r", "--requirement"):
            cible = jetons[i + 1] if i + 1 < len(jetons) else "<manquant>"
            if (rel, cible) not in _REQUIREMENTS_ENGENDRES:
                erreurs.append(
                    f"{rel} : `pip install -r {cible}` — ce fichier de requirements est produit "
                    "au build, donc son contenu n'est pas lisible ici. Si c'est une COPIE du "
                    "manifeste, l'écrire dans _REQUIREMENTS_ENGENDRES ; sinon la surface n'est "
                    "pas auditée."
                )
            i += 2
        elif jeton.startswith("-"):
            erreurs.append(
                f"{rel} : drapeau inconnu `{jeton}` dans un `pip install` — le script ne peut "
                "pas affirmer avoir compris la ligne. L'ajouter à la table de drapeaux."
            )
            i += 1
        else:
            specs.append(jeton)
            i += 1
    return specs


# Fichiers de requirements ENGENDRÉS au build, dont le contenu est déjà audité par ailleurs.
# SCOPÉ AU COUPLE (Dockerfile, chemin), avec la raison écrite et la date. Tout autre `-r` fait
# échouer la collecte, parce qu'on ne saurait alors pas ce qui est installé.
_REQUIREMENTS_ENGENDRES = {
    ("deploy/Dockerfile.test", "/tmp/reqs.txt"): (
        "ÉCRIT par l'étape précédente du même `RUN`, qui lit `pyproject.toml` avec tomllib et "
        "concatène `dependencies` + `optional-dependencies.dev` : le contenu est donc "
        "EXACTEMENT la surface 1, déjà auditée (2026-08-03)"
    ),
}


def _plancher_python(pyproject: dict) -> str:
    """La version Python la plus BASSE que le manifeste autorise.

    C'est elle qu'on audite : sur un plancher, un résolveur choisit les publications les plus
    anciennes encore compatibles — le pire cas en matière d'avis de sécurité. La lire ici plutôt
    que de la recopier dans la CI évite qu'elles divergent en silence.
    """
    brut = pyproject.get("project", {}).get("requires-python", "")
    m = re.fullmatch(r"\s*>=\s*(\d+\.\d+)\s*", brut)
    if not m:
        raise SystemExit(
            f"[deps] ÉCHEC — `requires-python` vaut {brut!r}, dont ce script ne sait pas tirer "
            "un plancher. Étendre la lecture plutôt que de deviner une version."
        )
    return m.group(1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", default=".", help="racine du dépôt (défaut : répertoire courant)")
    ap.add_argument("--out", required=True, help="répertoire où écrire les surfaces collectées")
    args = ap.parse_args()
    repo = Path(args.repo).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    erreurs: list[str] = []
    suivis = _fichiers_suivis(repo)

    # --- Surface 1 : le manifeste -------------------------------------------------------
    pyproject = tomllib.loads((repo / "pyproject.toml").read_text("utf-8"))
    projet = pyproject.get("project", {})
    manifeste = list(projet.get("dependencies", []))
    extras = projet.get("optional-dependencies", {})
    for nom in sorted(extras):
        manifeste.extend(extras[nom])
    if not manifeste:
        erreurs.append(
            "pyproject.toml : aucune dépendance collectée — ce contrôle est devenu muet, "
            "le réparer plutôt que de le croire."
        )
    (out / "manifeste.txt").write_text("\n".join(manifeste) + "\n", "utf-8")
    (out / "python-floor.txt").write_text(_plancher_python(pyproject) + "\n", "utf-8")

    # --- Surface 2 : les images -----------------------------------------------------------
    dockerfiles = [r for r in suivis if "Dockerfile" in Path(r).name]
    if not dockerfiles:
        erreurs.append(
            "aucun Dockerfile suivi trouvé — la découverte est devenue muette, la réparer."
        )

    surfaces = 0
    for rel in sorted(dockerfiles):
        texte = _lire(repo, rel)
        if texte is None:
            erreurs.append(f"{rel} : illisible, donc NON audité")
            continue
        specs: list[str] = []
        for ligne in _lignes_jointes(texte):
            m = _PIP_INSTALL.search(ligne)
            if m:
                specs.extend(_specs_dune_ligne(m.group("reste"), rel, erreurs))
        # « Le fichier installe quelque chose mais on n'en a rien tiré » = extraction muette,
        # sauf si TOUTES ses installations sont des `-r` déclarés engendrés (cas légitime).
        if (
            "pip install" in texte
            and not specs
            and not any(c[0] == rel for c in _REQUIREMENTS_ENGENDRES)
        ):
            erreurs.append(
                f"{rel} : contient `pip install` mais aucun paquet n'en a été extrait — "
                "l'extraction est muette sur ce fichier, la réparer."
            )
        if specs:
            nom = re.sub(r"[^A-Za-z0-9]+", "-", rel).strip("-")
            (out / f"image-{nom}.txt").write_text("\n".join(specs) + "\n", "utf-8")
            surfaces += 1

    # --- Garde de périmètre : aucune surface hors des deux ci-dessus -----------------------
    for rel in suivis:
        if "Dockerfile" in Path(rel).name or rel.startswith("docs/"):
            continue
        if rel in _SANS_SURFACE_PROPRE:
            continue
        texte = _lire(repo, rel)
        if texte and "pip install" in texte:
            erreurs.append(
                f"{rel} : contient `pip install` alors que ce n'est ni un Dockerfile ni de la "
                "prose sous `docs/`. Soit ses paquets sont audités (étendre la collecte), soit "
                "l'exemption est écrite et datée dans _SANS_SURFACE_PROPRE."
            )

    print(f"[deps] {len(suivis)} fichiers suivis · {len(dockerfiles)} Dockerfile(s)")
    print(f"[deps] surfaces collectées : 1 manifeste ({len(manifeste)} specs) + {surfaces} image(s)")
    print(f"[deps] plancher Python audité : {(out / 'python-floor.txt').read_text().strip()}")

    if erreurs:
        print("\n[deps] ÉCHEC — la collecte est INCOMPLÈTE ; l'auditer ainsi rendrait un")
        print("       « 0 vulnérabilité » qui ne couvre pas ce que le dépôt livre :")
        for e in erreurs:
            print(f"    - {e}")
        return 1

    print("[deps] OK — toutes les surfaces de dépendances du dépôt sont collectées")
    return 0


if __name__ == "__main__":
    sys.exit(main())
