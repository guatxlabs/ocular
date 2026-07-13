from __future__ import annotations

import base64
import os
import re

REF_HEX = "[0-9a-f]{64}"
REF_RE = re.compile(r"sha256:" + REF_HEX)
FILENAME_RE = re.compile(r"sha256_" + REF_HEX)


def ref_to_filename(ref: str) -> str:
    """Valide un ref d'artefact (anti-traversal, ancrage strict) et le mappe vers un nom de fichier sûr."""
    if not REF_RE.fullmatch(ref):
        raise ValueError(f"ref d'artefact invalide: {ref!r}")
    return ref.replace("sha256:", "sha256_")


def store_blobs(blobs: dict, artifacts_dir: str) -> None:
    """Écrit les blobs base64 (wrapper `{result, blobs}`) sur disque, un
    fichier par ref, sous `artifacts_dir`. Anti-traversal : toute ref qui ne
    matche pas `REF_RE` est silencieusement ignorée (`ref_to_filename` lève
    `ValueError`) — jamais de chemin dérivé d'une entrée non conforme.

    Module neutre (aucune dépendance Docker/subprocess) : réutilisé tel quel
    par `broker.launcher` (jobs jetables, conteneur + docker) ET par
    `web.app` (capture de session interactive, HTTP interne uniquement, sans
    accès conteneur) pour éviter de dupliquer cette logique de stockage.
    """
    os.makedirs(artifacts_dir, exist_ok=True)
    for ref, b64 in blobs.items():
        try:
            fname = ref_to_filename(ref)          # lève ValueError si ref non conforme (anti-traversal)
        except ValueError:
            continue
        with open(os.path.join(artifacts_dir, fname), "wb") as fh:
            fh.write(base64.b64decode(b64))


def filename_to_ref(fname: str) -> str:
    """Inverse de ref_to_filename : valide un nom de fichier d'artefact et le mappe vers son ref."""
    if not FILENAME_RE.fullmatch(fname):
        raise ValueError(f"nom d'artefact invalide: {fname!r}")
    return fname.replace("sha256_", "sha256:", 1)
