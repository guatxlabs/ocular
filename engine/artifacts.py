# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import base64
import hashlib
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

    Intégrité : le ref DOIT être le sha256 du contenu décodé (store
    content-addressé). Toute entrée dont le hash ne correspond pas est
    silencieusement ignorée — un écrivain compromis (ex: web, montage
    `/artifacts` en rw) ne peut donc jamais poser un blob mensonger sous un
    nom qu'il ne contrôle pas : il ne peut écrire QUE le fichier dont le nom
    est le vrai hash de son propre contenu, ce qui rend le montage rw sûr
    sans empoisonner le store partagé avec le broker.

    Idempotence multi-écrivain (bug interactif — la capture d'une session
    plantait en 500 avant même d'atteindre `/saved`) : `broker.launcher`
    écrit ce store en ROOT (jobs batch, conteneur+docker), `web.app` y écrit
    en UID non-root 10002 (capture de session interactive). Deux entrées de
    contenu strictement identique (ex. le même HTML rendu produit le même DOM
    octet pour octet par les deux moteurs) partagent le MÊME nom de fichier
    (store content-addressé) — si le fichier existe déjà (écrit par l'autre
    UID, mode 0644 non accessible en écriture à un autre utilisateur),
    tenter de le RÉÉCRIRE lève `PermissionError`, non rattrapée, qui faisait
    échouer toute la capture. Le contenu étant adressé par son propre hash,
    un fichier déjà présent sous ce nom est PAR CONSTRUCTION déjà le bon
    contenu (collision sha256 infaisable) : on saute l'écriture, sans jamais
    tenter d'ouvrir un fichier qu'on ne possède pas forcément.
    """
    os.makedirs(artifacts_dir, exist_ok=True)
    for ref, b64 in blobs.items():
        try:
            fname = ref_to_filename(ref)          # lève ValueError si ref non conforme (anti-traversal)
        except ValueError:
            continue
        path = os.path.join(artifacts_dir, fname)
        if os.path.exists(path):
            continue                                # déjà stocké (même hash -> même contenu) : rien à faire
        data = base64.b64decode(b64)
        if hashlib.sha256(data).hexdigest() != ref.split(":", 1)[1]:
            continue                                # intégrité : hash != ref -> pas d'écriture
        with open(path, "wb") as fh:
            fh.write(data)


def filename_to_ref(fname: str) -> str:
    """Inverse de ref_to_filename : valide un nom de fichier d'artefact et le mappe vers son ref."""
    if not FILENAME_RE.fullmatch(fname):
        raise ValueError(f"nom d'artefact invalide: {fname!r}")
    return fname.replace("sha256_", "sha256:", 1)
