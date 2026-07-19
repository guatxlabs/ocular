# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
import re
import time

import redis

from bus.queue import RESULT_PREFIX
from engine.artifacts import filename_to_ref
from ocular_settings import artifacts_dir, redis_url


def collect(artifacts_dir: str, client, min_age_seconds: int = 300) -> int:
    """Supprime les artefacts orphelins (aucun résultat Redis ne référence leur ref).
    Garde-fous : (1) période de grâce — un fichier plus récent que min_age_seconds n'est
    jamais supprimé (évite d'effacer les artefacts d'un job écrit mais pas encore stocké
    dans Redis) ; (2) ne touche QUE les fichiers au format `sha256_<64hex>`.
    Retourne le nombre de fichiers supprimés."""
    referenced: set[str] = set()
    for key in client.scan_iter(match=f"{RESULT_PREFIX}*"):
        raw = client.get(key)
        if raw:
            referenced.update(_refs_in(raw.decode() if isinstance(raw, bytes) else raw))
    if not os.path.isdir(artifacts_dir):
        return 0
    now = time.time()
    removed = 0
    for fname in os.listdir(artifacts_dir):
        try:
            ref = filename_to_ref(fname)
        except ValueError:
            continue                                   # ignore les fichiers étrangers
        path = os.path.join(artifacts_dir, fname)
        if now - os.path.getmtime(path) < min_age_seconds:
            continue                                   # période de grâce : job possiblement en cours
        if ref not in referenced:
            os.remove(path)
            removed += 1
    return removed


def _refs_in(result_json: str) -> set[str]:
    return set(re.findall(r"sha256:[0-9a-f]{64}", result_json))


if __name__ == "__main__":
    # Passe par l'accesseur commun, comme tout le reste du système : lire
    # REDIS_URL en direct IGNORAIT OCULAR_REDIS_URL, donc un déploiement
    # utilisant ce nom (prioritaire partout ailleurs) faisait pointer le GC
    # vers un AUTRE Redis que celui du broker et du web — il n'y aurait vu
    # aucun résultat, et aurait donc supprimé des artefacts encore référencés.
    c = redis.Redis.from_url(redis_url())
    n = collect(artifacts_dir(), c)
    print(f"gc: {n} artefacts supprimés")
