from __future__ import annotations

import os
import re
import time

import redis

from bus.queue import RESULT_PREFIX
from engine.artifacts import filename_to_ref


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
    c = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))
    n = collect(os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts"), c)
    print(f"gc: {n} artefacts supprimés")
