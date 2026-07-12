from __future__ import annotations

import os

import redis

from broker.queue import _RESULT_PREFIX  # noqa: F401  (documentaire)


def collect(artifacts_dir: str, client) -> int:
    """Supprime les fichiers d'artefacts dont plus aucun résultat Redis ne référence le ref.
    Retourne le nombre de fichiers supprimés."""
    referenced: set[str] = set()
    for key in client.scan_iter(match="ocular:result:*"):
        raw = client.get(key)
        if raw:
            referenced.update(_refs_in(raw.decode() if isinstance(raw, bytes) else raw))
    removed = 0
    if not os.path.isdir(artifacts_dir):
        return 0
    for fname in os.listdir(artifacts_dir):
        ref = fname.replace("sha256_", "sha256:", 1)
        if ref not in referenced:
            os.remove(os.path.join(artifacts_dir, fname))
            removed += 1
    return removed


def _refs_in(result_json: str) -> set[str]:
    import re
    return set(re.findall(r"sha256:[0-9a-f]{64}", result_json))


if __name__ == "__main__":
    c = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))
    n = collect(os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts"), c)
    print(f"gc: {n} artefacts supprimés")
