from __future__ import annotations

import re

REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def ref_to_filename(ref: str) -> str:
    """Valide un ref d'artefact (anti-traversal) et le mappe vers un nom de fichier sûr."""
    if not REF_RE.match(ref):
        raise ValueError(f"ref d'artefact invalide: {ref!r}")
    return ref.replace("sha256:", "sha256_")
