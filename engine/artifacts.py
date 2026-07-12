from __future__ import annotations

import re

REF_HEX = "[0-9a-f]{64}"
REF_RE = re.compile(r"sha256:" + REF_HEX)
FILENAME_RE = re.compile(r"sha256_" + REF_HEX)


def ref_to_filename(ref: str) -> str:
    """Valide un ref d'artefact (anti-traversal, ancrage strict) et le mappe vers un nom de fichier sûr."""
    if not REF_RE.fullmatch(ref):
        raise ValueError(f"ref d'artefact invalide: {ref!r}")
    return ref.replace("sha256:", "sha256_")


def filename_to_ref(fname: str) -> str:
    """Inverse de ref_to_filename : valide un nom de fichier d'artefact et le mappe vers son ref."""
    if not FILENAME_RE.fullmatch(fname):
        raise ValueError(f"nom d'artefact invalide: {fname!r}")
    return fname.replace("sha256_", "sha256:", 1)
