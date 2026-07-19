# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import hashlib
import os
import stat

import pytest

from engine.artifacts import ref_to_filename, store_blobs


def test_valid_ref_maps_to_safe_filename():
    ref = "sha256:" + "a" * 64
    assert ref_to_filename(ref) == "sha256_" + "a" * 64


def test_store_blobs_writes_valid_refs_only(tmp_path):
    data = b"PNGDATA"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()  # ref cohérent : intégrité vérifiée par store_blobs
    store_blobs({ref: base64.b64encode(data).decode(),
                 "../evil": base64.b64encode(b"x").decode()}, str(tmp_path))
    assert (tmp_path / ref_to_filename(ref)).read_bytes() == data
    assert not (tmp_path / "../evil").exists()
    assert list(tmp_path.iterdir()) == [tmp_path / ref_to_filename(ref)]


def test_store_blobs_rejects_ref_not_matching_sha256_of_content(tmp_path):
    """Intégrité : si le ref ne correspond pas au sha256 réel des octets
    (empoisonnement / erreur), store_blobs n'écrit rien pour cette entrée —
    ceci rend un montage /artifacts en rw sûr même pour un écrivain compromis."""
    data = b"PNGDATA"
    bad_ref = "sha256:" + "a" * 64  # ne correspond PAS au sha256 de data
    store_blobs({bad_ref: base64.b64encode(data).decode()}, str(tmp_path))
    assert not (tmp_path / ref_to_filename(bad_ref)).exists()
    assert list(tmp_path.iterdir()) == []


def test_store_blobs_writes_when_ref_matches_sha256_of_content(tmp_path):
    data = b"some artifact bytes"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()
    store_blobs({ref: base64.b64encode(data).decode()}, str(tmp_path))
    assert (tmp_path / ref_to_filename(ref)).read_bytes() == data


def test_store_blobs_skips_write_when_file_already_exists(tmp_path):
    # BUG 1 (régression) : `broker.launcher` (jobs batch, en ROOT) et
    # `web.app` (capture de session interactive, UID non-root 10002) écrivent
    # dans le MÊME store content-addressé. Deux contenus identiques (même
    # HTML rendu par deux moteurs différents) donnent la MÊME ref -> le
    # fichier existe déjà, écrit avec un autre propriétaire/mode restrictif
    # (0644, non accessible en écriture à un autre UID). Avant le correctif,
    # `store_blobs` tentait quand même `open(path, "wb")` -> `PermissionError`
    # non rattrapée -> 500 sur `POST /sessions/{id}/capture`, qui empêchait
    # d'atteindre `/saved` avec un job_id valide.
    #
    # Prouvé ici indépendamment des droits d'exécution du test (root en
    # conteneur de test contourne les permissions fichier) via l'horodatage :
    # si `store_blobs` rouvrait le fichier en écriture, mtime changerait même
    # à contenu identique. On fige mtime dans le passé et on vérifie qu'il
    # est INCHANGÉ après l'appel -> preuve que l'écriture a bien été sautée.
    data = b"same content, two writers"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()
    path = tmp_path / ref_to_filename(ref)
    path.write_bytes(data)
    old_time = 1_000_000_000.0  # 2001, loin dans le passé
    os.utime(path, (old_time, old_time))

    store_blobs({ref: base64.b64encode(data).decode()}, str(tmp_path))  # ne doit PAS lever

    assert path.read_bytes() == data
    assert os.stat(path).st_mtime == old_time  # jamais rouvert en écriture

    # belt-and-suspenders : si le process tourne sans privilège root, un
    # fichier en lecture seule doit aussi survivre à l'appel sans exception.
    if os.geteuid() != 0:
        os.chmod(path, stat.S_IRUSR)
        store_blobs({ref: base64.b64encode(data).decode()}, str(tmp_path))
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


@pytest.mark.parametrize("bad", [
    "sha256:xyz", "../../etc/passwd", "sha256:" + "a" * 63,
    "sha256:" + "A" * 64, "md5:" + "a" * 32, "sha256:" + "a" * 64 + "/..",
    "sha256:" + "a" * 64 + "\n",       # newline final (piège $ vs \Z)
    "sha256:" + "a" * 64 + "\x00",     # null byte
    "sha256:" + "a" * 64 + "extra",    # suffixe après 64 hex
    "\nsha256:" + "a" * 64,            # newline en tête
])
def test_invalid_ref_rejected(bad):
    with pytest.raises(ValueError):
        ref_to_filename(bad)
