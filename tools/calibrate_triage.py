"""Calibration HORS-LIGNE des poids de triage par régression logistique.
Lecture seule de la base saved, aucun accès réseau. Sortie = fichier de poids
proposé (même forme que BUILTIN) + rapport ; l'opérateur relit puis pointe
OCULAR_TRIAGE_WEIGHTS dessus. Déterministe (graine fixe).

Usage : python -m tools.calibrate_triage --db <path> --out <weights.json>
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from typing import Optional

import numpy as np

import saved_store
from engine.result import DomInfo, StaticFinding
from engine.triage import extract_signals
from engine.triage_weights import BUILTIN

_LABEL_MAP = {"legitimate": "benign", "suspicious": "suspicious", "malicious": "malicious"}
_CLASSES = ["benign", "suspicious", "malicious"]
_FEATURE_KEYS = [k for k in BUILTIN["signals"]]  # ordre stable


def _signal_vector(result: dict) -> list[int]:
    findings = [StaticFinding(**f) for f in result.get("static_findings", [])]
    dom = DomInfo(**(result.get("dom") or {}))
    sig = extract_signals(findings, result.get("network", []), result.get("console", []), dom)
    return [1 if sig[k][0] else 0 for k in _FEATURE_KEYS]


def collect_dataset(conn) -> tuple[list[list[int]], list[str]]:
    try:
        rows = conn.execute(
            "SELECT id, analyst_verdict FROM saved_analysis WHERE analyst_verdict IS NOT NULL"
        ).fetchall()
    except sqlite3.OperationalError:
        # base à l'ancien schéma (colonne analyst_verdict absente) ouverte en
        # lecture seule -> pas de migration possible ; aucun label -> le refus
        # de calibration (données insuffisantes) s'appliquera proprement.
        return [], []
    X, y = [], []
    for row in rows:
        result = saved_store.get_result(conn, row["id"])
        if not result:
            continue
        X.append(_signal_vector(result))
        y.append(_LABEL_MAP[row["analyst_verdict"]])
    return X, y


def _softmax_fit(X: np.ndarray, y_idx: np.ndarray, n_classes: int,
                 iters: int = 4000, lr: float = 0.1, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    n, d = X.shape
    W = rng.normal(0, 0.01, size=(d, n_classes))
    Y = np.eye(n_classes)[y_idx]
    for _ in range(iters):
        logits = X @ W
        logits -= logits.max(axis=1, keepdims=True)
        p = np.exp(logits)
        p /= p.sum(axis=1, keepdims=True)
        grad = X.T @ (p - Y) / n
        W -= lr * grad
    return W


def fit_weights(X: list[list[int]], y: list[str], feature_keys: list[str]) -> dict:
    Xa = np.asarray(X, dtype=float)
    y_idx = np.asarray([_CLASSES.index(v) for v in y])
    W = _softmax_fit(Xa, y_idx, len(_CLASSES))
    # coefficient « malicious » - « benign » = tendance d'un signal à aggraver.
    delta = W[:, _CLASSES.index("malicious")] - W[:, _CLASSES.index("benign")]
    scale = 35.0 / (np.abs(delta).max() or 1.0)  # borne le plus fort à ~35
    signals = {}
    for i, key in enumerate(feature_keys):
        signals[key] = [round(float(delta[i] * scale), 1), BUILTIN["signals"][key][1]]
    return {
        # Placeholder déterministe (pas de Date/now ici) ; le caller (main)
        # remplace par calibrated-<--date>. Le suffixe garde la forme calibrated-*.
        "version": "calibrated-pending",
        "base": 5,
        "bands": {"medium": 40, "high": 70},
        "signals": signals,
    }


def _report(X, y, weights) -> str:
    from collections import Counter
    counts = Counter(y)
    lines = [f"labels: {dict(counts)} (total {len(y)})", "poids (calibré vs builtin):"]
    for key in _FEATURE_KEYS:
        old = BUILTIN["signals"][key][0]
        new = weights["signals"][key][0]
        lines.append(f"  {key:24s} {old:6.1f} -> {new:6.1f}")
    return "\n".join(lines)


def calibrate(conn, *, min_total: int = 30, min_per_class: int = 5
              ) -> tuple[Optional[dict], str]:
    from collections import Counter
    X, y = collect_dataset(conn)
    counts = Counter(y)
    if len(y) < min_total:
        return None, f"{len(y)} labels, {min_total} requis"
    # On calibre un discriminant : il faut au moins 2 classes présentes, et
    # chaque classe *présente* doit atteindre min_per_class. Une classe absente
    # (ex. « suspicious », qui est aussi une bande dérivée du score, pas
    # nécessairement un label analyste) n'empêche pas la calibration.
    present = [c for c in _CLASSES if counts.get(c, 0) > 0]
    under = [c for c in present if counts[c] < min_per_class]
    if len(present) < 2 or under:
        return None, (f"classes insuffisantes: présentes={present}, "
                      f"sous {min_per_class}={under} (compte {dict(counts)})")
    weights = fit_weights(X, y, _FEATURE_KEYS)
    return weights, _report(X, y, weights)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--date", required=True, help="suffixe version, ex. 2026-07-18")
    ap.add_argument("--min-total", type=int, default=30)
    ap.add_argument("--min-per-class", type=int, default=5)
    args = ap.parse_args()
    # LECTURE SEULE : la calibration ne doit jamais muter la base des
    # sauvegardes (pas même le _migrate idempotent de connect()).
    conn = saved_store.connect_readonly(args.db)
    try:
        weights, report = calibrate(conn, min_total=args.min_total,
                                    min_per_class=args.min_per_class)
    finally:
        conn.close()
    print(report)
    if weights is None:
        raise SystemExit("calibration refusée : données insuffisantes")
    weights["version"] = f"calibrated-{args.date}"
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(weights, fh, ensure_ascii=False, indent=2)
    print(f"\nÉcrit {args.out} (version {weights['version']}). "
          f"Relire, puis pointer OCULAR_TRIAGE_WEIGHTS dessus pour activer.")


if __name__ == "__main__":
    main()
