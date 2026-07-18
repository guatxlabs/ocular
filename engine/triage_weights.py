"""Poids par défaut du scoreur de triage (engine/triage.py). SEUL point de
réglage des poids/seuils : éditable à la main, versionné en Git. Un jeu calibré
(tools/calibrate_triage.py) a la même forme et remplace celui-ci via
OCULAR_TRIAGE_WEIGHTS. Poids calés sur la logique de engine/verdict.py."""

BUILTIN = {
    "version": "builtin-1",
    "base": 5,
    "bands": {"medium": 40, "high": 70},  # score < medium -> low ; >= high -> high
    "signals": {
        # clé -> (poids, libellé FR)
        "obfuscation_cluster":   (35.0, "Cluster d'obfuscation/exécution"),
        "obfuscation_single":    (18.0, "Obfuscation isolée"),
        "cred_and_urgency":      (25.0, "Identifiants + langage d'urgence"),
        "cred_external_form":    (22.0, "Identifiants postés vers un domaine externe"),
        "external_form":         (10.0, "Formulaire vers action externe"),
        "mailto_exfil":          (12.0, "Exfiltration par mailto:"),
        "high_severity_finding": (15.0, "Finding de sévérité haute"),
        "many_third_parties":    (8.0,  "Nombreux tiers réseau"),
        "console_errors":        (4.0,  "Erreurs console"),
        "redirect_chain":        (6.0,  "Chaîne de redirections"),
    },
}

# Seuil (nombre d'hôtes réseau distincts) au-delà duquel `many_third_parties`
# se déclenche. Ici (pas dans BUILTIN) car c'est un paramètre d'extraction, pas
# un poids calibrable.
MANY_THIRD_PARTIES_THRESHOLD = 10
