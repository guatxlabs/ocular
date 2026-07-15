# Phase 3d-2 (J) — Recalibration du verdict (corroboration) — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Un verdict `malicious`/`suspicious` doit refléter une menace réelle, pas un signal isolé bénin. Une page de login légitime = `benign` ; un phishing (credential + langage d'urgence + form externe) = `malicious` ; du malware obfusqué (eval+atob+…) = `malicious`. Décision de modèle de menace validée avec l'utilisateur : **re-tier des sévérités + corroboration**.

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. Le verdict doit rester **explicable** (règles nommées, pas de boîte noire). Tests exhaustifs. Mettre à jour TOUS les tests existants qui dépendent de l'ancien comportement de verdict (leur intention change légitimement).

---

### Task J1 — Re-tier `engine/static.py` + détecteur « External form action »

**Files:** Modify `engine/static.py` ; Test `tests/test_static.py`.

**Re-tier des sévérités** (remplace la colonne severity de `PATTERNS`) :

*Obfuscation / exécution de code (signaux forts) :*
- `Dynamic code evaluation` (eval) → **high**
- `Dynamic function creation` (Function) → **high**
- `Base64 decode` (atob "...") → **medium**
- `Base64 decoding function` (atob() → **low**
- `URL decode` (unescape) → **medium**
- `String construction` (String.fromCharCode) → **medium**
- `Direct DOM write` (document.write) → **medium**
- `Delayed code execution` (setTimeout string) → **medium**
- `Repeated code execution` (setInterval string) → **medium**

*Structurel / courant (bénin en isolation) → **low** :*
- `Forced URL change`, `Forced navigation`, `HTML injection` (innerHTML=), `Complete HTML replacement` (outerHTML=), `Fetch request`, `AJAX request`, `Form submission` (.submit()), `Form action URL`, `POST form detected`, `External image`, `Cookie access`, `Local storage read/write`, `Session storage read`, `Browser detection`, `OS detection`, `Resolution detection`, `Language detection`, `Event handler`, `Event listener`, `Form submit handler` (onsubmit), `Copy disabled`, `Paste handler`, `Base64 encode` (btoa), `Character code access` (charCodeAt), `Password input field`, `Password field (name)`, `Email input field`, `Username input field`.

*Ressources embarquées / notable → **medium** :*
- `External script` (déjà medium), `Embedded iframe`, `Embedded object`, `Embedded content`.

*Langage de phishing → **medium** :*
- `Account verification text`, `Identity confirmation text`, `Payment update text`, `Account suspended text`.

**Nouveau détecteur** (ajouter à `PATTERNS`, AVANT ou après `Form action URL`) :
- pattern `r"<form[^>]*action\s*=\s*[\"']https?://[^\"']+[\"']"`, description **`External form action`**, severity **medium**. (Un formulaire qui poste vers une URL absolue http(s) = signal de collecte externe, brique du cluster phishing.)

- [ ] Tests `tests/test_static.py` : chaque nouvelle sévérité clé vérifiée (eval=high, password=low, external form=medium détecté, langage phishing=medium). `analyze_html` d'un `<form action="https://evil.tld/x">` → finding `External form action`.
- [ ] `pytest tests/test_static.py -q` vert. Commit : `feat(3d-J): re-tier sévérités static + détecteur External form action`.

---

### Task J2 — `compute_verdict` avec corroboration

**Files:** Modify `engine/verdict.py` ; Test `tests/test_verdict.py`.

**Nouvelle logique** (explicable, par ensembles de règles nommées) :
```python
from __future__ import annotations
from engine.result import StaticFinding, Verdict

# clusters de règles (par `rule`)
_OBF = {"Dynamic code evaluation", "Dynamic function creation", "Base64 decode",
        "URL decode", "String construction", "Direct DOM write"}
_CRED = {"Password input field", "Password field (name)",
         "Email input field", "Username input field"}
_URGENCY = {"Account verification text", "Identity confirmation text",
            "Payment update text", "Account suspended text"}


def compute_verdict(findings: list[StaticFinding]) -> Verdict:
    rules = {f.rule for f in findings}
    sev = {f.severity for f in findings}
    obf = _OBF & rules
    cred = bool(_CRED & rules)
    urgency = bool(_URGENCY & rules)
    ext_form = "External form action" in rules

    # 1. Menace forte / corroborée -> malicious
    if "critical" in sev:
        return "malicious"
    if len(obf) >= 2:                       # cluster obfuscation/exécution
        return "malicious"
    if cred and urgency and ext_form:       # kit phishing complet
        return "malicious"

    # 2. Faisceau d'indices -> suspicious
    if cred and urgency:                    # collecte de credentials + langage d'urgence
        return "suspicious"
    if "high" in sev:                       # un eval/Function isolé
        return "suspicious"
    if obf and (cred or ext_form):          # obfuscation + collecte/form externe
        return "suspicious"

    # 3. Sinon
    return "benign"
```

**Résultats attendus (à tester)** :
- login légitime (`password` + `email` + `form action` relatif + `POST form`) → **benign**.
- SPA légitime (`fetch` + `addEventListener` + `innerHTML=`) → **benign**.
- `eval` seul → **suspicious** (high isolé).
- phishing (`password` + `Account verification text` + `External form action`) → **malicious**.
- phishing partiel (`password` + `Payment update text`, form interne) → **suspicious**.
- malware obfusqué (`eval` + `atob "..."` + `String.fromCharCode`) → obf≥2 → **malicious**.
- un `External script` seul → **benign** (déjà couvert par A ; re-vérifier).

- [ ] Tests `tests/test_verdict.py` : les 7 cas ci-dessus (construis des `StaticFinding` avec les `rule`/`severity` attendus). Explicabilité : le verdict découle de règles nommées.
- [ ] `pytest tests/test_verdict.py -q` vert. Commit : `feat(3d-J): compute_verdict corroboré (cluster obfuscation + kit phishing)`.

---

### Task J3 — Mettre à jour les tests dépendants + non-régression globale

**Files:** Modify les tests qui asserted l'ancien verdict : `tests/test_render.py`, `tests/test_saved_api.py`, `tests/test_saved_store.py`, `tests/test_session_server_logic.py`, `tests/test_web_api.py`, `tests/test_capture_logic.py`, `tests/test_result_schema.py` (repère ceux qui échouent).

- [ ] Lancer `pytest -m "not integration" -q` ; pour CHAQUE test rouge lié au verdict, corriger l'attendu selon la **nouvelle intention** (un HTML de fixture qui n'a qu'un signal structurel doit désormais être `benign` ; un HTML délibérément malveillant doit rester `malicious` — ajuster la fixture si besoin pour qu'elle porte un vrai cluster). Ne pas « forcer » un test à passer en trahissant l'intention : si une fixture était censée être « malveillante », lui donner un vrai cluster (ex. ajouter langage d'urgence + external form).
- [ ] `pytest -m "not integration" -q` entièrement vert.
- [ ] Commit : `test(3d-J): aligne les tests de verdict sur la corroboration`.

---

### Task J4 — Audit + e2e réel + merge
- [ ] Audit (sécu : faux négatifs — un vrai phishing/malware ne doit pas passer benign ; faux positifs — login légitime benign ; explicabilité ; pas de ReDoS dans le nouveau pattern). Remédier Critical/Important.
- [ ] **e2e réel** (rebuild `ocular-runner-analysis`) : analyser (POST /jobs analysis) — (a) un login légitime (`<form action="/login" method=post>` + password + email) → **benign** ; (b) un phishing (`<form action="https://evil.tld/collect">` + password + « verify your account ») → **malicious** ; (c) du JS obfusqué (`eval(atob("..."))` + `String.fromCharCode`) → **malicious**. Confirmer les findings visibles (les signaux restent détectés, même en `low`).
- [ ] Merge via finishing-a-development-branch + MAJ mémoire/roadmap (J fait).

## Self-review
- Le verdict reste explicable (clusters nommés). Signaux toujours détectés (findings), seule la sévérité et l'agrégation changent. Login légitime → benign ; phishing/malware corroboré → malicious. Tous les tests dépendants réalignés sur la nouvelle intention (pas de triche).
