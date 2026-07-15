# Phase 3g — SSRF egress guard (runner) — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Fermer le trou SSRF résiduel : `validate_capture_url` valide au submit, mais le navigateur (réseau ON) suit les redirections et le DNS peut rebind → il atteint quand même des IP internes. Un **garde egress dans le runner** (proxy HTTP/CONNECT avec résolution + **pinning IP** + check `is_global` à chaque connexion) l'empêche.

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. Secure-by-default (garde **ON** par défaut sur les runners réseau-ON ; `OCULAR_EGRESS_GUARD=0` pour désactiver). Réutilise la logique `is_global` de `engine/ssrf.py` (DRY — une seule source de vérité IP). Ne casse pas la capture légitime (sites publics OK). Jamais de secret/URL sensible loggé. L'analyse (réseau none) n'est pas concernée.
- **Défaite du rebinding** : le garde **résout au moment de la connexion** et **connecte à l'IP validée** (pinning) — jamais de re-résolution entre le check et le connect. Chaque redirection vers un nouvel hôte = nouveau CONNECT re-vérifié.

---

### Task G1 — `is_ip_allowed` factorisé + `engine/egress_guard.py` (le proxy)

**Files:** Modify `engine/ssrf.py` ; Create `engine/egress_guard.py` ; Test `tests/test_ssrf.py`, `tests/test_egress_guard.py`.

**1. `engine/ssrf.py`** — factorise la décision IP (DRY) :
- `def is_ip_allowed(ip: str | ipaddress._BaseAddress) -> bool` : `True` ssi l'IP est `is_global` (rejette loopback/RFC1918/link-local 169.254/fe80/metadata/CGNAT/réservé/multicast). Accepte une string ou un objet ipaddress.
- `def resolve_allowed_ip(host: str, port: int) -> str | None` : résout `host` (`socket.getaddrinfo`, littéral IP géré), retourne la **première IP résolue qui est `is_allowed`** (string), ou `None` si aucune (→ à bloquer). C'est la primitive de pinning du garde.
- `validate_capture_url` : réutilise `is_ip_allowed` (comportement inchangé).

**2. `engine/egress_guard.py`** — proxy asyncio HTTP/CONNECT filtrant :
- `class EgressGuard` : serveur `asyncio.start_server` sur `127.0.0.1:{port}` (port éphémère si 0). Pour chaque connexion cliente lit la 1ʳᵉ ligne de requête :
  - **`CONNECT host:port HTTP/1.1`** (HTTPS/tunnels) : parse host/port ; `ip = resolve_allowed_ip(host, port)` ; si `None` → répond `HTTP/1.1 403 Forbidden\r\n\r\n` et ferme (log `egress blocked host=<host>` — host non secret, jamais l'URL complète) ; sinon connecte à **`ip:port`** (l'IP épinglée), répond `HTTP/1.1 200 Connection established\r\n\r\n`, puis **pipe bidirectionnel** (relais octets) jusqu'à fermeture.
  - **HTTP absolu** `GET http://host[:port]/path HTTP/1.1` (forme proxy) : parse host/port depuis la ligne + `Host:` ; `resolve_allowed_ip` ; bloqué → `403` ; sinon ouvre vers l'IP épinglée, ré-émet la requête (en forme origine `GET /path`), pipe la réponse.
  - Toute autre 1ʳᵉ ligne malformée → `400`, ferme.
- Robuste : timeouts de connexion, fermeture propre, une connexion cliente lente/hostile ne bloque pas le serveur (gestion par tâche). Ne JAMAIS suivre lui-même une redirection (c'est le navigateur qui re-CONNECT → re-check). Ne pas mettre en cache la résolution (pinning per-connexion).
- API : `async def start(self) -> int` (démarre, retourne le port réel), `async def stop(self)`.

**Tests** :
- `tests/test_ssrf.py` : `is_ip_allowed` (`127.0.0.1`/`10.0.0.1`/`169.254.169.254`/`192.168.1.1`/`100.64.0.1` CGNAT/`::1`/`fe80::1`/`fd00::1` ULA → False ; `8.8.8.8`/`1.1.1.1`/`2606:4700:4700::1111` → True) ; `resolve_allowed_ip` avec un littéral privé → None, littéral public → l'IP, host mocké résolvant privé+public → l'IP publique, host résolvant que privé → None (mocke `socket.getaddrinfo`). `validate_capture_url` inchangé (tests existants verts).
- `tests/test_egress_guard.py` : démarre le garde ; un client envoie `CONNECT 127.0.0.1:80` → **403** (bloqué, sans ouvrir de connexion) ; `CONNECT 169.254.169.254:80` → 403 ; une 1ʳᵉ ligne malformée → 400. Le chemin ALLOWED (tunnel vers une IP publique) est couvert par l'intégration G2 (nécessite un vrai serveur ; ici on peut mocker `resolve_allowed_ip` pour retourner l'adresse d'un serveur de test **local** et vérifier que le tunnel relaie — attention : un serveur de test local est sur 127.0.0.1 donc « non global » ; pour tester le relais, mocke `resolve_allowed_ip` pour bypasser le check et pointer vers le serveur de test → prouve le PIPE, pas la sécu). Sépare bien : test sécu (blocage réel) vs test relais (avec check mocké).

`pytest -m "not integration" -q` vert. Commit : `feat(3g): egress guard (proxy CONNECT/HTTP, résolution+pinning IP, is_global) + is_ip_allowed factorisé`.

---

### Task G2 — Câblage runner (recon + session) + intégration réelle

**Files:** Modify `runner_recon/capture.py`, `runner_recon_vnc/session_server.py`, `ocular_settings.py` ; Test `tests/test_egress_integration.py` (marqueur `integration`).

- `ocular_settings.py` : `egress_guard_enabled() -> bool` (`OCULAR_EGRESS_GUARD`, défaut **True**).
- `runner_recon/capture.py` : si `egress_guard_enabled()`, avant de lancer Camoufox : `guard = EgressGuard(); port = await guard.start()` ; lancer `AsyncCamoufox(..., proxy={"server": f"http://127.0.0.1:{port}"})` (vérifie la façon exacte dont Camoufox/Playwright accepte un proxy — option `proxy` du launch). `stop()` en fin (finally). S'applique à `capture_url` ET `capture_scripted` (DRY : un helper `_with_egress(...)` ou démarrer le garde dans le `async with` commun). Si désactivé → comportement actuel.
- `runner_recon_vnc/session_server.py` : idem au lancement de Camoufox (`_ensure_browser`) — le tier interactif est aussi réseau-ON.
- Le garde n'affecte PAS la résolution/fetch légitime (sites publics passent).

**Intégration** (`tests/test_egress_integration.py`, docker) :
- rebuild `ocular-runner-recon`. Sers une page fixture qui **redirige (302) vers `http://127.0.0.1:<port>/secret`** (ou vers `169.254.169.254`) ; capture-la → vérifie que la requête interne est **bloquée** (pas de contenu interne récupéré ; le réseau capté montre le blocage / absence de la ressource interne). ET une capture normale d'une page publique fonctionne toujours (réseau capté, DOM ok).
- Alternative testable sans internet : fixture sur un réseau docker qui `fetch('http://<ip-interne>/')` → la requête n'aboutit pas (garde bloque), vérifiable dans la trace réseau/console.

Commit : `feat(3g): câble l'egress guard dans les runners recon+session (Camoufox via proxy filtrant)`.

---

### Task G3 — Audit + e2e réel + merge
- [ ] Audit sécu : le garde bloque-t-il **réellement** metadata/RFC1918/loopback/IPv6-internes même via redirection et rebinding (résolution au connect + pinning) ? Pas de bypass (host avec IP littérale, IPv6, encodage, `CONNECT` vers un port arbitraire) ? Pas de DoS (connexion hostile) ? La capture légitime marche ? Fail-safe si le garde crashe (le runner ne doit pas fetch en direct sans garde — ou échoue proprement).
- [ ] **e2e réel** (rebuild runner) : (a) capture d'une page publique (example.com) → OK à travers le garde ; (b) une page redirigeant vers `169.254.169.254`/`127.0.0.1` → la ressource interne **n'est jamais atteinte** ; (c) guatx.com (Turnstile) → résout toujours À TRAVERS le garde (le trafic CF est public, doit passer). (d) mesurer que le garde n'ajoute pas de latence notable sur une capture normale.
- [ ] Merge via finishing-a-development-branch + MAJ roadmap/mémoire (SSRF DNS-rebinding/redirections **fermé**).

## Self-review
- Rebinding défait (résolution+pinning au connect). Redirections re-vérifiées (nouveau CONNECT). is_global = source unique (`is_ip_allowed`). Secure-by-default. Capture légitime + Turnstile préservés. Analyse (réseau none) non concernée.
