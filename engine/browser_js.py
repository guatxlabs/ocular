"""Snippets JS FIXES partagés entre le tier batch (runner_recon/capture.py) et le
tier interactif (runner_recon_vnc/session_server.py). Source UNIQUE : ces deux
chaînes étaient dupliquées à l'identique (marquées « miroir de… » en commentaire),
ce qui laissait dériver le comportement entre les tiers (audit qualité 3k).

AUCUN contenu utilisateur n'est interpolé dans ces chaînes (elles sont exécutées
telles quelles via `page.evaluate`)."""
from __future__ import annotations

# Présence d'un challenge Cloudflare Turnstile dans le DOM (booléen).
CF_INDICATOR_JS = (
    "() => !!document.querySelector("
    "'[data-sitekey], .cf-turnstile, "
    "script[src*=\"challenges.cloudflare.com\"], "
    "iframe[src*=\"challenges.cloudflare.com\"]')"
)

# Parcourt la page PAS À PAS (attente à chaque palier -> déclenche le lazy-load),
# pause en bas, retour en haut. Tout est `await` -> `page.evaluate` ne rend la
# main qu'à la FIN du parcours. Borné (hauteur + nombre de pas).
SCROLL_TO_LOAD_JS = """async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  let total = 0, steps = 0;
  const dist = Math.max(200, Math.floor(window.innerHeight * 0.85));
  while (total < document.body.scrollHeight && steps < 80 && total < 200000) {
    window.scrollBy(0, dist); total += dist; steps += 1;
    await sleep(150);
  }
  await sleep(500);
  window.scrollTo(0, 0);
  await sleep(200);
}"""
