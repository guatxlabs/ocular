// i18n.js — dictionnaire FR->EN appliqué au DOM (même approche que plume : seuls
// les libellés connus sont traduits ; les données — verdict brut, urls, matches —
// ne matchent aucune clé donc restent intactes). Actif seulement si LANG === 'en'.
import { LANG } from './state.js';

const I18N_EN = {
  // header / nav
  'Analyser': 'Analyze', 'Jobs': 'Jobs', 'Se déconnecter': 'Sign out',
  'Sauvegardes': 'Saved', 'Admin': 'Admin',
  'Langue / Language': 'Language', 'Thème clair / sombre': 'Light / dark theme',
  'Changer de thème': 'Toggle theme',
  // login
  'Connexion': 'Sign in', 'Jeton d\'accès': 'Access token',
  'Colle ton jeton Ocular pour accéder au moteur.': 'Paste your Ocular token to reach the engine.',
  'jeton (Bearer)': 'token (Bearer)', 'Se connecter': 'Sign in',
  'Jeton refusé — vérifie la valeur et réessaie.': 'Token rejected — check the value and try again.',
  'Le serveur n\'a pas de jeton configuré (OCULAR_TOKEN).': 'The server has no token configured (OCULAR_TOKEN).',
  // submit
  'Analyser une page': 'Analyze a page', 'Colle du HTML ou dépose un .eml, puis lance l\'analyse.': 'Paste HTML or drop an .eml, then run the analysis.',
  'HTML à analyser': 'HTML to analyze',
  'colle du HTML (ou charge un fichier .htm/.html/.eml)': 'paste HTML (or load a .htm/.html/.eml file)',
  'Charger un fichier': 'Load a file', 'aucun fichier': 'no file',
  'URL à analyser': 'URL to analyze', 'analyse d\'URL live': 'live URL analysis',
  'Lancer l\'analyse': 'Run analysis', 'Analyse en cours…': 'Analyzing…',
  'Ajoute du HTML ou charge un fichier .htm/.html/.eml avant de lancer.': 'Add HTML or load a .htm/.html/.eml file before running.',
  // submit — toggle profil + capture URL
  'Colle du HTML, dépose un fichier .htm/.html/.eml, ou capture une URL live.':
    'Paste HTML, drop a .htm/.html/.eml file, or capture a live URL.',
  'Analyser HTML': 'Analyze HTML', 'Analyser URL': 'Analyze URL',
  'Profil d\'analyse': 'Analysis profile',
  'capture live via moteur furtif (Camoufox) — Turnstile géré':
    'live capture via stealth engine (Camoufox) — Turnstile handled',
  'Renseigne une URL avant de lancer.': 'Enter a URL before running.',
  'URL manquante — renseigne une URL avant de lancer.': 'URL missing — enter a URL before running.',
  'URL invalide — vérifie le format (ex. https://exemple.com).':
    'Invalid URL — check the format (e.g. https://example.com).',
  'URL interdite : cible non publique (IP exposée / SSRF). Utilise une URL publique.':
    'Forbidden URL: non-public target (exposed IP / SSRF). Use a public URL.',
  'HTML manquant ou trop volumineux.': 'HTML missing or too large.',
  'Cette URL a déjà été capturée et conservée. Tu peux la revoir sans relancer le moteur.':
    'This URL has already been captured and saved. You can review it without rerunning the engine.',
  // submit — champ script (tier dynamique scripté 3c)
  'Script (JSON, optionnel)': 'Script (JSON, optional)',
  'Rejoue une séquence d\'actions (fill/click/wait/press/capture/scroll) après le chargement — DSL borné, aucun JS arbitraire.':
    'Replays a sequence of actions (fill/click/wait/press/capture/scroll) after loading — bounded DSL, no arbitrary JS.',
  'Exemple : accepter les cookies': 'Example: accept cookies',
  'Exemple : remplir un formulaire': 'Example: fill a form',
  // jobs
  'Mes analyses': 'My analyses', 'Les jobs soumis depuis ce navigateur.': 'Jobs submitted from this browser.',
  'Aucune analyse pour l\'instant.': 'No analysis yet.', 'Lancer une analyse': 'Run an analysis',
  'en attente': 'pending', 'échec': 'failed', 'Échec': 'Failed',
  // detail
  '← Jobs': '← Jobs', 'Capture d\'écran': 'Screenshot', 'chargement de la capture…': 'loading screenshot…',
  'Aucune capture pour ce job.': 'No screenshot for this job.',
  'Détections statiques': 'Static findings', 'Aucune détection statique.': 'No static findings.',
  'Réseau': 'Network', 'Console': 'Console', 'DOM': 'DOM',
  'Télécharger le DOM': 'Download the DOM', 'aucune requête réseau': 'no network request',
  'console vide': 'empty console', 'Titre': 'Title', 'URL finale': 'Final URL',
  'Chaîne de redirection': 'Redirect chain', 'détections': 'findings', 'requêtes': 'requests',
  'Job introuvable ou expiré.': 'Job not found or expired.',
  'Analyse en attente — actualisation automatique…': 'Analysis pending — auto-refreshing…',
  'Aucune capture pour cette analyse.': 'No screenshot for this analysis.',
  'Capture indisponible.': 'Screenshot unavailable.',
  // detail — journal d'actions (tier dynamique scripté 3c)
  'Journal d\'actions': 'Action log', 'ok': 'ok',
  // detail — furtivité / capture (profil capture)
  'Moteur furtif': 'Stealth engine', 'Turnstile passé': 'Turnstile solved',
  'Capture initiale': 'Initial capture', 'Après Turnstile': 'After Turnstile',
  'Capture finale': 'Final capture', 'Capture': 'Capture',
  'IP exposée': 'Exposed IP', 'URL interdite': 'Forbidden URL',
  // sauvegarde (panneau détail)
  'Conserver cette analyse': 'Keep this analysis', 'Sauvegarder': 'Save',
  'étiquette (optionnelle)': 'label (optional)', 'Analyse sauvegardée': 'Analysis saved',
  'Voir dans Sauvegardes': 'View in Saved',
  'Artefacts expirés — relance l\'analyse avant de sauvegarder.': 'Artifacts expired — rerun the analysis before saving.',
  'Nom déjà utilisé — choisis une autre étiquette.': 'Name already used — pick another label.',
  // vue Sauvegardes
  'Analyses conservées côté serveur, indépendantes du navigateur.': 'Analyses kept server-side, independent of the browser.',
  'Aucune analyse sauvegardée.': 'No saved analysis.',
  'Ouvre une analyse terminée puis « Sauvegarder ».': 'Open a finished analysis then “Save”.',
  '(sans étiquette)': '(no label)',
  // modale de dédup
  'Analyse déjà sauvegardée': 'Already saved',
  'Ce HTML a déjà été analysé et conservé. Tu peux la revoir sans relancer le moteur.':
    'This HTML has already been analyzed and saved. You can review it without rerunning the engine.',
  'Sauvegardée': 'Saved', 'Étiquette': 'Label',
  'Analyser quand même': 'Analyze anyway', 'Voir': 'View', 'Annuler': 'Cancel',
  // vue Admin
  'Purge des analyses sauvegardées. Actions destructives.': 'Purge saved analyses. Destructive actions.',
  'Token administrateur': 'Admin token',
  'Gardé en mémoire pour cette session uniquement — jamais stocké. Requis pour supprimer.':
    'Kept in memory for this session only — never stored. Required to delete.',
  'Tout purger': 'Purge all', 'Supprimer': 'Delete',
  'Supprimer cette sauvegarde ?': 'Delete this save?',
  'Purger toutes les sauvegardes ?': 'Purge all saves?',
  'Renseigne le token admin avant de supprimer.': 'Enter the admin token before deleting.',
  'Token admin refusé — vérifie la valeur.': 'Admin token rejected — check the value.',
  'Administration désactivée : le serveur n\'a pas de OCULAR_ADMIN_TOKEN.':
    'Administration disabled: the server has no OCULAR_ADMIN_TOKEN.',
  // interactif (sessions live — T8)
  'Interactif': 'Interactive', 'Session interactive': 'Interactive session',
  'Ouvre une page live et pilote son rendu dans le conteneur isolé.':
    'Open a live page and drive its rendering in the isolated container.',
  'IP exposée · contenu rendu côté conteneur.': 'Exposed IP · content rendered in the container.',
  'Ouvrir une URL': 'Open a URL', 'Rendre du HTML': 'Render HTML',
  'URL à ouvrir': 'URL to open', 'HTML à rendre': 'HTML to render',
  'chargement live dans le conteneur (moteur furtif)': 'live loading in the container (stealth engine)',
  'Ouvrir la session': 'Open the session', 'Ouverture de la session…': 'Opening the session…',
  'Renseigne une URL avant d\'ouvrir.': 'Enter a URL before opening.',
  'Ajoute du HTML avant d\'ouvrir.': 'Add HTML before opening.',
  'Session non prête — le conteneur n\'a pas démarré à temps.':
    'Session not ready — the container did not start in time.',
  'Requête invalide (URL/HTML manquant ou trop volumineux).':
    'Invalid request (URL/HTML missing or too large).',
  'connexion…': 'connecting…', 'connecté': 'connected', 'déconnecté': 'disconnected',
  'connexion perdue': 'connection lost', 'accès refusé': 'access denied',
  'noVNC introuvable': 'noVNC not found',
  'Capturer': 'Capture', 'capture…': 'capturing…', 'Fermer': 'Close',
  'Capture enregistrée': 'Capture saved', 'Voir l\'analyse': 'View the analysis',
  'Capture échouée — la session ne répond pas.': 'Capture failed — the session is not responding.',
  // sévérités
  'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
  // verdicts
  'Verdict': 'Verdict',
  'chargement…': 'loading…', 'Réessayer': 'Retry',
};

export function i18nWalk(root) {
  if (LANG !== 'en' || !root) return;
  root.querySelectorAll('[placeholder],[title],[aria-label]').forEach((el) => {
    ['placeholder', 'title', 'aria-label'].forEach((a) => {
      const v = el.getAttribute(a);
      if (v && I18N_EN[v.trim()]) el.setAttribute(a, I18N_EN[v.trim()]);
    });
  });
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
  const nodes = [];
  let n;
  while ((n = w.nextNode())) nodes.push(n);
  nodes.forEach((t) => {
    const k = t.nodeValue.trim();
    if (k && I18N_EN[k]) t.nodeValue = t.nodeValue.replace(k, I18N_EN[k]);
  });
}
