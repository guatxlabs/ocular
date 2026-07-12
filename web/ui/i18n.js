// i18n.js — dictionnaire FR->EN appliqué au DOM (même approche que plume : seuls
// les libellés connus sont traduits ; les données — verdict brut, urls, matches —
// ne matchent aucune clé donc restent intactes). Actif seulement si LANG === 'en'.
import { LANG } from './state.js';

const I18N_EN = {
  // header / nav
  'Analyser': 'Analyze', 'Jobs': 'Jobs', 'Se déconnecter': 'Sign out',
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
  'HTML à analyser': 'HTML to analyze', 'colle ici le HTML (ou charge un .eml)': 'paste HTML here (or load an .eml)',
  'Charger un .eml': 'Load an .eml', 'aucun fichier': 'no file',
  'URL à analyser': 'URL to analyze', 'analyse d\'URL live': 'live URL analysis',
  'Lancer l\'analyse': 'Run analysis', 'Analyse en cours…': 'Analyzing…',
  'Ajoute du HTML ou charge un .eml avant de lancer.': 'Add HTML or load an .eml before running.',
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
