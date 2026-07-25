// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// triage.js — helpers PURS du panneau « Triage » (2e avis IA/ML). Données en
// entrée -> données/chaînes en sortie ; AUCUN import de core.js et AUCUN accès
// DOM ici (cf. filter.js : core.js exécute du bootstrap navigateur au chargement,
// donc non importable en test node). L'assemblage DOM (appels à el()) vit dans
// les VUES (views/detail.js, views/saved.js) qui, elles, importent el de core.js.
//
// Le triage vient de NOTRE moteur (score/signaux non hostiles), mais on suit la
// même discipline que le reste de l'UI : rendu 100% textNode côté vue, jamais
// innerHTML. Ces helpers restent défensifs (triage null, champs manquants).

export const TRIAGE_BAND_LABEL = { low: 'BASSE', medium: 'MOYENNE', high: 'HAUTE' };

// Texte de la pastille compacte (liste Sauvegardes) : « triage <score> », ou
// `null` si aucun triage (pas de pastille affichée).
export function triageBadgeText(triage) {
  if (!triage) return null;
  return 'triage ' + String(triage.score);
}

// Le 2e avis diverge-t-il du verdict règles ? `rulesVerdict` n'est pas utilisé
// pour la décision (le moteur a déjà posé `agrees_with_rules`) mais la signature
// le conserve pour que la vue puisse le passer (titre/tooltip de divergence).
export function triageDiverges(triage, rulesVerdict) {  // eslint-disable-line no-unused-vars
  return !!triage && triage.agrees_with_rules === false;
}

// Arrondi « au pair le plus proche » (banker's rounding, round-half-to-even).
// Le moteur Python calcule le score et ses contributions avec round() (half-even)
// et garantit Σ(contributions arrondies) == score. `Math.round` de JS est half-up
// et divergerait de ±1 sur un poids calibré à EXACTEMENT .5 (ex. 22.5) : on
// reproduit donc half-even ici pour que la somme AFFICHÉE égale toujours le score.
export function roundHalfEven(x) {
  const n = Number(x) || 0;
  if (Math.abs(n - Math.trunc(n)) === 0.5) {
    const floor = Math.floor(n);
    return (floor % 2 === 0) ? floor : floor + 1;  // vers l'entier pair
  }
  return Math.round(n);
}

// Décompose les signaux en rangées affichables : { label, weightText, detail }.
// `weightText` = contribution signée arrondie ('+35', '-4', '+5'). Ordre préservé
// (le scorer a déjà trié : base en tête puis |poids| décroissant). [] si !triage.
export function triageSignalRows(triage) {
  if (!triage || !Array.isArray(triage.signals)) return [];
  return triage.signals.map((s) => {
    const w = roundHalfEven(s && s.weight);
    return {
      label: (s && s.label) || '',
      weightText: (w >= 0 ? '+' : '') + String(w),
      detail: (s && s.detail) || '',
    };
  });
}
