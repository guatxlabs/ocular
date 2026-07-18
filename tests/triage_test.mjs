// Test comportemental des helpers PURS de web/ui/triage.js (aucun DOM, aucun
// import de core.js — même convention que filter_test.mjs). On importe
// directement les fonctions pures et on asserte sur leurs valeurs de retour.
import assert from 'node:assert';
import {
  triageBadgeText, triageDiverges, triageSignalRows, TRIAGE_BAND_LABEL, roundHalfEven,
} from '../web/ui/triage.js';

// --- libellés de bande ---
assert.strictEqual(TRIAGE_BAND_LABEL.low, 'BASSE');
assert.strictEqual(TRIAGE_BAND_LABEL.medium, 'MOYENNE');
assert.strictEqual(TRIAGE_BAND_LABEL.high, 'HAUTE');

// --- triageBadgeText ---
assert.strictEqual(triageBadgeText(null), null, 'triage null -> badge null');
assert.strictEqual(triageBadgeText(undefined), null, 'triage undefined -> badge null');
const badge = triageBadgeText({ score: 72, band: 'high' });
assert.ok(badge.includes('72'), 'le badge contient le score');
assert.strictEqual(badge, 'triage 72');

// --- triageDiverges ---
assert.strictEqual(
  triageDiverges({ agrees_with_rules: false }, 'benign'), true,
  'diverge quand agrees_with_rules === false');
assert.strictEqual(
  triageDiverges({ agrees_with_rules: true }, 'malicious'), false,
  'pas de divergence quand agrees_with_rules === true');
assert.strictEqual(triageDiverges(null, 'benign'), false, 'triage null -> pas de divergence');
// défensif : champ absent -> pas === false -> pas de divergence
assert.strictEqual(triageDiverges({}, 'benign'), false, 'champ absent -> pas de divergence');

// --- triageSignalRows ---
assert.deepStrictEqual(triageSignalRows(null), [], 'triage null -> []');
const tri = {
  score: 72, band: 'high',
  signals: [
    { key: 'base', label: 'base', weight: 5, detail: '' },
    { key: 'obf', label: "Cluster d'obfuscation", weight: 35, detail: '2 patterns' },
    { key: 'few', label: 'peu de tiers', weight: -4, detail: '' },
  ],
};
const rows = triageSignalRows(tri);
assert.strictEqual(rows.length, 3, '3 signaux -> 3 rangées');
// mapping des poids en texte signé arrondi
assert.strictEqual(rows[0].weightText, '+5');
assert.strictEqual(rows[1].weightText, '+35');
assert.strictEqual(rows[2].weightText, '-4');
// ordre préservé (déjà trié par le scorer)
assert.strictEqual(rows[0].label, 'base');
assert.strictEqual(rows[1].label, "Cluster d'obfuscation");
assert.strictEqual(rows[2].label, 'peu de tiers');
// label + detail transportés
assert.strictEqual(rows[1].detail, '2 patterns');
assert.strictEqual(rows[0].detail, '');
// arrondi d'un poids fractionnaire
assert.strictEqual(
  triageSignalRows({ signals: [{ label: 'x', weight: 4.6, detail: '' }] })[0].weightText, '+5');

// --- roundHalfEven : cohérence avec round() de Python (half-to-even) ---
// (Math.round divergerait : 2.5->3, 22.5->23 ; Python round : 2.5->2, 22.5->22.)
assert.strictEqual(roundHalfEven(2.5), 2, '2.5 -> 2 (pair)');
assert.strictEqual(roundHalfEven(3.5), 4, '3.5 -> 4 (pair)');
assert.strictEqual(roundHalfEven(22.5), 22, '22.5 -> 22 (pair)');
assert.strictEqual(roundHalfEven(-2.5), -2, '-2.5 -> -2 (pair)');
assert.strictEqual(roundHalfEven(-3.5), -4, '-3.5 -> -4 (pair)');
assert.strictEqual(roundHalfEven(4.6), 5, 'non-demi : arrondi normal');
assert.strictEqual(roundHalfEven(4.4), 4, 'non-demi : arrondi normal');
assert.strictEqual(roundHalfEven(0), 0);
assert.strictEqual(roundHalfEven(undefined), 0, 'défensif');
// un poids calibré à .5 s'affiche donc au pair (cohérent avec le score serveur)
assert.strictEqual(
  triageSignalRows({ signals: [{ label: 'x', weight: 22.5, detail: '' }] })[0].weightText, '+22');

console.log('triage_test OK');
