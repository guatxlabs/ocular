// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// interactive_live_test.mjs — la VRAIE vue interactive (web/ui/views/interactive.js,
// montée par core.js) sur le DOM minimal de tests/dom_shim.mjs, face à un
// `/live` qui échoue puis revient. Ce qui est vérifié n'est pas le code source
// de la vue mais CE QUE L'ANALYSTE A SOUS LES YEUX.
//
// TROIS DÉFAUTS MESURÉS SUR 651840c, qu'aucun `grep` n'aurait vus :
//   1. `pollLive` faisait `catch { stopPoll(); }` : UN SEUL 502 arrêtait le
//      panneau live pour de bon, SANS MESSAGE. Un panneau arrêté ressemble à
//      une page qui n'émet plus rien.
//   2. `truncated_fields` pouvait nommer `headers` : aucun rendu ne le
//      consommait, la coupe n'atteignait donc jamais l'analyste.
//   3. `/live` produit désormais des compteurs de troncature qui ne sont dans
//      aucun modèle (`forms_dropped`, cf. `_fit_live_payload`) : le bandeau
//      doit les annoncer sans que personne ne les ait déclarés côté UI.
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { installDom, reply, until } from './dom_shim.mjs';

const UI = pathToFileURL(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'web', 'ui') + path.sep,
).href;

const calls = { live: 0 };
let liveFails = false;

const LIVE_OK = {
  network: [{
    url: 'https://evil.test/collect?tok=AAA', method: 'GET', status: 200,
    resource_type: 'xhr',
    // `headers` : champ COUPÉ que la vue n'affiche NULLE PART. Sans marqueur
    // dérivé, la coupe n'atteint jamais l'analyste.
    truncated_fields: ['url', 'headers'],
  }],
  console: [{ level: 'error', text: 'boum', truncated_fields: ['text'] }],
  findings: [], forms: [], mailtos: [],
  counts: { network: 1, findings: 0, console: 1, forms: 0, mailtos: 0 },
  // `forms_dropped` n'est dans AUCUN modèle : compteur produit par le
  // délestage dérivé de `/live`. Il doit être annoncé quand même.
  truncation: { network_dropped: 0, forms_dropped: 3 },
  analysis_stale: true,
  verdict: 'suspicious',
};

const { appNode, screen } = installDom({
  hash: '#/interactive',
  routes: (url, opts = {}) => {
    const method = (opts.method || 'GET').toUpperCase();
    if (url === '/auth/whoami') return reply({ identity: 'a', method: 'token', groups: [] });
    if (url === '/sessions' && method === 'POST') return reply({ session_id: 's1', token: 't1' }, 202);
    if (url === '/sessions/s1' && method === 'GET') return reply({ session_id: 's1', state: 'ready', ready: true });
    if (url === '/sessions/s1/live') {
      calls.live += 1;
      return liveFails ? reply({ detail: 'live échoué' }, 502) : reply(LIVE_OK);
    }
    return undefined;
  },
});

await import(UI + 'core.js');
await until('vue interactive montée', () => appNode.querySelectorAll('form').length > 0);

const form = appNode.querySelector('form');
const urlInput = appNode.querySelectorAll('input').find((e) => e.getAttribute('id') === 'live-url');
assert.ok(urlInput, 'champ URL introuvable — la vue interactive n\'est pas montée');
urlInput.value = 'https://cible.test/';

// 1) le direct tombe DÈS le premier poll et reste tombé.
liveFails = true;
form.dispatch('submit');
await until('premier poll tenté', () => calls.live >= 1);

// UN échec ne doit pas éteindre la boucle : elle continue d'essayer...
const afterFirst = calls.live;
await until('la boucle réessaie après échec', () => calls.live > afterFirst + 2);
// ... et elle le DIT à l'écran, pendant l'incident.
assert.match(screen(), /Direct interrompu/,
  'panneau live muet pendant l\'incident : un direct arrêté ressemble à une page calme');
assert.match(screen(), /nouvelle tentative dans/,
  'l\'analyste ne sait pas que le direct va reprendre');

// 2) reprise : le panneau se remplit à nouveau, sans rien redémarrer à la main.
liveFails = false;
await until('panneau rempli après reprise', () => /1 appels réseau/.test(screen()));
assert.doesNotMatch(screen(), /Direct interrompu/, 'le bandeau d\'incident survit à la reprise');

// 3) ce que l'analyste voit du contenu coupé et de l'analyse périmée.
const shown = screen();
assert.match(shown, /✂ coupé/, 'aucun marqueur de coupe rendu');
assert.match(shown, /✂ coupé : headers/,
  '`headers` est coupé et n\'a aucune colonne dans cette vue : sans marqueur '
  + 'résiduel, la coupe n\'atteint jamais l\'analyste');
assert.match(shown, /3 formulaires non conservés/,
  'un compteur de troncature absent des modèles doit être annoncé quand même');
assert.match(shown, /tour précédent/,
  '`analysis_stale` non rendu : une analyse périmée passe pour l\'analyse du tour');

console.log(`interactive_live_test OK (polls /live tentés : ${calls.live})`);
process.exit(0);
