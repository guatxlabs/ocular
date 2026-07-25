// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// detail_truncation_test.mjs — la VRAIE vue détail (web/ui/views/detail.js,
// montée par core.js) sur le DOM minimal de tests/dom_shim.mjs, avec un
// résultat dont plusieurs champs ont été COUPÉS par les plafonds anti-OOM.
//
// CE QUI ÉTAIT MESURÉ SUR 651840c : `engine.wrapper` nomme le champ amputé dans
// `truncated_fields` — `url`, `post_data`, `headers`, `text`, `title`,
// `final_url` — mais `grep -rn truncatedBadge web/ui/` ne rendait que trois
// appels (url, post_data, text). Avec
// `dom.truncated_fields = ['title', 'final_url']`, la vue détail affichait
// `addRow('URL finale', dom.final_url)` SANS le moindre signe : une URL
// d'atterrissage amputée avait exactement l'apparence d'une URL entière — et
// sur un kit de phishing, ce qui disparaît est la fin de la query string,
// c'est-à-dire la pièce à conviction.
//
// Le champ inventé `champ_du_futur` n'est traité NULLE PART dans le code de
// production : s'il n'apparaît pas à l'écran, c'est que le rendu est redevenu
// une liste de champs écrite à la main.
import assert from 'node:assert';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { installDom, reply, until } from './dom_shim.mjs';

const UI = pathToFileURL(
  path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'web', 'ui') + path.sep,
).href;

const RESULT = {
  schema_version: '1.0',
  job_id: 'j1',
  profile: 'capture',
  target: 'https://cible.test/',
  timestamp: '2026-07-25T10:00:00Z',
  verdict: 'suspicious',
  screenshots: [],
  network: [{
    url: 'https://evil.test/collect?tok=AAA', method: 'POST', status: 200,
    resource_type: 'xhr', post_data: 'user=a', headers: {},
    truncated_fields: ['url', 'post_data', 'headers'],
  }],
  console: [{ level: 'error', text: 'boum', truncated_fields: ['text', 'location'] }],
  dom: {
    title: 'Banque — connexion',
    final_url: 'https://evil.test/login?redir=aHR0cHM6',
    redirect_chain: [],
    forms: [], mailtos: [], links: [],
    truncated_fields: ['title', 'final_url', 'champ_du_futur'],
  },
  static_findings: [],
  dynamic_steps: [],
  artifacts: {},
  truncation: { text_truncated: 5, mailtos_dropped: 2 },
};

const { appNode, screen } = installDom({
  hash: '#/job/j1',
  routes: (url) => {
    if (url === '/auth/whoami') return reply({ identity: 'a', method: 'token', groups: [] });
    if (url === '/jobs/j1') return reply(RESULT);
    return undefined;
  },
});

await import(UI + 'core.js');
await until('résultat affiché', () => /URL finale/.test(screen()));

const shown = screen();

// 1. les champs du DOM que la vue AFFICHE portent leur marqueur, DANS LEUR
//    PROPRE CASE — un marqueur ailleurs sur la page ne dit pas QUELLE valeur
//    est amputée, et c'est précisément ce que le compteur global ne disait pas.
assert.match(shown, /Titre/, 'la vue détail n\'affiche pas le DOM');
const cases = appNode.querySelectorAll('dd');
const caseDe = (extrait) => cases.find((d) => d.textContent.includes(extrait));
const caseUrlFinale = caseDe('evil.test/login');
assert.ok(caseUrlFinale, 'ligne « URL finale » introuvable');
assert.match(caseUrlFinale.textContent, /✂ coupé/,
  'URL finale amputée rendue avec l\'apparence d\'une URL entière');
const caseTitre = caseDe('Banque');
assert.ok(caseTitre && /✂ coupé/.test(caseTitre.textContent),
  'titre amputé rendu sans marqueur');

// 2. un champ coupé que la vue n'affiche NULLE PART sort quand même.
assert.match(shown, /champ_du_futur/,
  'un champ coupé sans ligne dédiée disparaît : c\'est le défaut « marqueur sans '
  + 'consommateur », déplacé d\'un champ à l\'autre');

// 3. la rangée réseau et la ligne console : idem, `headers` et `location` n'ont
//    pas de colonne et doivent quand même être nommés.
assert.match(shown, /✂ coupé : headers/, 'coupe des en-têtes invisible dans le tableau réseau');
assert.match(shown, /✂ coupé : location/, 'coupe de `location` invisible dans la console');

// 4. le bandeau global annonce AUSSI un compteur qui n'est dans aucun modèle.
assert.match(shown, /2 cibles mailto non conservées/,
  'compteur de troncature inconnu de l\'UI : passé sous silence');
assert.match(shown, /5 champs texte coupés/);

console.log('detail_truncation_test OK');
process.exit(0);
