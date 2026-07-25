// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// poll_test.mjs — comportement de web/ui/poll.js avec une horloge INJECTÉE :
// aucune attente réelle, donc aucune dépendance à la charge de la machine.
//
// Les trois propriétés verrouillées ici sont celles qui manquaient au panneau
// live sur 651840c : jamais deux appels en vol, un échec ne rompt pas la
// boucle, et l'état de la boucle est dit à l'appelant.
import assert from 'node:assert';
import { createPoller } from '../web/ui/poll.js';

// Horloge de test : les minuteries sont des données, pas du temps.
function fakeClock() {
  let now = 0;
  let seq = 0;
  const timers = new Map();
  return {
    now: () => now,
    setTimer(fn, ms) { const id = ++seq; timers.set(id, { at: now + ms, fn }); return id; },
    clearTimer(id) { timers.delete(id); },
    pending: () => timers.size,
    /** Avance jusqu'à `now + ms` en déclenchant les minuteries échues, dans
     *  l'ordre, et en laissant les microtâches se dérouler entre chacune. */
    async advance(ms) {
      const target = now + ms;
      for (;;) {
        let due = null;
        for (const [id, t] of timers) {
          if (t.at <= target && (!due || t.at < due[1].at)) due = [id, t];
        }
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await drain();
      }
      now = target;
      await drain();
    },
  };
}

const drain = () => new Promise((r) => setImmediate(r));

// Un `run` dont on tient la promesse à la main : c'est le seul moyen de créer
// l'état « appel en vol » et de vérifier ce que la boucle en fait.
function controllable() {
  const calls = [];
  const run = () => {
    let settle;
    const p = new Promise((resolve, reject) => { settle = { resolve, reject }; });
    calls.push(settle);
    return p;
  };
  return { run, calls };
}

const INTERVAL = 2000;

// --- 1. JAMAIS deux appels en vol ------------------------------------------
{
  const clock = fakeClock();
  const { run, calls } = controllable();
  const p = createPoller(run, { intervalMs: INTERVAL, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  p.start();
  await drain();
  assert.equal(calls.length, 1, 'start() doit lancer un tour tout de suite');

  // Le tour DURE (l'analyse d'un DOM hostile met des centaines de ms, parfois
  // plus que l'intervalle) : quoi qu'il arrive à l'horloge, aucun second appel.
  await clock.advance(INTERVAL * 50);
  assert.equal(calls.length, 1,
    'un second appel est parti alors que le premier n\'avait pas rendu la main : '
    + 'c\'est exactement la file sans borne du finding A');
  // Même en réclamant un tour immédiat (bouton « réessayer »).
  p.now();
  await drain();
  assert.equal(calls.length, 1, 'now() double l\'appel en vol');

  // Le tour se termine -> le suivant est armé, pas avant.
  calls[0].resolve({});
  await drain();
  assert.equal(calls.length, 1, 'le tour suivant part sans attendre l\'intervalle');
  await clock.advance(INTERVAL);
  assert.equal(calls.length, 2, 'la cadence nominale ne reprend pas après un tour réussi');
  p.stop();
}

// --- 2. un échec ne tue pas la boucle, et le recul est dit ------------------
{
  const clock = fakeClock();
  const { run, calls } = controllable();
  const states = [];
  const p = createPoller(run, {
    intervalMs: INTERVAL, setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    onState: (s) => states.push(s),
  });
  p.start();
  await drain();

  // Échec n°1 : sur 651840c, UN SEUL suffisait à arrêter le panneau pour de bon.
  calls[0].reject(new Error('502'));
  await drain();
  assert.equal(states.at(-1).ok, false);
  assert.equal(states.at(-1).failures, 1);
  assert.equal(states.at(-1).nextDelayMs, INTERVAL, 'le premier recul vaut l\'intervalle');

  await clock.advance(INTERVAL);
  assert.equal(calls.length, 2, 'la boucle s\'est arrêtée au premier échec');

  // Échecs suivants : le recul DOUBLE, et l'appelant reçoit de quoi l'afficher.
  calls[1].reject(new Error('502'));
  await drain();
  assert.equal(states.at(-1).nextDelayMs, INTERVAL * 2);
  await clock.advance(INTERVAL);           // pas encore l'heure
  assert.equal(calls.length, 2, 'le recul n\'est pas respecté');
  await clock.advance(INTERVAL);           // maintenant si
  assert.equal(calls.length, 3);

  // Le succès remet la cadence nominale, sans intervention.
  calls[2].resolve({});
  await drain();
  assert.deepEqual(
    { ok: states.at(-1).ok, failures: states.at(-1).failures, next: states.at(-1).nextDelayMs },
    { ok: true, failures: 0, next: INTERVAL },
    'un succès doit effacer le recul');
  await clock.advance(INTERVAL);
  assert.equal(calls.length, 4);
  p.stop();
}

// --- 3. le recul est PLAFONNÉ (il ne part pas à l'infini) -------------------
{
  const clock = fakeClock();
  const { run, calls } = controllable();
  const states = [];
  const p = createPoller(run, {
    intervalMs: INTERVAL, setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    onState: (s) => states.push(s),
  });
  p.start();
  await drain();
  for (let i = 0; i < 12; i += 1) {
    calls.at(-1).reject(new Error('502'));
    await drain();
    await clock.advance(states.at(-1).nextDelayMs);
  }
  const delays = states.map((s) => s.nextDelayMs);
  assert.deepEqual(delays.slice(0, 5), [INTERVAL, INTERVAL * 2, INTERVAL * 4, INTERVAL * 8, INTERVAL * 16]);
  assert.ok(delays.every((d) => d <= INTERVAL * 16), `recul non plafonné : ${delays.join(',')}`);
  // ... et la boucle essaie toujours après une douzaine d'échecs.
  assert.ok(calls.length >= 12, `boucle éteinte après ${calls.length} tours`);
  p.stop();
}

// --- 4. FORMES NON TRAITÉES : rien n'a de sort particulier ------------------
// La boucle ne classe AUCUNE erreur (pas de liste de statuts « transitoires »
// vs « définitifs ») : ce qui est jeté, quoi que ce soit, la fait reculer et
// repartir. Les formes ci-dessous ne sont nommées nulle part dans poll.js.
{
  const jetables = [
    new Error('502'),
    Object.assign(new Error('404'), { status: 404 }),
    Object.assign(new Error('401'), { status: 401 }),
    'une chaîne nue',
    null,
    undefined,
    { message: 'objet nu' },
    Symbol('rien'),
  ];
  for (const jetable of jetables) {
    const clock = fakeClock();
    let calls = 0;
    const p = createPoller(async () => { calls += 1; throw jetable; }, {
      intervalMs: INTERVAL, setTimer: clock.setTimer, clearTimer: clock.clearTimer,
    });
    p.start();
    await drain();
    await clock.advance(INTERVAL);
    assert.ok(calls >= 2, `la boucle s'est arrêtée sur ${String(jetable)}`);
    p.stop();
  }
}

// --- 5. stop() arrête pour de bon ; start() est idempotent ------------------
{
  const clock = fakeClock();
  const { run, calls } = controllable();
  const p = createPoller(run, { intervalMs: INTERVAL, setTimer: clock.setTimer, clearTimer: clock.clearTimer });
  p.start();
  p.start();                       // idempotent : pas de seconde boucle
  await drain();
  assert.equal(calls.length, 1);
  calls[0].resolve({});
  await drain();
  p.stop();
  await clock.advance(INTERVAL * 10);
  assert.equal(calls.length, 1, 'la boucle survit à stop()');
  assert.equal(clock.pending(), 0, 'une minuterie fantôme survit à stop()');
  p.now();                         // sans effet après stop()
  await drain();
  assert.equal(calls.length, 1);
}

// --- 6. la cadence appartient à l'appelant ---------------------------------
{
  assert.throws(() => createPoller(() => {}, {}), /intervalMs/);
  assert.throws(() => createPoller(null, { intervalMs: 1 }), /run/);
}

console.log('poll_test OK');
