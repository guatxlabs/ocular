// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// poll.js — cadence d'un sondage périodique : UN SEUL appel en vol, recul
// progressif après échec, reprise automatique, état OBSERVABLE.
//
// AUCUN import (ni core.js, ni DOM) : ce module est la cadence toute seule,
// exercée hors navigateur par tests/poll_test.mjs avec une horloge injectée.
//
// CE QUE CE MODULE FERME, mesuré sur 651840c. Banc bout en bout : uvicorn
// servant `runner_recon_vnc.session_server.app` + le vrai client interne
// `web.internal_http.internal_get_json` et son échéance de 5,0 s ; page hostile
// de 512 Kio de `atob(` dont le DOM change d'un octet à chaque lecture (donc ni
// le mémo ni le single-flight ne s'appliquent).
//
//   1. LA FILE SANS BORNE. La vue interactive armait `setInterval(pollLive,
//      2000)` et `pollLive` n'avait AUCUNE garde d'appel en vol : dès qu'un
//      tour dépassait l'intervalle, le suivant partait par-dessus. Balayage du
//      nombre de polls SIMULTANÉS sur ce banc : N=1 -> 1/1 servi, pire latence
//      1 867 ms ; N=2 -> 2/2, 4 823 ms ; N=4 -> 0/4, 5 292 ms ; N=20 -> 0/20,
//      8 287 ms — au-delà de l'échéance, l'appel interne rend 502.
//      Combien d'onglets pour y entrer : la file grandit dès que la cadence
//      d'arrivée dépasse la cadence de service, soit dès que la durée d'un tour
//      dépasse l'intervalle divisé par le nombre d'onglets. Sur ce banc, un
//      tour à 1 Mio de DOM hostile a mesuré 1 617 à 1 850 ms pour un intervalle
//      de 2 000 ms : deux onglets suffisent à franchir ce rapport.
//      ICI : le tour suivant n'est ARMÉ qu'une fois le précédent terminé, et
//      `tick` refuse de rentrer tant qu'un appel est en vol. Il n'existe pas
//      d'état où deux appels de `run` coexistent, quel que soit le temps que
//      `run` met à rendre la main.
//
//   2. LE SILENCE APRÈS UN ÉCHEC. `pollLive` faisait `catch { stopPoll(); }` :
//      UN SEUL 502 arrêtait définitivement le panneau live, sans message. Le
//      coût de l'attaque n'était donc pas « un 502 par poll », c'était « un
//      poll ». Et un panneau arrêté ressemble à une page qui n'émet plus rien —
//      dans un outil d'analyse, le silence est un mode de défaillance à part
//      entière.
//      ICI : un échec ne rompt pas la boucle. Il recule, il le DIT (`onState`),
//      et l'appelant en fait un état visible.

// Plafond du recul, en multiples de l'intervalle nominal. CHOIX DE POLITIQUE,
// aucune mesure derrière : il borne l'écart entre ce que l'analyste voit et ce
// que la session vit. Le doublement le fait atteindre après quelques échecs ;
// la reprise, elle, est immédiate dès le premier succès.
const BACKOFF_CAP_FACTOR = 16;

export function createPoller(run, opts = {}) {
  if (typeof run !== 'function') throw new TypeError('createPoller: run (fonction) requis');
  const intervalMs = Number(opts.intervalMs);
  // Aucun intervalle par défaut : la cadence appartient à l'appelant, la
  // dupliquer ici ferait deux valeurs à tenir d'accord.
  if (!(intervalMs > 0)) throw new TypeError('createPoller: opts.intervalMs (> 0) requis');
  const maxDelayMs = Number(opts.maxDelayMs) > 0
    ? Number(opts.maxDelayMs) : intervalMs * BACKOFF_CAP_FACTOR;
  const setTimer = typeof opts.setTimer === 'function'
    ? opts.setTimer : ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = typeof opts.clearTimer === 'function'
    ? opts.clearTimer : ((h) => clearTimeout(h));
  const onState = typeof opts.onState === 'function' ? opts.onState : () => {};

  let timer = null;
  let inFlight = false;   // un appel de `run` n'a pas encore rendu la main
  let live = false;       // la boucle tourne (start() sans stop())
  let failures = 0;       // échecs CONSÉCUTIFS ; remis à zéro par tout succès

  // Recul exponentiel plafonné. `failures` vaut au moins 1 quand on l'appelle.
  const backoffMs = () => Math.min(maxDelayMs, intervalMs * (2 ** (failures - 1)));
  const nextDelayMs = () => (failures === 0 ? intervalMs : backoffMs());

  function arm(ms) {
    if (timer !== null) { clearTimer(timer); timer = null; }
    if (!live) return;
    timer = setTimer(() => { timer = null; tick(); }, ms);
  }

  async function tick() {
    // LA garde d'appel en vol. Elle est ici, dans la boucle, et pas chez
    // l'appelant : un appelant ajouté demain ne peut pas l'oublier, il n'a pas
    // d'autre chemin pour déclencher un tour.
    if (!live || inFlight) return;
    inFlight = true;
    try {
      await run();
      failures = 0;
      onState({ ok: true, failures: 0, nextDelayMs: intervalMs, error: null });
    } catch (error) {
      failures += 1;
      onState({ ok: false, failures, nextDelayMs: backoffMs(), error });
    } finally {
      inFlight = false;
      arm(nextDelayMs());
    }
  }

  return {
    /** Démarre la boucle : un tour TOUT DE SUITE, les suivants à la cadence. */
    start() {
      if (live) return;
      live = true;
      failures = 0;
      tick();
    },
    /** Arrête la boucle. Idempotent. Un appel déjà en vol finit sans réarmer. */
    stop() {
      live = false;
      if (timer !== null) { clearTimer(timer); timer = null; }
    },
    /** Tour immédiat (bouton « réessayer ») — sans jamais doubler un appel en
     *  vol : `tick` garde l'entrée, et le tour en cours réarmera de lui-même. */
    now() {
      if (!live) return;
      if (timer !== null) { clearTimer(timer); timer = null; }
      tick();
    },
    /** Pour les tests et l'affichage : état courant, sans effet de bord. */
    state() {
      return { live, inFlight, failures, nextDelayMs: nextDelayMs() };
    },
  };
}
