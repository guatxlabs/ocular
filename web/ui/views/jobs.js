// jobs.js — liste des jobs soumis depuis ce navigateur + polling des "pending".
// L'API n'a pas d'endpoint de listing : la source est localStorage (state.js).
import { el, iconNode, fmtTs } from '../core.js';
import { getJobs, removeJobs } from '../state.js';
import { getJob, Unauthorized } from '../api.js';
import { verdictPill } from './saved.js';

export function renderJobs(app) {
  const jobs = getJobs();

  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Mes analyses'),
    el('span.sub', {}, 'Les jobs soumis depuis ce navigateur.'),
  ]));

  if (!jobs.length) {
    app.appendChild(el('div.card', {}, [
      el('div.emptyview', {}, [
        iconNode('inbox'),
        el('p', {}, 'Aucune analyse pour l\'instant.'),
        el('a.btn-primary', { href: '#/submit' }, 'Lancer une analyse'),
      ]),
    ]));
    return null;
  }

  // Purge des jobs terminés/expirés de la liste locale (localStorage). Les jobs
  // « expiré/inconnu » (résultat perdu après un down/up, ou jamais produit) ne
  // reviennent plus poller une fois retirés — évite l'accumulation de fantômes.
  const terminal = new Set();   // ids devenus terminaux (done/erreur/expiré)
  const purgeBtn = el('button.btn-ghost', {
    type: 'button', title: 'Retirer de la liste les analyses terminées ou expirées',
    onclick: () => { if (terminal.size) { removeJobs([...terminal]); location.reload(); } },
  }, [iconNode('trash'), 'Nettoyer les terminés']);

  app.appendChild(el('div.jobs-actions', {}, [purgeBtn]));

  const rows = new Map(); // id -> {statusEl}
  const list = el('div.joblist');
  jobs.forEach((j) => {
    const statusEl = el('span.pending-pill', {}, [el('span.spin'), 'en attente']);
    const row = el('div.jobrow', {
      role: 'button', tabindex: '0',
      onclick: () => { location.hash = '#/job/' + j.id; },
      onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); location.hash = '#/job/' + j.id; } },
    }, [
      el('span.jobid', {}, j.id),
      el('span.jobtarget', { title: j.target || '' }, j.target || j.id),
      el('time', {}, fmtTs(j.ts)),
      statusEl,
      iconNode('chevright'),
    ]);
    rows.set(j.id, statusEl);
    list.appendChild(row);
  });
  app.appendChild(list);

  // ---- polling : rafraîchit uniquement les jobs encore en attente ----
  const done = new Set();
  async function tick() {
    const pending = [...rows.keys()].filter((id) => !done.has(id));
    if (!pending.length) { stop(); return; }
    await Promise.all(pending.map(async (id) => {
      let res;
      try { res = await getJob(id); }
      catch (ex) {
        if (ex instanceof Unauthorized) { stop(); return; }
        done.add(id);
        terminal.add(id);
        replaceStatus(rows.get(id), errorPill());
        return;
      }
      if (res && res.status === 'pending') return; // toujours en cours
      done.add(id);
      if (res && res.status === 'unknown') {
        // job perdu/expiré (Redis vidé par un down/up, ou jamais traité) :
        // terminal — on ARRÊTE de poller (plus de fantôme « en attente »).
        terminal.add(id);
        replaceStatus(rows.get(id), expiredPill());
        return;
      }
      if (res && res.status === 'error') {
        terminal.add(id);
        replaceStatus(rows.get(id), errorPill(res.error));
        return;
      }
      terminal.add(id);
      const v = (res && res.verdict) || 'unknown';
      replaceStatus(rows.get(id), verdictPill(v));
    }));
  }
  function replaceStatus(oldEl, newEl) { if (oldEl && oldEl.parentNode) oldEl.replaceWith(newEl); }

  let timer = null;
  function stop() { if (timer) { clearInterval(timer); timer = null; } }
  tick();
  timer = setInterval(tick, 3000);
  return stop; // cleanup au changement de route
}

// Badge « Échec » : job réellement en erreur côté broker (pas un simple verdict
// "unknown"). Le label est un textNode (via el()) ; le message d'erreur complet
// (potentiellement issu de stderr) n'est posé qu'en attribut `title` (échappé
// nativement par setAttribute) — jamais en innerHTML. Le détail complet en
// textNode est affiché sur la page de détail (detail.js).
function errorPill(message) {
  return el('span.pending-pill.sev-err', { title: message || '' }, 'échec');
}

// Job perdu/expiré (résultat introuvable, hors fenêtre d'acceptation) : terminal,
// non rejouable — l'analyste peut le retirer via « Nettoyer les terminés ».
function expiredPill() {
  return el('span.pending-pill', { title: 'Résultat expiré ou introuvable — relance l\'analyse si besoin.', style: 'color:var(--mut);background:var(--card2)' }, 'expiré');
}

