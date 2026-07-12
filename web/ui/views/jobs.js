// jobs.js — liste des jobs soumis depuis ce navigateur + polling des "pending".
// L'API n'a pas d'endpoint de listing : la source est localStorage (state.js).
import { el, iconNode, fmtTs } from '../core.js';
import { getJobs } from '../state.js';
import { getJob, Unauthorized } from '../api.js';

const VERDICT_LABEL = { benign: 'benign', suspicious: 'suspicious', malicious: 'malicious', unknown: 'unknown' };

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
        replaceStatus(rows.get(id), el('span.pending-pill', { style: 'color:var(--bad);border-color:color-mix(in srgb,var(--bad) 38%,transparent);background:color-mix(in srgb,var(--bad) 12%,transparent)' }, 'échec'));
        return;
      }
      if (res && res.status === 'pending') return; // toujours en cours
      done.add(id);
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

function verdictPill(v) {
  const label = VERDICT_LABEL[v] || v;
  const cls = { benign: 'ok', suspicious: 'warn', malicious: 'bad' }[v] || 'mut';
  const map = {
    ok: 'color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent);border-color:color-mix(in srgb,var(--ok) 40%,transparent)',
    warn: 'color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,transparent);border-color:color-mix(in srgb,var(--warn) 40%,transparent)',
    bad: 'color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent);border-color:color-mix(in srgb,var(--bad) 42%,transparent)',
    mut: 'color:var(--mut);background:var(--card2)',
  };
  return el('span.pending-pill', { style: map[cls] }, label);
}
