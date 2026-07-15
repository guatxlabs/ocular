// detail.js — résultat d'une analyse. Le VERDICT est le héros de la vue. Screenshot
// et DOM chargés en blob (fetch + Bearer) car un <img src> nu n'envoie pas l'en-tête.
// Le DOM (potentiellement hostile) n'est JAMAIS rendu inline : lien de téléchargement.
//
// Deux sources partagent le même rendu (paramétré par `src`) :
//   - job   : GET /jobs/{id}      (polling des "pending" + panneau « Sauvegarder »)
//   - saved : GET /saved/{id}/... (analyse figée en base, pas de polling ni de save)
import { el, iconNode, esc } from '../core.js';
import {
  getJob, artifactObjectUrl, getSavedResult, savedArtifactObjectUrl,
  saveAnalysis, Unauthorized,
} from '../api.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const SEV_CLASS = { critical: 'sev-4', high: 'sev-3', medium: 'sev-2', low: 'sev-1' };
const VERDICT_CLASS = { benign: 'v-benign', suspicious: 'v-suspicious', malicious: 'v-malicious', unknown: 'v-unknown' };

// ---- points d'entrée : une source « job », une source « saved » ----
export function renderDetail(app, id) {
  return mount(app, id, {
    getResult: () => getJob(id),
    artifactUrl: (ref) => artifactObjectUrl(id, ref),
    back: { href: '#/jobs', label: 'Jobs' },
    poll: true,
    saveable: true,
  });
}

export function renderSavedDetail(app, sid) {
  return mount(app, sid, {
    getResult: () => getSavedResult(sid),
    artifactUrl: (ref) => savedArtifactObjectUrl(sid, ref),
    back: { href: '#/saved', label: 'Sauvegardes' },
    poll: false,
    saveable: false,
  });
}

function mount(app, id, src) {
  let timer = null;
  const urls = []; // objectURLs à révoquer au départ
  const stop = () => {
    if (timer) { clearInterval(timer); timer = null; }
    urls.forEach((u) => URL.revokeObjectURL(u));
  };

  app.appendChild(el('a.backlink', { href: src.back.href }, [iconNode('chevleft'), src.back.label]));
  const body = el('div');
  app.appendChild(body);
  body.appendChild(el('div.card', {}, [el('div.emptyview', {}, [el('p', {}, 'chargement…')])]));

  async function load() {
    let res;
    try { res = await src.getResult(); }
    catch (ex) {
      if (ex instanceof Unauthorized) { stop(); return; }
      body.replaceChildren(el('div.card', {}, [
        el('div.errbox', {}, String(ex.message || ex)),
        el('button.btn-ghost', { onclick: load }, 'Réessayer'),
      ]));
      return;
    }
    if (src.poll && res && res.status === 'pending') {
      body.replaceChildren(el('div.card', {}, [
        el('div.emptyview', {}, [
          el('span.pending-pill', {}, [el('span.spin'), 'en attente']),
          el('p', { style: 'margin-top:14px' }, 'Analyse en attente — actualisation automatique…'),
        ]),
      ]));
      if (!timer) timer = setInterval(load, 3000);
      return;
    }
    stop();
    if (res && res.status === 'error') { renderError(res); return; }
    renderResult(res);
  }

  // Job réellement en échec côté broker (distinct d'un verdict "unknown") :
  // badge « Échec » + message d'erreur brut posé en textNode (jamais innerHTML —
  // le message peut contenir du stderr Docker non fiable).
  function renderError(r) {
    body.replaceChildren(el('div', { class: 'verdict-hero v-error' }, [
      el('span.sev.sev-err', {}, 'Échec'),
      el('div.verdict-meta', {}, [
        el('span.vt', { title: r.target || '' }, r.target || id),
      ]),
    ]));
    body.appendChild(el('div.errbox', {}, r.error || ''));
  }

  function renderResult(r) {
    const frag = document.createDocumentFragment();

    // ---- HERO : verdict ----
    const verdict = r.verdict || 'unknown';
    const findings = r.static_findings || [];
    frag.appendChild(el('div', { class: 'verdict-hero ' + (VERDICT_CLASS[verdict] || 'v-unknown') }, [
      el('span.verdict-badge', {}, verdict),
      el('div.verdict-meta', {}, [
        el('span.vt', { title: r.target || '' }, r.target || id),
        el('span.vm', {}, (r.profile || 'analysis') + ' · ' + (r.timestamp || '')),
      ]),
      el('div.finding-count', {}, [el('b', {}, String(findings.length)), 'détections']),
    ]));

    // ---- furtivité (profil capture) : moteur + statut Turnstile ----
    if (r.stealth) frag.appendChild(buildStealth(r.stealth));

    // ---- panneau « Sauvegarder » (source job uniquement) ----
    if (src.saveable) frag.appendChild(buildSavePanel(r));

    // ---- journal d'actions (tier scripté 3c) : rejoué SEULEMENT si `steps`
    // a été soumis. Chaque entrée vient de `dynamic_steps` (action déjà
    // redigée côté runner — jamais de valeur `fill` en clair) ----
    if (r.dynamic_steps && r.dynamic_steps.length) frag.appendChild(buildDynamicSteps(r.dynamic_steps));

    // ---- screenshot(s) (blob) — inclut aussi les `capture` du script (même liste) ----
    frag.appendChild(buildScreenshot(r));

    // ---- détections statiques groupées par sévérité ----
    frag.appendChild(buildFindings(findings));

    // ---- réseau ----
    frag.appendChild(buildNetwork(r.network || []));

    // ---- console ----
    frag.appendChild(buildConsole(r.console || []));

    // ---- DOM ----
    frag.appendChild(buildDom(r));

    body.replaceChildren(frag);
  }

  // Panneau de sauvegarde : label optionnel + bouton. Succès -> « sauvegardée ✓ »
  // + lien vers la vue Sauvegardes. 409 -> artefacts GC côté serveur : relancer.
  function buildSavePanel(r) {
    const sec = el('div.savepanel');
    const label = el('input', {
      type: 'text', maxlength: '120', 'aria-label': 'Étiquette (optionnelle)',
      placeholder: 'étiquette (optionnelle)',
    });
    const err = el('div.errbox', { role: 'alert', hidden: 'hidden' });
    const btn = el('button.btn-primary', { type: 'button' }, [iconNode('bookmark'), 'Sauvegarder']);
    const done = (savedId) => {
      sec.replaceChildren(
        el('span.savedok', {}, [iconNode('check'), 'Analyse sauvegardée']),
        el('a.savedlink', { href: '#/saved/' + savedId }, 'Voir dans Sauvegardes'),
      );
    };
    btn.addEventListener('click', async () => {
      err.hidden = true;
      btn.disabled = true;
      try {
        const out = await saveAnalysis(id, label.value.trim());
        done(out.id);
      } catch (ex) {
        if (ex instanceof Unauthorized) return;
        btn.disabled = false;
        // XSS-clean : toujours textContent, jamais innerHTML (le message peut
        // provenir d'un ex.message serveur non fiable dans le cas générique).
        err.textContent = ex && ex.duplicateLabel
          ? 'Nom déjà utilisé — choisis une autre étiquette.'
          : ex && ex.expired
          ? 'Artefacts expirés — relance l\'analyse avant de sauvegarder.'
          : String(ex.message || ex);
        err.hidden = false;
      }
    });
    sec.appendChild(el('div.saverow', {}, [
      el('span.savelead', {}, [iconNode('bookmark'), 'Conserver cette analyse']),
      label,
      btn,
    ]));
    sec.appendChild(err);
    return sec;
  }

  // Étiquette lisible d'une étape de capture (phase brute -> libellé traduisible).
  const PHASE_LABEL = {
    initial: 'Capture initiale',
    'post-turnstile': 'Après Turnstile',
    post_turnstile: 'Après Turnstile',
    final: 'Capture finale',
  };

  function buildStealth(st) {
    const sec = el('div.stealth-bar');
    sec.appendChild(el('span.stealth-engine', {}, [
      iconNode('shield'), 'Moteur furtif ', el('b', {}, st.engine || 'inconnu'),
    ]));
    if (st.turnstile_solved) {
      sec.appendChild(el('span.turnstile-ok', {}, [iconNode('check'), 'Turnstile passé']));
    } else if (st.challenge) {
      sec.appendChild(el('span.turnstile-pending', {}, [iconNode('warn'), 'Challenge : ' + st.challenge]));
    }
    return sec;
  }

  // Journal d'actions (tier scripté 3c) : une ligne par step rejoué, dans l'ordre.
  // `action`/`error` proviennent du runner (contenu potentiellement hostile, même
  // redigé côté serveur) : posés en textNode via `el(...)` — JAMAIS `.innerHTML`.
  function buildDynamicSteps(steps) {
    const sec = el('div.detsec', {}, [
      el('h3', {}, ['Journal d\'actions ', el('span.cnt', {}, String(steps.length))]),
    ]);
    const list = el('div.actionlist');
    steps.forEach((s, i) => {
      const ok = s.ok !== false;
      const row = el('div', { class: 'action-row ' + (ok ? 'action-ok' : 'action-fail') }, [
        el('span.action-idx', {}, String(i + 1)),
        el('span.action-verb', {}, s.action || ''), // textContent — jamais innerHTML
        el('span.action-status', {}, ok ? 'ok' : 'échec'),
        el('span.action-ms', {}, s.duration_ms != null ? s.duration_ms + ' ms' : '—'),
      ]);
      if (s.error) row.appendChild(el('span.action-err', {}, s.error)); // textContent — jamais innerHTML
      list.appendChild(row);
    });
    sec.appendChild(el('div.card', {}, [list]));
    return sec;
  }

  function buildScreenshot(r) {
    const sec = el('div.shot-wrap');
    const shots = (r.screenshots || []).slice().sort((a, b) => (a.step || 0) - (b.step || 0));
    if (!shots.length) {
      sec.appendChild(el('div.shot-ph', {}, 'Aucune capture pour cette analyse.'));
      return sec;
    }
    const multi = shots.length > 1;
    shots.forEach((shot) => {
      const fig = el('figure.shot-fig');
      if (multi) fig.appendChild(el('figcaption.shot-cap', {}, PHASE_LABEL[shot.phase] || shot.phase || 'Capture'));
      const ph = el('div.shot-ph', {}, 'chargement de la capture…');
      fig.appendChild(ph);
      sec.appendChild(fig);
      src.artifactUrl(shot.image_ref).then((url) => {
        urls.push(url);
        const img = el('img', { alt: 'Capture d\'écran — ' + (PHASE_LABEL[shot.phase] || shot.phase || 'page analysée') });
        img.src = url;
        ph.replaceWith(img);
      }).catch((ex) => {
        if (!(ex instanceof Unauthorized)) ph.textContent = 'Capture indisponible.';
      });
    });
    return sec;
  }

  function buildFindings(findings) {
    const sec = el('div.detsec', {}, [
      el('h3', {}, ['Détections statiques ', el('span.cnt', {}, String(findings.length))]),
    ]);
    if (!findings.length) { sec.appendChild(el('div.card', {}, [el('p.muted', {}, 'Aucune détection statique.')])); return sec; }
    const byServ = {};
    findings.forEach((f) => { (byServ[f.severity] = byServ[f.severity] || []).push(f); });
    const wrap = el('div.card');
    SEV_ORDER.forEach((sv) => {
      const items = byServ[sv];
      if (!items || !items.length) return;
      const group = el('div.sevgroup', {}, [el('div.sevlabel', {}, sv + ' · ' + items.length)]);
      items.forEach((f) => {
        group.appendChild(el('div', { class: 'alert finding ' + (SEV_CLASS[sv] || '') }, [
          el('span.sev', {}, sv),
          el('div.title', {}, [
            el('div.frule', {}, f.rule || ''),
            el('div.fmatch', { title: f.match || '' }, f.match || ''),
          ]),
          el('span.fline', {}, 'L' + (f.line != null ? f.line : '?')),
        ]));
      });
      wrap.appendChild(group);
    });
    sec.appendChild(wrap);
    return sec;
  }

  function buildNetwork(net) {
    const sec = el('div.detsec', {}, [
      el('h3', {}, ['Réseau ', el('span.cnt', {}, String(net.length))]),
    ]);
    if (!net.length) { sec.appendChild(el('div.card', {}, [el('p.muted', {}, 'aucune requête réseau')])); return sec; }
    const table = el('table.qtable');
    const thead = el('thead', {}, [el('tr', {}, [
      el('th', {}, 'method'), el('th', {}, 'status'), el('th', {}, 'type'), el('th', {}, 'url'),
    ])]);
    const tb = el('tbody');
    net.forEach((n) => {
      tb.appendChild(el('tr', {}, [
        el('td', {}, n.method || ''),
        el('td', {}, n.status != null ? String(n.status) : '—'),
        el('td', {}, n.resource_type || ''),
        el('td', { title: n.url || '' }, n.url || ''),
      ]));
    });
    table.appendChild(thead); table.appendChild(tb);
    sec.appendChild(el('div.card', {}, [el('div.plscroll', {}, [table])]));
    return sec;
  }

  function buildConsole(cons) {
    const sec = el('div.detsec', {}, [
      el('h3', {}, ['Console ', el('span.cnt', {}, String(cons.length))]),
    ]);
    if (!cons.length) { sec.appendChild(el('div.card', {}, [el('p.muted', {}, 'console vide')])); return sec; }
    const listEl = el('div.conslist');
    cons.forEach((c) => {
      listEl.appendChild(el('div.consline', {}, [
        el('span', { class: 'lvl ' + esc(c.level || '') }, c.level || ''),
        el('span.ctext', {}, c.text || ''),
      ]));
    });
    sec.appendChild(el('div.card', {}, [listEl]));
    return sec;
  }

  function buildDom(r) {
    const dom = r.dom || {};
    const artifacts = r.artifacts || {};
    const sec = el('div.detsec', {}, [el('h3', {}, 'DOM')]);
    const kv = el('dl.kvdetail');
    const addRow = (k, v) => { kv.appendChild(el('dt', {}, k)); kv.appendChild(el('dd', {}, v == null || v === '' ? '—' : v)); };
    addRow('Titre', dom.title);
    addRow('URL finale', dom.final_url);
    addRow('Chaîne de redirection', (dom.redirect_chain && dom.redirect_chain.length) ? dom.redirect_chain.join(' → ') : '—');
    const card = el('div.card', {}, [kv]);
    if (artifacts.dom_html_ref) {
      const dl = el('button.domdl', {
        type: 'button', style: 'margin-top:14px',
        onclick: async (e) => {
          const b = e.currentTarget; b.disabled = true;
          try {
            const url = await src.artifactUrl(artifacts.dom_html_ref);
            const a = el('a', { href: url, download: id + '-dom.txt' });
            document.body.appendChild(a); a.click(); a.remove();
            setTimeout(() => URL.revokeObjectURL(url), 4000);
          } catch (ex) { if (!(ex instanceof Unauthorized)) b.textContent = 'Téléchargement indisponible'; }
          b.disabled = false;
        },
      }, [iconNode('download'), 'Télécharger le DOM']);
      card.appendChild(dl);
    }
    sec.appendChild(card);
    return sec;
  }

  load();
  return stop;
}
