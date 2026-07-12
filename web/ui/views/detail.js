// detail.js — résultat d'un job. Le VERDICT est le héros de la vue. Screenshot et
// DOM chargés en blob (fetch + Bearer) car un <img src> nu n'envoie pas l'en-tête.
// Le DOM (potentiellement hostile) n'est JAMAIS rendu inline : lien de téléchargement.
import { el, iconNode, esc } from '../core.js';
import { getJob, artifactObjectUrl, Unauthorized } from '../api.js';

const SEV_ORDER = ['critical', 'high', 'medium', 'low'];
const SEV_CLASS = { critical: 'sev-4', high: 'sev-3', medium: 'sev-2', low: 'sev-1' };
const VERDICT_CLASS = { benign: 'v-benign', suspicious: 'v-suspicious', malicious: 'v-malicious', unknown: 'v-unknown' };

export function renderDetail(app, id) {
  let timer = null;
  const urls = []; // objectURLs à révoquer au départ
  const stop = () => {
    if (timer) { clearInterval(timer); timer = null; }
    urls.forEach((u) => URL.revokeObjectURL(u));
  };

  app.appendChild(el('a.backlink', { href: '#/jobs' }, [iconNode('chevleft'), 'Jobs']));
  const body = el('div');
  app.appendChild(body);
  body.appendChild(el('div.card', {}, [el('div.emptyview', {}, [el('p', {}, 'chargement…')])]));

  async function load() {
    let res;
    try { res = await getJob(id); }
    catch (ex) {
      if (ex instanceof Unauthorized) { stop(); return; }
      body.replaceChildren(el('div.card', {}, [
        el('div.errbox', {}, String(ex.message || ex)),
        el('button.btn-ghost', { onclick: load }, 'Réessayer'),
      ]));
      return;
    }
    if (res && res.status === 'pending') {
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

    // ---- screenshot (blob) ----
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

  function buildScreenshot(r) {
    const sec = el('div.shot-wrap');
    const shots = r.screenshots || [];
    if (!shots.length) {
      sec.appendChild(el('div.shot-ph', {}, 'Aucune capture pour ce job.'));
      return sec;
    }
    const ph = el('div.shot-ph', {}, 'chargement de la capture…');
    sec.appendChild(ph);
    artifactObjectUrl(id, shots[0].image_ref).then((url) => {
      urls.push(url);
      const img = el('img', { alt: 'Capture d\'écran de la page analysée' });
      img.src = url;
      ph.replaceWith(img);
    }).catch((ex) => {
      if (!(ex instanceof Unauthorized)) ph.textContent = 'Capture indisponible.';
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
            const url = await artifactObjectUrl(id, artifacts.dom_html_ref);
            const a = el('a', { href: url, download: id + '-dom.html' });
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
