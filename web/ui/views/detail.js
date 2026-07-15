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
  saveAnalysis, getSavedMeta, setAnalystVerdict, Unauthorized,
} from '../api.js';
import { buildFilterBar } from '../filter.js';
import { fmtIso } from './saved.js';

// seuil au-delà duquel la barre de filtre SOC s'affiche au-dessus du tableau
// réseau (petit résultat -> pas de bruit inutile).
const NETWORK_FILTER_THRESHOLD = 8;

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
    getMeta: null, // pas encore sauvegardée -> pas de provenance/verdict analyste
  });
}

export function renderSavedDetail(app, sid) {
  return mount(app, sid, {
    getResult: () => getSavedResult(sid),
    artifactUrl: (ref) => savedArtifactObjectUrl(sid, ref),
    back: { href: '#/saved', label: 'Sauvegardes' },
    poll: false,
    saveable: false,
    // provenance/verdict analyste (Phase 3e) : GET /saved n'a pas de route par id
    // dédiée -> getSavedMeta filtre la liste (cf. api.js).
    getMeta: () => getSavedMeta(sid),
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
    let meta = null;
    if (src.getMeta) {
      try { meta = await src.getMeta(); }
      catch (ex) {
        if (ex instanceof Unauthorized) return;
        // provenance/verdict analyste : best-effort — un échec ici ne doit pas
        // empêcher l'affichage du résultat déjà chargé.
      }
    }
    renderResult(res, meta);
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

  function renderResult(r, meta) {
    const frag = document.createDocumentFragment();

    // ---- HERO : verdict (auto — toujours visible, jamais masqué par le verdict
    // analyste, qui vit dans un panneau séparé plus bas) ----
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

    // ---- provenance + verdict analyste (source saved uniquement, Phase 3e) ----
    if (meta) {
      const prov = buildProvenance(meta);
      if (prov) frag.appendChild(prov);
      frag.appendChild(buildAnalystPanel(id, meta));
    }

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

  // Provenance de la sauvegarde : « sauvé par X @ T » + statut Turnstile (✓/✗,
  // omis si `turnstile_solved` est null — non applicable, ex. profil html). `null`
  // si aucune donnée à afficher (ex. sauvegarde antérieure à la migration 3e).
  // `saved_by` est une identité potentiellement hostile (forward-auth) -> posée en
  // textNode via el(), JAMAIS innerHTML.
  function buildProvenance(meta) {
    const sec = el('div.provenance');
    if (meta.saved_by) {
      const by = ['sauvé par ', el('b', {}, meta.saved_by)];
      if (meta.saved_at) by.push(' @ ' + fmtIso(meta.saved_at));
      sec.appendChild(el('span.prov-item', {}, by));
    }
    if (meta.turnstile_solved === 1) {
      sec.appendChild(el('span.prov-item.prov-ts.ok', {}, [iconNode('check'), 'Turnstile passé']));
    } else if (meta.turnstile_solved === 0) {
      sec.appendChild(el('span.prov-item.prov-ts.bad', {}, [iconNode('warn'), 'Turnstile non passé']));
    }
    return sec.childNodes.length ? sec : null;
  }

  // Panneau verdict ANALYSTE (vocabulaire distinct du verdict auto : legitimate,
  // pas benign — cf. AnalystVerdictRequest côté serveur) : affiche le verdict déjà
  // posé (s'il existe) + contrôles de classification. `analyst`/`analyst_note` sont
  // des données potentiellement hostiles (identité forward-auth / texte libre) ->
  // TOUJOURS posées en textNode via el(), jamais innerHTML. Mise à jour à chaud :
  // la réponse de setAnalystVerdict repeint `current` sans recharger la page.
  function buildAnalystPanel(sid, meta) {
    const sec = el('div.analystpanel');
    sec.appendChild(el('h4', {}, 'Verdict analyste'));

    const current = el('div.analyst-current');
    const paintCurrent = (m) => {
      current.replaceChildren();
      if (m && m.analyst_verdict) {
        current.appendChild(el('span', { class: 'analyst-badge av-' + m.analyst_verdict }, m.analyst_verdict));
        const by = ['classé par ', el('b', {}, m.analyst || '?')];
        if (m.analyst_at) by.push(' @ ' + fmtIso(m.analyst_at));
        current.appendChild(el('span.analyst-by', {}, by));
        if (m.analyst_note) current.appendChild(el('p.analyst-note', {}, m.analyst_note));
      } else {
        current.appendChild(el('span.muted', {}, 'Pas de verdict analyste.'));
      }
    };
    paintCurrent(meta);

    const noteInput = el('input', {
      type: 'text', maxlength: '2000', placeholder: 'note (optionnelle)',
      'aria-label': 'Note analyste',
    });
    const err = el('div.errbox', { role: 'alert', hidden: 'hidden' });

    const VERDICTS = [['legitimate', 'légitime'], ['suspicious', 'suspect'], ['malicious', 'malveillant']];
    const btns = [];
    VERDICTS.forEach(([value, label]) => {
      const b = el('button', { type: 'button', class: 'verdict-btn vb-' + value }, label);
      b.addEventListener('click', async () => {
        err.hidden = true;
        btns.forEach((x) => { x.disabled = true; });
        try {
          const updated = await setAnalystVerdict(sid, value, noteInput.value.trim());
          paintCurrent(updated);
          noteInput.value = '';
        } catch (ex) {
          if (ex instanceof Unauthorized) return;
          // XSS-clean : toujours textContent (ex.message peut inclure un detail serveur).
          err.textContent = ex && ex.status === 422 ? 'Verdict invalide.' : String(ex.message || ex);
          err.hidden = false;
        } finally {
          btns.forEach((x) => { x.disabled = false; });
        }
      });
      btns.push(b);
    });

    sec.appendChild(current);
    sec.appendChild(el('div.verdict-controls', {}, [
      el('span.verdict-lead', {}, 'Classer'),
      ...btns,
      noteInput,
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
    // Rendu des lignes factorisé : réutilisé pour l'affichage initial ET pour
    // le re-rendu déclenché par le filtre — mêmes colonnes, même el() XSS-clean.
    const renderRows = (rows) => {
      tb.replaceChildren(...rows.map((n) => el('tr', {}, [
        el('td', {}, n.method || ''),
        el('td', {}, n.status != null ? String(n.status) : '—'),
        el('td', {}, n.resource_type || ''),
        el('td', { title: n.url || '' }, n.url || ''),
      ])));
    };
    table.appendChild(thead); table.appendChild(tb);
    const card = el('div.card', {}, [el('div.plscroll', {}, [table])]);

    // Filtre SOC (filter.js, Task 1) : affiché seulement au-delà du seuil, pour
    // ne pas ajouter de bruit sur un petit résultat. Filtrage 100% côté client
    // sur `net` déjà chargé : `getEntries` referme sur le tableau en mémoire,
    // `onChange` re-rend le <tbody> via `renderRows` — AUCUN fetch/appel réseau
    // n'est jamais déclenché par le filtre.
    if (net.length > NETWORK_FILTER_THRESHOLD) {
      // `el` (importé synchrone) est injecté -> buildFilterBar renvoie le nœud
      // immédiatement, inséré AVANT le retour de renderResult donc AVANT le
      // i18nWalk(app) synchrone de core.js (barre traduite en LANG='en').
      // buildFilterBar fait déjà un refresh()/onChange initial qui appelle
      // renderRows -> le tableau est peuplé par ce refresh, pas de renderRows
      // manuel ici (évite un double rendu initial).
      const bar = buildFilterBar(() => net, renderRows, { el });
      const counter = bar.querySelector('.filter-count');
      if (counter) counter.setAttribute('aria-label', 'correspondances');
      sec.appendChild(el('div.filter-slot', {}, [bar]));
    } else {
      renderRows(net); // pas de barre -> rendu initial direct
    }

    sec.appendChild(card);
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
