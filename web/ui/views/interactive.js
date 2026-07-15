// interactive.js — session interactive (live) : ouvre une session côté conteneur,
// affiche ses pixels via noVNC (RFB embarqué localement, aucun CDN), et propose
// « Capturer » (fige l'état en analyse) et « Fermer » (détruit la session).
//
// Sécu critique :
//   • Le token capability de la session reste en MÉMOIRE JS (closure) — jamais
//     localStorage, jamais dans l'URL.
//   • L'auth du WebSocket passe par le SOUS-PROTOCOLE (`wsProtocols`), pas par la
//     query string : `['binary', 'ocular.session.' + token]`. Le token ne doit
//     JAMAIS apparaître dans wsUrl (anti-fuite logs/referrer/historique).
//   • Anti-XSS : tout le contenu variable passe par des textNodes (el()/textContent),
//     jamais innerHTML (seules les icônes statiques via iconNode le sont, dans core.js).
import { el, iconNode } from '../core.js';
import {
  createSession, deleteSession, captureSession, liveSession, saveAnalysis, Unauthorized,
} from '../api.js';
import { getToken } from '../state.js';
import { buildFilterBar, filterEntries } from '../filter.js';

// Poll du panneau live (C4) : canal de données séparé du flux pixels VNC.
const POLL_INTERVAL_MS = 2000;
// Fermeture auto silencieuse (C2) : onglet caché en continu au-delà de ce délai.
const SESSION_HIDDEN_CLOSE_MS = 60000;
// Même seuil que le tableau réseau du résultat figé (detail.js) : pas de
// barre de filtre sur un petit résultat (bruit inutile).
const NETWORK_FILTER_THRESHOLD = 8;

const SEV_CLASS = { critical: 'sev-4', high: 'sev-3', medium: 'sev-2', low: 'sev-1' };
const VERDICT_CLASS = { benign: 'v-benign', suspicious: 'v-suspicious', malicious: 'v-malicious', unknown: 'v-unknown' };

// URL du WebSocket proxy, MÊME ORIGINE (couvert par CSP connect-src 'self').
// Le token n'y figure PAS : il voyage par sous-protocole (voir wsProtocols plus bas).
function wsUrlFor(sessionId) {
  const scheme = location.protocol === 'https:' ? 'wss://' : 'ws://';
  return scheme + location.host + '/sessions/' + encodeURIComponent(sessionId) + '/ws';
}

// Panneau live (C4) : compteurs + tableau réseau filtrable (réutilise filter.js,
// AUCUNE réimplémentation du matching) + liste des findings. `update(data)` est
// appelé à chaque tour de poll avec la réponse de `liveSession`. XSS-clean :
// tout passe par el()/textContent, jamais innerHTML.
function buildLivePanel(getLastNetwork) {
  const netCountEl = el('b', {}, '0');
  const findCountEl = el('b', {}, '0');
  const verdictEl = el('span.livesumverdict.v-unknown', {}, 'verdict inconnu');
  const summary = el('div.livesummary', {}, [
    el('span.livesumitem', {}, [netCountEl, ' appels réseau']),
    el('span.livesumsep', {}, '·'),
    el('span.livesumitem', {}, [findCountEl, ' findings']),
    el('span.livesumsep', {}, '·'),
    verdictEl,
  ]);

  const netWrap = el('div.livenet');
  const findWrap = el('div.livefindings');

  function renderNetwork(net) {
    netWrap.replaceChildren();
    if (!net.length) { netWrap.appendChild(el('p.muted', {}, 'aucune requête réseau')); return; }
    const table = el('table.qtable');
    const thead = el('thead', {}, [el('tr', {}, [
      el('th', {}, 'method'), el('th', {}, 'status'), el('th', {}, 'type'), el('th', {}, 'url'),
    ])]);
    const tb = el('tbody');
    // Même rendu de ligne que le tableau réseau du résultat figé (detail.js) —
    // XSS-clean, jamais innerHTML.
    const renderRows = (rows) => {
      tb.replaceChildren(...rows.map((n) => el('tr', {}, [
        el('td', {}, n.method || ''),
        el('td', {}, n.status != null ? String(n.status) : '—'),
        el('td', {}, n.resource_type || ''),
        el('td', { title: n.url || '' }, n.url || ''),
      ])));
    };
    table.appendChild(thead); table.appendChild(tb);
    if (net.length > NETWORK_FILTER_THRESHOLD) {
      // Barre de filtre SOC réutilisée telle quelle (filter.js, Task 1 3d-2 I).
      // Le canal live re-poll toutes les 2s : `getLastNetwork` referme sur les
      // données les plus fraîches, `renderRows` re-rend le <tbody> — DRY, pas
      // de réimplémentation du matching. Reconstruite à chaque tour (filter.js
      // n'expose pas de hook de rafraîchissement externe pour un jeu de chips
      // déjà posé) : compromis assumé pour un panneau live qui doit refléter
      // l'état courant du réseau à chaque poll.
      const bar = buildFilterBar(getLastNetwork, renderRows, { el });
      netWrap.appendChild(el('div.filter-slot', {}, [bar]));
    } else {
      renderRows(filterEntries(net, []));
    }
    netWrap.appendChild(el('div.card', {}, [el('div.plscroll', {}, [table])]));
  }

  function renderFindings(findings) {
    findWrap.replaceChildren();
    if (!findings.length) { findWrap.appendChild(el('p.muted', {}, 'Aucune détection statique.')); return; }
    findings.forEach((f) => {
      findWrap.appendChild(el('div', { class: 'alert finding ' + (SEV_CLASS[f.severity] || '') }, [
        el('span.sev', {}, f.severity || ''),
        el('div.title', {}, [el('div.frule', {}, f.rule || '')]),
      ]));
    });
  }

  function update(data) {
    const counts = (data && data.counts) || {};
    const network = Array.isArray(data && data.network) ? data.network : [];
    const findings = Array.isArray(data && data.findings) ? data.findings : [];
    netCountEl.textContent = String(counts.network != null ? counts.network : network.length);
    findCountEl.textContent = String(counts.findings != null ? counts.findings : findings.length);
    const verdict = (data && data.verdict) || 'unknown';
    verdictEl.textContent = verdict;
    verdictEl.className = 'livesumverdict ' + (VERDICT_CLASS[verdict] || 'v-unknown');
    renderNetwork(network);
    renderFindings(findings);
  }

  const node = el('div.livepanel', {}, [
    summary,
    el('div.detsec', {}, [el('h3', {}, 'Réseau'), netWrap]),
    el('div.detsec', {}, [el('h3', {}, 'Détections statiques'), findWrap]),
  ]);

  return { node, update };
}

export function renderInteractive(app) {
  // État vivant de la vue (closure) : session courante + client RFB.
  let rfb = null;          // instance noVNC (module chargé à la demande)
  let sessionId = null;    // id de la session côté serveur
  let token = null;        // token capability — MÉMOIRE UNIQUEMENT, jamais persisté
  let closed = false;      // garde anti-double-nettoyage
  let pollTimer = null;    // setInterval du panneau live (/live, C4)
  let lastNetwork = [];    // dernier réseau reçu par le poll (closure pour buildFilterBar)
  let livePanel = null;    // panneau live courant (recréé à chaque ouverture de session)
  let hiddenTimer = null;  // setTimeout de fermeture auto (C2, onglet caché)

  // Arrête le poll du panneau live — jamais de setInterval fantôme entre deux
  // sessions/vues. Idempotent.
  function stopPoll() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  // teardownRfb() est LE point de coupure du flux VNC (nav de vue, fermeture
  // explicite, fermeture auto onglet caché) : y arrêter le poll garantit qu'il
  // ne survit jamais à la scène live qui l'a démarré.
  function teardownRfb() {
    if (rfb) { try { rfb.disconnect(); } catch { /* déjà fermé */ } rfb = null; }
    stopPoll();
  }

  // Nettoyage appelé par le routeur au changement de vue : coupe le flux RFB
  // + le poll live, retire les listeners globaux (visibilitychange/beforeunload)
  // pour ne pas fuiter entre navigations de vue. On NE supprime PAS la session
  // ici (le serveur la recycle sur inactivité) — la destruction explicite reste
  // le bouton « Fermer » (ou l'auto-fermeture C2 ci-dessous).
  const cleanup = () => {
    closed = true;
    teardownRfb();
    if (hiddenTimer) { clearTimeout(hiddenTimer); hiddenTimer = null; }
    document.removeEventListener('visibilitychange', onVisibilityChange);
    window.removeEventListener('beforeunload', onBeforeUnload);
  };

  // ---- C2 : fermeture auto silencieuse (onglet caché > 60s) ----
  // Toujours caché à l'échéance -> ferme la session (DELETE) + teardown RFB +
  // arrêt du poll (doClose() fait déjà tout ça). Redevenu visible avant -> on
  // annule simplement le timer, rien d'autre ne change.
  function onVisibilityChange() {
    if (document.hidden) {
      if (hiddenTimer) clearTimeout(hiddenTimer);
      hiddenTimer = setTimeout(() => {
        hiddenTimer = null;
        if (sessionId) doClose();
      }, SESSION_HIDDEN_CLOSE_MS);
    } else if (hiddenTimer) {
      clearTimeout(hiddenTimer);
      hiddenTimer = null;
    }
  }

  // Fermeture brutale du navigateur/onglet : tentative best-effort, ne doit
  // JAMAIS bloquer la fermeture. `sendBeacon` ne porte ni la méthode DELETE ni
  // l'en-tête Authorization (limite native de l'API) : la fermeture fiable
  // reste le `disconnect_grace` + reaper côté serveur (C2 backend, déjà en
  // place sur le proxy WS) — ceci ne fait que réduire la fenêtre d'exposition.
  function onBeforeUnload() {
    if (!sessionId) return;
    const url = '/sessions/' + encodeURIComponent(sessionId);
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(url);
      } else {
        fetch(url, { method: 'DELETE', keepalive: true, headers: { Authorization: 'Bearer ' + getToken() } })
          .catch(() => {});
      }
    } catch { /* best-effort, ignore */ }
  }

  document.addEventListener('visibilitychange', onVisibilityChange);
  window.addEventListener('beforeunload', onBeforeUnload);

  // ---- C4 : poll du panneau live (/sessions/{id}/live, canal données séparé
  // du flux pixels VNC). Une erreur (session fermée -> 404, conteneur en panne
  // -> 502, 401) arrête proprement le poll sans jamais casser l'UI existante.
  async function pollLive() {
    if (!sessionId || !livePanel) return;
    try {
      const data = await liveSession(sessionId);
      lastNetwork = Array.isArray(data.network) ? data.network : [];
      livePanel.update(data);
    } catch {
      stopPoll();
    }
  }

  // ---- en-tête + bandeau d'avertissement (héros de la vue) ----
  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Session interactive'),
    el('span.sub', {}, 'Ouvre une page live et pilote son rendu dans le conteneur isolé.'),
  ]));
  app.appendChild(el('div.livewarn', { role: 'note' }, [
    iconNode('warn'),
    el('div.livewarn-txt', {}, [
      el('b', {}, 'IP exposée · contenu rendu côté conteneur.'),
      el('span', {}, ' L\'IP du serveur est visible du site cible, et le contenu '
        + '(potentiellement hostile) est rendu dans le conteneur isolé — jamais dans ce navigateur.'),
    ]),
  ]));

  const err = el('div.errbox', { role: 'alert', hidden: 'hidden' });
  const showErr = (msg) => { err.textContent = msg; err.hidden = false; };
  app.appendChild(err);

  // ---- formulaire d'ouverture (URL live ou HTML inline) ----
  let mode = 'url'; // 'url' | 'html'

  const urlInput = el('input', {
    type: 'url', id: 'live-url', placeholder: 'https://…', 'aria-label': 'URL à ouvrir',
    autocapitalize: 'off', autocomplete: 'off', spellcheck: 'false',
  });
  const urlField = el('div.oc-field', {}, [
    el('label', { for: 'live-url' }, 'URL à ouvrir'),
    urlInput,
    el('span.hint', {}, 'chargement live dans le conteneur (moteur furtif)'),
  ]);

  const htmlArea = el('textarea', {
    id: 'live-html', spellcheck: 'false', 'aria-label': 'HTML à rendre',
    placeholder: 'colle du HTML (ou charge un fichier .htm/.html/.eml)',
  });
  const liveFileLabel = el('span', {}, 'aucun fichier');
  const liveFileInput = el('input', {
    type: 'file', accept: '.htm,.html,.eml,text/html', hidden: 'hidden',
    onchange: () => {
      const f = liveFileInput.files && liveFileInput.files[0];
      if (!f) return;
      liveFileLabel.textContent = f.name;
      const reader = new FileReader();
      reader.onload = () => { htmlArea.value = String(reader.result || ''); };
      reader.readAsText(f);
    },
  });
  const htmlField = el('div.oc-field', { hidden: 'hidden' }, [
    el('label', { for: 'live-html' }, 'HTML à rendre'),
    htmlArea,
    el('div.filepick', {}, [
      el('button.btn-ghost', { type: 'button', onclick: () => liveFileInput.click() }, [iconNode('upload'), 'Charger un fichier']),
      liveFileInput,
      liveFileLabel,
    ]),
  ]);

  function makeSeg(value, icon, text) {
    const input = el('input', { type: 'radio', name: 'live-mode', value, class: 'seg-input' });
    if (value === mode) input.setAttribute('checked', 'checked');
    input.addEventListener('change', () => { if (input.checked) setMode(value); });
    return el('label.seg', {}, [input, iconNode(icon), el('span', {}, text)]);
  }
  const toggle = el('div.profile-toggle', { role: 'radiogroup', 'aria-label': 'Source de la session' }, [
    makeSeg('url', 'eye', 'Ouvrir une URL'),
    makeSeg('html', 'flask', 'Rendre du HTML'),
  ]);

  function setMode(value) {
    mode = value;
    err.hidden = true;
    urlField.hidden = value !== 'url';
    htmlField.hidden = value !== 'html';
    setTimeout(() => (value === 'url' ? urlInput : htmlArea).focus(), 20);
  }

  const openBtn = el('button.btn-primary', { type: 'submit' }, [iconNode('eye'), 'Ouvrir la session']);
  const resetOpenBtn = () => {
    openBtn.disabled = false;
    openBtn.replaceChildren(iconNode('eye'), document.createTextNode('Ouvrir la session'));
  };

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      err.hidden = true;
      let body;
      if (mode === 'url') {
        const raw = urlInput.value.trim();
        if (!raw) { showErr('Renseigne une URL avant d\'ouvrir.'); return; }
        body = { url: raw };
      } else {
        const html = htmlArea.value.trim();
        if (!html) { showErr('Ajoute du HTML avant d\'ouvrir.'); return; }
        body = { html };
      }
      openBtn.disabled = true;
      const spin = document.createElement('span');
      spin.className = 'spin';
      openBtn.replaceChildren(spin, document.createTextNode('Ouverture de la session…'));
      try {
        const out = await createSession(body);
        if (closed) { deleteSession(out.session_id).catch(() => {}); return; }
        sessionId = out.session_id;
        token = out.token;            // reste en mémoire — jamais persisté
        openStage();
      } catch (ex) {
        if (ex instanceof Unauthorized) return;
        resetOpenBtn();
        showErr(openErrMsg(ex));
      }
    },
  }, [toggle, urlField, htmlField, el('div.formactions', {}, [openBtn])]);

  const formCard = el('div.card', {}, [form]);
  app.appendChild(formCard);

  function openErrMsg(ex) {
    if (ex && ex.status === 400) {
      return 'URL interdite : cible non publique (IP exposée / SSRF). Utilise une URL publique.';
    }
    if (ex && ex.status === 504) return 'Session non prête — le conteneur n\'a pas démarré à temps.';
    if (ex && ex.status === 422) return 'Requête invalide (URL/HTML manquant ou trop volumineux).';
    return String((ex && ex.message) || ex);
  }

  // ---- scène live : canvas noVNC + barre d'action (Capturer / Fermer) ----
  const stage = el('div.livestage', { hidden: 'hidden' });
  app.appendChild(stage);

  async function openStage() {
    formCard.hidden = true;
    err.hidden = true;

    const status = el('span.livestat', {}, [el('span.spin'), 'connexion…']);
    const target = el('div.vncframe', { 'aria-label': 'Rendu de la session interactive' });
    const capBtn = el('button.btn-primary', { type: 'button' }, [iconNode('eye'), 'Capturer']);
    const closeBtn = el('button.btn-danger', { type: 'button' }, [iconNode('trash'), 'Fermer']);
    const captureOut = el('div.captureout');

    capBtn.addEventListener('click', () => doCapture(capBtn, captureOut));
    closeBtn.addEventListener('click', () => doClose());

    // Panneau live (C4) : réseau + findings en continu, canal séparé du flux
    // pixels VNC ci-dessous — démarré indépendamment de la connexion RFB.
    livePanel = buildLivePanel(() => lastNetwork);

    stage.replaceChildren(
      el('div.livebar', {}, [
        el('span.livemeta', { title: sessionId || '' }, sessionId || ''),
        status,
        el('div.livebar-act', {}, [capBtn, closeBtn]),
      ]),
      target,
      livePanel.node,
      captureOut,
    );
    stage.hidden = false;

    stopPoll(); // garde anti-doublon si openStage() était rappelée
    pollLive();
    pollTimer = setInterval(pollLive, POLL_INTERVAL_MS);

    // Chargement paresseux du module RFB embarqué localement (aucun CDN, CSP-safe).
    let RFB;
    try {
      ({ default: RFB } = await import('/vendor/novnc/core/rfb.js'));
    } catch (ex) {
      status.replaceChildren(document.createTextNode('noVNC introuvable'));
      return;
    }
    if (closed) return;

    // ⚠️ Le token NE VA PAS dans wsUrl : il passe par le sous-protocole ci-dessous.
    rfb = new RFB(target, wsUrlFor(sessionId), {
      wsProtocols: ['binary', 'ocular.session.' + token],
    });
    rfb.scaleViewport = true;   // ajuste le rendu au conteneur
    rfb.resizeSession = false;  // on n'impose pas la taille au serveur
    rfb.addEventListener('connect', () => {
      status.replaceChildren(iconNode('check'), document.createTextNode('connecté'));
    });
    rfb.addEventListener('disconnect', (e) => {
      if (closed) return;
      const clean = e && e.detail && e.detail.clean;
      status.replaceChildren(
        iconNode('warn'),
        document.createTextNode(clean ? 'déconnecté' : 'connexion perdue'),
      );
    });
    rfb.addEventListener('securityfailure', () => {
      status.replaceChildren(iconNode('warn'), document.createTextNode('accès refusé'));
    });
  }

  // Capturer : fige l'état courant en analyse (stockée comme un job) et propose
  // un lien vers le rendu détail. La session reste ouverte (on peut recapturer).
  async function doCapture(btn, out) {
    btn.disabled = true;
    out.replaceChildren();
    const spin = document.createElement('span');
    spin.className = 'spin';
    btn.replaceChildren(spin, document.createTextNode('capture…'));
    try {
      const res = await captureSession(sessionId);
      const jobId = res.job_id || '';

      // Bouton Sauvegarder (C3) : même flux POST /saved que le résultat figé
      // (detail.js) — réutilise saveAnalysis() et les mêmes messages i18n,
      // aucune réimplémentation. XSS-clean : el()/textContent uniquement.
      const saveLabelInput = el('input', {
        type: 'text', maxlength: '120', 'aria-label': 'Étiquette (optionnelle)',
        placeholder: 'étiquette (optionnelle)',
      });
      const saveBtn = el('button.btn-ghost', { type: 'button' }, [iconNode('bookmark'), 'Sauvegarder']);
      const saveActions = el('div.saverow', {}, [saveLabelInput, saveBtn]);
      const saveErr = el('div.errbox', { role: 'alert', hidden: 'hidden' });

      saveBtn.addEventListener('click', async () => {
        saveErr.hidden = true;
        saveBtn.disabled = true;
        try {
          const saved = await saveAnalysis(jobId, saveLabelInput.value.trim());
          saveActions.replaceChildren(
            el('span.savedok', {}, [iconNode('check'), 'Analyse sauvegardée']),
            el('a.savedlink', { href: '#/saved/' + saved.id }, 'Voir dans Sauvegardes'),
          );
        } catch (ex) {
          if (ex instanceof Unauthorized) return;
          saveBtn.disabled = false;
          // XSS-clean : toujours textContent, jamais innerHTML.
          saveErr.textContent = ex && ex.duplicateLabel
            ? 'Nom déjà utilisé — choisis une autre étiquette.'
            : ex && ex.expired
            ? 'Artefacts expirés — relance l\'analyse avant de sauvegarder.'
            : String((ex && ex.message) || ex);
          saveErr.hidden = false;
        }
      });

      out.replaceChildren(el('div.savepanel', {}, [
        el('div.saverow', {}, [
          el('span.savelead', {}, [iconNode('check'), 'Capture enregistrée']),
          el('span.livemeta', {}, res.verdict || 'unknown'),
          el('a.savedlink', { href: '#/job/' + jobId }, 'Voir l\'analyse'),
        ]),
        saveActions,
        saveErr,
      ]));
    } catch (ex) {
      if (ex instanceof Unauthorized) return;
      out.replaceChildren(el('div.errbox', {}, ex && ex.status === 502
        ? 'Capture échouée — la session ne répond pas.'
        : String((ex && ex.message) || ex)));
    } finally {
      btn.disabled = false;
      btn.replaceChildren(iconNode('eye'), document.createTextNode('Capturer'));
    }
  }

  // Fermer : détruit la session côté serveur et coupe le flux, retour au formulaire.
  async function doClose() {
    teardownRfb();
    livePanel = null;
    const id = sessionId;
    sessionId = null;
    token = null;
    if (id) { try { await deleteSession(id); } catch (ex) { if (ex instanceof Unauthorized) return; } }
    stage.hidden = true;
    stage.replaceChildren();
    formCard.hidden = false;
    resetOpenBtn();
    setTimeout(() => urlInput.focus(), 20);
  }

  setTimeout(() => urlInput.focus(), 30);
  return cleanup;
}
