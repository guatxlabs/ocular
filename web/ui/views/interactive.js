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
import { el, iconNode, esc } from '../core.js';
import {
  createSession, deleteSession, captureSession, liveSession, saveAnalysis, Unauthorized,
} from '../api.js';
import { getToken } from '../state.js';
import {
  buildFilterBar, filterEntries, dedupEntries, networkKey, consoleKey,
  CONSOLE_FIELD_DEFS, SEV_CLASS, VERDICT_CLASS,
  networkRow, consoleLine, exfilFormRow, exfilMailtoRow,
} from '../filter.js';

// Poll du panneau live (C4) : canal de données séparé du flux pixels VNC.
const POLL_INTERVAL_MS = 2000;
// Fermeture auto silencieuse (C2) : onglet caché en continu au-delà de ce délai.
const SESSION_HIDDEN_CLOSE_MS = 60000;

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
//
// La barre de filtre et le tableau réseau sont construits UNE SEULE FOIS (hors
// de toute boucle de poll) : `getLastNetwork` renvoie la réf mutable des données
// courantes, et `bar.refresh()` ré-applique les chips DÉJÀ posés par l'analyste
// sur ces nouvelles données à chaque poll — les chips PERSISTENT (plus de reset
// toutes les 2s).
function buildLivePanel(getLastNetwork) {
  const netCountEl = el('b', {}, '0');
  const findCountEl = el('b', {}, '0');
  const consCountEl = el('b', {}, '0');
  const verdictEl = el('span.livesumverdict.v-unknown', {}, 'verdict inconnu');
  const summary = el('div.livesummary', {}, [
    el('span.livesumitem', {}, [netCountEl, ' appels réseau']),
    el('span.livesumsep', {}, '·'),
    el('span.livesumitem', {}, [findCountEl, ' findings']),
    el('span.livesumsep', {}, '·'),
    el('span.livesumitem', {}, [consCountEl, ' console']),
    el('span.livesumsep', {}, '·'),
    verdictEl,
  ]);

  const findWrap = el('div.livefindings');
  // Console live (parité 3b/3c avec le résultat statique, cf. detail.js::
  // buildConsole) : mêmes classes CSS (`.conslist`/`.consline`), XSS-clean —
  // uniquement el()/textContent, jamais innerHTML.
  const consWrap = el('div.conslist');
  let lastConsole = [];  // dernière console reçue (réf mutable pour le filtre live)
  // Formulaires + mailto live (exfiltration) — mêmes classes que detail.js.
  const exfilWrap = el('div');

  // ---- tableau réseau + barre de filtre : construits UNE FOIS ----
  const table = el('table.qtable');
  const thead = el('thead', {}, [el('tr', {}, [
    el('th', {}, 'method'), el('th', {}, 'status'), el('th', {}, 'type'), el('th', {}, 'url'),
  ])]);
  const tb = el('tbody');
  // Même rendu de ligne que le tableau réseau du résultat figé (detail.js) —
  // XSS-clean, jamais innerHTML.
  const renderRows = (rows) => {
    tb.replaceChildren(...rows.map((n) => networkRow(el, n)));
  };
  table.appendChild(thead); table.appendChild(tb);

  // Barre de filtre SOC réutilisée telle quelle (filter.js, Task 1 3d-2 I) :
  // `getLastNetwork` referme sur les données les PLUS FRAÎCHES (réf mutable),
  // dédupliquées natif (method+status+type+url, badge ×N) ; `renderRows` re-rend
  // le <tbody> — DRY, aucune réimplémentation du matching. Construite ici, une
  // seule fois : le poll appelle `bar.refresh()` (voir `refreshNetwork`), il ne
  // reconstruit JAMAIS la barre -> chips préservés.
  const bar = buildFilterBar(() => dedupEntries(getLastNetwork(), networkKey), renderRows, { el });
  const netSection = el('div.detsec', {}, [
    el('h3', {}, 'Réseau'),
    el('div.filter-slot', {}, [bar]),
    el('div.card', {}, [el('div.plscroll', {}, [table])]),
  ]);

  // Rafraîchit le tableau réseau en préservant les chips : délègue au refresh
  // interne de la barre (fallback sûr si `.refresh` absent — filtre neutre).
  function refreshNetwork() {
    if (typeof bar.refresh === 'function') bar.refresh();
    else renderRows(filterEntries(getLastNetwork(), []));
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

  // Même rendu que buildConsole (detail.js) : level/text posés en textNode,
  // jamais innerHTML — la console d'une page hostile est du contenu non fiable.
  // Badge ×N pour les lignes dédupliquées.
  const renderConsoleLines = (rows) => {
    if (!rows.length) { consWrap.replaceChildren(el('p.muted', {}, 'console vide')); return; }
    consWrap.replaceChildren(...rows.map((c) => consoleLine(el, esc, c)));
  };
  // Filtre console (exclure/rechercher) à parité du réseau : construit UNE fois,
  // `getEntries` referme sur `lastConsole` (dédupliqué), le poll appelle
  // `consBar.refresh()` -> chips préservés + rafraîchissement live.
  const consBar = buildFilterBar(() => dedupEntries(lastConsole, consoleKey), renderConsoleLines,
    { el, fieldDefs: CONSOLE_FIELD_DEFS });
  function refreshConsole(cons) {
    lastConsole = Array.isArray(cons) ? cons : [];
    if (typeof consBar.refresh === 'function') consBar.refresh();
    else renderConsoleLines(dedupEntries(lastConsole, consoleKey));
  }

  // Formulaires (action+méthode) + mailto — indicateur d'exfiltration, live.
  // XSS-clean (action/mailto = contenu de page hostile → textNode).
  function renderExfil(forms, mailtos) {
    const f = Array.isArray(forms) ? forms : [];
    const m = Array.isArray(mailtos) ? mailtos : [];
    if (!f.length && !m.length) { exfilWrap.replaceChildren(el('p.muted', {}, 'aucun formulaire ni mailto')); return; }
    const kids = [
      ...f.map((fo) => exfilFormRow(el, fo)),
      ...m.map((mt) => exfilMailtoRow(el, mt)),
    ];
    exfilWrap.replaceChildren(el('div.exfil-list', {}, kids));
  }

  // Appelé à chaque poll. `getLastNetwork()` a déjà été mis à jour par
  // l'appelant (pollLive) : ici on rafraîchit les compteurs/findings/console/
  // verdict (pas d'état utilisateur) et on relance le filtre réseau (chips
  // conservés).
  function update(data) {
    const counts = (data && data.counts) || {};
    const network = Array.isArray(data && data.network) ? data.network : [];
    const findings = Array.isArray(data && data.findings) ? data.findings : [];
    const console_ = Array.isArray(data && data.console) ? data.console : [];
    netCountEl.textContent = String(counts.network != null ? counts.network : network.length);
    findCountEl.textContent = String(counts.findings != null ? counts.findings : findings.length);
    consCountEl.textContent = String(counts.console != null ? counts.console : console_.length);
    const verdict = (data && data.verdict) || 'unknown';
    verdictEl.textContent = verdict;
    verdictEl.className = 'livesumverdict ' + (VERDICT_CLASS[verdict] || 'v-unknown');
    refreshNetwork();
    renderFindings(findings);
    refreshConsole(console_);
    renderExfil(data && data.forms, data && data.mailtos);
  }

  const node = el('div.livepanel', {}, [
    summary,
    // Formulaires & mailto AVANT le réseau (signal d'exfiltration prioritaire).
    el('div.detsec', {}, [el('h3', {}, 'Formulaires & mailto'), el('div.card', {}, [exfilWrap])]),
    netSection,
    el('div.detsec', {}, [el('h3', {}, 'Détections statiques'), findWrap]),
    el('div.detsec', {}, [
      el('h3', {}, 'Console'),
      el('div.filter-slot', {}, [consBar]),
      el('div.card', {}, [consWrap]),
    ]),
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
    window.removeEventListener('pagehide', onPageHide);
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

  // Rechargement (Ctrl/Cmd+R) ou fermeture d'onglet AVEC une session active :
  // on DEMANDE confirmation. Sans ce garde, un simple Ctrl+R quand le focus
  // clavier n'est PAS sur le canvas noVNC recharge la page Ocular et détruit la
  // session — donc l'état DERRIÈRE un login/Turnstile passé, plus toute capture
  // non encore enregistrée. Le token de session est en mémoire seule (jamais
  // persisté, choix sécu) : un rechargement le perd de toute façon, la session
  // deviendrait irrécupérable côté client -> on la libère au unload RÉEL
  // (pagehide), pas ici. (Note : si le focus EST sur le canvas, noVNC capte
  // Ctrl+R et le route vers le navigateur DISTANT — seule la page cible se
  // recharge, les cookies persistent, on reste derrière le login ; ce cas
  // n'atteint jamais ce handler.)
  function onBeforeUnload(e) {
    if (!sessionId) return;
    e.preventDefault();
    e.returnValue = '';   // déclenche la confirmation native « quitter le site ? »
    return '';
  }

  // pagehide ne se déclenche QUE si la page se décharge vraiment (confirmation
  // acceptée / onglet fermé) — jamais si la confirmation beforeunload est
  // annulée. On libère alors la session côté serveur (best-effort ; `sendBeacon`
  // ne porte ni DELETE ni Authorization, le reaper/disconnect_grace reste le
  // filet fiable). Confirmation annulée -> pagehide non déclenché -> session
  // préservée -> l'état post-login reste accessible.
  function onPageHide() {
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
  window.addEventListener('pagehide', onPageHide);

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

  // type="text" (PAS "url") : accepte un domaine nu (« guatx.com »). La
  // normalisation canonique est faite côté serveur (normalize_url).
  const urlInput = el('input', {
    type: 'text', inputmode: 'url', id: 'live-url', placeholder: 'guatx.com, http://… ou https://…',
    'aria-label': 'URL à ouvrir', autocapitalize: 'off', autocomplete: 'off', spellcheck: 'false',
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
  // URL à gauche, HTML à droite — cohérent avec le formulaire « Analyser une page ».
  const toggle = el('div.profile-toggle', { role: 'radiogroup', 'aria-label': 'Source de la session' }, [
    makeSeg('url', 'eye', 'URL'),
    makeSeg('html', 'flask', 'HTML'),
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
    // « Sauvegarder » = fige l'état courant (capture d'écran + analyse) en une
    // sauvegarde éphémère, puis demande un NOM ci-dessous. Rien n'est persisté
    // tant que l'analyste n'a pas nommé + validé (cf. doCapture / nettoyage
    // serveur des captures non nommées à la fermeture de session).
    const capBtn = el('button.btn-primary', { type: 'button' }, [iconNode('bookmark'), 'Sauvegarder']);
    const closeBtn = el('button.btn-danger', { type: 'button' }, [iconNode('trash'), 'Fermer']);
    const captureOut = el('div.captureout');

    // Turnstile passé MANUELLEMENT : le solve interactif n'est pas introspectable
    // de façon fiable (l'iframe CF subsiste dans le DOM après résolution). Cette
    // case déclare explicitement la résolution ; sinon le statut reste honnête
    // (challenge présent -> « non passé » ; absent -> aucun badge).
    const tsCheck = el('input', { type: 'checkbox', id: 'ts-passed', class: 'ts-check' });
    const tsLabel = el('label.ts-passed', { for: 'ts-passed', title: 'Coche si tu as résolu le Turnstile à la main avant de capturer' }, [
      tsCheck, el('span', {}, 'Turnstile passé'),
    ]);

    // Vue de la SCÈNE live. Le navigateur distant est rendu par matchbox en PLEIN
    // ÉCRAN sur un Xvfb 1920x1080 (entrypoint_vnc.sh) : la fenêtre couvre tout le
    // framebuffer, et `scaleViewport` en montre l'INTÉGRALITÉ dans le cadre client
    // (letterbox si l'aspect diffère, JAMAIS de crop droite/bas). Un viewport
    // 1080p montre nettement plus qu'avant (720p). « Agrandir » agrandit le cadre
    // -> scaleViewport met la scène à l'échelle plus grande. Pour le bas d'une
    // page longue : on défile ; la page ENTIÈRE se fige via « Sauvegarder ».
    let big = false;
    const zoomBtn = el('button.btn-ghost', {
      type: 'button', title: 'Agrandir la scène (voir plus grand) / réduire',
    }, [iconNode('eye'), 'Agrandir']);
    const applyZoom = () => {
      zoomBtn.replaceChildren(iconNode('eye'), document.createTextNode(big ? 'Réduire' : 'Agrandir'));
      target.classList.toggle('vnc-big', big);
      if (rfb) {
        rfb.scaleViewport = true;   // montre TOUT le framebuffer dans le cadre (aucun crop)
        requestAnimationFrame(() => { try { rfb.scaleViewport = true; } catch { /* ignore */ } });
      }
    };
    zoomBtn.addEventListener('click', () => { big = !big; applyZoom(); });

    capBtn.addEventListener('click', () => doCapture(capBtn, captureOut, tsCheck.checked));
    closeBtn.addEventListener('click', () => doClose());

    // Panneau live (C4) : réseau + findings en continu, canal séparé du flux
    // pixels VNC ci-dessous — démarré indépendamment de la connexion RFB.
    livePanel = buildLivePanel(() => lastNetwork);

    stage.replaceChildren(
      el('div.livebar', {}, [
        el('span.livemeta', { title: sessionId || '' }, sessionId || ''),
        status,
        el('div.livebar-act', {}, [zoomBtn, tsLabel, capBtn, closeBtn]),
      ]),
      captureOut,   // panneau de nommage/sauvegarde JUSTE sous la barre (pas en bas)
      target,
      livePanel.node,
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
    applyZoom();                // resize distant responsive + échelle initiale
    rfb.addEventListener('connect', () => {
      applyZoom();              // (re)applique après connexion (dimensions connues)
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

  // Sauvegarder : fige l'état courant (capture d'écran + analyse) en une
  // sauvegarde ÉPHÉMÈRE côté serveur, puis demande un NOM juste sous la barre.
  // RIEN n'est persisté tant que l'analyste n'a pas nommé + validé : la capture
  // sans nom est purgée à la fermeture de la session (nettoyage serveur des
  // résultats `sesscap-*`). On N'AVERTIT PAS de la capture temporaire — seul un
  // enregistrement effectif (nom donné) affiche une confirmation.
  async function doCapture(btn, out, turnstilePassed) {
    btn.disabled = true;
    out.replaceChildren();
    const spin = document.createElement('span');
    spin.className = 'spin';
    btn.replaceChildren(spin, document.createTextNode('capture…'));
    try {
      const res = await captureSession(sessionId, { turnstilePassed: !!turnstilePassed });
      const jobId = res.job_id || '';

      // Panneau de nommage : un NOM est REQUIS pour enregistrer (sinon la
      // capture reste temporaire et sera purgée à la fermeture). XSS-clean.
      const saveLabelInput = el('input', {
        type: 'text', maxlength: '120', 'aria-label': 'Nom de la sauvegarde',
        placeholder: 'nom de la sauvegarde (requis)',
      });
      const saveBtn = el('button.btn-primary', { type: 'button' }, [iconNode('bookmark'), 'Enregistrer']);
      const saveActions = el('div.saverow', {}, [saveLabelInput, saveBtn]);
      const saveErr = el('div.errbox', { role: 'alert', hidden: 'hidden' });

      const doSave = async () => {
        const name = saveLabelInput.value.trim();
        if (!name) {           // pas de nom -> pas de sauvegarde (capture reste temporaire)
          saveErr.textContent = 'Donne un nom pour enregistrer la sauvegarde.';
          saveErr.hidden = false;
          saveLabelInput.focus();
          return;
        }
        saveErr.hidden = true;
        saveBtn.disabled = true;
        try {
          const saved = await saveAnalysis(jobId, name);
          // Confirmation UNIQUEMENT après enregistrement effectif.
          out.replaceChildren(el('div.savepanel', {}, [el('div.saverow', {}, [
            el('span.savedok', {}, [iconNode('check'), 'Sauvegardé']),
            el('a.savedlink', { href: '#/saved/' + saved.id }, 'Voir dans Sauvegardes'),
          ])]));
        } catch (ex) {
          if (ex instanceof Unauthorized) return;
          saveBtn.disabled = false;
          saveErr.textContent = ex && ex.duplicateLabel
            ? 'Nom déjà utilisé — choisis-en un autre.'
            : ex && ex.expired
            ? 'Artefacts expirés — relance la capture avant d\'enregistrer.'
            : String((ex && ex.message) || ex);
          saveErr.hidden = false;
        }
      };
      saveBtn.addEventListener('click', doSave);
      saveLabelInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doSave(); } });

      out.replaceChildren(el('div.savepanel', {}, [saveActions, saveErr]));
      setTimeout(() => saveLabelInput.focus(), 20);
    } catch (ex) {
      if (ex instanceof Unauthorized) return;
      out.replaceChildren(el('div.errbox', {}, ex && ex.status === 502
        ? 'Capture échouée — la session ne répond pas.'
        : String((ex && ex.message) || ex)));
    } finally {
      btn.disabled = false;
      btn.replaceChildren(iconNode('bookmark'), document.createTextNode('Sauvegarder'));
    }
  }

  // Fermer : détruit la session côté serveur et coupe le flux, retour au formulaire.
  async function doClose() {
    teardownRfb();
    if (hiddenTimer) { clearTimeout(hiddenTimer); hiddenTimer = null; }  // hygiène : pas de timer d'auto-fermeture qui survit
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
