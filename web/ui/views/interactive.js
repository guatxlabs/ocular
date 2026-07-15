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
import { createSession, deleteSession, captureSession, Unauthorized } from '../api.js';

// URL du WebSocket proxy, MÊME ORIGINE (couvert par CSP connect-src 'self').
// Le token n'y figure PAS : il voyage par sous-protocole (voir wsProtocols plus bas).
function wsUrlFor(sessionId) {
  const scheme = location.protocol === 'https:' ? 'wss://' : 'ws://';
  return scheme + location.host + '/sessions/' + encodeURIComponent(sessionId) + '/ws';
}

export function renderInteractive(app) {
  // État vivant de la vue (closure) : session courante + client RFB.
  let rfb = null;          // instance noVNC (module chargé à la demande)
  let sessionId = null;    // id de la session côté serveur
  let token = null;        // token capability — MÉMOIRE UNIQUEMENT, jamais persisté
  let closed = false;      // garde anti-double-nettoyage

  function teardownRfb() {
    if (rfb) { try { rfb.disconnect(); } catch { /* déjà fermé */ } rfb = null; }
  }

  // Nettoyage appelé par le routeur au changement de vue : coupe le flux RFB.
  // On NE supprime PAS la session ici (le serveur la recycle sur inactivité) —
  // la destruction explicite reste le bouton « Fermer ».
  const cleanup = () => { closed = true; teardownRfb(); };

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

    stage.replaceChildren(
      el('div.livebar', {}, [
        el('span.livemeta', { title: sessionId || '' }, sessionId || ''),
        status,
        el('div.livebar-act', {}, [capBtn, closeBtn]),
      ]),
      target,
      captureOut,
    );
    stage.hidden = false;

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
      out.replaceChildren(el('div.savepanel', {}, [
        el('div.saverow', {}, [
          el('span.savelead', {}, [iconNode('check'), 'Capture enregistrée']),
          el('span.livemeta', {}, res.verdict || 'unknown'),
          el('a.savedlink', { href: '#/job/' + (res.job_id || '') }, 'Voir l\'analyse'),
        ]),
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
