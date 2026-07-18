// submit.js — deux profils d'analyse, sélectionnés par un toggle segmenté :
//   • « Analyser HTML » (profile: analysis) : textarea HTML + upload .eml.
//   • « Analyser URL »  (profile: capture)  : capture live d'une URL (stealth).
// Avant POST /jobs : dédup. Profil HTML : hash du HTML brut (sha256Hex côté client,
// identique à l'input_hash du moteur) puis /saved/{hash}. Profil URL : normalisation
// ET hash calculés côté serveur via POST /saved/lookup (un seul normaliseur Python
// canonique — évite la divergence avec un parseur URL JS). Si une analyse existe
// déjà, une modale propose de la revoir.
import { el, iconNode, openModal, fmtIso } from '../core.js';
import { addJob } from '../state.js';
import { submitJob, sha256Hex, lookupSaved, lookupSavedByUrl, Unauthorized } from '../api.js';

export function renderSubmit(app) {
  let profile = 'capture'; // défaut URL ('capture') ; 'analysis' = HTML

  const err = el('div.errbox', { role: 'alert', hidden: 'hidden' });
  const showErr = (msg) => { err.textContent = msg; err.hidden = false; };

  // ---- champ HTML (profil analysis) ----
  const ta = el('textarea', {
    id: 'html', spellcheck: 'false', 'aria-label': 'HTML à analyser',
    placeholder: 'colle du HTML (ou charge un fichier .htm/.html/.eml)',
  });
  const fileLabel = el('span', {}, 'aucun fichier');
  const fileInput = el('input', {
    type: 'file', accept: '.htm,.html,.eml,message/rfc822,text/html', hidden: 'hidden',
    onchange: () => {
      const f = fileInput.files && fileInput.files[0];
      if (!f) return;
      fileLabel.textContent = f.name;
      const reader = new FileReader();
      reader.onload = () => { ta.value = String(reader.result || ''); };
      reader.readAsText(f);
    },
  });
  const htmlField = el('div.oc-field', {}, [
    el('label', { for: 'html' }, 'HTML à analyser'),
    ta,
    el('div.filepick', {}, [
      el('button.btn-ghost', { type: 'button', onclick: () => fileInput.click() }, [iconNode('upload'), 'Charger un fichier']),
      fileInput,
      fileLabel,
    ]),
  ]);

  // ---- champ URL (profil capture) — actif : capture live, moteur furtif ----
  // type="text" (PAS "url") : la validation native de type="url" rejette un
  // domaine nu (« guatx.com ») faute de scheme. La normalisation est faite
  // côté serveur (normalize_url canonique) — l'UI n'envoie que la chaîne brute
  // et accepte « guatx.com », « http://guatx.com », « https://guatx.com ».
  const urlInput = el('input', {
    type: 'text', inputmode: 'url', id: 'url', placeholder: 'guatx.com, http://… ou https://…',
    'aria-label': 'URL à analyser', autocapitalize: 'off', autocomplete: 'off', spellcheck: 'false',
  });
  const urlField = el('div.oc-field', { hidden: 'hidden' }, [
    el('label', { for: 'url' }, 'URL à analyser'),
    urlInput,
    el('span.hint', {}, 'domaine nu accepté (guatx.com) — scheme http/https respecté ; capture furtive (Camoufox), Turnstile géré'),
  ]);

  // ---- champ script (profil capture, optionnel) — DSL borné rejoué après le
  // chargement (fill/click/wait/sleep/hide/press/capture/scroll). Aucun JS
  // arbitraire : la textarea ne porte que du JSON, validé côté client
  // (JSON.parse) puis revalidé côté serveur (validate_steps) avant exécution.
  const scriptTa = el('textarea', {
    id: 'script', spellcheck: 'false', 'aria-label': 'Script (JSON, optionnel)',
    placeholder: '[{"click": "#accept"}, {"sleep": 2}, {"capture": {"label": "page", "full_page": true}}]',
  });
  const EXAMPLES = [
    {
      label: 'Exemple : accepter les cookies',
      steps: [{ click: '#accept' }, { sleep: 1 }, { capture: 'apres-cookies' }],
    },
    {
      label: 'Exemple : remplir un formulaire',
      steps: [
        { fill: { sel: 'input[name=email]', value: 'a@b.c' } },
        { click: 'button[type=submit]' },
        { sleep: 2 },
        { capture: 'apres-envoi' },
      ],
    },
    {
      label: 'Exemple : full-page (attendre le rendu)',
      steps: [
        { hide: '.cookie-banner' },
        { sleep: 3 },
        { capture: { label: 'page-entiere', full_page: true } },
      ],
    },
  ];
  const examplesRow = el('div.examples', {},
    EXAMPLES.map((ex) => el('button.btn-ghost', {
      type: 'button',
      onclick: () => { scriptTa.value = JSON.stringify(ex.steps, null, 2); },
    }, ex.label)));
  const scriptField = el('div.oc-field.sc-field', { hidden: 'hidden' }, [
    el('label', { for: 'script' }, 'Script (JSON, optionnel)'),
    scriptTa,
    el('span.hint', {}, 'Rejoue une séquence d\'actions (click/fill/sleep/hide/press/scroll/wait/capture) après le chargement — DSL borné, aucun JS arbitraire. sleep est en SECONDES (ex. {"sleep": 3}). capture : {label, full_page} (page entière) ou {label, selector} (région) ; sinon seulement le viewport.'),
    examplesRow,
  ]);

  const btn = el('button.btn-primary', { type: 'submit' }, [iconNode('flask'), 'Analyser']);
  const btnIcon = { analysis: 'flask', capture: 'eye' };
  // Bouton unique « Analyser » (le profil est déjà porté par le toggle HTML/URL).
  const btnLabel = { analysis: 'Analyser', capture: 'Analyser' };
  const resetBtn = () => {
    btn.disabled = false;
    btn.replaceChildren(iconNode(btnIcon[profile]), document.createTextNode(btnLabel[profile]));
  };

  // ---- toggle segmenté de profil ----
  function makeSeg(value, icon, text) {
    const input = el('input', { type: 'radio', name: 'profile', value, class: 'seg-input' });
    if (value === profile) input.setAttribute('checked', 'checked');
    input.addEventListener('change', () => { if (input.checked) setProfile(value); });
    return el('label.seg', {}, [input, iconNode(icon), el('span', {}, text)]);
  }
  // URL à gauche, HTML à droite.
  const toggle = el('div.profile-toggle', { role: 'radiogroup', 'aria-label': 'Profil d\'analyse' }, [
    makeSeg('capture', 'eye', 'URL'),
    makeSeg('analysis', 'flask', 'HTML'),
  ]);

  function setProfile(value) {
    profile = value;
    err.hidden = true;
    const isHtml = value === 'analysis';
    htmlField.hidden = !isHtml;
    urlField.hidden = isHtml;
    scriptField.hidden = isHtml; // le script n'a de sens que pour la capture live
    resetBtn();
    setTimeout(() => (isHtml ? ta : urlInput).focus(), 20);
  }

  // POST /jobs puis navigation vers le détail (chemin commun aux deux issues de dédup).
  async function doSubmit(payload, target) {
    err.hidden = true;
    btn.disabled = true;
    const spin = document.createElement('span');
    spin.className = 'spin';
    btn.replaceChildren(spin, document.createTextNode('Analyse en cours…'));
    try {
      const { job_id } = await submitJob(payload);
      addJob({ id: job_id, target, ts: Date.now() });
      location.hash = '#/job/' + job_id;
    } catch (ex) {
      if (ex instanceof Unauthorized) return;
      showErr(submitErrMsg(ex, payload.profile));
      resetBtn();
    }
  }

  // Messages clairs pour les erreurs serveur du profil capture (garde SSRF & payload).
  // Le 422 d'un script invalide porte le motif exact de validate_steps (ex.detail,
  // extrait côté api.js) : on l'affiche tel quel plutôt qu'un message générique.
  function submitErrMsg(ex, prof) {
    if (ex && ex.status === 400 && prof === 'capture') {
      // Le 400 recouvre PLUSIEURS causes (cf. engine.ssrf.validate_capture_url) :
      // on s'appuie sur le détail serveur pour ne PAS afficher un faux « SSRF »
      // sur un simple échec DNS transitoire (un domaine public momentanément non
      // résolu par le conteneur web n'est pas une cible interne).
      const d = (ex.detail || '').toLowerCase();
      if (d.includes('dns') || d.includes('résolution') || d.includes('resolution')) {
        return 'Domaine introuvable pour l\'instant (résolution DNS échouée) — vérifie l\'orthographe, ou réessaie dans un instant.';
      }
      if (d.includes('scheme')) return 'Schéma d\'URL non autorisé (seuls http/https).';
      if (ex.detail) return 'URL refusée : ' + ex.detail;
      return 'URL interdite : cible non publique (IP exposée / SSRF). Utilise une URL publique.';
    }
    if (ex && ex.status === 422) {
      if (ex.detail) return 'Requête refusée : ' + ex.detail;
      return prof === 'capture'
        ? 'Requête invalide (URL manquante ou trop longue).'
        : 'HTML manquant ou trop volumineux.';
    }
    return String((ex && ex.message) || ex);
  }

  // Modale de dédup : analyse déjà sauvegardée pour cette entrée (HTML ou URL).
  function showDedupModal(meta, payload, target) {
    const isCapture = payload.profile === 'capture';
    const modal = el('div.modal', {}, [
      el('h3', {}, 'Analyse déjà sauvegardée'),
      el('p.modal-msg', {}, isCapture
        ? 'Cette URL a déjà été capturée et conservée. Tu peux la revoir sans relancer le moteur.'
        : 'Ce HTML a déjà été analysé et conservé. Tu peux la revoir sans relancer le moteur.'),
      el('dl.dedup-meta', {}, [
        el('dt', {}, 'Verdict'), el('dd', {}, meta.verdict || 'unknown'),
        el('dt', {}, 'Sauvegardée'), el('dd', {}, fmtIso(meta.saved_at)),
        el('dt', {}, 'Étiquette'), el('dd', {}, meta.label || '(sans étiquette)'),
      ]),
    ]);
    const cancel = el('button.m-cancel', { type: 'button' }, 'Annuler');
    const again = el('button.m-cancel', { type: 'button' }, 'Analyser quand même');
    const view = el('button.m-ok', { type: 'button' }, [iconNode('eye'), 'Voir']);
    modal.appendChild(el('div.modal-act', {}, [cancel, again, view]));
    const close = openModal(modal);
    cancel.addEventListener('click', () => { close(); resetBtn(); });
    again.addEventListener('click', () => { close(); doSubmit(payload, target); });
    view.addEventListener('click', () => { close(); location.hash = '#/saved/' + meta.id; });
  }

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      let payload, target;
      const isCapture = profile === 'capture';
      if (isCapture) {
        const raw = urlInput.value.trim();
        if (!raw) { showErr('Renseigne une URL avant de lancer.'); return; }
        payload = { profile: 'capture', url: raw };
        const rawScript = scriptTa.value.trim();
        if (rawScript) {
          let steps;
          try { steps = JSON.parse(rawScript); }
          catch (ex) { showErr('Script JSON invalide : ' + ex.message); return; }
          if (!Array.isArray(steps)) { showErr('Script JSON invalide : une liste de steps est attendue.'); return; }
          payload.steps = steps;
        }
        target = raw;
      } else {
        const html = ta.value.trim();
        if (!html) { showErr('Ajoute du HTML ou charge un fichier .htm/.html/.eml avant de lancer.'); return; }
        const m = html.match(/<title[^>]*>([^<]{0,80})/i);
        payload = { profile: 'analysis', html };
        target = (m && m[1].trim()) || (html.slice(0, 60).replace(/\s+/g, ' ').trim() + '…');
      }
      err.hidden = true;
      btn.disabled = true;
      // dédup best-effort : en cas d'échec du lookup, on n'empêche pas l'analyse.
      // Profil URL : normalisation + hash calculés côté serveur (normaliseur canonique
      // unique) — élimine la divergence avec un parseur URL JS. Profil HTML : hash
      // client du HTML brut, identique à l'input_hash du moteur.
      let meta = null;
      try {
        meta = isCapture ? await lookupSavedByUrl(payload.url) : await lookupSaved(await sha256Hex(payload.html));
      } catch (ex) {
        if (ex instanceof Unauthorized) return;
        meta = null; // lookup indisponible -> on soumet directement
      }
      if (meta) { showDedupModal(meta, payload, target); return; }
      doSubmit(payload, target);
    },
  }, [
    err,
    toggle,
    htmlField,
    urlField,
    scriptField,
    el('div.formactions', {}, [btn]),
  ]);

  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Analyser une page'),
    el('span.sub', {}, 'Colle du HTML, dépose un fichier .htm/.html/.eml, ou capture une URL live.'),
  ]));
  app.appendChild(el('div.card', {}, [form]));
  // synchronise la visibilité des champs + le focus sur le profil par défaut (URL)
  setProfile(profile);
  return null;
}
