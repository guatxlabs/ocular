// submit.js — deux profils d'analyse, sélectionnés par un toggle segmenté :
//   • « Analyser HTML » (profile: analysis) : textarea HTML + upload .eml.
//   • « Analyser URL »  (profile: capture)  : capture live d'une URL (stealth).
// Avant POST /jobs : dédup. On calcule le hash d'entrée (identique à l'input_hash
// du moteur — HTML brut pour analysis, URL normalisée pour capture) et on interroge
// /saved/{hash} ; si une analyse existe déjà, une modale propose de la revoir.
import { el, iconNode, openModal } from '../core.js';
import { addJob } from '../state.js';
import { submitJob, sha256Hex, normalizeUrlClient, lookupSaved, Unauthorized } from '../api.js';

function fmtIso(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

export function renderSubmit(app) {
  let profile = 'analysis'; // 'analysis' (HTML) | 'capture' (URL)

  const err = el('div.errbox', { role: 'alert', hidden: 'hidden' });
  const showErr = (msg) => { err.textContent = msg; err.hidden = false; };

  // ---- champ HTML (profil analysis) ----
  const ta = el('textarea', {
    id: 'html', spellcheck: 'false', 'aria-label': 'HTML à analyser',
    placeholder: 'colle ici le HTML (ou charge un .eml)',
  });
  const fileLabel = el('span', {}, 'aucun fichier');
  const fileInput = el('input', {
    type: 'file', accept: '.eml,message/rfc822,text/html', hidden: 'hidden',
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
      el('button.btn-ghost', { type: 'button', onclick: () => fileInput.click() }, [iconNode('upload'), 'Charger un .eml']),
      fileInput,
      fileLabel,
    ]),
  ]);

  // ---- champ URL (profil capture) — actif : capture live, moteur furtif ----
  const urlInput = el('input', {
    type: 'url', id: 'url', placeholder: 'https://…', 'aria-label': 'URL à analyser',
    autocapitalize: 'off', autocomplete: 'off', spellcheck: 'false',
  });
  const urlField = el('div.oc-field', { hidden: 'hidden' }, [
    el('label', { for: 'url' }, 'URL à analyser'),
    urlInput,
    el('span.hint', {}, 'capture live via moteur furtif (Camoufox) — Turnstile géré'),
  ]);

  const btn = el('button.btn-primary', { type: 'submit' }, [iconNode('flask'), 'Analyser HTML']);
  const btnIcon = { analysis: 'flask', capture: 'eye' };
  const btnLabel = { analysis: 'Analyser HTML', capture: 'Analyser URL' };
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
  const toggle = el('div.profile-toggle', { role: 'radiogroup', 'aria-label': 'Profil d\'analyse' }, [
    makeSeg('analysis', 'flask', 'Analyser HTML'),
    makeSeg('capture', 'eye', 'Analyser URL'),
  ]);

  function setProfile(value) {
    profile = value;
    err.hidden = true;
    const isHtml = value === 'analysis';
    htmlField.hidden = !isHtml;
    urlField.hidden = isHtml;
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
  function submitErrMsg(ex, prof) {
    if (ex && ex.status === 400 && prof === 'capture') {
      return 'URL interdite : cible non publique (IP exposée / SSRF). Utilise une URL publique.';
    }
    if (ex && ex.status === 422) {
      return prof === 'capture'
        ? 'URL manquante — renseigne une URL avant de lancer.'
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
      let payload, target, hashInput;
      if (profile === 'capture') {
        const raw = urlInput.value.trim();
        if (!raw) { showErr('Renseigne une URL avant de lancer.'); return; }
        let norm;
        try { norm = normalizeUrlClient(raw); }
        catch { showErr('URL invalide — vérifie le format (ex. https://exemple.com).'); return; }
        payload = { profile: 'capture', url: raw };
        target = norm;
        hashInput = norm;
      } else {
        const html = ta.value.trim();
        if (!html) { showErr('Ajoute du HTML ou charge un .eml avant de lancer.'); return; }
        const m = html.match(/<title[^>]*>([^<]{0,80})/i);
        payload = { profile: 'analysis', html };
        target = (m && m[1].trim()) || (html.slice(0, 60).replace(/\s+/g, ' ').trim() + '…');
        hashInput = html;
      }
      err.hidden = true;
      btn.disabled = true;
      // dédup best-effort : en cas d'échec du lookup, on n'empêche pas l'analyse.
      let meta = null;
      try {
        const h = await sha256Hex(hashInput);
        meta = await lookupSaved(h);
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
    el('div.formactions', {}, [btn]),
  ]);

  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Analyser une page'),
    el('span.sub', {}, 'Colle du HTML, dépose un .eml, ou capture une URL live.'),
  ]));
  app.appendChild(el('div.card', {}, [form]));
  setTimeout(() => ta.focus(), 30);
  return null;
}
