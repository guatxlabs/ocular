// submit.js — textarea HTML + upload .eml + champ URL désactivé (phase 3).
// Avant POST /jobs : dédup. On calcule le hash du HTML (identique à l'input_hash
// du moteur) et on interroge /saved/{hash} ; si une analyse existe déjà, une modale
// propose de la revoir plutôt que de relancer. Sinon POST /jobs -> détail du job.
import { el, iconNode, openModal } from '../core.js';
import { addJob } from '../state.js';
import { submitJob, sha256Hex, lookupSaved, Unauthorized } from '../api.js';

function fmtIso(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

export function renderSubmit(app) {
  const err = el('div.errbox', { role: 'alert', hidden: 'hidden' });
  const ta = el('textarea', {
    id: 'html', spellcheck: 'false', 'aria-label': 'HTML à analyser',
    placeholder: 'colle ici le HTML (ou charge un .eml)',
  });

  // upload .eml : lu en texte et versé dans le textarea (le moteur scanne le HTML)
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

  const btn = el('button.btn-primary', { type: 'submit' }, [iconNode('flask'), 'Lancer l\'analyse']);
  const showErr = (msg) => { err.textContent = msg; err.hidden = false; };
  const resetBtn = () => {
    btn.disabled = false;
    btn.replaceChildren(iconNode('flask'), document.createTextNode('Lancer l\'analyse'));
  };

  // POST /jobs puis navigation vers le détail (chemin commun aux deux issues de dédup).
  async function doSubmit(html) {
    err.hidden = true;
    btn.disabled = true;
    btn.replaceChildren(document.createElement('span'), document.createTextNode('Analyse en cours…'));
    btn.firstChild.className = 'spin';
    try {
      const { job_id } = await submitJob(html);
      const m = html.match(/<title[^>]*>([^<]{0,80})/i);
      const target = (m && m[1].trim()) || (html.slice(0, 60).replace(/\s+/g, ' ').trim() + '…');
      addJob({ id: job_id, target, ts: Date.now() });
      location.hash = '#/job/' + job_id;
    } catch (ex) {
      if (!(ex instanceof Unauthorized)) showErr(String(ex.message || ex));
      resetBtn();
    }
  }

  // Modale de dédup : analyse déjà sauvegardée pour ce HTML.
  function showDedupModal(meta, html) {
    const modal = el('div.modal', {}, [
      el('h3', {}, 'Analyse déjà sauvegardée'),
      el('p.modal-msg', {}, 'Ce HTML a déjà été analysé et conservé. Tu peux la revoir sans relancer le moteur.'),
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
    again.addEventListener('click', () => { close(); doSubmit(html); });
    view.addEventListener('click', () => { close(); location.hash = '#/saved/' + meta.id; });
  }

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      const html = ta.value.trim();
      if (!html) { showErr('Ajoute du HTML ou charge un .eml avant de lancer.'); return; }
      err.hidden = true;
      btn.disabled = true;
      // dédup best-effort : en cas d'échec du lookup, on n'empêche pas l'analyse.
      let meta = null;
      try {
        const h = await sha256Hex(html);
        meta = await lookupSaved(h);
      } catch (ex) {
        if (ex instanceof Unauthorized) { return; }
        meta = null; // lookup indisponible -> on soumet directement
      }
      if (meta) { showDedupModal(meta, html); return; }
      doSubmit(html);
    },
  }, [
    err,
    el('div.oc-field', {}, [
      el('label', { for: 'html' }, 'HTML à analyser'),
      ta,
      el('div.filepick', {}, [
        el('button.btn-ghost', { type: 'button', onclick: () => fileInput.click() }, [iconNode('upload'), 'Charger un .eml']),
        fileInput,
        fileLabel,
      ]),
    ]),
    el('div.oc-field.disabled', {}, [
      el('label', { for: 'url' }, ['URL à analyser', el('span.soon-badge', {}, 'phase 3')]),
      el('input', { type: 'url', id: 'url', disabled: 'disabled', placeholder: 'https://…', 'aria-label': 'URL à analyser' }),
      el('span.hint', {}, 'analyse d\'URL live'),
    ]),
    el('div.formactions', {}, [btn]),
  ]);

  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Analyser une page'),
    el('span.sub', {}, 'Colle du HTML ou dépose un .eml, puis lance l\'analyse.'),
  ]));
  app.appendChild(el('div.card', {}, [form]));
  setTimeout(() => ta.focus(), 30);
  return null;
}
