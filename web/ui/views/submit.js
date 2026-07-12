// submit.js — textarea HTML + upload .eml + champ URL désactivé (phase 3).
// POST /jobs {profile:"analysis", html} puis navigation vers le détail du job.
import { el, iconNode } from '../core.js';
import { addJob } from '../state.js';
import { submitJob, Unauthorized } from '../api.js';

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

  const form = el('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      const html = ta.value.trim();
      if (!html) { showErr('Ajoute du HTML ou charge un .eml avant de lancer.'); return; }
      err.hidden = true;
      btn.disabled = true;
      btn.replaceChildren(document.createElement('span'), document.createTextNode('Analyse en cours…'));
      btn.firstChild.className = 'spin';
      try {
        const { job_id } = await submitJob(html);
        // libellé de cible : titre <title> si présent, sinon extrait
        const m = html.match(/<title[^>]*>([^<]{0,80})/i);
        const target = (m && m[1].trim()) || (html.slice(0, 60).replace(/\s+/g, ' ').trim() + '…');
        addJob({ id: job_id, target, ts: Date.now() });
        location.hash = '#/job/' + job_id;
      } catch (ex) {
        if (!(ex instanceof Unauthorized)) showErr(String(ex.message || ex));
        btn.disabled = false;
        btn.replaceChildren(iconNode('flask'), document.createTextNode('Lancer l\'analyse'));
      }
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
