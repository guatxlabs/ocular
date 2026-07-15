// admin.js — vue privilégiée : purge des analyses sauvegardées. Les DELETE exigent
// l'en-tête X-Admin-Token EN PLUS du Bearer. Le token admin est gardé en variable
// de MÉMOIRE (module ES singleton), JAMAIS en localStorage — il disparaît au reload.
// Toutes les données affichées passent en textNode/attribut (jamais innerHTML).
import { el, iconNode, openModal, isAdmin, getGroups } from '../core.js';
import { listSaved, deleteSaved, flushSaved, Unauthorized } from '../api.js';
import { verdictPill, fmtIso } from './saved.js';

// Session en mémoire : survit aux changements de route (module importé une fois),
// perdu au rechargement de la page. NON persisté -> pas de fuite dans le stockage.
let adminToken = '';

// 403 = token admin faux ; 503 = OCULAR_ADMIN_TOKEN non configuré côté serveur.
function adminMsg(ex) {
  if (ex && ex.status === 403) return 'Token admin refusé — vérifie la valeur.';
  if (ex && ex.status === 503) return 'Administration désactivée : le serveur n\'a pas de OCULAR_ADMIN_TOKEN.';
  return String((ex && ex.message) || ex);
}

function shortHash(h) {
  const hex = String(h || '').replace(/^sha256:/, '');
  return hex.length > 14 ? hex.slice(0, 12) + '…' : hex;
}

export function renderAdmin(app) {
  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Admin'),
    el('span.sub', {}, 'Purge des analyses sauvegardées. Actions destructives.'),
  ]));

  // Deux voies d'admin (Phase 3h) : (1) X-Admin-Token saisi ci-dessous — la voie
  // par défaut, toujours disponible ; (2) groupe IdP admin (forward-auth), qui
  // autorise DELETE /saved côté backend SANS token. On affiche donc TOUJOURS le
  // formulaire de token (sinon un admin par token ne pourrait jamais se connecter),
  // et si l'appelant est déjà admin via son groupe, on signale que le token est
  // facultatif. Le backend REST reste la vraie garde (403/503 quoi qu'il arrive).
  if (isAdmin()) {
    const groups = getGroups();
    app.appendChild(el('div.card', {}, [
      el('span.muted', {}, groups.length
        ? ['Admin via ton groupe IdP — token facultatif. Groupes :', ' ', el('b', {}, groups.join(', '))]
        : 'Admin via ton identité — token facultatif.'),
    ]));
  }

  const notice = el('div.errbox', { role: 'alert', hidden: 'hidden' });

  // --- carte token admin (mémoire de session) ---
  const tokenInput = el('input', {
    type: 'password', value: adminToken, autocomplete: 'off', spellcheck: 'false',
    'aria-label': 'Token admin', placeholder: 'X-Admin-Token',
  });
  tokenInput.addEventListener('input', () => { adminToken = tokenInput.value; notice.hidden = true; });
  const tokenCard = el('div.card.admtoken', {}, [
    el('div.admlead', {}, [iconNode('shield'), 'Token administrateur']),
    el('p.muted', {}, 'Gardé en mémoire pour cette session uniquement — jamais stocké. Requis pour supprimer.'),
    tokenInput,
  ]);
  app.appendChild(tokenCard);
  app.appendChild(notice);

  const host = el('div');
  app.appendChild(host);
  host.appendChild(el('div.card', {}, [el('div.emptyview', {}, [el('p', {}, 'chargement…')])]));

  const showNotice = (msg) => { notice.textContent = msg; notice.hidden = false; };

  async function loadList() {
    let rows;
    try { rows = await listSaved(); }
    catch (ex) {
      if (ex instanceof Unauthorized) return;
      host.replaceChildren(el('div.card', {}, [el('div.errbox', {}, String(ex.message || ex))]));
      return;
    }
    if (!rows.length) {
      host.replaceChildren(el('div.card', {}, [
        el('div.emptyview', {}, [iconNode('bookmark'), el('p', {}, 'Aucune analyse sauvegardée.')]),
      ]));
      return;
    }

    // barre d'actions globales (Flush)
    const bar = el('div.admbar', {}, [
      el('span.admcount', {}, rows.length + ' sauvegarde' + (rows.length > 1 ? 's' : '')),
      el('button.btn-danger', { type: 'button', onclick: () => confirmFlush(rows.length) }, [iconNode('trash'), 'Tout purger']),
    ]);

    const list = el('div.joblist');
    rows.forEach((m) => {
      const del = el('button.picon.admdel', {
        type: 'button', title: 'Supprimer', 'aria-label': 'Supprimer cette sauvegarde',
        onclick: () => confirmDelete(m),
      }, [iconNode('trash')]);
      list.appendChild(el('div.jobrow.admrow', {}, [
        verdictPill(m.verdict),
        el('span.jobtarget', { title: m.label || '' }, m.label || '(sans étiquette)'),
        el('span.savedhash', { title: m.input_hash || '' }, shortHash(m.input_hash)),
        el('time', {}, fmtIso(m.saved_at)),
        del,
      ]));
    });
    host.replaceChildren(bar, list);
  }

  // --- confirmations (modales dédiées, contenu en textNode) ---
  function confirmDelete(m) {
    if (!requireToken()) return;
    const modal = el('div.modal.danger', {}, [
      el('h3', {}, 'Supprimer cette sauvegarde ?'),
      el('p.modal-msg', {}, 'Verdict ' + (m.verdict || 'unknown') + (m.label ? ' · ' + m.label : '') + '. Cette action est définitive.'),
    ]);
    wireConfirm(modal, 'Supprimer', async () => {
      await deleteSaved(m.id, adminToken);
      await loadList();
    });
  }

  function confirmFlush(n) {
    if (!requireToken()) return;
    const modal = el('div.modal.danger', {}, [
      el('h3', {}, 'Purger toutes les sauvegardes ?'),
      el('p.modal-msg', {}, 'Supprime définitivement les ' + n + ' analyses sauvegardées. Irréversible.'),
    ]);
    wireConfirm(modal, 'Tout purger', async () => {
      await flushSaved(adminToken);
      await loadList();
    });
  }

  function requireToken() {
    if (adminToken.trim()) return true;
    showNotice('Renseigne le token admin avant de supprimer.');
    tokenInput.focus();
    return false;
  }

  // Ajoute [Annuler] [action danger] au modal + gère l'exécution et les erreurs.
  function wireConfirm(modal, okLabel, action) {
    const err = el('div.modal-err', { hidden: 'hidden' });
    const cancel = el('button.m-cancel', { type: 'button' }, 'Annuler');
    const ok = el('button.m-ok.danger', { type: 'button' }, okLabel);
    modal.appendChild(err);
    modal.appendChild(el('div.modal-act', {}, [cancel, ok]));
    const close = openModal(modal);
    cancel.addEventListener('click', close);
    ok.addEventListener('click', async () => {
      ok.disabled = true; cancel.disabled = true; err.hidden = true;
      try { await action(); close(); }
      catch (ex) {
        if (ex instanceof Unauthorized) { close(); return; }
        ok.disabled = false; cancel.disabled = false;
        err.textContent = adminMsg(ex); err.hidden = false;
      }
    });
  }

  loadList();
  return null;
}
