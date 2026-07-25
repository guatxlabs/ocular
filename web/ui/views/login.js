// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// login.js — saisie du jeton Bearer -> localStorage, vérifié contre le serveur
// avant de naviguer. 401 = jeton refusé ; 503 = serveur sans OCULAR_TOKEN.
import { el, iconNode } from '../core.js';
import { setToken } from '../state.js';
import { checkToken, Unauthorized } from '../api.js';

export function renderLogin(app) {
  const err = el('div.errbox', { role: 'alert', hidden: 'hidden' });
  const input = el('input', {
    type: 'password', id: 'tok', placeholder: 'jeton (Bearer)',
    autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Jeton d\'accès',
  });
  const btn = el('button.btn-primary', { type: 'submit' }, 'Se connecter');

  const showErr = (msg) => { err.textContent = msg; err.hidden = false; };

  const form = el('form.card.login-card', {
    onsubmit: async (e) => {
      e.preventDefault();
      const val = input.value.trim();
      if (!val) return;
      setToken(val);
      err.hidden = true;
      btn.disabled = true;
      try {
        await checkToken();
        location.hash = '#/jobs';
      } catch (ex) {
        if (ex instanceof Unauthorized) {
          showErr('Jeton refusé — vérifie la valeur et réessaie.');
        } else if (String(ex.message).includes('503')) {
          showErr('Le serveur n\'a pas de jeton configuré (OCULAR_TOKEN).');
        } else {
          showErr(String(ex.message || ex));
        }
        btn.disabled = false;
      }
    },
  }, [
    el('div.oc-eye', {}, [iconNode('eye', 'ic-lg')]),
    el('h2', {}, 'Connexion'),
    el('p.sub', {}, 'Colle ton jeton Ocular pour accéder au moteur.'),
    el('div.oc-field', {}, [
      el('label', { for: 'tok' }, 'Jeton d\'accès'),
      input,
    ]),
    err,
    el('div.formactions', {}, [btn]),
  ]);

  app.appendChild(el('div.login-wrap', {}, [form]));
  setTimeout(() => input.focus(), 30);
  return null;
}
