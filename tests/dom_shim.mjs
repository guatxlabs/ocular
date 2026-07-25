// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// dom_shim.mjs — DOM minimal permettant de MONTER les vraies vues d'Ocular
// (web/ui/views/*.js, via core.js) hors navigateur, et de lire ce que
// l'analyste a sous les yeux.
//
// Pourquoi : les défauts qui coûtent le plus cher dans un outil d'analyse ne
// sont pas dans le code source, ils sont à l'écran — un panneau qui s'arrête
// sans message, une valeur coupée affichée avec l'apparence d'une valeur
// entière, un compteur de troncature que personne ne rend. Aucun `grep` ne les
// voit ; un DOM, oui.
//
// Ce shim implémente exactement ce dont le shell et les vues se servent, rien
// de plus. Il n'imite pas un navigateur : il rend le texte rendu observable.
//
// USAGE : `installDom()` PUIS `await import(UI + 'core.js')` — l'import doit
// être dynamique, les `import` statiques étant évalués avant le corps du module.

class TextNode {
  constructor(t) { this.nodeValue = String(t); this.nodeType = 3; this.childNodes = []; }
  get textContent() { return this.nodeValue; }
  set textContent(v) { this.nodeValue = String(v); }
}

class Elem {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.childNodes = [];
    this.attrs = new Map();
    this.listeners = new Map();
    this.nodeType = 1;
    this.style = {};
    this.value = '';
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    const classes = new Set();
    this.classList = {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)),
      contains: (c) => classes.has(c),
    };
  }

  setAttribute(k, v) {
    this.attrs.set(k, String(v));
    if (k === 'id') this.id = String(v);
    if (k === 'hidden') this.hidden = true;
    if (k === 'class') String(v).split(/\s+/).forEach((c) => c && this.classList.add(c));
  }

  getAttribute(k) { return this.attrs.has(k) ? this.attrs.get(k) : null; }
  removeAttribute(k) { this.attrs.delete(k); }
  appendChild(n) { this.childNodes.push(n); n.parentNode = this; return n; }
  insertBefore(n, ref) {
    const i = ref ? this.childNodes.indexOf(ref) : 0;
    this.childNodes.splice(i < 0 ? 0 : i, 0, n);
    n.parentNode = this;
    return n;
  }

  removeChild(n) { const i = this.childNodes.indexOf(n); if (i >= 0) this.childNodes.splice(i, 1); return n; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  replaceChildren(...kids) {
    this.childNodes = [];
    kids.forEach((k) => { if (k != null) this.appendChild(k); });
  }

  get firstChild() { return this.childNodes[0] || null; }
  addEventListener(t, fn) {
    if (!this.listeners.has(t)) this.listeners.set(t, []);
    this.listeners.get(t).push(fn);
  }

  removeEventListener(t, fn) {
    const l = this.listeners.get(t) || [];
    const i = l.indexOf(fn);
    if (i >= 0) l.splice(i, 1);
  }

  dispatch(t, ev = {}) {
    (this.listeners.get(t) || []).forEach((fn) =>
      fn(Object.assign({ preventDefault() {}, target: this, currentTarget: this }, ev)));
  }

  click() { this.dispatch('click'); }
  focus() {}
  get textContent() { return this.childNodes.map((c) => c.textContent).join(''); }
  set textContent(v) { this.childNodes = [new TextNode(v)]; }
  _all(out) {
    for (const c of this.childNodes) if (c.nodeType === 1) { out.push(c); c._all(out); }
    return out;
  }

  /** Sélecteurs supportés : `tag`, `.classe`, `tag.classe` — le nécessaire. */
  querySelectorAll(sel) {
    const m = String(sel).match(/^([a-z0-9]+)?(?:\.([\w-]+))?$/i);
    if (!m) return [];
    return this._all([]).filter((e) => (!m[1] || e.tagName === m[1].toUpperCase())
      && (!m[2] || e.classList.contains(m[2])));
  }

  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Attend qu'une condition soit vraie, avec une échéance : aucun test ne dépend
 *  d'une durée choisie au hasard. */
export async function until(label, cond, budgetMs = 5000) {
  const t0 = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - t0 > budgetMs) throw new Error(`condition jamais atteinte : ${label}`);
    await sleep(5);
  }
}

/**
 * Installe le DOM minimal + les globales du navigateur.
 *  - `hash`   : route montée par le routeur de core.js.
 *  - `routes` : fonction (url, opts) -> réponse simulée, ou `undefined` pour 404.
 * Rend `{ appNode, screen }` — `screen()` est le TEXTE à l'écran.
 */
export function installDom({ hash = '#/jobs', token = 'tok', routes = () => undefined } = {}) {
  const doc = new Elem('document');
  doc.createElement = (t) => new Elem(t);
  doc.createElementNS = (_ns, t) => new Elem(t);
  doc.createTextNode = (t) => new TextNode(t);
  // Un fragment se comporte ici comme un nœud ordinaire : ce qu'on lit est le
  // texte de l'arbre, pas la sémantique d'insertion du navigateur.
  doc.createDocumentFragment = () => new Elem('fragment');
  doc.documentElement = new Elem('html');
  doc.body = new Elem('body');
  const appNode = new Elem('div');
  appNode.setAttribute('id', 'app');
  doc.body.appendChild(appNode);
  doc.querySelector = (sel) => (sel === '#app' ? appNode : null);
  doc.querySelectorAll = () => [];
  doc.hidden = false;
  doc.addEventListener = Elem.prototype.addEventListener.bind(doc);
  doc.removeEventListener = Elem.prototype.removeEventListener.bind(doc);

  const store = new Map(token ? [['ocular_token', token]] : []);
  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  globalThis.document = doc;
  Object.defineProperty(globalThis, 'navigator', { value: {}, configurable: true });
  globalThis.location = { hash, protocol: 'http:', host: 'ocular.test', reload() {} };
  globalThis.window = globalThis;
  globalThis.window.addEventListener = () => {};
  globalThis.window.removeEventListener = () => {};
  globalThis.scrollTo = () => {};
  const realTimeout = globalThis.setTimeout;
  globalThis.requestAnimationFrame = (fn) => realTimeout(fn, 0);
  // Horloge ACCÉLÉRÉE : tout délai des vues (poll de 2 s, sondage de
  // disponibilité, recul) est ramené à quelques millisecondes. Ces harnais
  // mesurent l'ENCHAÎNEMENT ; les durées sont mesurées avec une horloge
  // injectée par tests/poll_test.mjs.
  globalThis.setTimeout = (fn, ms) => realTimeout(fn, Math.min(Number(ms) || 0, 3));

  globalThis.fetch = async (url, opts = {}) => {
    const res = routes(url, opts);
    if (res) return res;
    return reply({ detail: 'non stubé ' + url }, 404);
  };

  return { appNode, screen: () => appNode.textContent };
}

/** Réponse simulée à la forme de celles que `api.js` consomme. */
export function reply(obj, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
  };
}
