// SPDX-FileCopyrightText: 2026 guatx
// SPDX-License-Identifier: AGPL-3.0-or-later
// state.js — persistance légère côté client (token, thème, langue, jobs soumis).
// L'API Ocular n'expose pas de "liste des jobs" : on garde les ids soumis en
// localStorage pour peupler la vue Jobs et poller les résultats en attente.

const TOKEN_KEY = 'ocular_token';
const THEME_KEY = 'ocular_theme';
const LANG_KEY = 'ocular_lang';
const JOBS_KEY = 'ocular_jobs';

// --- token (Bearer) ---
export const getToken = () => localStorage.getItem(TOKEN_KEY) || '';
export const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);
export const clearToken = () => localStorage.removeItem(TOKEN_KEY);

// --- langue (fr par défaut ; EN via dico FR->EN, appliqué au reload) ---
export const LANG = localStorage.getItem(LANG_KEY) || 'fr';
export const setLang = (l) => localStorage.setItem(LANG_KEY, l);

// --- thème (sombre par défaut ; reflété sur <html data-theme>) ---
export const getTheme = () => localStorage.getItem(THEME_KEY) || 'dark';
export const setTheme = (t) => localStorage.setItem(THEME_KEY, t);

// --- jobs soumis (id + cible + horodatage) ---
export function getJobs() {
  try { return JSON.parse(localStorage.getItem(JOBS_KEY)) || []; }
  catch { return []; }
}
export function addJob(job) {
  const list = getJobs().filter((j) => j.id !== job.id);
  list.unshift(job);
  localStorage.setItem(JOBS_KEY, JSON.stringify(list.slice(0, 100)));
}
// Retire d'un coup tous les jobs dont l'id est dans `ids` (purge des terminés).
export function removeJobs(ids) {
  const drop = new Set(ids);
  localStorage.setItem(JOBS_KEY, JSON.stringify(getJobs().filter((j) => !drop.has(j.id))));
}
