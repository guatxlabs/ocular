// SPDX-FileCopyrightText: 2026 guatx
// SPDX-License-Identifier: AGPL-3.0-or-later
// boot.js — thème appliqué AVANT le rendu (évite le flash clair/sombre).
// Externalisé depuis index.html pour respecter script-src 'self' (CSP sans 'unsafe-inline').
try { document.documentElement.setAttribute('data-theme', localStorage.getItem('ocular_theme') || 'dark'); } catch (e) {}
try { document.documentElement.setAttribute('lang', localStorage.getItem('ocular_lang') || 'fr'); } catch (e) {}
