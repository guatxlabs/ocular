"""
vision.py — port de guatx-ia-vision dans browser-automation.

Même idée (perception pixels -> (x,y) -> clic humain) mais branchée sur les
primitives PLAYWRIGHT au lieu de mss + xdotool :
  - capture : page.screenshot()  (viewport exact, pas de chrome navigateur)
  - clic    : page.mouse         (events isTrusted=true, dans le contexte page)

Deux briques, reprises de guatx-ia-vision (detector.py / human.py) :
  - detect(frame_bgr, ...)            : pixels -> (x, y) | None   (color | edges)
  - async human_move_click(page,...)  : trajectoire Bézier humaine + clic trusted

La détection reste SPÉCIFIQUE à la cible (couleur ou forme) — c'est le pipeline
qui est générique. Voir le README de guatx-ia-vision (§ généralisation).
"""
import os
import math
import random
import asyncio
import subprocess
import numpy as np

_DISP = {"DISPLAY": os.environ.get("DISPLAY", ":99"), "PATH": "/usr/bin:/bin"}


# ───────────────────────── detection (ex detector.py) ─────────────────────────
def _detect_color(frame_bgr, target_rgb, tolerance, min_pixels):
    rgb = frame_bgr[:, :, 2::-1].astype(np.int32)          # BGR -> RGB
    tr, tg, tb = target_rgb
    d2 = (rgb[:, :, 0] - tr) ** 2 + (rgb[:, :, 1] - tg) ** 2 + (rgb[:, :, 2] - tb) ** 2
    ys, xs = np.where(d2 < tolerance * tolerance)
    if xs.size < min_pixels:
        return None
    return int(np.median(xs)), int(np.median(ys))


def _detect_edges(frame_bgr, edge_lo, edge_hi, min_area, max_area, aspect):
    import cv2
    bgr = np.ascontiguousarray(frame_bgr[:, :, :3])
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (3, 3), 0)
    edges = cv2.Canny(gray, edge_lo, edge_hi)
    edges = cv2.dilate(edges, np.ones((3, 3), np.uint8), iterations=1)
    contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    best, best_area = None, 0
    for c in contours:
        area = cv2.contourArea(c)
        if area < min_area or area > max_area:
            continue
        approx = cv2.approxPolyDP(c, 0.04 * cv2.arcLength(c, True), True)
        if len(approx) != 4 or not cv2.isContourConvex(approx):
            continue
        x, y, w, h = cv2.boundingRect(approx)
        if abs(w / float(h) - 1.0) > aspect:
            continue
        if area > best_area:
            M = cv2.moments(approx)
            if M["m00"]:
                best_area = area
                best = (int(M["m10"] / M["m00"]), int(M["m01"] / M["m00"]))
    return best


# Template Turnstile bundlé (case "Verify you are human" vide), chargé une fois.
_TEMPLATE_PATH = os.environ.get(
    "TURNSTILE_TEMPLATE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "turnstile_checkbox.png"))
_turnstile_tpl = None


def _load_turnstile_template():
    global _turnstile_tpl
    if _turnstile_tpl is None:
        import cv2
        _turnstile_tpl = cv2.imread(_TEMPLATE_PATH)   # None si absent
    return _turnstile_tpl


def _detect_template(frame_bgr, template_bgr, threshold,
                     scales=(0.6, 0.75, 0.9, 1.0, 1.15, 1.35, 1.6)):
    """Template matching MULTI-ÉCHELLE (cv2.matchTemplate n'est pas scale-invariant —
    la case Turnstile varie de taille selon le viewport/DSF). Retourne le centre du
    meilleur match au-dessus du seuil, ou None."""
    import cv2
    best, best_val = None, float(threshold)
    fh, fw = frame_bgr.shape[:2]
    for s in scales:
        t = template_bgr if s == 1.0 else cv2.resize(
            template_bgr, None, fx=s, fy=s,
            interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_LINEAR)
        th, tw = t.shape[:2]
        if th >= fh or tw >= fw or th < 6 or tw < 6:
            continue
        res = cv2.matchTemplate(frame_bgr, t, cv2.TM_CCOEFF_NORMED)
        _, mv, _, ml = cv2.minMaxLoc(res)
        if mv > best_val:
            best_val = mv
            best = (int(ml[0] + tw / 2), int(ml[1] + th / 2))
    return best


def detect(frame_bgr, strategy="color", target_rgb=(34, 238, 85), tolerance=70,
           min_pixels=25, edge_lo=20, edge_hi=70, min_area=600, max_area=40000,
           aspect=0.30, template_bgr=None, threshold=0.75):
    """pixels (ndarray BGR) -> (x, y) en px IMAGE, ou None."""
    if strategy == "edges":
        return _detect_edges(frame_bgr, edge_lo, edge_hi, min_area, max_area, aspect)
    if strategy == "turnstile":                       # template Turnstile bundlé, multi-échelle
        tpl = _load_turnstile_template()
        return _detect_template(frame_bgr, tpl, threshold) if tpl is not None else None
    if strategy == "template" and template_bgr is not None:
        return _detect_template(frame_bgr, template_bgr, threshold)
    return _detect_color(frame_bgr, target_rgb, tolerance, min_pixels)


def png_to_bgr(png_bytes):
    """Décode des octets PNG (page.screenshot) -> ndarray BGR (comme mss/cv2)."""
    import cv2
    arr = np.frombuffer(png_bytes, dtype=np.uint8)
    return cv2.imdecode(arr, cv2.IMREAD_COLOR)   # BGR, 3 canaux


# ─────────────────── clic humain via Playwright (ex human.py) ──────────────────
def _ease(t):
    return 2 * t * t if t < 0.5 else 1 - (-2 * t + 2) ** 2 / 2


def _bezier(p, c1, c2, q, t):
    mt = 1 - t
    a, b, c, d = mt**3, 3 * mt**2 * t, 3 * mt * t**2, t**3
    return (a * p[0] + b * c1[0] + c * c2[0] + d * q[0],
            a * p[1] + b * c1[1] + c * c2[1] + d * q[1])


async def human_move_click(page, tx, ty, x0=None, y0=None, aim_min=0.4, aim_max=1.1,
                           click=True, jitter=True):
    """Va jusqu'à (tx, ty) en trajectoire humaine (Bézier + ease + jitter) via
    page.mouse (isTrusted), pause de visée, puis clique. Coords en px CSS viewport.

    aim_min/aim_max plus courts que guatx-ia-vision (0.4-1.1s vs 2-3s) : ici on
    automatise un flux, pas un aim-trainer. Mets-les plus longs si besoin de
    réalisme renforcé.
    """
    if x0 is None or y0 is None:
        x0, y0 = 0, 0                                     # Playwright démarre coin HG
    tx += random.randint(-4, 4)                           # impact décentré
    ty += random.randint(-4, 4)
    dist = math.hypot(tx - x0, ty - y0)

    if dist < 3:
        await page.mouse.move(tx, ty)
    else:
        ang = math.atan2(ty - y0, tx - x0) + math.pi / 2
        ctrl = []
        for f in (0.33, 0.66):
            off = random.uniform(-0.18, 0.18) * dist
            ctrl.append((x0 + (tx - x0) * f + math.cos(ang) * off,
                         y0 + (ty - y0) * f + math.sin(ang) * off))
        # peu de pas : camoufox humanise DÉJÀ chaque mouse.move (humanize=0.3s) —
        # 45 pas × 0.3s ≈ 13s. On garde la courbe Bézier mais ~8-14 pas suffisent.
        steps = max(6, min(14, int(dist / 60)))
        await asyncio.sleep(random.uniform(0.05, 0.15))   # temps de réaction
        for i in range(1, steps + 1):
            x, y = _bezier((x0, y0), ctrl[0], ctrl[1], (tx, ty), _ease(i / steps))
            if jitter:
                x += random.uniform(-1.0, 1.0)
                y += random.uniform(-1.0, 1.0)
            await page.mouse.move(x, y)                   # camoufox ajoute le micro-jitter temporel

    await asyncio.sleep(round(random.uniform(aim_min, aim_max), 2))  # visée
    if click:
        await page.mouse.click(tx, ty)
    return tx, ty


# ───────── clic OS xdotool (X11 réel) — passe les Turnstile interactifs ─────────
# Différence clé vs page.mouse : événement X11 réel au niveau OS, non injecté par
# le protocole d'automation → indistinguable d'un humain, franchit les iframes
# cross-origin (case Turnstile). C'est CE clic qui passe le challenge, pas page.mouse.
def _xdo(*cmd):
    subprocess.run(["xdotool", *map(str, cmd)], env=_DISP, check=False)


def _xdo_pos():
    out = subprocess.run(["xdotool", "getmouselocation", "--shell"],
                         env=_DISP, capture_output=True, text=True).stdout
    d = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    return int(d.get("X", 0)), int(d.get("Y", 0))


async def human_click_xdotool(sx, sy, aim_min=0.6, aim_max=1.2, jitter=True, click=True):
    """Va jusqu'à (sx, sy) en ÉCRAN (coords écran Xvfb) en trajectoire humaine via
    xdotool (clic X11 réel), pause de visée, puis clique. C'est la méthode fidèle
    à guatx-ia-vision — celle qui passe les Turnstile interactifs."""
    x0, y0 = _xdo_pos()
    sx += random.randint(-3, 3); sy += random.randint(-3, 3)
    dist = math.hypot(sx - x0, sy - y0)
    if dist < 3:
        _xdo("mousemove", int(sx), int(sy))
    else:
        ang = math.atan2(sy - y0, sx - x0) + math.pi / 2
        ctrl = []
        for f in (0.33, 0.66):
            off = random.uniform(-0.18, 0.18) * dist
            ctrl.append((x0 + (sx - x0) * f + math.cos(ang) * off,
                         y0 + (sy - y0) * f + math.sin(ang) * off))
        steps = max(15, min(40, int(dist / 12)))
        dur = random.uniform(0.3, 0.6) + dist / 2500
        await asyncio.sleep(random.uniform(0.2, 0.45))    # réaction
        for i in range(1, steps + 1):
            x, y = _bezier((x0, y0), ctrl[0], ctrl[1], (sx, sy), _ease(i / steps))
            if jitter:
                x += random.uniform(-1, 1); y += random.uniform(-1, 1)
            _xdo("mousemove", int(x), int(y))
            await asyncio.sleep(dur / steps)
    await asyncio.sleep(round(random.uniform(aim_min, aim_max), 2))   # fixation
    if click:
        _xdo("click", "1")
    return int(sx), int(sy)


async def fast_click_xdotool(x, y):
    """Clic OS unique RAPIDE (~40-60ms): mousemove --sync -> click. Pour le coup
    d'échecs fiable en 2 temps piloté par le bot (clic source = sélection, attendre
    le hint de coup légal, clic destination). Événement X11 réel (isTrusted=true)."""
    sx, sy = int(x) + random.randint(-2, 2), int(y) + random.randint(-2, 2)
    _xdo("mousemove", "--sync", sx, sy, "click", "1")
    await asyncio.sleep(random.uniform(0.02, 0.04))
    return sx, sy


async def fast_drag_xdotool(x0, y0, x1, y1):
    """Coup OS RAPIDE & FIABLE par CLICK-CLICK (~350-420ms) en UN SEUL appel xdotool
    chaîné: clic case SOURCE (sélectionne la pièce + affiche les coups légaux) ->
    PAUSE 0.30s (le board doit enregistrer la sélection AVANT le 2e clic) -> clic case
    DESTINATION (joue). Diagnostic confirmé: un drag rapide se fait interpréter comme
    un simple clic de SÉLECTION (la pièce se surligne mais ne bouge pas) ; le
    click-click avec un vrai délai est la méthode fiable (c'est l'interaction standard
    du site). Un seul spawn subprocess. Événements X11 réels (isTrusted=true).
    NB: pour les échecs, le 'temps de réflexion' est la PAUSE avant cet appel."""
    sx, sy = int(x0) + random.randint(-2, 2), int(y0) + random.randint(-2, 2)
    ex, ey = int(x1) + random.randint(-2, 2), int(y1) + random.randint(-2, 2)
    _xdo("mousemove", "--sync", sx, sy, "click", "1",
         "sleep", "0.30",
         "mousemove", "--sync", ex, ey, "click", "1")
    await asyncio.sleep(random.uniform(0.03, 0.06))
    return ex, ey


async def human_drag_xdotool(x0, y0, x1, y1, jitter=True, fast=False):
    """Drag OS humain (X11) de (x0,y0) à (x1,y1) en coords ÉCRAN : mousedown →
    trajectoire Bézier → mouseup. Pour les sliders/puzzle (DataDome, geetest) :
    vision détecte le handle + le trou, on drague le handle dans le trou.

    fast=True : flick rapide (~0.1-0.25s total) pour les coups instantanés /
    premoves d'un bot d'échecs — garde une vraie trajectoire (events X11 réels)
    mais sans les pauses d'approche/visée. fast=False : drag posé (~1s)."""
    _xdo("mousemove", int(x0), int(y0))
    await asyncio.sleep(random.uniform(0.02, 0.05) if fast else random.uniform(0.12, 0.25))
    _xdo("mousedown", "1")
    await asyncio.sleep(random.uniform(0.015, 0.04) if fast else random.uniform(0.08, 0.16))
    dist = math.hypot(x1 - x0, y1 - y0)
    ang = math.atan2(y1 - y0, x1 - x0) + math.pi / 2
    curve = 0.06 if fast else 0.12
    ctrl = []
    for f in (0.33, 0.66):
        off = random.uniform(-curve, curve) * dist        # courbe plus douce qu'un clic
        ctrl.append((x0 + (x1 - x0) * f + math.cos(ang) * off,
                     y0 + (y1 - y0) * f + math.sin(ang) * off))
    if fast:
        steps = max(4, min(10, int(dist / 35)))
        dur = random.uniform(0.05, 0.12)
    else:
        steps = max(20, min(60, int(dist / 8)))           # plus de pas = drag fluide
        dur = random.uniform(0.5, 1.0) + dist / 1800
    for i in range(1, steps + 1):
        x, y = _bezier((x0, y0), ctrl[0], ctrl[1], (x1, y1), _ease(i / steps))
        if jitter:
            x += random.uniform(-0.8, 0.8); y += random.uniform(-0.8, 0.8)
        _xdo("mousemove", int(x), int(y))
        await asyncio.sleep(dur / steps)
    await asyncio.sleep(random.uniform(0.01, 0.03) if fast else random.uniform(0.06, 0.14))
    _xdo("mouseup", "1")
    return int(x1), int(y1)
