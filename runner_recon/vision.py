"""
vision.py — port de guatx-ia-vision dans runner_recon (Ocular).

Élagué au strict nécessaire pour capture.py (cf. audit phase3a) : seules les
briques réellement utilisées par Ocular sont conservées, reprises de
guatx-ia-vision (detector.py / human.py) :
  - detect(frame_bgr, ...)                 : pixels -> (x, y) | None (color/edges/template)
  - png_to_bgr(png_bytes)                  : octets PNG -> ndarray BGR
  - async human_click_xdotool(sx, sy, ...) : clic OS X11 réel (xdotool), passe les
                                              Turnstile interactifs (isTrusted=true)

La détection reste SPÉCIFIQUE à la cible (couleur ou forme) — c'est le pipeline
qui est générique. Voir le README de guatx-ia-vision (§ généralisation).
"""
import os
import math
import random
import asyncio
import subprocess

_DISP = {"DISPLAY": os.environ.get("DISPLAY", ":99"), "PATH": "/usr/bin:/bin"}


# ───────────────────────── detection (ex detector.py) ─────────────────────────
# numpy (comme cv2 plus bas) est importé paresseusement, dans chaque fonction qui
# en a besoin, pas au niveau module : `numpy`/`opencv-python-headless` ne sont
# installés que dans l'image runner_recon (cf. Dockerfile), pas dans le venv de
# dev/test -- ça garde les helpers purs (`image_to_screen`, le clic xdotool) et
# `capture.py` (qui importe `vision` seulement à l'intérieur de ses fonctions
# async, jamais au niveau module) importables/testables sans ces deps lourdes.
def _detect_color(frame_bgr, target_rgb, tolerance, min_pixels):
    import numpy as np
    rgb = frame_bgr[:, :, 2::-1].astype(np.int32)          # BGR -> RGB
    tr, tg, tb = target_rgb
    d2 = (rgb[:, :, 0] - tr) ** 2 + (rgb[:, :, 1] - tg) ** 2 + (rgb[:, :, 2] - tb) ** 2
    ys, xs = np.where(d2 < tolerance * tolerance)
    if xs.size < min_pixels:
        return None
    return int(np.median(xs)), int(np.median(ys))


def _detect_edges(frame_bgr, edge_lo, edge_hi, min_area, max_area, aspect):
    import cv2
    import numpy as np
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
    import numpy as np
    arr = np.frombuffer(png_bytes, dtype=np.uint8)
    return cv2.imdecode(arr, cv2.IMREAD_COLOR)   # BGR, 3 canaux


# ───────────────── mapping coords image (viewport) -> écran (Xvfb) ─────────────────
def image_to_screen(det, moz_x, moz_y, dpr):
    """(x, y) px IMAGE (viewport du screenshot Playwright, ce que renvoie
    `detect()`) -> (x, y) px ÉCRAN Xvfb (ce qu'attend `human_click_xdotool`).

    Cause racine n°1 du Turnstile qui rate sa cible (cf. plan phase3d-2b) :
    `detect()` travaille sur le screenshot, dont l'origine (0,0) est le coin
    haut-gauche du VIEWPORT de la page -- pas de l'écran. `human_click_xdotool`
    clique en coordonnées ÉCRAN absolues (xdotool/X11). Il manque l'offset du
    chrome du navigateur (barre d'URL/onglets Firefox) + la position de la
    fenêtre, exposé par `window.mozInnerScreenX/Y` (API Gecko, px CSS) --
    sans lui, le clic tombe à côté de la case, décalé de la hauteur du chrome.

    `dpr` = `window.devicePixelRatio` : le screenshot est capturé en px
    *device* (peut différer des px *CSS* si dpr != 1), alors que
    `mozInnerScreenX/Y` est en px CSS -- diviser par `dpr` avant d'ajouter
    l'offset remet les deux quantités dans la même unité. `dpr` falsy (0 ou
    None -- valeur JS foireuse ou absente) retombe sur 1 (jamais de division
    par zéro).

    Fonction PURE (aucune dépendance vision/navigateur) : testée isolément
    dans tests/test_vision_coords.py."""
    d = dpr or 1
    return (int(round(moz_x + det[0] / d)), int(round(moz_y + det[1] / d)))


# ───────── clic OS xdotool (X11 réel) — passe les Turnstile interactifs ─────────
def _ease(t):
    return 2 * t * t if t < 0.5 else 1 - (-2 * t + 2) ** 2 / 2


def _bezier(p, c1, c2, q, t):
    mt = 1 - t
    a, b, c, d = mt**3, 3 * mt**2 * t, 3 * mt * t**2, t**3
    return (a * p[0] + b * c1[0] + c * c2[0] + d * q[0],
            a * p[1] + b * c1[1] + c * c2[1] + d * q[1])


# Différence clé vs page.mouse : événement X11 réel au niveau OS, non injecté par
# le protocole d'automation → indistinguable d'un humain, franchit les iframes
# cross-origin (case Turnstile). C'est CE clic qui passe le challenge, pas page.mouse.
def _xdo(*cmd):
    subprocess.run(["xdotool", *map(str, cmd)], env=_DISP, check=False)


def _xdo_pos():
    out = subprocess.run(["xdotool", "getmouselocation", "--shell"],
                         env=_DISP, capture_output=True, text=True).stdout
    d = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return int(d.get("X", 0)), int(d.get("Y", 0))


async def human_click_xdotool(sx, sy, aim_min=0.6, aim_max=1.2, jitter=True, click=True):
    """Va jusqu'à (sx, sy) en ÉCRAN (coords écran Xvfb) en trajectoire humaine via
    xdotool (clic X11 réel), pause de visée, puis clique. C'est la méthode fidèle
    à guatx-ia-vision — celle qui passe les Turnstile interactifs."""
    x0, y0 = _xdo_pos()
    sx += random.randint(-3, 3)
    sy += random.randint(-3, 3)
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
                x += random.uniform(-1, 1)
                y += random.uniform(-1, 1)
            _xdo("mousemove", int(x), int(y))
            await asyncio.sleep(dur / steps)
    await asyncio.sleep(round(random.uniform(aim_min, aim_max), 2))   # fixation
    if click:
        _xdo("click", "1")
    return int(sx), int(sy)
