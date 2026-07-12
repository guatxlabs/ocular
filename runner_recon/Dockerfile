FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates xvfb xdotool scrot \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libgtk-3-0 libdbus-glib-1-2 libxt6 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
# playwright PINNÉ (pas la dernière version) : le binaire Camoufox fetché plus
# bas est un Firefox patché v135.0.1-beta.24 (protocole d'automation Juggler
# figé à cette release). `pip install playwright` sans version prend la
# dernière (1.61.0 au moment d'écrire) dont le driver Juggler a dérivé du
# protocole de ce Firefox v135 -- observé empiriquement : le lancement du
# navigateur (`BrowserType.launch`) reste bloqué indéfiniment (deadlock de
# handshake, 180s de timeout Playwright), IDENTIQUE avec
# `--security-opt seccomp=unconfined` (donc PAS un blocage seccomp : le
# process Firefox reste juste en lecture bloquante sur le pipe
# `-wait-for-browser`, en attente d'un signal du driver Node qui ne vient
# jamais). `playwright==1.49.1` (contemporain de ce build Camoufox) résout le
# handshake -- testé empiriquement : navigation + capture OK.
RUN pip install --no-cache-dir camoufox[geoip] opencv-python-headless numpy "playwright==1.49.1" pydantic
# Patch Playwright coreBundle (survie erreurs JS CF/Auth0)
RUN CB=$(python3 -c "import playwright,os;print(os.path.join(os.path.dirname(playwright.__file__),'driver/package/lib/coreBundle.js'))") \
    && sed -i 's/const pageError = { error, location: location2 };/const pageError = { error, location: location2 || { url: "", lineNumber: 0, columnNumber: 0 } };/' "$CB" || true

# --- Binaire Camoufox : DOIT vivre dans une couche IMAGE en lecture seule, pas
# dans /work (tmpfs éphémère monté au runtime). Au runtime le conteneur tourne
# --user 10001:10001, donc le binaire doit être lisible (pas forcément
# possédé) par cet UID, dans un HOME persistant de l'image (/opt/camoufox) --
# pas /root (racine par défaut du fetch, hors de portée d'un UID non-root au
# runtime) ni /work (tmpfs, recréé vide à chaque démarrage de conteneur).
#
# Tentative initiale : faire le fetch en tant qu'UID 10001 (`su runner -c
# "python3 -m camoufox fetch"`) AVANT le `USER 10001` final, avec
# HOME=/opt/camoufox déjà réglé. Ça ÉCHOUE :
#   PermissionError: [Errno 13] Permission denied:
#   '/usr/local/lib/python3.11/site-packages/camoufox/GeoLite2-City.mmdb'
# `camoufox[geoip]` télécharge la base GeoIP DANS l'arborescence pip
# (site-packages/camoufox/), pas sous $HOME -- ce chemin appartient à root
# (créé par `pip install` exécuté en root plus haut) et n'est pas accessible
# en écriture à l'UID 10001. Donc le fetch DOIT s'exécuter en root (seul le
# binaire Camoufox lui-même respecte $HOME ; le sidecar GeoIP non).
#
# Fix retenu : fetch en ROOT (écriture OK partout) avec HOME=/opt/camoufox
# déjà positionné -> le binaire Camoufox atterrit dans /opt/camoufox (couche
# image, lecture seule au runtime) et la mmdb GeoIP dans site-packages
# (également couche image). On chown ensuite /opt/camoufox vers 10001:10001
# par cohérence/traçabilité, même si la lecture seule suffirait déjà (fichiers
# world-readable par défaut après un `pip install`/fetch en root).
RUN useradd -u 10001 -m runner \
    && mkdir -p /opt/camoufox /work \
    && chown -R 10001:10001 /opt/camoufox /work
ENV HOME=/opt/camoufox
RUN python3 -m camoufox fetch && chown -R 10001:10001 /opt/camoufox

# Bug de nommage upstream camoufox==0.4.11 : `camoufox/utils.py` construit
# FONTCONFIG_PATH via get_path("fontconfig/<os>") mais le binaire fetché
# stocke ces fichiers sous "fontconfigs/<os>" (avec un s) -- constaté
# empiriquement (le dossier "fontconfig" n'existe pas, seul "fontconfigs"
# existe). Sans correctif, FONTCONFIG_PATH pointe vers un répertoire
# inexistant : fontconfig retombe sur les polices système au lieu du jeu de
# polices bundlées anti-fingerprinting de Camoufox (régression furtivité,
# silencieuse). Symlink minimal qui fait pointer "fontconfig" vers
# "fontconfigs" existant, sans toucher au code Python vendored.
RUN ln -s fontconfigs /opt/camoufox/.cache/camoufox/fontconfig

COPY engine/ ./engine/
COPY ocular_settings.py ocular_logging.py ./
COPY runner_recon/ ./runner_recon/
COPY runner_recon/vision.py ./vision.py
# vision.py résout son template Turnstile via son PROPRE __file__ (voir
# runner_recon/vision.py) ; comme vision.py est aplati à la racine /app (ligne
# ci-dessus), le template doit être copié au même niveau, pas seulement sous
# runner_recon/ -- sinon `cv2.imread` échoue silencieusement (try/except dans
# capture.py) et la détection Turnstile est un no-op silencieux.
COPY runner_recon/turnstile_checkbox.png ./turnstile_checkbox.png
COPY runner_recon/entrypoint_recon.sh /entrypoint_recon.sh
RUN chmod +x /entrypoint_recon.sh && chown -R 10001:10001 /app

# --- CORRECTIF CRITIQUE (celui qui débloque le smoke durci) ---
# `HOME=/opt/camoufox` (comme réglé pendant le build ci-dessus) casse tout au
# RUNTIME dès que `--read-only` est appliqué : constaté empiriquement en
# isolant flag par flag (`--cap-drop ALL` seul => OK ; `--read-only`+tmpfs
# seul, SANS cap-drop => bloqué quand même) que c'est spécifiquement
# `--read-only` le coupable, PAS seccomp (testé jusqu'à
# `--security-opt seccomp=unconfined` : même blocage) ni `--cap-drop ALL`
# (testé seul : navigation OK). Sous `--read-only`, `/opt/camoufox` devient
# réellement en lecture seule (couche image) ; or de nombreux composants
# (fontconfig, ICEauthority X11, dconf/GTK, ...) écrivent des fichiers de
# profil/cache sous `$HOME` par défaut -- ces écritures échouent
# silencieusement, et la combinaison finit par bloquer indéfiniment le
# handshake Playwright<->Firefox (`BrowserType.launch` timeout 180s, aucune
# erreur explicite).
#
# Fix : découpler HOME (règle où les composants tiers écrivent leurs
# dotfiles -> DOIT être inscriptible -> /work, tmpfs monté au runtime) de
# XDG_CACHE_HOME (règle où *camoufox* résout son propre binaire/fontconfig
# via `platformdirs.user_cache_dir("camoufox")`, qui consulte XDG_CACHE_HOME
# EN PRIORITÉ sur HOME -- donc rester pointé sur la couche image en lecture
# seule où `camoufox fetch` a écrit plus haut, sans avoir besoin d'écrire dedans
# au runtime, uniquement de le lire). Vérifié empiriquement : avec ce split,
# le smoke durci complet (cap-drop ALL + read-only + tmpfs + user 10001)
# navigue et émet un wrapper valide.
ENV HOME=/work XDG_CACHE_HOME=/opt/camoufox/.cache TMPDIR=/work DISPLAY=:99
USER 10001
ENTRYPOINT ["/entrypoint_recon.sh"]
