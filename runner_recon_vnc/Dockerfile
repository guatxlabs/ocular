# Image conteneur session interactif (phase 3b). DÉRIVE de l'image recon
# (ocular-runner-recon) qui a déjà : Camoufox fetché dans /opt/camoufox,
# playwright==1.49.1, fix fontconfig, HOME=/work + XDG_CACHE_HOME=/opt/camoufox/.cache,
# engine/, runner_recon/, vision.py, user 10001. On n'ajoute QUE la couche VNC
# (x11vnc clipboard-off + websockify + noVNC + session_server) — DRY, aucune
# duplication du setup Camoufox, build en ~1 min (couches recon réutilisées).
#
# Prérequis : `docker build -f runner_recon/Dockerfile -t ocular-runner-recon:latest .`
# doit avoir tourné avant (le Makefile build-runner le garantit).
FROM ocular-runner-recon:latest

USER root

# Tier interactif : serveur VNC + pont websocket + client noVNC. `curl` pour le
# smoke (health/noVNC depuis l'intérieur). Le clipboard est coupé à la source
# côté x11vnc dans runner_recon_vnc/entrypoint_vnc.sh (-noclipboard -nosetclipboard).
#
# matchbox-window-manager : window manager minimal (kiosk) qui met la fenêtre du
# navigateur en PLEIN ÉCRAN sur l'Xvfb. Sans WM, Firefox/Camoufox s'ouvrait à sa
# taille par défaut (souvent > 1280x720), ancré en haut-gauche -> bas+droite hors
# framebuffer = croppés dans noVNC (footer/bord droit invisibles). matchbox force
# la fenêtre à couvrir exactement l'écran -> plus de crop.
RUN apt-get update && apt-get install -y --no-install-recommends \
    x11vnc websockify novnc curl matchbox-window-manager \
    && rm -rf /var/lib/apt/lists/*

# fastapi/uvicorn pour le session_server (l'image recon n'a que playwright/camoufox).
RUN pip install --no-cache-dir fastapi "uvicorn[standard]"

COPY runner_recon_vnc/ ./runner_recon_vnc/
COPY runner_recon_vnc/entrypoint_vnc.sh /entrypoint_vnc.sh
RUN chmod +x /entrypoint_vnc.sh && chown -R 10001:10001 /app/runner_recon_vnc

# EXPOSE purement documentaire : AUCUN `-p`/publication de port au `docker run`
# (cf. entrypoint + build_session_args) ; l'isolation vient de l'absence de
# mapping + du réseau docker interne `ocular-sessions` (tâches suivantes).
EXPOSE 6080 8090

USER 10001
ENTRYPOINT ["/entrypoint_vnc.sh"]
