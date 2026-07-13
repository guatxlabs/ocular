#!/bin/bash
# Entrypoint conteneur session interactive (tier VNC, phase 3b) : Xvfb + x11vnc
# (clipboard COUPÉ à la source) + websockify/noVNC + session_server FastAPI.
#
# Isolation réseau : ce conteneur ne publie AUCUN port hôte (pas de `-p` au
# `docker run`, cf. tests/test_deploy_images.py + brief tâche 1/10) -- ni ici
# ni ailleurs dans ce script. session_server (8090) et noVNC/websockify (6080)
# écoutent sur 0.0.0.0 UNIQUEMENT parce qu'il n'y a rien à publier vers
# l'hôte : l'isolation vient de l'absence de `-p` combinée au réseau Docker
# interne (tâches suivantes de la phase 3b), pas d'un bind localhost ici.
set -euo pipefail

rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
Xvfb :99 -screen 0 1280x720x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99

# --noclipboard --nosetclipboard --localhost : LE point sécu de cette tâche --
# clipboard coupé à la source côté serveur VNC (get ET set), donc aucun
# transfert presse-papiers possible entre le viewer distant et la session,
# quel que soit le client noVNC utilisé côté navigateur de l'opérateur.
# -localhost : le serveur VNC brut (port 5900) n'écoute QUE sur loopback --
# seul websockify (même conteneur, localhost:5900 -> 0.0.0.0:6080) y accède ;
# aucun client VNC natif ne peut se connecter directement au 5900, seul le
# pont websocket noVNC est exposé (intra-conteneur, cf. absence de mapping de port ci-dessus).
# -noshm : le conteneur tourne sous le seccomp `RECON_SECCOMP` (broker/sessions.py),
# qui n'autorise PAS shmget/shmat (surface syscall réduite, cf. schémas
# schemas/seccomp-recon.json) — sans -noshm, x11vnc tente MIT-SHM au démarrage,
# shmget échoue avec EPERM et le process meurt silencieusement (observé : le
# conteneur reste "up" via uvicorn/websockify, mais aucune session VNC n'est
# jamais réellement servie). -noshm désactive l'extension côté x11vnc — pas de
# syscall shm nécessaire, pas d'assouplissement du profil seccomp.
x11vnc -display :99 -forever -shared -rfbport 5900 -noclipboard -nosetclipboard -localhost -noshm >/dev/null 2>&1 &

websockify --web=/usr/share/novnc 6080 localhost:5900 >/dev/null 2>&1 &

exec uvicorn runner_recon_vnc.session_server:app --host 0.0.0.0 --port 8090
