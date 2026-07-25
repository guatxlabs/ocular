#!/bin/bash
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
Xvfb :99 -screen 0 1280x720x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99
exec python -m runner_recon.capture "$@"
