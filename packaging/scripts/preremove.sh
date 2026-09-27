#!/bin/sh
# Only on a real removal (deb remove, rpm $1 = 0): stop and disable, so no
# wants-symlink is left behind. Upgrades leave the service alone.
set -e
case "$1" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now mail-auth-proxy.service || true
        fi
        ;;
esac
exit 0
