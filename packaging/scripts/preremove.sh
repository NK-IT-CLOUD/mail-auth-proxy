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
# rpm removes config.toml (%ghost) with the package: keep a changed one as
# config.toml.rpmsave, as rpm does for a changed %config file.
conf=/etc/mail-auth-proxy/config.toml
if [ "$1" = 0 ] && [ -f "$conf" ] \
    && [ "$(sha256sum < "$conf")" != "$(sha256sum < /usr/share/mail-auth-proxy/config.example.toml)" ]; then
    cp -p "$conf" "$conf.rpmsave"
fi
exit 0
