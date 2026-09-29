#!/bin/sh
# The user and group stay (files the admin created may belong to them). On deb
# purge remove config.toml, which postinstall created (dpkg itself removes one an
# earlier release shipped as conffile), and the directory if nothing else is left.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    rm -f /etc/mail-auth-proxy/config.toml
    rmdir --ignore-fail-on-non-empty /etc/mail-auth-proxy 2>/dev/null || true
fi
exit 0
