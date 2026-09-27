#!/bin/sh
# The user and group stay (files the admin created may belong to them). On deb
# purge dpkg has removed the conffile; drop the directory if nothing else is left.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    rmdir --ignore-fail-on-non-empty /etc/mail-auth-proxy 2>/dev/null || true
fi
exit 0
