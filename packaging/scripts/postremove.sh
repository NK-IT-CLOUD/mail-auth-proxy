#!/bin/sh
# The group stays (it may own files the admin created). On deb purge dpkg has
# removed the conffile; drop the directory if nothing else is left in it.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    rmdir --ignore-fail-on-non-empty /etc/mail-auth-proxy 2>/dev/null || true
fi
exit 0
