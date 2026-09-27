#!/bin/sh
# The conffile is owned by group mail-auth-proxy, so the group must exist before
# dpkg/rpm unpack it (otherwise it ends up root:root). The line matches
# /usr/lib/sysusers.d/mail-auth-proxy.conf, which the package installs.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
    echo 'g mail-auth-proxy -' | systemd-sysusers --replace=/usr/lib/sysusers.d/mail-auth-proxy.conf -
    echo "mail-auth-proxy: group via systemd-sysusers"
elif ! getent group mail-auth-proxy >/dev/null; then
    groupadd -r mail-auth-proxy
    echo "mail-auth-proxy: group via groupadd"
fi
exit 0
