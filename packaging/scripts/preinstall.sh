#!/bin/sh
# The service runs as the system user mail-auth-proxy and the conffile is owned by
# its group, so both must exist before dpkg/rpm unpack it (otherwise it ends up
# root:root). The line matches /usr/lib/sysusers.d/mail-auth-proxy.conf, which the
# package installs. An existing group of that name is reused as the primary group.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
    echo 'u mail-auth-proxy - "mail-auth-proxy"' | systemd-sysusers --replace=/usr/lib/sysusers.d/mail-auth-proxy.conf -
    echo "mail-auth-proxy: user via systemd-sysusers"
else
    # The group is needed for the conffile even when the user already exists.
    getent group mail-auth-proxy >/dev/null || groupadd --system mail-auth-proxy
    if ! getent passwd mail-auth-proxy >/dev/null; then
        useradd --system --gid mail-auth-proxy --no-create-home --home-dir / \
            --shell /usr/sbin/nologin --comment mail-auth-proxy mail-auth-proxy
        echo "mail-auth-proxy: user via useradd"
    fi
fi
exit 0
