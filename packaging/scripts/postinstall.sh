#!/bin/sh
# Never enables or starts the service. On upgrade: restart only a running unit,
# and only with a valid config; otherwise the old process keeps running.
set -e
upgrade=0
case "$1" in
    configure) [ -n "${2:-}" ] && upgrade=1 ;; # deb: configure <old-version>
    '' | *[!0-9]*) ;;
    *) [ "$1" -ge 2 ] && upgrade=1 ;; # rpm: $1 = installed versions after this one
esac
[ -d /run/systemd/system ] || exit 0
# A failed reload must not leave the package half-configured (as in postremove).
systemctl daemon-reload || echo "mail-auth-proxy: warning: systemctl daemon-reload failed" >&2

conf=/etc/mail-auth-proxy/config.toml
# Check with the service's credentials, so an unreadable key or config blocks
# the restart as it would block the start.
check_config() {
    if command -v systemd-run >/dev/null 2>&1; then
        systemd-run --wait --pipe --collect --quiet -p DynamicUser=yes -p SupplementaryGroups=mail-auth-proxy \
            /usr/bin/mail-auth-proxy --check-config "$conf"
    else
        echo "mail-auth-proxy: warning: no systemd-run, config checked as root (file permissions not checked)" >&2
        /usr/bin/mail-auth-proxy --check-config "$conf"
    fi
}

if [ "$upgrade" = 1 ] && systemctl is-active --quiet mail-auth-proxy.service; then
    if check_config; then
        systemctl try-restart mail-auth-proxy.service \
            || echo "mail-auth-proxy: warning: restart failed, see: journalctl -u mail-auth-proxy" >&2
    else
        echo "mail-auth-proxy: warning: config check failed, the running service was NOT restarted" >&2
    fi
fi
exit 0
