#!/bin/sh
# Package install test, run as root inside a throwaway container:
#   smoke-test.sh OLD.deb|rpm NEW.deb|rpm COMMIT systemd-sysusers|useradd
# OLD and NEW are the same build with two versions: install, check, upgrade with
# a changed config, remove (and purge on deb). Then the restart logic of the
# maintainer scripts against a stub systemctl (and systemd-run, where installed).
set -eu
old=$1 new=$2 commit=$3 branch=$4
conf=/etc/mail-auth-proxy/config.toml
fail() { echo "FAIL: $*" >&2; exit 1; }

case "$old" in
    *.deb)
        fmt=deb
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        install_pkg() { apt-get install -y -qq "$1"; }
        reinstall_pkg() { apt-get install -y -qq --reinstall "$1"; }
        remove_pkg() { apt-get purge -y -qq mail-auth-proxy; }
        verify_pkg() { dpkg -V mail-auth-proxy; }
        ;;
    *.rpm)
        fmt=rpm
        install_pkg() { dnf install -y "$1"; }
        reinstall_pkg() { dnf reinstall -y "$1"; }
        remove_pkg() { dnf remove -y -q mail-auth-proxy; }
        verify_pkg() { rpm -V mail-auth-proxy; }
        ;;
    *) fail "unknown package $old" ;;
esac

echo "== install $old"
out=$(install_pkg "$old" 2>&1) || { echo "$out"; fail "install"; }
echo "$out"
echo "$out" | grep -q "mail-auth-proxy: user via $branch" || fail "preinstall did not take the $branch branch"

mail-auth-proxy --version | grep -q "(commit $commit)" || fail "--version: $(mail-auth-proxy --version)"
getent group mail-auth-proxy >/dev/null || fail "group missing"
gid=$(getent group mail-auth-proxy | cut -d: -f3)
# name:x:uid:gid:gecos:home:shell, with the group as primary group, no login shell.
getent passwd mail-auth-proxy | grep -q -x "mail-auth-proxy:x:[0-9]*:$gid:[^:]*:/:/usr/sbin/nologin" \
    || fail "user: $(getent passwd mail-auth-proxy)"
[ "$(stat -c '%U:%G %a' $conf)" = "root:mail-auth-proxy 640" ] || fail "config: $(stat -c '%U:%G %a' $conf)"
[ "$(stat -c '%U:%G %a' /etc/mail-auth-proxy)" = "root:mail-auth-proxy 750" ] \
    || fail "config dir: $(stat -c '%U:%G %a' /etc/mail-auth-proxy)"
[ ! -e /etc/systemd/system/multi-user.target.wants/mail-auth-proxy.service ] || fail "unit enabled"
if command -v systemctl >/dev/null 2>&1; then
    state=$(systemctl is-enabled mail-auth-proxy.service 2>/dev/null || true)
    [ "$state" = disabled ] || fail "is-enabled: $state"
fi
# The example config names TLS files that do not exist here; nothing else may fail.
problems=$(mail-auth-proxy --check-config $conf 2>&1 | grep -E '^  - ' || true)
[ -n "$problems" ] || fail "--check-config found no TLS file problems"
if echo "$problems" | grep -v -E '^  - tls\.(cert|key):'; then fail "--check-config"; fi
verify_pkg || fail "$fmt verify"
# CrowdSec examples are in the package (as docs: container images may skip them on disk).
case $fmt in
    # tar members may be ./usr/…, usr/… or /usr/…: normalise to /usr/…
    deb) listing=$(dpkg-deb --fsys-tarfile "$new" | tar -t | sed -E 's|^\./|/|; s|^([^/])|/\1|') ;;
    rpm) listing=$(rpm -qlp "$new") ;;
esac
for f in crowdsec/README.md crowdsec/acquis/mail-auth-proxy.yaml \
        crowdsec/parsers/s01-parse/mail-auth-proxy-logs.yaml crowdsec/scenarios/mail-auth-proxy-bf.yaml \
        crowdsec/scenarios/mail-auth-proxy-slow-bf.yaml; do
    echo "$listing" | grep -q -x "/usr/share/doc/mail-auth-proxy/$f" \
        || { echo "$listing" | grep doc/ | head -20; fail "package lacks $f"; }
done
echo "$listing" | grep -q -x /usr/share/doc/mail-auth-proxy/THIRD-PARTY-NOTICES.html \
    || fail "package lacks THIRD-PARTY-NOTICES.html"
[ "$(echo "$listing" | grep -c '^/usr/share/doc/mail-auth-proxy/crowdsec/scenarios/.*\.yaml$')" -eq 5 ] || fail "not 5 scenarios"
echo "$listing" | grep -q '/\.tests/' && fail "hubtest cases in the package"

echo "== upgrade to $new with a changed config"
echo "# local change" >> $conf
install_pkg "$new"
grep -q '^# local change$' $conf || fail "upgrade replaced the changed config"
[ ! -e $conf.dpkg-new ] && [ ! -e $conf.rpmnew ] || fail "upgrade left a new config next to it"
mail-auth-proxy --version | grep -q "(commit $commit)" || fail "--version after upgrade"

echo "== remove"
if [ $fmt = deb ]; then
    apt-get remove -y -qq mail-auth-proxy
    [ -e $conf ] || fail "remove deleted the conffile"
    apt-get purge -y -qq mail-auth-proxy
    [ ! -e /etc/mail-auth-proxy ] || fail "purge left /etc/mail-auth-proxy"
else
    dnf remove -y -q mail-auth-proxy
    [ ! -e $conf ] || fail "remove left $conf"
    [ -e $conf.rpmsave ] || fail "remove did not keep the changed config as .rpmsave"
fi
[ ! -e /usr/bin/mail-auth-proxy ] || fail "binary still installed"
getent group mail-auth-proxy >/dev/null || fail "remove deleted the group"
getent passwd mail-auth-proxy >/dev/null || fail "remove deleted the user"

echo "== restart logic (stub systemctl, /run/systemd/system)"
if [ $fmt = deb ]; then apt-get install -y -qq openssl >/dev/null; else dnf install -y -q openssl >/dev/null; fi
calls=/tmp/systemctl.calls
mkdir -p /run/systemd/system
cat > /usr/bin/systemctl <<'STUB'
#!/bin/sh
# Test stub: logs the call, the unit is always active.
echo "systemctl $*" >> /tmp/systemctl.calls
exit 0
STUB
chmod 0755 /usr/bin/systemctl
if command -v systemd-run >/dev/null 2>&1; then
    # Test stub: runs the command with the User= and Group= it is given.
    cat > "$(command -v systemd-run)" <<'STUB'
#!/bin/sh
echo "systemd-run $*" >> /tmp/systemctl.calls
while [ $# -gt 0 ]; do
    case "$1" in
        -p) case "$2" in User=*) user=${2#User=} ;; Group=*) group=${2#Group=} ;; esac; shift 2 ;;
        -*) shift ;;
        *) break ;;
    esac
done
exec setpriv --reuid="$(id -u "$user")" --regid="$(getent group "$group" | cut -d: -f3)" --clear-groups -- "$@"
STUB
    sd_run=1
else
    sd_run=0
fi
called() { grep -q -- "$1" $calls; }

: > $calls
install_pkg "$old" >/dev/null
called "daemon-reload" || fail "fresh install: no daemon-reload"
# Only calls that name the unit count: the systemd rpm file trigger adds
# "reload-or-restart --marked", which touches marked units only.
! called "mail-auth-proxy" || fail "fresh install touched the service: $(cat $calls)"
# The example config names /path/to/{fullchain,privkey}.pem: create them.
mkdir -p /path/to
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=mail.example.org -addext subjectAltName=DNS:mail.example.org \
    -keyout /path/to/privkey.pem -out /path/to/fullchain.pem 2>/dev/null
chown root:mail-auth-proxy /path/to/privkey.pem /path/to/fullchain.pem
chmod 0640 /path/to/privkey.pem /path/to/fullchain.pem
mail-auth-proxy --check-config $conf >/dev/null || fail "test config is not valid"

: > $calls
install_pkg "$new" >/dev/null
called "try-restart mail-auth-proxy.service" || fail "upgrade, valid config: no try-restart: $(cat $calls)"
! called "disable" || fail "upgrade disabled the service"
if [ $sd_run = 1 ]; then
    called "systemd-run .*User=mail-auth-proxy -p Group=mail-auth-proxy" || fail "check did not run with the service's credentials"
    called "systemd-run .*--collect" || fail "check without --collect (a failed unit would stay loaded)"
fi

cp $conf /tmp/config.good
echo "unknown_key = 1" >> $conf
: > $calls
out=$(reinstall_pkg "$new" 2>&1) || { echo "$out"; fail "reinstall with an invalid config failed"; }
! called "try-restart" || fail "invalid config: restarted anyway"
echo "$out" | grep -q "config check failed, the running service was NOT restarted" || fail "invalid config: no warning"
cp /tmp/config.good $conf

if [ $sd_run = 1 ]; then
    # Readable for root only: the root check passes, the service check must not.
    chown root:root /path/to/privkey.pem
    chmod 0600 /path/to/privkey.pem
    mail-auth-proxy --check-config $conf >/dev/null || fail "root check should pass"
    : > $calls
    reinstall_pkg "$new" >/dev/null 2>&1
    ! called "try-restart" || fail "key unreadable for the service: restarted anyway"
fi

: > $calls
remove_pkg >/dev/null
called "disable --now mail-auth-proxy.service" || fail "remove did not disable: $(cat $calls)"
echo "OK: $old -> $new ($branch)"
