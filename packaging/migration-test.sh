#!/bin/sh
# Upgrade from a release that shipped config.toml as conffile (%config(noreplace)),
# run as root inside a throwaway container:
#   migration-test.sh RELEASE.deb|rpm NEW.deb|rpm
# With a locally changed config the upgrade must not ask (stdin is closed, as under
# unattended-upgrades), must leave the config byte for byte and put nothing next to
# it. rpm: the package keeps owning the file (%ghost). Then removal: deb remove
# keeps the config and purge removes it; rpm erase keeps a changed config as
# .rpmsave (never on upgrade or reinstall) and removes an unchanged one.
# CI versions (0.0.0-ci.N) sort below the release, so "upgrade" is a downgrade by
# version; dpkg and rpm treat the config file the same either way.
set -eu
old=$1 new=$2
conf=/etc/mail-auth-proxy/config.toml
fail() { echo "FAIL: $*" >&2; exit 1; }

case "$old" in
    *.deb)
        fmt=deb
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "$old" > /dev/null
        # Dependencies of the new package first: dpkg -i resolves none.
        apt-get install -y -qq procps > /dev/null
        upgrade() { dpkg -i "$new"; }
        ;;
    *.rpm)
        fmt=rpm
        dnf install -y -q "$old"
        upgrade() { dnf install -y -q "$new"; }
        ;;
    *) fail "unknown package $old" ;;
esac

echo "== $old installed, config changed locally"
echo "# local change" >> $conf
before=$(sha256sum $conf; stat -c '%U:%G %a' $conf)

echo "== upgrade to $new without a terminal"
upgrade < /dev/null || fail "upgrade"
[ "$(sha256sum $conf; stat -c '%U:%G %a' $conf)" = "$before" ] || fail "upgrade changed the config"
leftovers=$(ls -A /etc/mail-auth-proxy | grep -v -x config.toml || true)
[ -z "$leftovers" ] || fail "upgrade left: $leftovers"
case $fmt in
    deb) dpkg-query -W -f='${Conffiles}\n' mail-auth-proxy | grep -q " obsolete$" \
             || fail "conffile not obsolete: $(dpkg-query -W -f='${Conffiles}' mail-auth-proxy)" ;;
    rpm) rpm -q --qf '[%{FILEFLAGS:fflags} %{FILENAMES}\n]' mail-auth-proxy | grep -q -x "g $conf" \
             || fail "config.toml not owned as %ghost" ;;
esac
sum=$(sha256sum < $conf)
listing() { echo "$(ls -A /etc/mail-auth-proxy 2> /dev/null | tr '\n' ' ')"; }

case $fmt in
    deb)
        echo "== remove keeps the config, purge removes it"
        apt-get remove -y -qq mail-auth-proxy > /dev/null
        [ "$(sha256sum < $conf)" = "$sum" ] || fail "remove changed the config"
        echo "after remove: $(listing)"
        apt-get purge -y -qq mail-auth-proxy > /dev/null
        [ ! -e /etc/mail-auth-proxy ] || fail "purge left: $(listing)"
        echo "after purge: /etc/mail-auth-proxy removed"
        ;;
    rpm)
        # preremove saves only on erase ($1 = 0), never on upgrade ($1 >= 1).
        echo "== reinstall (preremove with \$1 = 1): no .rpmsave"
        dnf reinstall -y -q "$new" < /dev/null
        [ "$(sha256sum < $conf)" = "$sum" ] || fail "reinstall changed the config"
        [ ! -e $conf.rpmsave ] || fail "reinstall wrote $conf.rpmsave"
        echo "after reinstall: $(listing)"
        echo "== erase with the changed config: kept as .rpmsave"
        dnf remove -y -q mail-auth-proxy
        [ ! -e $conf ] || fail "erase left $conf"
        [ "$(sha256sum < $conf.rpmsave)" = "$sum" ] || fail "no .rpmsave with the changed config"
        echo "after erase: $(listing)"
        rm -rf /etc/mail-auth-proxy
        echo "== erase with the config as installed: nothing kept"
        dnf install -y -q "$new"
        [ "$(sha256sum < $conf)" = "$(sha256sum < /usr/share/mail-auth-proxy/config.example.toml)" ] \
            || fail "fresh install: config is not the example"
        dnf remove -y -q mail-auth-proxy
        [ ! -e /etc/mail-auth-proxy ] || fail "erase left: $(listing)"
        echo "after erase: /etc/mail-auth-proxy removed"
        ;;
esac
echo "migration test: ok ($fmt)"
