#!/bin/sh
# Start test of the packaged unit under a real systemd (PID 1), in a throwaway
# container (packaging/ci-systemd-test.sh):
#   systemd-test.sh setup   before boot: enable package-test.service
#   systemd-test.sh run     from package-test.service after boot
# `run` installs /pkg/old.deb (a release that shipped config.toml as conffile;
# 0.1.1 created only the group mail-auth-proxy), changes the config, upgrades to
# /pkg/new.deb, starts the service with a local JWKS and a self-signed
# certificate (the backends are never contacted), reloads, upgrades and stops it.
# It writes its output to /out/log; systemd then exits with its status
# (SuccessAction= and FailureAction=). The caller also requires the final OK line.
set -eu
old=/pkg/old.deb
pkg=/pkg/new.deb
conf=/etc/mail-auth-proxy/config.toml
unit=mail-auth-proxy.service

if [ "${1:-}" = setup ]; then
    cat > /etc/systemd/system/package-test.service <<'EOF'
[Unit]
Description=mail-auth-proxy package test under systemd
After=basic.target
# The container always ends: systemd exits with the test's status, or when the
# start job (boot and test) is not done in time.
JobTimeoutSec=300
JobTimeoutAction=exit-force
SuccessAction=exit-force
FailureAction=exit-force

[Service]
Type=oneshot
ExecStart=/bin/sh /pkg/systemd-test.sh run
EOF
    mkdir -p /etc/systemd/system/multi-user.target.wants
    ln -sf ../package-test.service /etc/systemd/system/multi-user.target.wants/package-test.service
    exit 0
fi
[ "${1:-}" = run ] || { echo "usage: systemd-test.sh setup|run" >&2; exit 2; }

state() { systemctl show -p ActiveState,SubState,Result,ExecMainCode,ExecMainStatus $unit | tr '\n' ' '; }
fail() {
    echo "FAIL: $*"
    echo "state: $(state)"
    systemctl status --no-pager $unit || true
    journalctl --no-pager -n 60 -u $unit -u test-jwks.service || true
    exit 1
}
main_pid() { systemctl show -P MainPID $unit; }

test_run() {
    echo "== systemd $(systemctl --version | head -n 1), $(systemctl is-system-running || true)"
    # No network: the dependencies come from the cache (ci-systemd-test.sh).
    echo "== install $old: $(dpkg-deb -f "$old" Version), config.toml as conffile"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$old" > /dev/null || fail "apt-get install $old"
    gid=$(getent group mail-auth-proxy | cut -d: -f3)

    echo "== TLS certificate and local JWKS"
    install -d -o root -g mail-auth-proxy -m 0750 /etc/mail-auth-proxy/tls
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
        -subj /CN=mail.example.org -addext subjectAltName=DNS:mail.example.org \
        -keyout /etc/mail-auth-proxy/tls/key.pem -out /etc/mail-auth-proxy/tls/cert.pem 2>/dev/null
    chown root:mail-auth-proxy /etc/mail-auth-proxy/tls/key.pem /etc/mail-auth-proxy/tls/cert.pem
    chmod 0640 /etc/mail-auth-proxy/tls/key.pem /etc/mail-auth-proxy/tls/cert.pem
    # An EC P-256 public key in DER ends with the point 0x04 || X || Y (32 bytes each).
    mkdir -p /srv/jwks
    openssl ecparam -name prime256v1 -genkey -noout -out /srv/jwk-key.pem
    b64url() { openssl base64 -A | tr '+/' '-_' | tr -d =; }
    x=$(openssl ec -in /srv/jwk-key.pem -pubout -outform DER 2>/dev/null | tail -c 64 | head -c 32 | b64url)
    y=$(openssl ec -in /srv/jwk-key.pem -pubout -outform DER 2>/dev/null | tail -c 32 | b64url)
    printf '{"keys":[{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"test","x":"%s","y":"%s"}]}\n' \
        "$x" "$y" > /srv/jwks/certs.json
    systemd-run --quiet --unit=test-jwks -p DynamicUser=yes \
        python3 -m http.server --bind 127.0.0.1 --directory /srv/jwks 8080
    for _ in $(seq 50); do
        python3 -c 'import urllib.request as u; u.urlopen("http://127.0.0.1:8080/certs.json", timeout=1)' \
            2>/dev/null && break
        sleep 0.2
    done

    # The local change to the conffile. The backends are never contacted: no client
    # logs in.
    cat > $conf <<'EOF'
config_version = 2
[server]
hostname = "mail.example.org"
[tls]
cert = "/etc/mail-auth-proxy/tls/cert.pem"
key = "/etc/mail-auth-proxy/tls/key.pem"
[imap]
listen = "0.0.0.0:993"
backend = { address = "127.0.0.1:10993", verify_name = "imap.example.org" }
[submission]
listen = "0.0.0.0:587"
backend = { address = "127.0.0.1:10587", verify_name = "smtp.example.org" }
[sieve]
listen = "0.0.0.0:4190"
backend = { address = "127.0.0.1:14190", verify_name = "imap.example.org" }
[[oauth.issuers]]
issuer = "https://sso.example.org/realms/mail"
jwks_url = "http://127.0.0.1:8080/certs.json"
audiences = ["mail"]
token_type = "keycloak"
EOF
    before=$(sha256sum $conf; stat -c '%U:%G %a' $conf)

    echo "== upgrade to $pkg without a terminal (as unattended-upgrades): no conffile question"
    echo "/bin/kill before: $(if [ -x /bin/kill ]; then echo present; else echo absent; fi)"
    # CI versions (0.0.0-ci.N) sort below the release; dpkg treats the conffile the
    # same either way.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends --allow-downgrades "$pkg" < /dev/null \
        || fail "apt-get install $pkg"
    [ "$(sha256sum $conf; stat -c '%U:%G %a' $conf)" = "$before" ] || fail "upgrade changed the config"
    [ -x /bin/kill ] || fail "no /bin/kill for ExecReload after the install"
    enabled=$(systemctl is-enabled $unit || true)
    [ "$enabled" = disabled ] || fail "is-enabled: $enabled"
    mail-auth-proxy --check-config $conf || fail "test config is not valid"

    echo "== start (Type=notify: returns after READY=1)"
    systemctl start $unit || fail "start"
    echo "state: $(state)"
    systemctl is-active --quiet $unit || fail "not active after start"
    pid=$(main_pid)
    [ "$(stat -c %U:%G /proc/"$pid")" = mail-auth-proxy:mail-auth-proxy ] \
        || fail "runs as $(stat -c %U:%G /proc/"$pid")"
    getent passwd mail-auth-proxy | grep -q -x "mail-auth-proxy:x:[0-9]*:$gid:[^:]*:/:/usr/sbin/nologin" \
        || fail "user does not reuse the existing group $gid: $(getent passwd mail-auth-proxy)"
    for port in 993 587 4190; do
        [ -n "$(ss -H -t -l -n "sport = :$port")" ] || fail "nothing listens on $port"
    done
    # No core dumps: they could hold tokens and the TLS key.
    grep -q -E '^Max core file size +0 +0 ' /proc/"$pid"/limits \
        || fail "core dumps allowed: $(grep '^Max core' /proc/"$pid"/limits)"

    echo "== reload (SIGHUP)"
    systemctl reload $unit || fail "reload"
    sleep 2
    systemctl is-active --quiet $unit || fail "not active after reload"
    [ "$(main_pid)" = "$pid" ] || fail "reload replaced the process"
    journalctl --no-pager -u $unit | grep -q "reload: certificate loaded" || fail "no reload in the journal"

    echo "== upgrade (reinstall) while running: config check with the service's credentials, restart"
    out=$(dpkg -i "$pkg" 2>&1) || { echo "$out"; fail "reinstall"; }
    echo "$out"
    ! echo "$out" | grep -q "mail-auth-proxy: warning" || fail "reinstall warned"
    systemctl is-active --quiet $unit || fail "not active after upgrade"
    [ "$(main_pid)" != "$pid" ] || fail "upgrade did not restart the service"
    pid=$(main_pid)

    echo "== upgrade with a key the service cannot read: no restart"
    chmod 0600 /etc/mail-auth-proxy/tls/key.pem
    out=$(dpkg -i "$pkg" 2>&1) || { echo "$out"; fail "reinstall"; }
    echo "$out" | grep -q "config check failed, the running service was NOT restarted" \
        || { echo "$out"; fail "unreadable key: no warning"; }
    [ "$(main_pid)" = "$pid" ] || fail "unreadable key: restarted anyway"
    chmod 0640 /etc/mail-auth-proxy/tls/key.pem

    echo "== stop"
    systemctl stop $unit || fail "stop"
    echo "state: $(state)"
    active=$(systemctl is-active $unit || true)
    [ "$active" = inactive ] || fail "after stop: $active"
    [ "$(systemctl show -P Result $unit)" = success ] || fail "result after stop"
    [ "$(systemctl show -P ExecMainStatus $unit)" = 0 ] || fail "exit status after stop"
    echo "OK: real systemd start, reload, upgrade and stop"
}

set +e
(set -e; test_run) > /out/log 2>&1
