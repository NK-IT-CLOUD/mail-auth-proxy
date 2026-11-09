#!/usr/bin/env bash
# The releases that shipped config.toml as conffile (%config(noreplace)), for the
# upgrade tests: DEST/VERSION/ with the .deb and the .rpm from the GitHub release,
# pinned by checksum (downloads through ci-fetch.sh). 0.2.0 shipped it too but has
# no GitHub release.
#   ci-fetch-releases.sh DEST
set -euo pipefail
dest=$1
github=https://github.com/NK-IT-CLOUD/mail-auth-proxy/releases/download
pinned() { # version -> "sha256  file" lines
    case $1 in
        0.1.1) cat <<'EOF'
486104bb4f5f01ef21674054c21651a1b4b25711bf111e37180fecb0f2aada23  mail-auth-proxy_0.1.1_amd64.deb
125d520e414eeed8abec4868602b2a8fb460b7f572288ef3b7ac2657e5136798  mail-auth-proxy-0.1.1-1.x86_64.rpm
EOF
            ;;
    esac
}
fetch=$(cd "$(dirname "$0")" && pwd)/ci-fetch.sh
for v in 0.1.1; do
    mkdir -p "$dest/$v"
    pinned $v | while read -r sum f; do
        "$fetch" "$github/v$v/$f" "$sum" "$dest/$v"
    done
done
