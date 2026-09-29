#!/usr/bin/env bash
# The releases that shipped config.toml as conffile (%config(noreplace)), for the
# upgrade tests: DEST/VERSION/ with the .deb and the .rpm from the GitHub release,
# pinned by checksum. A version that is not published there yet is skipped.
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
        0.2.0) cat <<'EOF'
576b81c2259d7c24f525de67aa7c06c63e598633e9410c6f88275c0bcc761515  mail-auth-proxy_0.2.0_amd64.deb
a648aed885e94e7ce98c7ccc7c3d76affe379c60f9425d0b5c67c66710011633  mail-auth-proxy-0.2.0-1.x86_64.rpm
EOF
            ;;
    esac
}
for v in 0.1.1 0.2.0; do
    mkdir -p "$dest/$v"
    for f in $(pinned $v | cut -d' ' -f3); do
        if ! curl -fsSL -o "$dest/$v/$f" "$github/v$v/$f"; then
            echo "SKIP: release $v is not published on GitHub"
            rm -rf "${dest:?}/$v"
            continue 2
        fi
    done
    (cd "$dest/$v" && pinned $v | sha256sum -c)
done
ls "$dest"/*/*.deb > /dev/null || { echo "FAIL: no release to upgrade from" >&2; exit 1; }
