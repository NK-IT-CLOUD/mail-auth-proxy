#!/usr/bin/env bash
# Install, upgrade and remove the packages in throwaway containers; the assertions
# are in packaging/smoke-test.sh. Then the upgrade from a release that shipped the
# config as conffile (packaging/migration-test.sh). CONTAINER_ENGINE is buildah
# (rootless, self-hosted runners) or docker (GitHub-hosted runners).
#   ci-install-tests.sh OLD_DIR NEW_DIR RELEASES_DIR   (each with one .deb and one .rpm;
#                                                     RELEASES_DIR/VERSION/ per release)
set -euo pipefail
old=$1 new=$2 release=$3
engine=${CONTAINER_ENGINE:-docker}
commit=$(git rev-parse --short=12 HEAD)
ctr=

c_from() { # image -> container id
    case $engine in
        buildah) buildah from --quiet "$1" ;;
        docker) docker run -d --quiet "$1" sleep infinity ;;
        *) echo "unsupported CONTAINER_ENGINE: $engine" >&2; exit 2 ;;
    esac
}
c_run() { # container, shell command
    case $engine in
        buildah) buildah run "$1" -- sh -c "$2" ;;
        docker) docker exec "$1" sh -c "$2" ;;
    esac
}
c_copy() { # container, source, destination
    case $engine in
        buildah) buildah copy --quiet "$1" "$2" "$3" ;;
        docker) docker exec "$1" mkdir -p "$(dirname "$3")" && docker cp -q "$2" "$1:$3" ;;
    esac
}
c_rm() {
    case $engine in
        buildah) buildah rm "$1" > /dev/null ;;
        docker) docker rm -f "$1" > /dev/null ;;
    esac
}
trap '[ -z "$ctr" ] || c_rm "$ctr"' EXIT

smoke() { # image, prepare command, package format, expected preinstall branch
    ctr=$(c_from "$1")
    c_run "$ctr" "$2"
    c_copy "$ctr" packaging/smoke-test.sh /pkg/smoke-test.sh
    c_copy "$ctr" "$(ls "$old"/*."$3")" "/pkg/old.$3"
    c_copy "$ctr" "$(ls "$new"/*."$3")" "/pkg/new.$3"
    c_run "$ctr" "sh /pkg/smoke-test.sh /pkg/old.$3 /pkg/new.$3 $commit $4"
    c_rm "$ctr"
    ctr=
}
# Debian without systemd takes the useradd branch; Ubuntu and Rocky get systemd so
# preinstall uses systemd-sysusers.
smoke docker.io/library/debian:12@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26 \
    true deb useradd
smoke docker.io/library/ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 \
    'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd > /dev/null' deb systemd-sysusers
smoke docker.io/rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f \
    'dnf install -y -q systemd > /dev/null' rpm systemd-sysusers

migrate() { # image, package format, release directory
    ctr=$(c_from "$1")
    c_copy "$ctr" packaging/migration-test.sh /pkg/migration-test.sh
    c_copy "$ctr" "$(ls "$3"/*."$2")" "/pkg/old.$2"
    c_copy "$ctr" "$(ls "$new"/*."$2")" "/pkg/new.$2"
    c_run "$ctr" "sh /pkg/migration-test.sh /pkg/old.$2 /pkg/new.$2"
    c_rm "$ctr"
    ctr=
}
for r in "$release"/*/; do
    migrate docker.io/library/debian:12@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26 deb "$r"
    migrate docker.io/rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f rpm "$r"
done
echo "install tests: ok ($engine)"
