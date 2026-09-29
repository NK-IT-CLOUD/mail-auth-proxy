#!/usr/bin/env bash
# The packaged unit under a real systemd as PID 1: the smoke tests run the
# maintainer scripts against a stub systemctl and cannot see what systemd refuses
# at start (user, sandbox, capabilities, sd_notify). Assertions in
# packaging/systemd-test.sh; it ends the container with its status.
# CONTAINER_ENGINE is buildah (rootless, the maintainer's runner) or docker
# (GitHub-hosted runners).
#   ci-systemd-test.sh NEW_DIR RELEASES_DIR   (one .deb in NEW_DIR and in each
#                                              RELEASES_DIR/VERSION/, the releases
#                                              the test upgrades from)
#
# systemd needs a writable cgroup. buildah: the container runs in a delegated
# scope of the runner's user manager and mounts its own cgroup2; --cap-add ALL
# only grants capabilities inside the container's user namespace. docker:
# --privileged with a private cgroup namespace.
# The container must always end: the test unit's job timeout stops systemd
# (exit-force); if that fails, the guard halts it. buildah: SIGRTMIN+3 to
# systemd (PID 1 ignores SIGTERM), then KILL to the whole process tree (crun puts
# the container into its own cgroup, so a signal to buildah alone would leave
# systemd running). docker: docker kill. The container's journal lands in
# $out/journal.
set -euo pipefail
new=$1 releases=$2
engine=${CONTAINER_ENGINE:-docker}
guard_secs=420
ctr= img= boot= out=

tree() { local c; for c in $(pgrep -P "$1" || true); do tree "$c"; done; echo "$1"; }
halt_and_kill() { # pid of the backgrounded buildah run
    local p
    for p in $(tree "$1"); do
        [ "$(ps -o comm= -p "$p" 2> /dev/null)" != systemd ] || kill -s RTMIN+3 "$p" 2> /dev/null || true
    done
    for _ in $(seq 30); do kill -0 "$1" 2> /dev/null || return 0; sleep 1; done
    echo "systemd did not halt: killing the process tree"
    # shellcheck disable=SC2046 # one pid per word
    kill -KILL $(tree "$1") 2> /dev/null || true
}
cleanup() {
    [ -z "$boot" ] || halt_and_kill "$boot"
    case $engine in
        buildah) [ -z "$ctr" ] || buildah rm "$ctr" > /dev/null ;;
        docker)
            [ -z "$ctr" ] || docker rm -f "$ctr" > /dev/null
            # Written as root: hand the directory back before removing it.
            [ -z "$img" ] || [ -z "$out" ] \
                || docker run --rm --network none -v "$out:/out" "$img" chown -R "$(id -u):$(id -g)" /out || true
            [ -z "$img" ] || docker rmi -f "$img" > /dev/null
            ;;
    esac
    [ -z "$out" ] || rm -rf "$out"
}
trap cleanup EXIT

c_run() { # container, shell command
    case $engine in
        buildah) buildah run "$1" -- sh -c "$2" < /dev/null ;;
        docker) docker exec "$1" sh -c "$2" ;;
    esac
}
c_copy() { # container, source, destination
    case $engine in
        buildah) buildah copy --quiet "$1" "$2" "$3" ;;
        docker) docker exec "$1" mkdir -p "$(dirname "$3")" && docker cp -q "$2" "$1:$3" ;;
    esac
}

# Boots systemd in the prepared container and waits for it to end; exit status
# of the container.
boot_buildah() {
    XDG_RUNTIME_DIR="/run/user/$(id -u)" systemd-run --user --scope --quiet -- \
        env -u XDG_RUNTIME_DIR buildah run --cgroupns private --network none --cap-add ALL \
        --mount type=tmpfs,destination=/run --mount type=tmpfs,destination=/tmp \
        --mount type=tmpfs,destination=/sys/fs/cgroup --volume "$out:/out" \
        --volume "$out/journal:/var/log/journal" --env container=oci \
        "$ctr" -- /bin/sh -c 'mount -t cgroup2 cgroup2 /sys/fs/cgroup && exec /lib/systemd/systemd' \
        < /dev/null &
    boot=$!
    (sleep $guard_secs; echo "timeout: halting the container"; halt_and_kill "$boot") &
    local guard=$! rc=0
    wait "$boot" || rc=$?
    boot=
    # shellcheck disable=SC2046 # one pid per word
    kill $(tree "$guard") 2> /dev/null || true
    return $rc
}
boot_docker() {
    img=$(docker commit -q "$ctr")
    docker rm -f "$ctr" > /dev/null
    ctr=$(docker create --privileged --cgroupns private --network none \
        --tmpfs /run --tmpfs /tmp -v "$out:/out" -v "$out/journal:/var/log/journal" \
        --env container=docker "$img" /lib/systemd/systemd)
    docker start "$ctr" > /dev/null
    local rc
    rc=$(timeout $guard_secs docker wait "$ctr") || { echo "timeout: killing the container"; docker kill "$ctr" > /dev/null; return 1; }
    return "$rc"
}

systemd_test() { # image, release directory
    echo "== $1, upgrade from $2"
    out=$(mktemp -d)
    mkdir "$out/journal"
    case $engine in
        buildah) ctr=$(buildah from --quiet "$1") ;;
        docker) ctr=$(docker run -d --quiet "$1" sleep infinity) ;;
        *) echo "unsupported CONTAINER_ENGINE: $engine" >&2; exit 2 ;;
    esac
    # dbus: systemd-run --wait in postinstall needs the system bus.
    c_run "$ctr" 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd dbus openssl ca-certificates python3 iproute2 > /dev/null'
    c_copy "$ctr" packaging/systemd-test.sh /pkg/systemd-test.sh
    c_copy "$ctr" "$(ls "$new"/*.deb)" /pkg/new.deb
    c_copy "$ctr" "$(ls "$2"/*.deb)" /pkg/old.deb
    # The package's dependencies (procps for /bin/kill) come from its own metadata:
    # downloaded now, installed from the cache under systemd without network. The
    # images' docker-clean would empty the cache after the first dpkg run.
    c_run "$ctr" 'rm -f /etc/apt/apt.conf.d/docker-clean && apt-get install -y -qq --no-install-recommends --download-only /pkg/new.deb > /dev/null'
    c_run "$ctr" 'sh /pkg/systemd-test.sh setup'
    echo "booting systemd"
    local start=$SECONDS rc=0
    "boot_$engine" || rc=$?
    echo "container ended after $((SECONDS - start)) s with status $rc"
    cat "$out/log" 2> /dev/null || echo "no test log"
    if [ "$rc" != 0 ] || ! grep -q '^OK: ' "$out/log" 2> /dev/null; then
        echo "FAIL: container exit status $rc or the test did not finish; journal:"
        [ "$engine" != docker ] \
            || docker run --rm --network none -v "$out:/out" "$img" chown -R "$(id -u):$(id -g)" /out || true
        journalctl --directory="$out/journal" --no-pager -n 100 -o short-monotonic 2> /dev/null || true
        exit 1
    fi
    cleanup
    ctr= img= out=
}
for r in "$releases"/*/; do
    systemd_test docker.io/library/debian:12@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26 "$r"
    systemd_test docker.io/library/ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 "$r"
done
echo "systemd start tests: ok ($engine)"
