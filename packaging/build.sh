#!/usr/bin/env bash
# Hermetic static musl build of HEAD in the digest-pinned Rust image. Writes
# OUT/mail-auth-proxy and OUT/THIRD-PARTY-NOTICES.html (cargo-about, offline, for
# the binary's dependency set) and prints their sha256. Every run uses a fresh
# source tree, CARGO_HOME and target dir, so two runs must give the same bytes.
#
#   AUDITABLE_BIN=/path/to/cargo-auditable ABOUT_BIN=/path/to/cargo-about \
#     packaging/build.sh OUT
#
# The image is the one in packaging/build-image at HEAD (CI and the RC workflow
# use it as is); BUILD_IMAGE overrides it for local experiments only.
#
# CONTAINER_ENGINE: buildah (default when installed, rootless on the CI runner),
# podman (rootless, --userns=keep-id) or docker. The image's rustc must be the
# channel from rust-toolchain.toml; nothing is downloaded by rustup.
set -euo pipefail
IMAGE="${BUILD_IMAGE:-$(git show HEAD:packaging/build-image)}"
AUDITABLE="${AUDITABLE_BIN:?AUDITABLE_BIN (checksum-verified cargo-auditable) not set}"
ABOUT="${ABOUT_BIN:?ABOUT_BIN (checksum-verified cargo-about) not set}"
OUT="${1:?usage: packaging/build.sh OUT_DIR}"
case "$IMAGE" in *@sha256:*) ;; *) echo "BUILD_IMAGE must be pinned by digest" >&2; exit 1 ;; esac
echo "build image: $IMAGE"
TOOLCHAIN=$(git show HEAD:rust-toolchain.toml | sed -n 's/^channel = "\(.*\)"$/\1/p')
[ -n "$TOOLCHAIN" ] || { echo "no channel in rust-toolchain.toml" >&2; exit 1; }
if [ -z "${CONTAINER_ENGINE:-}" ]; then
    for e in buildah podman docker; do
        if command -v "$e" >/dev/null 2>&1; then CONTAINER_ENGINE=$e; break; fi
    done
fi
: "${CONTAINER_ENGINE:?no buildah, podman or docker found}"

EPOCH=$(git log -1 --format=%ct)
COMMIT=$(git rev-parse --short=12 HEAD)
SRC=$(mktemp -d)
CH=$(mktemp -d)
ctr=
cleanup() {
    if [ -n "$ctr" ]; then buildah rm "$ctr" >/dev/null || true; fi
    rm -rf "$SRC" "$CH"
}
trap cleanup EXIT
git archive HEAD | tar -x -C "$SRC" # the commit, never the work tree

mounts=(-v "$SRC:/src:Z" -v "$CH:/cargo:Z" -v "$(realpath "$AUDITABLE"):/usr/local/bin/cargo-auditable:ro"
    -v "$(realpath "$ABOUT"):/usr/local/bin/cargo-about:ro")
# RUSTUP_TOOLCHAIN: use the image's toolchain as is, rustup must not try to add
# the components from rust-toolchain.toml or install anything.
envs=(--env CARGO_HOME=/cargo --env RUSTUP_TOOLCHAIN="$TOOLCHAIN" --env RUSTUP_AUTO_INSTALL=0)
build_envs=(--env SOURCE_DATE_EPOCH="$EPOCH" --env MAIL_AUTH_PROXY_COMMIT="$COMMIT"
    --env RUSTFLAGS="--remap-path-prefix=/src=."
    --env CFLAGS="-ffile-prefix-map=/src=.")
version=(rustc --version)
fetch=(cargo fetch --locked)
build=(cargo auditable build --release --locked --offline --target x86_64-unknown-linux-musl)
# License texts from the fetched crate sources only (--frozen: no network, no git).
notices=(cargo-about generate --frozen --fail -c packaging/about.toml
    -o THIRD-PARTY-NOTICES.html packaging/about.hbs)

check_rustc() {
    echo "$rustc"
    case "$rustc" in
        "rustc $TOOLCHAIN "*) ;;
        *) echo "image rustc is not $TOOLCHAIN (rust-toolchain.toml)" >&2; exit 1 ;;
    esac
}

case "$CONTAINER_ENGINE" in
    buildah)
        ctr=$(buildah from --quiet "$IMAGE")
        rustc=$(buildah run --network=none "${envs[@]}" "$ctr" -- "${version[@]}")
        check_rustc
        buildah run "${mounts[@]}" "${envs[@]}" --workingdir /src "$ctr" -- "${fetch[@]}"
        buildah run --network=none "${mounts[@]}" "${envs[@]}" "${build_envs[@]}" \
            --workingdir /src "$ctr" -- "${build[@]}"
        buildah run --network=none "${mounts[@]}" "${envs[@]}" --workingdir /src "$ctr" -- "${notices[@]}"
        ;;
    podman|docker)
        if [ "$CONTAINER_ENGINE" = podman ]; then user=(--userns=keep-id); else user=(--user "$(id -u):$(id -g)"); fi
        run=("$CONTAINER_ENGINE" run --rm "${user[@]}" "${mounts[@]}" "${envs[@]}" -w /src)
        rustc=$("${run[@]}" --network=none "$IMAGE" "${version[@]}")
        check_rustc
        "${run[@]}" "$IMAGE" "${fetch[@]}"
        "${run[@]}" --network=none "${build_envs[@]}" "$IMAGE" "${build[@]}"
        "${run[@]}" --network=none "$IMAGE" "${notices[@]}"
        ;;
    *)
        echo "unsupported CONTAINER_ENGINE: $CONTAINER_ENGINE" >&2
        exit 1
        ;;
esac

mkdir -p "$OUT"
install -m 0755 "$SRC/target/x86_64-unknown-linux-musl/release/mail-auth-proxy" "$OUT/"
install -m 0644 "$SRC/THIRD-PARTY-NOTICES.html" "$OUT/"
sha256sum "$OUT/mail-auth-proxy" "$OUT/THIRD-PARTY-NOTICES.html"
