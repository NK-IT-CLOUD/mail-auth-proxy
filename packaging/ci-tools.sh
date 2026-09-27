#!/usr/bin/env bash
# Pinned, checksum-verified packaging tools for CI: nfpm, cargo-auditable and
# cargo-about into $RUNNER_TEMP/bin, which is added to the job's PATH.
set -euo pipefail
bin=$RUNNER_TEMP/bin
mkdir -p "$bin"
cd "$RUNNER_TEMP"
get() { # url sha256
    local f=${1##*/}
    curl -fsSLO "$1"
    echo "$2  $f" | sha256sum -c
}
get https://github.com/goreleaser/nfpm/releases/download/v2.47.0/nfpm_2.47.0_Linux_x86_64.tar.gz \
    0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783
tar -xzf nfpm_2.47.0_Linux_x86_64.tar.gz -C "$bin" nfpm
get https://github.com/rust-secure-code/cargo-auditable/releases/download/v0.7.6/cargo-auditable-x86_64-unknown-linux-musl.tar.xz \
    42b66c852fbb9074a9ca356279a92eb753f48dde16017b8c82f48dcd05d6c856
tar -xJf cargo-auditable-x86_64-unknown-linux-musl.tar.xz -C "$bin" --strip-components=1 \
    cargo-auditable-x86_64-unknown-linux-musl/cargo-auditable
get https://github.com/EmbarkStudios/cargo-about/releases/download/0.9.2/cargo-about-0.9.2-x86_64-unknown-linux-musl.tar.gz \
    9099a59e820c38a68b9d65f300662a567d56562f9a10f6aa4c7e86c17c2566af
tar -xzf cargo-about-0.9.2-x86_64-unknown-linux-musl.tar.gz -C "$bin" --strip-components=1 \
    cargo-about-0.9.2-x86_64-unknown-linux-musl/cargo-about
echo "$bin" >> "$GITHUB_PATH"
