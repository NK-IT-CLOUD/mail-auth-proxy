#!/usr/bin/env bash
# Downloads one pinned file into DIR (default: the current directory) and checks its
# sha256. With TOOLS_CACHE set (repository variable on the maintainer's Gitea) the
# verified file is kept there under its checksum and later runs copy it from there
# instead of downloading it; the checksum is checked on every use.
#   ci-fetch.sh URL SHA256 [DIR]
set -euo pipefail
url=$1 sum=$2 dir=${3:-.}
f=${url##*/}
cached=${TOOLS_CACHE:+$TOOLS_CACHE/$sum/$f}
if [ -n "$cached" ] && [ -f "$cached" ]; then
    cp "$cached" "$dir/$f"
else
    curl -fsSL -o "$dir/$f" "$url"
fi
(cd "$dir" && echo "$sum  $f" | sha256sum -c)
if [ -n "$cached" ] && [ ! -f "$cached" ]; then
    mkdir -p "${cached%/*}"
    cp "$dir/$f" "$cached.$$"
    mv "$cached.$$" "$cached"
fi
