#!/usr/bin/env bash
# Builds a one-commit repository in DEST from the paths in packaging/public-files.txt
# at REF (straight from the tree: no .gitignore, no export-ignore can drop a file).
#
#   public-tree.sh REF DEST
#
# Every listed path has to exist at REF; a carriage return in the list is an error.
set -euo pipefail
export LC_ALL=C
# List entries are literal paths: no pathspec magic (":(exclude)…", globs).
export GIT_LITERAL_PATHSPECS=1
# Exported shell functions must not replace the tools this relies on.
unset -f grep sed awk cut head git 2> /dev/null || true
[ $# -eq 2 ] || { echo "usage: public-tree.sh REF DEST" >&2; exit 2; }
ref=$1 dest=$2
list=$(git show "$ref:packaging/public-files.txt")
case "$list" in *$'\r'*) echo "public-tree: public-files.txt contains CRLF" >&2; exit 2 ;; esac
mapfile -t paths < <(printf '%s\n' "$list" | grep -v -E '^[[:space:]]*(#|$)')
[ "${#paths[@]}" -gt 0 ] || { echo "public-tree: public-files.txt lists nothing" >&2; exit 2; }
for p in "${paths[@]}"; do
    # Directories end with '/'; any other entry must be a file, so a bare name never
    # pulls in a whole tree by accident.
    case "$p" in
        */) ;;
        *) [ "$(git ls-tree --full-tree --format='%(objecttype)' "$ref" -- "$p")" = blob ] \
               || { echo "public-tree: '$p' is not a file (directories end with '/')" >&2; exit 2; } ;;
    esac
    case "$p" in
        .|./|..|../*|*/..|*/../*|/*|:*|*'*'*|*'?'*|*'['*) echo "public-tree: entry '$p' is not an explicit path" >&2; exit 2 ;;
    esac
    [ -n "$(git ls-tree --full-tree "$ref" -- "${p%/}")" ] || { echo "public-tree: $p does not exist at $ref" >&2; exit 2; }
done
# A fresh destination only: stale files or index entries must never reach the commit.
[ ! -e "$dest" ] || { echo "public-tree: $dest already exists" >&2; exit 2; }
mkdir -p "$dest"
git -C "$dest" init -q -b main
# Copy blobs with their mode (symlinks stay symlinks, submodules fail).
git ls-tree -r -z --full-tree "$ref" -- "${paths[@]}" | while IFS= read -r -d '' entry; do
    read -r mode type sha <<< "${entry%%$'\t'*}"
    path=${entry#*$'\t'}
    [ "$type" = blob ] || { echo "public-tree: $path is a $type" >&2; exit 2; }
    case "$path" in docs/internal/*) echo "public-tree: $path is internal documentation" >&2; exit 2 ;; esac
    git -C "$dest" update-index --add --cacheinfo "$mode,$(git cat-file blob "$sha" | git -C "$dest" hash-object -w --stdin),$path"
done
git -C "$dest" -c user.name=ci -c user.email=ci@localhost commit -q -m tree
