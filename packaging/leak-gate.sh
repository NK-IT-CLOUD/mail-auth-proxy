#!/usr/bin/env bash
# Leak gate: nothing private may reach a public tree, commit or tag.
#
#   leak-gate.sh REF [RANGE]
#
# REF    tree to check: every path and every blob at REF (and the tag object, if
#        REF is an annotated tag).
# RANGE  optional revision range (for example `github/main..v1.2.3`): every commit
#        and tag object in it (raw, including merge-tag and encoding headers), the full
#        tree of every commit, and every author, committer and tagger.
#
# Environment (newline-separated lists; the patterns are kept outside this repo):
#   LEAK_PATTERNS    required, extended regexes (case-insensitive) that must not appear
#   LEAK_ALLOW       optional, regexes for allowed text; a match counts only between
#                    boundaries and is cut out, the rest of the line is still checked
#   LEAK_IDENTITIES  exact "Name <email>" allowed as author/committer/tagger; required
#                    with RANGE or when REF is an annotated tag
#
# Blobs are read as bytes: a NUL makes a blob binary whatever .gitattributes says, and
# binary blobs, LFS pointers and submodules fail the gate (they cannot be scanned).
# Exit 0 = clean, 1 = hits (listed on stderr), 2 = usage or configuration error. An
# empty or malformed list is an error, never a pass.
set -euo pipefail
export LC_ALL=C
# Exported shell functions must not replace the tools this relies on.
unset -f grep sed awk cut head git 2> /dev/null || true

usage() { echo "usage: leak-gate.sh REF [RANGE]" >&2; exit 2; }
conf() { echo "leak-gate: $*" >&2; exit 2; }
[ $# -ge 1 ] && [ $# -le 2 ] || usage
ref=$1
range=
if [ $# -eq 2 ]; then
    [ -n "$2" ] || conf "RANGE is given but empty"
    range=$2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Blank lines and #-comments are dropped. Any control character other than the line
# break is an error: a CR (CRLF) would become part of every regex and make it match
# nothing, and \x01 is the delimiter of the allow cut below.
list() { # $1 = name, $2 = value, $3 = output file
    # Never pipe into grep with -q: under pipefail its early exit can make the
    # writer die of SIGPIPE, the pipeline fail, and a positive check read as negative.
    if grep -q '[[:cntrl:]]' <<< "${2//$'\n'/}"; then
        conf "$1 contains a control character (CRLF?)"
    fi
    printf '%s\n' "$2" | { grep -v -E '^[[:space:]]*(#|$)' || true; } > "$3"
}
list LEAK_PATTERNS "${LEAK_PATTERNS:-}" "$tmp/patterns"
list LEAK_ALLOW "${LEAK_ALLOW:-}" "$tmp/allow"
list LEAK_IDENTITIES "${LEAK_IDENTITIES:-}" "$tmp/identities"
[ -s "$tmp/patterns" ] || conf "LEAK_PATTERNS is empty"
git rev-parse --verify --quiet "$ref^{commit}" > /dev/null || conf "unknown ref $ref"
ref_is_tag=
[ "$(git cat-file -t "$ref")" = tag ] && ref_is_tag=1
if { [ -n "$range" ] || [ -n "$ref_is_tag" ]; } && [ ! -s "$tmp/identities" ]; then
    conf "LEAK_IDENTITIES is empty but commit or tag metadata has to be checked"
fi

# A regex grep rejects or only warns about must not silently match something else.
# Escapes outside ERE (PCRE's \d reads as a literal d) are rejected explicitly.
for f in patterns allow; do
    rc=0
    grep -n -E '\\[^]b[BwWsS<>.\\(){}|*+?^$/-]' "$tmp/$f" > "$tmp/err" 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || conf "unsupported escape in LEAK_${f^^} (ERE only): $(head -1 "$tmp/err")"
    rc=0
    grep -E -f "$tmp/$f" /dev/null 2> "$tmp/err" || rc=$?
    if [ "$rc" -gt 1 ] || [ -s "$tmp/err" ]; then
        conf "invalid regex in LEAK_${f^^}: $(head -1 "$tmp/err")"
    fi
done

# An allow entry is spliced into a sed expression whose groups \\1 and \\3 are the
# boundaries: a group inside the entry would shift them. Entries contain no "(" at all
# (not even escaped: "\\\\(" is a backslash plus a group).
rc=0
grep -n -F '(' "$tmp/allow" > "$tmp/err" || rc=$?
[ "$rc" -eq 1 ] || conf "LEAK_ALLOW entries must not contain \"(\": $(head -1 "$tmp/err")"

# Allowed text is cut out only between boundaries, so an allowed address never hides
# a longer private one that ends with it (a sentence-final "." still ends a match).
# GNU sed, \x01 as delimiter.
left='[:alnum:]._%+@-' right='[:alnum:]_%+@-'
: > "$tmp/allow.sed"
while IFS= read -r re; do
    printf 's\x01(^|[^%s])(%s)([^%s]|$)\x01\\1 \\3\x01gI\n' "$left" "$re" "$right" >> "$tmp/allow.sed"
done < "$tmp/allow"
sed -E -f "$tmp/allow.sed" /dev/null 2> "$tmp/err" || conf "invalid regex in LEAK_ALLOW for sed: $(head -1 "$tmp/err")"
# An allow entry that matches short or random text would cut almost anything.
while IFS= read -r re; do
    for probe in '' x ab 42 zz9 'qzx7.kw-3' 'Q_8 m' '..' '@-'; do
        if grep -q -i -E -e "$re" <<< "$probe"; then
            conf "LEAK_ALLOW entry matches almost anything (e.g. '$probe'): $re"
        fi
    done
done < "$tmp/allow"

# Prefixes every line of stdin with $1 (a label: never interpolated into sed/awk code).
label() { L="$1" awk '{ print ENVIRON["L"] $0 }'; }

# Lines of stdin that still match a pattern after the allowed text is cut out.
# With "numbered", stdin comes from grep -n: the "N:" prefix is output only and is
# removed before cutting and matching (an anchored pattern like ^x must still match).
# -a everywhere: a NUL or invalid byte must never turn a hit into "binary file matches".
not_allowed() {
    cat > "$tmp/na.in"
    if [ "${1:-}" = numbered ]; then
        sed -E 's/^[0-9]+://' "$tmp/na.in" > "$tmp/na.body"
    else
        cp "$tmp/na.in" "$tmp/na.body"
    fi
    sed -E -f "$tmp/allow.sed" "$tmp/na.body" > "$tmp/na.cut"
    { grep -a -n -i -E -f "$tmp/patterns" "$tmp/na.cut" || true; } | cut -d: -f1 > "$tmp/na.keep"
    awk 'NR == FNR { keep[$1] = 1; next } FNR in keep' "$tmp/na.keep" "$tmp/na.in"
}

for f in paths content binary meta ident; do : > "$tmp/h.$f"; done
declare -A seen=()

# One blob: binary (any NUL) and LFS pointers are listed, text is scanned.
scan_blob() { # $1 = sha, $2 = label
    [ -z "${seen[$1]:-}" ] || return 0
    seen[$1]=1
    git cat-file blob "$1" > "$tmp/blob"
    if grep -q -a -P '\x00' "$tmp/blob"; then
        echo "$2 (binary)" >> "$tmp/h.binary"
    elif head -c 200 "$tmp/blob" > "$tmp/blob.head" && grep -q -a '^version https://git-lfs' "$tmp/blob.head"; then
        echo "$2 (LFS pointer)" >> "$tmp/h.binary"
    else
        { grep -a -n -i -E -f "$tmp/patterns" "$tmp/blob" || true; } | not_allowed numbered \
            | label "$2:" >> "$tmp/h.content"
    fi
}

# Every entry of a tree, NUL-separated so no path can hide. Paths are checked in one
# pass; the loop itself forks only for blobs not seen before.
scan_tree() { # $1 = commit, $2 = label prefix
    local entry mode type sha path
    git ls-tree -r -z --full-tree "$1" > "$tmp/tree"
    tr '\0' '\n' < "$tmp/tree" | cut -d "$(printf '\t')" -f 2- \
        | { grep -a -i -E -f "$tmp/patterns" || true; } | not_allowed | label "$2" >> "$tmp/h.paths"
    while IFS= read -r -d '' entry; do
        read -r mode type sha <<< "${entry%%$'\t'*}"
        path=${entry#*$'\t'}
        # A line break or other control character in a path can split a pattern.
        case "$path" in *[[:cntrl:]]*) echo "$2$(printf '%q' "$path") (control character in the path)" >> "$tmp/h.binary" ;; esac
        case "$type" in
            blob) [ -n "${seen[$sha]:-}" ] || scan_blob "$sha" "$2$path" ;;
            commit) echo "$2$path (submodule)" >> "$tmp/h.binary" ;;
            *) echo "$2$path (type $type)" >> "$tmp/h.binary" ;;
        esac
    done < "$tmp/tree"
}

# A raw commit or tag object: every header (merge-tag, encoding) and the message, and
# the identities of author/committer/tagger lines (also inside merge-tag headers).
scan_object() { # $1 = sha, $2 = type
    [ -z "${seen[$1]:-}" ] || return 0
    seen[$1]=1
    git cat-file "$2" "$1" > "$tmp/obj"
    { grep -a -n -i -E -f "$tmp/patterns" "$tmp/obj" || true; } | not_allowed numbered \
        | label "$2 $1:" >> "$tmp/h.meta"
    if grep -q -a -E '^encoding ' "$tmp/obj" && ! grep -q -a -i -x -E 'encoding utf-?8' "$tmp/obj"; then
        echo "$2 $1: non-UTF-8 encoding header" >> "$tmp/h.meta"
    fi
    { grep -a -E '^ ?(author|committer|tagger) ' "$tmp/obj" || true; } \
        | sed -E 's/^ ?(author|committer|tagger) //; s/ [0-9]+ [+-][0-9]{4}$//' > "$tmp/ids"
    while IFS= read -r id; do
        grep -q -x -F -- "$id" "$tmp/identities" || echo "$2 $1: $id" >> "$tmp/h.ident"
    done < "$tmp/ids"
}

scan_tree "$ref" ""
# An annotated tag at REF: the whole chain of tag objects down to the commit.
obj=$(git rev-parse "$ref")
while [ "$(git cat-file -t "$obj")" = tag ]; do
    scan_object "$obj" tag
    obj=$(git cat-file tag "$obj" | sed -n '1s/^object //p')
done

if [ -n "$range" ]; then
    git rev-list --objects "$range" > "$tmp/objects" || conf "bad range $range"
    cut -d' ' -f1 "$tmp/objects" | git cat-file --batch-check='%(objecttype) %(objectname)' > "$tmp/types"
    while read -r type sha; do
        case "$type" in
            commit) scan_object "$sha" commit; scan_tree "$sha" "${sha:0:12}:" ;;
            tag) scan_object "$sha" tag ;;
        esac
    done < "$tmp/types"
    # A tag at the tip of the range, in case rev-list only lists its commit.
    git rev-parse --symbolic "$range" > "$tmp/tips" 2> /dev/null || true
    while IFS= read -r tip; do
        case "$tip" in ^*) continue ;; esac
        [ "$(git cat-file -t "$tip" 2> /dev/null)" = tag ] && scan_object "$(git rev-parse "$tip")" tag
    done < "$tmp/tips"
fi

: > "$tmp/hits"
add() { # $1 = heading, $2 = file
    [ -s "$2" ] || return 0
    printf 'leak-gate: %s\n' "$1" >> "$tmp/hits"
    cat "$2" >> "$tmp/hits"
}
add "paths" "$tmp/h.paths"
add "content" "$tmp/h.content"
add "binary, LFS or submodule entries (cannot be scanned)" "$tmp/h.binary"
add "commit and tag objects" "$tmp/h.meta"
add "identities not on the list" "$tmp/h.ident"

if [ -s "$tmp/hits" ]; then
    cat "$tmp/hits" >&2
    echo "leak-gate: FAIL" >&2
    exit 1
fi
echo "leak-gate: clean ($ref${range:+, $range})"
