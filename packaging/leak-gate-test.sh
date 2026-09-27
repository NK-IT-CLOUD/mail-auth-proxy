#!/usr/bin/env bash
# Self-test for leak-gate.sh and public-tree.sh against throwaway repositories.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
gate=$here/leak-gate.sh
pubtree=$here/public-tree.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GNUPGHOME=$work/gnupg
repo=$work/repo
mkdir -p "$repo" "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
cd "$repo"
git init -q -b main
export GIT_AUTHOR_NAME=Pub GIT_AUTHOR_EMAIL=pub@example.org
export GIT_COMMITTER_NAME=Pub GIT_COMMITTER_EMAIL=pub@example.org
export LEAK_PATTERNS=$'# comment\ncorp\\.internal\n10\\.99\\.'
export LEAK_ALLOW=$'runs-on: corp\\.internal-runner\nsec@corp\\.internal'
export LEAK_IDENTITIES='Pub <pub@example.org>'

fails=0
expect() { # $1 = expected exit code, $2 = case name, rest = command
    local want=$1 name=$2 rc=0
    shift 2
    "$@" > "$work/out" 2>&1 || rc=$?
    if [ "$rc" -ne "$want" ]; then
        echo "FAIL [$name]: exit $rc, want $want: $*" >&2
        sed 's/^/    /' "$work/out" >&2
        fails=1
    fi
}
undo() { git reset -q --hard "$1"; git tag -l | xargs -r git tag -d > /dev/null; }

echo 'public text' > a.txt
echo 'runs-on: corp.internal-runner' > ci.yaml
echo 'mail sec@corp.internal.' > contact.txt
: > empty.txt
git add . && git commit -q -m 'clean'
base=$(git rev-parse HEAD)
expect 0 "clean tree" "$gate" HEAD
expect 0 "clean range" "$gate" HEAD "$base~0..HEAD"

echo 'host CORP.internal' >> a.txt && git commit -q -am x
expect 1 "content, case-insensitive" "$gate" HEAD
undo "$base"

echo 'runs-on: corp.internal-runner # 10.99.0.7' >> ci.yaml && git commit -q -am x
expect 1 "allowed and forbidden on one line" "$gate" HEAD
undo "$base"

echo 'corp.internal at line start' > anchored.txt && git add . && git commit -q -m x
expect 1 "anchored pattern still matches after the line number is added" env LEAK_PATTERNS='^corp\.internal' "$gate" HEAD
undo "$base"

echo 'mail ops-sec@corp.internal' >> a.txt && git commit -q -am x
expect 1 "allow entry is not cut out of a longer address" "$gate" HEAD
undo "$base"

echo x > 10.99.1.1.txt && git add . && git commit -q -m x
expect 1 "path" "$gate" HEAD
undo "$base"

printf '\0\1\2' > blob.bin && git add . && git commit -q -m x
expect 1 "binary file" "$gate" HEAD
undo "$base"

{ head -c 9000 /dev/zero | tr '\0' 'a'; printf '\0 corp.internal\n'; } > late-nul.txt
git add . && git commit -q -m x
expect 1 "NUL after the first 8000 bytes makes the file binary" "$gate" HEAD
undo "$base"

printf '*.txt diff\n' > .gitattributes
printf 'c\0o\0r\0p\0.\0i\0n\0t\0e\0r\0n\0a\0l\0' > u16.txt
git add . && git commit -q -m x
expect 1 "UTF-16 file forced to text by an attribute" "$gate" HEAD
undo "$base"

ln -s /srv/corp.internal/key link && git add . && git commit -q -m x
expect 1 "symlink target" "$gate" HEAD
undo "$base"

printf 'version https://git-lfs.github.com/spec/v1\noid sha256:%064d\nsize 1\n' 0 > big.dat
git add . && git commit -q -m x
expect 1 "LFS pointer" "$gate" HEAD
undo "$base"

git update-index --add --cacheinfo "160000,$base,sub" && git commit -q -m x
expect 1 "submodule" "$gate" HEAD
undo "$base"

git commit -q --allow-empty -m 'deploy to 10.99.0.1'
expect 1 "commit message" "$gate" HEAD "$base..HEAD"
undo "$base"

GIT_AUTHOR_EMAIL=someone@corp.example git commit -q --allow-empty -m x
expect 1 "author identity" "$gate" HEAD "$base..HEAD"
undo "$base"

GIT_COMMITTER_NAME=Other git commit -q --allow-empty -m x
expect 1 "committer identity" "$gate" HEAD "$base..HEAD"
undo "$base"

echo 'corp.internal' > gone.txt && git add . && git commit -q -m x
git rm -q gone.txt && git commit -q -m y
expect 0 "added-and-removed leak: tree at HEAD alone is clean" "$gate" HEAD
expect 1 "added-and-removed leak: range scans every commit's tree" "$gate" HEAD "$base..HEAD"
undo "$base"

git checkout -q -b side && git commit -q --allow-empty -m side && git checkout -q main
git merge -q --no-ff -m 'merge from 10.99.0.9' side
expect 1 "merge commit message" "$gate" HEAD "$base..HEAD"
undo "$base"
git branch -q -D side

git commit -q --allow-empty -m 'release'
GIT_COMMITTER_EMAIL=me@corp.example git tag -a -m 'release' v1
expect 1 "tagger identity" "$gate" v1 "$base..v1"
expect 2 "tag as REF without identities" env LEAK_IDENTITIES= "$gate" v1
undo "$base"
git commit -q --allow-empty -m 'release'
git tag -a -m 'release from 10.99.0.3' v1
expect 1 "tag message" "$gate" v1 "$base..v1"
expect 1 "tag message, tag as REF" "$gate" v1
undo "$base"
git commit -q --allow-empty -m 'release'
git tag -a -m 'release' v1
expect 0 "clean tag" "$gate" v1 "$base..v1"
undo "$base"

git -c i18n.commitEncoding=UTF-16LE commit -q --allow-empty -m x
expect 1 "non-UTF-8 encoding header" "$gate" HEAD "$base..HEAD"
undo "$base"

if command -v gpg > /dev/null; then
    gpg --batch --quiet --passphrase '' --quick-gen-key 'Pub <pub@example.org>' ed25519 sign never 2> /dev/null
    git checkout -q -b side && git commit -q --allow-empty -m side
    git tag -s -m 'note corp.internal' vs && git checkout -q main
    git merge -q --no-ff -m 'Merge side' vs
    expect 1 "signed tag message inside a mergetag header" "$gate" HEAD "$base..HEAD"
    undo "$base"
    git branch -q -D side
fi

# File names are data, never code (sed/awk injection through a label).
printf 'corp.internal\n' > 'n|;d;#'
git add . && git commit -q -m x
expect 1 "file name with sed syntax does not hide hits" "$gate" HEAD
expect 1 "same, in a range" "$gate" HEAD "$base..HEAD"
undo "$base"
printf 'corp.internal\n' > 'touch PWNED;#|e;#'
git add . && git commit -q -m x
expect 1 "file name with sed e command" "$gate" HEAD
[ ! -e PWNED ] || { echo "FAIL [file name executed code]" >&2; fails=1; }
undo "$base"

printf 'x\n' > "$(printf 'corp.\ninternal')"
git add . && git commit -q -m x
expect 1 "line break in a file name" "$gate" HEAD
undo "$base"

# A nested annotated tag: every tag object in the chain is checked.
git commit -q --allow-empty -m 'release'
git tag -a -m 'inner 10.99.0.4' inner
git -c advice.nestedTag=false tag -a -m 'outer' v2 inner
git tag -d inner > /dev/null
expect 1 "nested tag at REF" "$gate" v2
undo "$base"

# Performance: 400 files, 20 commits stay well below a CI timeout.
mkdir -p many
for i in $(seq 1 400); do echo "file $i" > "many/f$i.txt"; done
git add . && git commit -q -m many
for i in $(seq 1 19); do echo "change $i" >> many/f1.txt; git commit -q -am "c$i"; done
t0=$(date +%s)
expect 0 "400 files x 20 commits" "$gate" HEAD "$base..HEAD"
t=$(( $(date +%s) - t0 ))
[ "$t" -le 60 ] || { echo "FAIL [performance]: ${t}s for 400 files x 20 commits" >&2; fails=1; }
undo "$base"

# Configuration errors are never a pass.
expect 2 "empty patterns" env LEAK_PATTERNS= "$gate" HEAD
expect 2 "only comments" env LEAK_PATTERNS=$'# only a comment\n' "$gate" HEAD
expect 2 "broken pattern" env LEAK_PATTERNS='(' "$gate" HEAD
expect 2 "PCRE-only syntax" env LEAK_PATTERNS='acct \d{8}' "$gate" HEAD
expect 2 "CRLF in patterns" env LEAK_PATTERNS=$'corp\\.internal\r\n' "$gate" HEAD
expect 2 "CRLF in allow" env LEAK_ALLOW=$'x\r\n' "$gate" HEAD
expect 2 "broken allow" env LEAK_ALLOW='(' "$gate" HEAD
expect 2 "group in an allow entry" env LEAK_ALLOW='(sec|ops)@corp\.internal' "$gate" HEAD
expect 2 "group after an escaped backslash in an allow entry" env LEAK_ALLOW='x\\\\(sec|ops)@corp\.internal' "$gate" HEAD
expect 2 "control character in allow" env LEAK_ALLOW=$'q)\x01\x01;d;#' "$gate" HEAD
expect 2 "allow entry matching everything" env LEAK_ALLOW='.*' "$gate" HEAD
expect 2 "allow entry matching one letter" env LEAK_ALLOW='[a-z]' "$gate" HEAD
expect 2 "allow entry matching two characters" env LEAK_ALLOW='..+' "$gate" HEAD
expect 2 "allow entry matching a word class" env LEAK_ALLOW='[[:alnum:].]{2,}' "$gate" HEAD
expect 2 "allow entry matching digits" env LEAK_ALLOW='[[:digit:]]{2,}' "$gate" HEAD
expect 2 "allow entry matching punctuation" env LEAK_ALLOW='[[:punct:]]+' "$gate" HEAD
expect 2 "no identities with range" env LEAK_IDENTITIES= "$gate" HEAD "$base..HEAD"
expect 2 "empty range" "$gate" HEAD ''
expect 2 "unknown ref" "$gate" no-such-ref
expect 2 "bad range" "$gate" HEAD 'no-such-ref..HEAD'
expect 2 "no arguments" "$gate"

# public-tree.sh: nested .gitignore does not drop a tracked file, missing paths and
# CRLF in the list fail.
mkdir -p packaging tests/fx
echo '*.env' > tests/fx/.gitignore
echo 'corp.internal' > tests/fx/prod.env
git add -f tests/fx/prod.env tests/fx/.gitignore
printf 'tests/\n' > packaging/public-files.txt
git add packaging && git commit -q -m x
rm -rf "$work/pub"
expect 0 "public tree from list" "$pubtree" HEAD "$work/pub"
expect 1 "ignored file in the public tree is still scanned" bash -c "cd '$work/pub' && '$gate' HEAD"
printf 'tests/\nno-such-dir/\n' > packaging/public-files.txt && git commit -q -am x
expect 2 "missing path in list" "$pubtree" HEAD "$work/pub2"
printf 'tests/\r\n' > packaging/public-files.txt && git commit -q -am x
expect 2 "CRLF in list" "$pubtree" HEAD "$work/pub3"
printf 'tests/\n.\n' > packaging/public-files.txt && git commit -q -am x
expect 2 "'.' in list" "$pubtree" HEAD "$work/pub4"
printf 'tests/\n:(exclude)tests/fx\n' > packaging/public-files.txt && git commit -q -am x
expect 2 "pathspec magic in list" "$pubtree" HEAD "$work/pub5"
printf 'tests/\n' > packaging/public-files.txt && git commit -q -am x
expect 2 "existing destination" "$pubtree" HEAD "$work/pub"
printf 'tests\n' > packaging/public-files.txt && git commit -q -am x
expect 2 "bare directory name in list" "$pubtree" HEAD "$work/pub6"
mkdir -p docs/internal && echo x > docs/internal/n.md && git add docs
printf 'docs/\n' > packaging/public-files.txt && git commit -q -am x
expect 2 "docs/internal never in the public tree" "$pubtree" HEAD "$work/pub7"
undo "$base"

# Under pipefail, `… | grep -q` can turn a match into a failed pipeline (SIGPIPE in the
# writer): never in these scripts.
if grep -n -E '\|[[:space:]]*grep\b[^|]*[[:space:]](-[[:alnum:]]*q[[:alnum:]]*|--quiet)\b' "$gate" "$pubtree"; then
    echo "FAIL [piped grep -q in a script]" >&2
    fails=1
fi

[ "$fails" -eq 0 ] || exit 1
echo "leak-gate-test: ok"
