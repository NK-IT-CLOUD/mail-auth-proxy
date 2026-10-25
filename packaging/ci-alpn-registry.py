#!/usr/bin/env python3
"""Compare REGISTERED_ALPN in src/server/tls.rs with the IANA ALPN registry.

The submission listeners refuse a ClientHello that offers an ID of the IANA
registry "TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs"; the
list in the code is a copy of that registry without the GREASE values of
RFC 8701. A newly registered ID only takes effect once it is in the list, so
the scheduled workflow .github/workflows/alpn-registry.yml runs this script
against the current registry CSV:

    curl -fsSL -o alpn.csv \\
        https://www.iana.org/assignments/tls-extensiontype-values/alpn-protocol-ids.csv
    packaging/ci-alpn-registry.py alpn.csv src/server/tls.rs

Exit 0: both lists hold the same IDs. Exit 1: they differ; the IDs missing in
the code are printed as array lines to add (+), the IDs in the code that are
not registered (or GREASE) as lines to remove (-). Exit 2: the CSV or the
source file is not in the expected format. Standard library only, no network
access.
"""

import csv
import re
import sys

CSV_HEADER = ["Protocol", "Identification Sequence", "Reference", "Comment"]
# "0x68 0x32 (""h2"")" in the CSV: the octets, optionally followed by the
# quoted text. The octets are authoritative.
SEQUENCE = re.compile(r'((?:0x[0-9A-Fa-f]{2})(?: 0x[0-9A-Fa-f]{2})*)(?: \("(.*)"\))?')
ARRAY_START = "const REGISTERED_ALPN: &[&[u8]] = &["
ARRAY_END = "];"
# One element per line as rustfmt writes it: printable ASCII except '"' and
# '\', or \xHH escapes.
ELEMENT = re.compile(r'b"((?:[\x20\x21\x23-\x5b\x5d-\x7e]|\\x[0-9A-Fa-f]{2})*)",')


class FormatError(Exception):
    pass


def is_grease(octets):
    """RFC 8701 §2: 0x?A 0x?A, the same rule as the unit test in tls.rs."""
    return len(octets) == 2 and octets[0] == octets[1] and octets[0] & 0x0F == 0x0A


def rust_literal(octets):
    out = []
    for b in octets:
        if 0x20 <= b <= 0x7E and b not in (0x22, 0x5C):
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return 'b"' + "".join(out) + '"'


def registry_ids(path):
    """The registry's IDs without GREASE, in registry order, with a note each."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    if not rows or rows[0] != CSV_HEADER:
        raise FormatError(f"{path}: header is not {','.join(CSV_HEADER)}: {rows[:1]}")
    ids = {}
    for n, row in enumerate(rows[1:], start=2):
        if len(row) != len(CSV_HEADER):
            raise FormatError(f"{path}: row {n} has {len(row)} fields: {row}")
        protocol, sequence, reference, _ = row
        m = SEQUENCE.fullmatch(sequence.strip())
        if not m:
            raise FormatError(f"{path}: row {n}: identification sequence {sequence!r}")
        octets = bytes(int(h, 16) for h in m.group(1).split())
        text = m.group(2)
        if text is not None and text.encode() != octets:
            raise FormatError(f"{path}: row {n}: octets {m.group(1)} are not {text!r}")
        if is_grease(octets):
            continue
        if octets in ids:
            raise FormatError(f"{path}: row {n}: {rust_literal(octets)} registered twice")
        ids[octets] = f"{protocol}; {reference}".replace("\n", " ")
    return ids


def code_ids(path):
    """The elements of REGISTERED_ALPN in source order."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    try:
        start = [line.strip() for line in lines].index(ARRAY_START)
    except ValueError:
        raise FormatError(f"{path}: no line {ARRAY_START!r}") from None
    ids = []
    for n, line in enumerate(lines[start + 1 :], start=start + 2):
        line = line.strip()
        if line == ARRAY_END:
            break
        m = ELEMENT.fullmatch(line)
        if not m:
            raise FormatError(f"{path}:{n}: not a byte string element: {line!r}")
        lit = m.group(1)
        octets = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda e: chr(int(e.group(1), 16)), lit)
        ids.append(octets.encode("latin-1"))
    else:
        raise FormatError(f"{path}: REGISTERED_ALPN has no closing {ARRAY_END!r}")
    if not ids:
        raise FormatError(f"{path}: REGISTERED_ALPN is empty")
    return ids


def main(argv):
    if len(argv) != 3:
        print(f"usage: {argv[0]} <alpn-protocol-ids.csv> <src/server/tls.rs>", file=sys.stderr)
        return 2
    csv_path, src_path = argv[1:]
    try:
        registry = registry_ids(csv_path)
        code = code_ids(src_path)
    except (OSError, UnicodeDecodeError, csv.Error, FormatError) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 2
    missing = [i for i in registry if i not in code]
    removed = [i for i in code if i not in registry]
    print(
        f"IANA registry: {len(registry)} ALPN IDs without GREASE; "
        f"REGISTERED_ALPN in {src_path}: {len(code)}"
    )
    if not (missing or removed):
        print("OK: REGISTERED_ALPN matches the registry")
        return 0
    if missing:
        print(f"\nRegistered, missing in REGISTERED_ALPN ({len(missing)}):")
        for i in missing:
            print(f"+    {rust_literal(i)},\n         ({registry[i]})")
    if removed:
        print(f"\nIn REGISTERED_ALPN, not in the registry or GREASE ({len(removed)}):")
        for i in removed:
            print(f"-    {rust_literal(i)},")
    print(
        "\nFAIL: update REGISTERED_ALPN in src/server/tls.rs and its date, "
        "with a CHANGELOG entry"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
