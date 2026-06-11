#!/usr/bin/env python3
"""Extract ShellCheck's embedded prop_* test cases into a JSON corpus.

Usage: python tools/extract_corpus.py /path/to/shellcheck/checkout

Reads the Haskell sources of koalaman/shellcheck, finds every
``prop_X = verify[Not][Tree] checkFunc "snippet"`` test, resolves the SC codes
each check function can emit, and writes tests/data/corpus.json.

The extracted snippets originate from the GPLv3-licensed ShellCheck project
and are used here as a development-time conformance corpus only; they are not
part of the distributed pureshellcheck package. See tests/data/README.md.
"""

import json
import os
import re
import sys

SOURCES = [
    "src/ShellCheck/Analytics.hs",
    "src/ShellCheck/Checks/Commands.hs",
]

PROP_RE = re.compile(
    r"^prop_(\w+'?)\s*=\s*(verifyNotTree|verifyTree|verifyNot|verify|verifyCodes)"
    r"\s+(?:(\w+)|\((\w+)[^)]*\))\s+(.*)$"
)
TOPLEVEL_DEF_RE = re.compile(r"^([a-z]\w*'?)\s")
CODE_RE = re.compile(r"(?<![\d.])([123]\d{3})(?![\d.])")

# Checks whose SC codes are emitted from shared helper functions and thus
# cannot be resolved by scanning the check's own body.
FALLBACK_CODES = {
    "subshellAssignmentCheck": [2030, 2031],
    "checkSpacefulnessCfg": [2086, 2223],
    "checkUnassignedReferences": [2153, 2154],
    "checkVerboseSpacefulnessCfg": [2248, 2250],
}


def decode_haskell_string(s):
    """Decode the contents of a Haskell string literal (without the quotes)."""
    out = []
    i = 0
    n = len(s)
    simple = {
        "n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b",
        "f": "\f", "v": "\v", "\\": "\\", '"': '"', "'": "'",
    }
    while i < n:
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        c = s[i]
        if c in simple:
            out.append(simple[c])
            i += 1
        elif c == "&":  # empty escape, separates e.g. \123 from digits
            i += 1
        elif c.isspace():  # string gap: backslash, whitespace, backslash
            while i < n and s[i].isspace():
                i += 1
            if i < n and s[i] == "\\":
                i += 1
        elif c == "x":
            j = i + 1
            while j < n and s[j] in "0123456789abcdefABCDEF":
                j += 1
            out.append(chr(int(s[i + 1:j], 16)))
            i = j
        elif c.isdigit():
            j = i
            while j < n and s[j].isdigit():
                j += 1
            out.append(chr(int(s[i:j])))
            i = j
        elif c == "E" and s[i:i + 3] == "ESC":
            out.append("\x1b")
            i += 3
        else:
            raise ValueError("unhandled Haskell escape: \\" + s[i:i + 4])
    return "".join(out)


def read_string_literal(s):
    """Parse a Haskell string literal at the start of s.

    Returns (decoded_string, rest) or None if s does not start with a quote.
    """
    if not s.startswith('"'):
        return None
    i = 1
    while i < len(s):
        if s[i] == "\\":
            if i + 1 < len(s) and s[i + 1].isspace():
                # string gap; skip to closing backslash
                j = i + 1
                while j < len(s) and s[j].isspace():
                    j += 1
                if j >= len(s) or s[j] != "\\":
                    raise ValueError("unterminated string gap")
                i = j + 1
            else:
                i += 2
        elif s[i] == '"':
            return decode_haskell_string(s[1:i]), s[i + 1:]
        else:
            i += 1
    raise ValueError("unterminated string literal")


def join_continuations(text):
    """Merge indented continuation lines into their top-level line."""
    lines = text.split("\n")
    merged = []
    for line in lines:
        if merged and (line.startswith(" ") or line.startswith("\t")):
            merged[-1] += "\n" + line
        else:
            merged.append(line)
    return merged


def function_bodies(text):
    """Map top-level function name -> concatenated source of its clauses."""
    bodies = {}
    current = None
    for line in text.split("\n"):
        m = TOPLEVEL_DEF_RE.match(line)
        if m and not line.startswith("prop_"):
            current = m.group(1)
        elif line and not line[0].isspace() and not line.startswith("--"):
            current = None
        if current:
            bodies.setdefault(current, []).append(line)
    return {k: "\n".join(v) for k, v in bodies.items()}


def strip_strings_and_comments(haskell):
    """Remove string literal contents and line comments, keeping structure."""
    out = []
    i = 0
    n = len(haskell)
    while i < n:
        c = haskell[i]
        if c == '"':
            j = i + 1
            while j < n:
                if haskell[j] == "\\":
                    j += 2
                elif haskell[j] == '"':
                    break
                else:
                    j += 1
            out.append('""')
            i = j + 1
        elif c == "-" and haskell[i:i + 2] == "--":
            j = haskell.find("\n", i)
            i = n if j == -1 else j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def codes_for(body):
    return sorted(int(m) for m in set(CODE_RE.findall(strip_strings_and_comments(body))))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    entries = []
    skipped = []
    for rel in SOURCES:
        text = open(os.path.join(root, rel), encoding="utf-8").read()
        bodies = function_bodies(text)
        for line in join_continuations(text):
            m = PROP_RE.match(line)
            if not m:
                continue
            name, op, func, func_paren, rest = m.groups()
            func = func or func_paren
            rest = rest.replace("\n", " ").strip()
            codes = None
            if op == "verifyCodes":
                cm = re.match(r"\[([\d,\s]*)\]\s*(.*)$", rest)
                if not cm:
                    skipped.append((name, "verifyCodes without literal list"))
                    continue
                codes = [int(x) for x in cm.group(1).split(",") if x.strip()]
                rest = cm.group(2)
                op = "verify"
            lit = None
            try:
                lit = read_string_literal(rest)
            except ValueError as e:
                skipped.append((name, str(e)))
                continue
            if lit is None:
                skipped.append((name, "no string literal: " + rest[:40]))
                continue
            script, trailing = lit
            trailing = trailing.strip()
            if trailing and not trailing.startswith("--"):
                skipped.append((name, "trailing tokens: " + trailing[:40]))
                continue
            if codes is None:
                codes = FALLBACK_CODES.get(func) or codes_for(bodies.get(func, ""))
                if not codes:
                    skipped.append((name, "no codes resolved for " + func))
                    continue
            entries.append({
                "id": name,
                "file": os.path.basename(rel),
                "check": func,
                "expect": "trigger" if op in ("verify", "verifyTree") else "no-trigger",
                "codes": codes,
                "script": script,
            })
    out_path = os.path.join(here, "..", "tests", "data", "corpus.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"extracted {len(entries)} cases, skipped {len(skipped)}")
    for name, why in skipped:
        print("  skipped", name, "--", why)


if __name__ == "__main__":
    main()
