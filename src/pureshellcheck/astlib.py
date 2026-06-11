"""Shared AST analysis helpers, ported from ShellCheck's ASTLib semantics."""

import re

from .shast import ancestors, walk
from .parser import literal_text, quoted_literal_text

SPECIAL_INTEGER_VARIABLES = frozenset({"$", "?", "!", "#"})
SPECIAL_VARIABLES_WITHOUT_SPACES = SPECIAL_INTEGER_VARIABLES | {"-"}
VARIABLES_WITHOUT_SPACES = SPECIAL_VARIABLES_WITHOUT_SPACES | {
    "BASHPID", "BASH_ARGC", "BASH_LINENO", "BASH_SUBSHELL", "EUID",
    "EPOCHREALTIME", "EPOCHSECONDS", "LINENO", "OPTIND", "PPID", "RANDOM",
    "READLINE_ARGUMENT", "READLINE_MARK", "READLINE_POINT", "SECONDS",
    "SHELLOPTS", "SHLVL", "SRANDOM", "UID", "COLUMNS", "HISTFILESIZE",
    "HISTSIZE", "LINES", "FLAGS_ERROR", "FLAGS_FALSE", "FLAGS_TRUE",
    "status",  # bats
}
SPECIAL_VARIABLES = SPECIAL_VARIABLES_WITHOUT_SPACES | {"@", "*"}
UNBRACED_VARIABLES = SPECIAL_VARIABLES | set("0123456789")

EXPANSION_KINDS = frozenset({
    "T_DollarBraced", "T_DollarExpansion", "T_Backticked",
    "T_DollarArithmetic", "T_DollarBraceCommandExpansion",
})

QUOTE_KINDS = frozenset({
    "T_SingleQuoted", "T_DoubleQuoted", "T_DollarSingleQuoted",
    "T_DollarDoubleQuoted",
})


def word_parts(word):
    if word is None:
        return []
    if word.kind == "T_NormalWord":
        return word.parts
    return [word]


def expanded_parts(word):
    """Word parts with double-quote layers flattened."""
    out = []
    for p in word_parts(word):
        if p.kind in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            out.extend(p.parts)
        else:
            out.append(p)
    return out


def is_constant(word):
    """True if the word contains no expansions at all (quotes ok)."""
    if word.kind == "T_NormalWord" and word.parts:
        first = word.parts[0]
        if first.kind == "T_Literal" and first.text.startswith("~") \
                and not first.get("escaped"):
            return False  # tilde expansion
    for n in walk(word):
        if n.kind in EXPANSION_KINDS:
            return False
    return True


def has_expansions(word):
    return not is_constant(word)


def onlyLiteralString(word):
    return literal_text(word)


def word_text_approx(word, glob_marker="\0"):
    """Approximate the word's expanded text; expansions become markers."""
    out = []
    for p in word_parts(word):
        k = p.kind
        if k == "T_Literal":
            out.append(p.text)
        elif k in ("T_SingleQuoted", "T_DollarSingleQuoted"):
            out.append(p.text)
        elif k in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            for q in p.parts:
                if q.kind == "T_Literal":
                    out.append(q.text)
                else:
                    out.append(glob_marker)
        elif k == "T_Glob":
            out.append(p.text)
        else:
            out.append(glob_marker)
    return "".join(out)


GLOB_CHARS = "*?["


def has_glob(word):
    for n in walk(word):
        if n.kind in ("T_Glob", "T_Extglob"):
            return True
    return False


def is_glob_free_literal(text):
    return not any(c in text for c in GLOB_CHARS)


# ----------------------------------------------------------------------
# ${...} decomposition

def braced_reference(content):
    """The variable name referenced by ${content}."""
    s = content
    if s.startswith("#") and len(s) > 1 and s != "##":
        s = s[1:]
    elif s.startswith("!") and len(s) > 1:
        s = s[1:]
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!_-]", s)
    return m.group(0) if m else s


def braced_modifier(content):
    """Everything after the name/indices in ${content}."""
    s = content
    if s.startswith("#") and len(s) > 1 and s != "##":
        s = s[1:]
    elif s.startswith("!") and len(s) > 1:
        s = s[1:]
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!_-]", s)
    if not m:
        return ""
    i = m.end()
    while i < len(s) and s[i] == "[":
        depth = 0
        j = i
        while j < len(s):
            if s[j] == "[":
                depth += 1
            elif s[j] == "]":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= len(s):
            break
        i = j + 1
    return s[i:]


def braced_index(content):
    """The text inside [..] following the name, or None."""
    m = re.match(r"[!#]?(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)\[(.*?)\]", content)
    return m.group(1) if m else None


def is_array_expansion(part):
    """${a[@]}, ${a[*]}, $@, $*, ${!a[@]} etc."""
    if part.kind != "T_DollarBraced":
        return False
    content = part.content
    name = braced_reference(content)
    if content.startswith("!") and not content.startswith("!!"):
        if content.endswith("[@]") or content.endswith("[*]") \
                or content.rstrip("@*") != content:
            return True
    if name in ("@", "*") and not content.startswith("#"):
        return True
    idx = braced_index(content)
    return idx in ("@", "*") and not content.startswith("#")


def is_counting_reference(part):
    """${#var} or ${#arr[@]}."""
    return (part.kind == "T_DollarBraced" and part.content.startswith("#")
            and len(part.content) > 1)


def is_quoted_alternative_reference(part):
    """${v:+"$v"} style: alternative value where the user quotes inside."""
    if part.kind != "T_DollarBraced":
        return False
    mod = braced_modifier(part.content)
    return mod.startswith(":+") or mod.startswith("+")


def part_is_quoted(part, stop_at):
    """Is `part` enclosed in quotes between itself and `stop_at` ancestor?"""
    for a in ancestors(part):
        if a is stop_at:
            return False
        if a.kind in ("T_DoubleQuoted", "T_DollarDoubleQuoted",
                      "T_SingleQuoted"):
            return True
    return False


# ----------------------------------------------------------------------
# Quoting context (port of isQuoteFreeNode)

def is_quote_free(node, shell="bash", strict=False):
    """True if expansion of `node` would not be subject to word splitting."""
    prev = node
    for a in ancestors(node):
        k = a.kind
        if k == "TC_Nullary" or k == "TC_Unary" or k == "TC_Binary":
            cond = _enclosing_condition(a)
            if cond is not None and not cond.single:
                return True
            # single bracket: keep walking; T_SimpleCommand-ish below
        elif k in ("TA_Sequence", "T_Arithmetic", "TA_Expansion",
                   "TA_Assignment", "TA_Binary", "TA_Unary", "TA_Trinary",
                   "TA_Variable", "TA_Parenthesis", "T_DollarArithmetic"):
            return True
        elif k == "T_Assignment":
            return _assignment_is_quoting(a, shell)
        elif k == "T_IndexedElement":
            return True
        elif k in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            return True
        elif k == "T_CaseExpression":
            return True
        elif k == "T_HereDoc":
            return True
        elif k == "T_DollarBraced":
            return True
        elif k in ("T_ForIn", "T_SelectIn"):
            if prev in a.get("words", ()):
                return not strict
        elif k in ("T_SimpleCommand", "T_Condition", "T_Script",
                   "T_DollarExpansion", "T_Backticked", "T_ProcSub",
                   "T_DollarBraceCommandExpansion"):
            return False
        prev = a
    return False


def _enclosing_condition(node):
    for a in ancestors(node):
        if a.kind == "T_Condition":
            return a
        if a.kind in ("T_SimpleCommand", "T_Script"):
            return None
    return None


def _assignment_is_quoting(assignment, shell):
    """Assignments don't split, except sh's `export foo=$bar` arguments."""
    if shell != "sh" and shell != "dash" and shell != "ash":
        return True
    parent = assignment.parent
    if parent is not None and parent.kind == "T_SimpleCommand":
        return assignment not in parent.assigns or not parent.words
    return True


def closest_command(node):
    for a in ancestors(node):
        if a.kind == "T_SimpleCommand":
            return a
        if a.kind in ("T_Script", "T_DollarExpansion", "T_Backticked"):
            return None
    return None


def used_as_command_name(node):
    """Is node (part of) the command-name word of a simple command?"""
    prev = node
    for a in ancestors(node):
        if a.kind == "T_NormalWord":
            prev = a
            continue
        if a.kind == "T_SimpleCommand":
            words = a.words
            return bool(words) and prev is words[0]
        return False
    return False


# ----------------------------------------------------------------------
# Space status of values (port of CFG SpaceStatus, simplified)

EMPTY, CLEAN, DIRTY = 0, 1, 2


def join_status(a, b):
    """Concatenation algebra: empty+clean=clean, dirty wins."""
    if a == DIRTY or b == DIRTY:
        return DIRTY
    if a == CLEAN or b == CLEAN:
        return CLEAN
    return EMPTY


def merge_status(a, b):
    """Control-flow merge: worst case wins; empty merges to dirty."""
    if a == b:
        return a
    return DIRTY


def literal_space_status(text):
    if text == "":
        return EMPTY
    if re.search(r"[\s*?\[\]]", text):
        return DIRTY
    return CLEAN
