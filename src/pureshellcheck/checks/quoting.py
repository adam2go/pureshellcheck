"""Quoting and word-splitting checks (SC2086 family and friends)."""

import re

from ..analyzer import node_check, tree_check
from ..astlib import (
    CLEAN, SPECIAL_VARIABLES_WITHOUT_SPACES, UNBRACED_VARIABLES,
    braced_modifier, braced_reference, closest_command, expanded_parts,
    is_array_expansion, is_counting_reference, is_quote_free,
    is_quoted_alternative_reference, word_parts,
)
from ..parser import literal_text, quoted_literal_text
from ..shast import ancestors
from ..varflow import VarFlow

WILL_SPLIT_KINDS = frozenset({
    "T_DollarBraced", "T_DollarExpansion", "T_Backticked",
    "T_BraceExpansion", "T_Glob", "T_Extglob",
    "T_DollarBraceCommandExpansion",
})


def will_split(part):
    if part.kind == "T_NormalWord":
        return any(will_split(p) for p in part.parts)
    return part.kind in WILL_SPLIT_KINDS


def may_become_multiple_args(word):
    for p in expanded_parts(word):
        if is_array_expansion(p):
            return True
        if p.kind == "T_DollarBraced" and p.content.startswith("!"):
            return True
    return False


def command_word_of(ctx, node):
    """True if node is (part of) the effective command name word."""
    word = ctx.parent_word(node)
    if word is None:
        return False
    cmd = closest_command(word)
    if cmd is None or not cmd.words:
        return False
    if word is cmd.words[0]:
        return True
    return word is ctx.command_name_word(cmd)


# ----------------------------------------------------------------------
# SC2086 / SC2223 / SC2248 spacefulness, and SC2089/SC2090 quotes-in-vars

QUOTE_CHARS_RE = re.compile(r'"|([/= ]|^)\'|\'( |$)|\\ ')


@tree_check
def check_spacefulness(ctx, root):
    reported = set()
    quote_holders = {}  # var name -> assignment node that embedded quotes

    def word_has_quotes(word):
        """Does this value contain shell quotes? Returns witness node."""
        if word is None:
            return None
        for p in word_parts(word):
            k = p.kind
            if k in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
                for q in p.parts:
                    w = word_has_quotes(q)
                    if w is not None:
                        return w
            elif k == "T_DollarBraced":
                if p.content in quote_holders:
                    return quote_holders[p.content]
            elif k in ("T_Literal", "T_SingleQuoted",
                       "T_DollarSingleQuoted"):
                text = p.text
                if k == "T_Literal" and p.get("escaped"):
                    text = "\\" + text
                if QUOTE_CHARS_RE.search(text):
                    return p
        return None

    def on_assign(name, value, node):
        if value is not None and value.kind == "T_Array":
            return
        witness = word_has_quotes(value)
        if witness is None:
            quote_holders.pop(name, None)
        else:
            quote_holders[name] = witness if witness.kind == "T_Literal" \
                or "Quoted" in witness.kind else witness

    def on_reference(node, name, status, integer):
        if node.pos in reported:
            return
        reported.add(node.pos)
        if is_array_expansion(node):
            return
        if is_counting_reference(node):
            return
        if is_quoted_alternative_reference(node):
            return
        if is_quote_free(node, ctx.shell):
            return
        check_quotes_in_literals(node, name)
        if command_word_of(ctx, node):
            return
        if name in SPECIAL_VARIABLES_WITHOUT_SPACES:
            return
        if status == CLEAN or integer:
            ctx.style(node, 2248, "Prefer double quoting even when variables"
                      " don't contain special characters.")
            return
        if is_default_assignment(node):
            ctx.info(node, 2223, "This default assignment may cause DoS due"
                     " to globbing. Quote it.")
        else:
            ctx.info(node, 2086, "Double quote to prevent globbing and word"
                     " splitting.")

    def check_quotes_in_literals(node, name):
        witness = quote_holders.get(node.content)
        if witness is None:
            return
        cmd = closest_command(node)
        if cmd is not None and cmd.words:
            first = literal_text(cmd.words[0])
            if first and first.rsplit("/", 1)[-1] == "eval":
                return
        ctx.warn(witness, 2089, "Quotes/backslashes will be treated "
                 "literally. Use an array.")
        ctx.warn(node, 2090, "Quotes/backslashes in this variable will "
                 "not be respected.")

    def is_default_assignment(node):
        mod = braced_modifier(node.content)
        if not (mod.startswith("=") or mod.startswith(":=")):
            return False
        cmd = closest_command(node)
        return cmd is not None and bool(cmd.words) \
            and literal_text(cmd.words[0]) == ":"

    VarFlow(on_reference, ctx.shell, on_assign=on_assign).run(root)


# ----------------------------------------------------------------------
# SC2046: unquoted command substitution

@node_check("T_DollarExpansion", "T_Backticked",
            "T_DollarBraceCommandExpansion")
def check_unquoted_expansions(ctx, node):
    if not node.commands:
        return
    if expansion_command_name(node) in ("seq", "pgrep"):
        return
    if is_quote_free(node, ctx.shell):
        return
    if command_word_of(ctx, node):
        return
    ctx.warn(node, 2046, "Quote this to prevent word splitting.")


def expansion_command_name(node):
    cmds = node.commands
    if len(cmds) != 1 or cmds[0].kind != "T_SimpleCommand":
        return None
    if not cmds[0].words:
        return None
    name = literal_text(cmds[0].words[0])
    return name.rsplit("/", 1)[-1] if name else None


# ----------------------------------------------------------------------
# SC2068: unquoted array expansions; SC2145: string/array concatenation

@node_check("T_NormalWord")
def check_unquoted_dollar_at(ctx, word):
    if is_quote_free(word, ctx.shell, strict=True):
        return
    for p in word.parts:
        if is_array_expansion(p):
            if not is_quoted_alternative_reference(p):
                ctx.err(p, 2068, "Double quote array expansions to avoid"
                        " re-splitting elements.")
            return


@node_check("T_NormalWord")
def check_concatenated_dollar_at(ctx, word):
    parts = expanded_parts(word)
    if len(parts) <= 1:
        return
    if is_quote_free(word, ctx.shell):
        return
    for p in parts:
        if is_array_expansion(p):
            ctx.err(p, 2145, "Argument mixes string and array. Use * or"
                    " separate argument.")
            return


# ----------------------------------------------------------------------
# SC2048: $* and ${a[*]}

@node_check("T_DollarBraced")
def check_dollar_star(ctx, node):
    content = node.content
    if content.startswith("#"):
        return
    name = braced_reference(content)
    is_star = name == "*"
    if not is_star:
        m = re.match(r"[A-Za-z_][A-Za-z0-9_]*\[\*\]", content)
        is_star = bool(m)
    if not is_star:
        return
    if is_quote_free(node, ctx.shell, strict=True):
        return
    ctx.warn(node, 2048, 'Use "$@" (with quotes) to prevent whitespace'
             ' problems.')


# ----------------------------------------------------------------------
# SC2006: legacy backticks

@node_check("T_Backticked")
def check_backticks(ctx, node):
    if not node.commands:
        return
    ctx.style(node, 2006, "Use $(...) notation instead of legacy"
              " backticks `...`.")


# ----------------------------------------------------------------------
# SC2016: expressions in single quotes

SQ_DOLLAR_RE = re.compile(r"\$[{(0-9a-zA-Z_]|`[^`]+`")
SED_CONTRA_RE = re.compile(r"\$[{dpsaic]($|[^a-zA-Z])")

SQ_OK_COMMANDS = frozenset({
    "trap", "sh", "bash", "ksh", "zsh", "ssh", "eval", "xprop", "alias",
    "sudo", "doas", "run0", "docker", "podman", "oc", "dpkg-query", "jq",
    "rename", "rg", "unset", "crontab", "watch", "git filter-branch",
})

PROMPT_VARS = frozenset({"PS1", "PS2", "PS3", "PS4", "PROMPT_COMMAND"})


@node_check("T_SingleQuoted")
def check_single_quoted_variables(ctx, node):
    if not SQ_DOLLAR_RE.search(node.text):
        return
    names = _sq_command_chain(ctx, node)
    if "sed" in names:
        if not SED_CONTRA_RE.search(node.text):
            ctx.info(node, 2016, "Expressions don't expand in single quotes,"
                     " use double quotes for that.")
        return
    for name in names:
        if name in SQ_OK_COMMANDS or name.endswith("awk") \
                or name.startswith("perl") or name.startswith("mumps"):
            return
    chain = [node] + list(ancestors(node))[:3]
    for a in chain[1:4]:
        if a.kind == "T_Assignment" and a.name in PROMPT_VARS:
            return
        if a.kind == "TC_Unary" and a.op == "-v":
            return
    ctx.info(node, 2016, "Expressions don't expand in single quotes, use"
             " double quotes for that.")


def _sq_command_chain(ctx, node):
    """All command names involved: wrappers plus the effective command."""
    cmd = closest_command(node)
    if cmd is None:
        return []
    raw = literal_text(cmd.words[0]) if cmd.words else None
    names = [raw.rsplit("/", 1)[-1]] if raw else []
    word, idx, wrappers = ctx.command_resolution(cmd)
    names.extend(wrappers)
    name = literal_text(word) if word is not None else None
    if name:
        name = name.rsplit("/", 1)[-1]
        names.append(name)
        args = [literal_text(w) for w in cmd.words]
        if name == "find":
            for i, a in enumerate(args):
                if a in ("-exec", "-execdir", "-ok", "-okdir") \
                        and i + 1 < len(args) and args[i + 1]:
                    names.append(args[i + 1].rsplit("/", 1)[-1])
        elif name == "git" and len(args) > idx + 1 \
                and args[idx + 1] == "filter-branch":
            names.append("git filter-branch")
    return names


# ----------------------------------------------------------------------
# SC2066 / SC2041 / SC2042 / SC2043 / SC2258: for-in words

@node_check("T_ForIn")
def check_for_in_quoted(ctx, node):
    words = node.words
    if not node.has_in:
        return
    if len(words) == 1:
        word = words[0]
        parts = word_parts(word)
        if len(parts) == 1 and parts[0].kind == "T_DoubleQuoted":
            dq = parts[0]
            lit = quoted_literal_text(word)
            if (any(will_split(p) for p in dq.parts)
                    and not may_become_multiple_args(word)) \
                    or (lit is not None
                        and any(c in lit for c in "*?[")):
                ctx.err(dq, 2066, "Since you double quoted this, it will"
                        " not word split, and the loop will only run once.")
            return
        if len(parts) == 1 and parts[0].kind == "T_SingleQuoted":
            ctx.warn(parts[0], 2041, "This is a literal string. To run as"
                     " a command, use $(..) instead of '..'.")
            return
        unquoted = _unquoted_literal(word)
        if unquoted is not None and "," in unquoted:
            ctx.warn(word, 2042, "Use spaces, not commas, to separate loop"
                     " elements.")
            return
        if not will_split(word) and not may_become_multiple_args(word):
            ctx.warn(word, 2043, "This loop will only ever run once. Bad"
                     " quoting or missing glob/expansion?")
        return
    for word in words:
        suffix = _trailing_unquoted_literal(word)
        if suffix is not None and suffix.text.endswith(","):
            ctx.warn(word, 2258, "The trailing comma is part of the value,"
                     " not a separator. Delete or quote it.")


def _unquoted_literal(word):
    out = []
    for p in word_parts(word):
        if p.kind != "T_Literal":
            return None
        out.append(p.text)
    return "".join(out)


def _trailing_unquoted_literal(word):
    parts = word_parts(word)
    if parts and parts[-1].kind == "T_Literal" \
            and not parts[-1].get("escaped"):
        return parts[-1]
    return None


# ----------------------------------------------------------------------
# SC2206 / SC2207: word splitting in array assignments

@node_check("T_Array")
def check_splitting_in_arrays(ctx, node):
    for element in node.elements:
        value = element.value if element.kind == "T_IndexedElement" \
            else element
        for p in word_parts(value):
            k = p.kind
            if k in ("T_DollarExpansion", "T_Backticked",
                     "T_DollarBraceCommandExpansion"):
                ctx.warn(p, 2207, "Prefer mapfile or read -a to split"
                         " command output (or quote to avoid splitting).")
            elif k == "T_DollarBraced":
                name = braced_reference(p.content)
                if name in SPECIAL_VARIABLES_WITHOUT_SPACES:
                    continue
                if is_counting_reference(p):
                    continue
                ctx.warn(p, 2206, "Quote to prevent word splitting/globbing,"
                         " or split robustly with mapfile or read -a.")


# ----------------------------------------------------------------------
# SC2026 / SC2027 / SC2140: inexplicably unquoted words

@node_check("T_NormalWord")
def check_inexplicably_unquoted(ctx, word):
    parts = word.parts
    for i in range(len(parts) - 1):
        a, b = parts[i], parts[i + 1]
        if a.kind == "T_SingleQuoted" and b.kind == "T_Literal" \
                and b.text and b.text.isalnum():
            ctx.info(b, 2026, "This word is outside of quotes. Did you"
                     " intend to 'nest '\"'single quotes'\"' instead'?")
        if i + 2 < len(parts) and a.kind == "T_DoubleQuoted" \
                and parts[i + 2].kind == "T_DoubleQuoted":
            trapped = b
            if trapped.kind in ("T_DollarExpansion", "T_DollarBraced"):
                ctx.warn(trapped, 2027, "The surrounding quotes actually"
                         " unquote this. Remove or escape them.")
            elif trapped.kind == "T_Literal":
                if trapped.text in ("=", ":", "/"):
                    continue
                if _quotes_single_thing(a) and \
                        _quotes_single_thing(parts[i + 2]):
                    continue
                if _is_regex_context(word):
                    continue
                ctx.warn(trapped, 2140, 'Word is of the form "A"B"C"'
                         ' (B indicated). Did you mean "ABC" or'
                         ' "A\\"B\\"C"?')


def _quotes_single_thing(dq):
    return len(dq.parts) == 1 and dq.parts[0].kind in (
        "T_DollarExpansion", "T_DollarBraced", "T_Backticked")


def _is_regex_context(word):
    for a in ancestors(word):
        if a.kind == "TC_Binary" and a.op == "=~" and a.rhs is word:
            return True
        if a.kind in ("T_SimpleCommand", "T_Script"):
            return False
    return False


# ----------------------------------------------------------------------
# SC2250 (optional): prefer braces around variable references

@node_check("T_DollarBraced")
def check_variable_braces(ctx, node):
    if node.get("braced"):
        return
    name = braced_reference(node.content)
    if name in UNBRACED_VARIABLES:
        return
    if command_word_of(ctx, node):
        return
    ctx.style(node, 2250, "Prefer putting braces around variable references"
              " even when not strictly required.")
