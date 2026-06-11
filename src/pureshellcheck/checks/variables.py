"""Variable lifecycle and array checks."""

import re

from ..analyzer import node_check, tree_check
from ..astlib import braced_modifier, braced_reference
from ..parser import literal_text
from ..shast import ancestors, walk
from ..varscan import NAME_RE, VarScan, levenshtein

INTERNAL_VARIABLES = frozenset({
    "_", "rest", "REST", "CDPATH", "ENV", "FCEDIT", "HISTFILE", "HISTSIZE",
    "HOME", "IFS", "LANG", "LC_ALL", "LC_COLLATE", "LC_CTYPE",
    "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "MAIL",
    "MAILCHECK", "MAILPATH", "OLDPWD", "OPTARG", "OPTIND", "PATH", "PWD",
    "BASH", "BASHOPTS", "BASHPID", "BASH_ALIASES", "BASH_ARGC",
    "BASH_ARGV", "BASH_ARGV0", "BASH_CMDS", "BASH_COMMAND",
    "BASH_EXECUTION_STRING", "BASH_LINENO", "BASH_LOADABLES_PATH",
    "BASH_REMATCH", "BASH_SOURCE", "BASH_SUBSHELL", "BASH_VERSINFO",
    "BASH_VERSION", "COMP_CWORD", "COMP_KEY", "COMP_LINE", "COMP_POINT",
    "COMP_TYPE", "COMP_WORDBREAKS", "COMP_WORDS", "COPROC", "DIRSTACK",
    "EPOCHREALTIME", "EPOCHSECONDS", "EUID", "FUNCNAME", "GROUPS",
    "HISTCMD", "HOSTNAME", "HOSTTYPE", "MACHTYPE", "MAPFILE", "OSTYPE",
    "PIPESTATUS", "RANDOM", "READLINE_ARGUMENT", "READLINE_LINE",
    "READLINE_MARK", "READLINE_POINT", "REPLY", "SECONDS", "SHELLOPTS",
    "SHLVL", "SRANDOM", "UID", "BASH_COMPAT", "BASH_ENV", "BASH_XTRACEFD",
    "CHILD_MAX", "COLUMNS", "COMPREPLY", "EMACS", "EXECIGNORE", "FIGNORE",
    "FUNCNEST", "GLOBIGNORE", "HISTCONTROL", "HISTFILESIZE", "HISTIGNORE",
    "HISTTIMEFORMAT", "HOSTFILE", "IGNOREEOF", "INPUTRC", "INSIDE_EMACS",
    "LINES", "OPTERR", "POSIXLY_CORRECT", "PROMPT_COMMAND",
    "PROMPT_DIRTRIM", "PS0", "PS1", "PS2", "PS3", "PS4", "SHELL",
    "TIMEFORMAT", "TMOUT", "BASH_MONOSECONDS", "BASH_TRAPSIG", "GLOBSORT",
    "auto_resume", "histchars", "USER", "TZ", "TERM", "LOGNAME",
    "LD_LIBRARY_PATH", "LANGUAGE", "DISPLAY", "KRB5CCNAME", "LINENO",
    "PPID", "TMPDIR", "XAUTHORITY", "FLAGS_ARGC", "FLAGS_ARGV",
    "FLAGS_ERROR", "FLAGS_FALSE", "FLAGS_HELP", "FLAGS_PARENT",
    "FLAGS_RESERVED", "FLAGS_TRUE", "FLAGS_VERSION", "flags_error",
    "flags_return", "stderr", "stderr_lines", "status", "output", "lines",
})

INTERNAL_ARRAYS = frozenset({
    "BASH_ALIASES", "BASH_ARGC", "BASH_ARGV", "BASH_CMDS", "BASH_LINENO",
    "BASH_REMATCH", "BASH_SOURCE", "BASH_VERSINFO", "COMP_WORDS",
    "COPROC", "DIRSTACK", "FUNCNAME", "GROUPS", "MAPFILE", "PIPESTATUS",
    "COMPREPLY", "lines",
})

COMMON_COMMANDS_HINT = frozenset({
    "cat", "cut", "date", "find", "grep", "head", "ls", "sed", "sort",
    "tail", "wc", "whoami", "pwd", "dirname", "basename",
})


def get_varscan(ctx):
    scan = ctx.cache.get("varscan")
    if scan is None:
        scan = VarScan(ctx.root, ctx.shell, nodes=ctx.nodes)
        ctx.cache["varscan"] = scan
    return scan


# ----------------------------------------------------------------------
# SC2034: unused variables

@tree_check
def check_unused_assignments(ctx, root):
    scan = get_varscan(ctx)
    referenced = set()
    prefixes = []
    for ref in scan.refs:
        if ref.kind == "prefix":
            prefixes.append(ref.name)
        else:
            referenced.add(ref.name)
    exported = {a.name for a in scan.assigns if a.exported}
    first_assign = {}
    for a in scan.assigns:
        if a.kind == "checked":
            referenced.add(a.name)
            continue
        if _is_env_prefix_assignment(a.node):
            referenced.add(a.name)
            continue
        if a.name not in first_assign:
            first_assign[a.name] = a
    for name, a in sorted(first_assign.items(),
                          key=lambda kv: kv[1].node.pos):
        if name in referenced or name in exported:
            continue
        if name.startswith("_"):
            continue
        if name in INTERNAL_VARIABLES or not NAME_RE.match(name):
            continue
        if any(name.startswith(p) for p in prefixes):
            continue
        ctx.warn(a.node, 2034, "%s appears unused. Verify use (or export"
                 " if used externally)." % name)


# ----------------------------------------------------------------------
# SC2154 / SC2153: referenced but not assigned

@tree_check
def check_unassigned_references(ctx, root):
    scan = get_varscan(ctx)
    assigned = {a.name for a in scan.assigns}
    written = sorted(a.name for a in scan.assigns
                     if a.kind != "checked" and NAME_RE.match(a.name))
    seen = set()
    for ref in scan.refs:
        name = ref.name
        if name in seen:
            continue
        if not NAME_RE.match(name):
            continue
        if name in assigned or name in INTERNAL_VARIABLES:
            continue
        if ref.kind in ("guarded", "index-of-other", "prefix"):
            seen.add(name)
            continue
        seen.add(name)
        if name.lower() == name or any(c.islower() for c in name):
            match = _best_match(name, written)
            tip = ""
            if name in COMMON_COMMANDS_HINT:
                tip = ' (for output from commands, use "$(%s ...)" )' % name
            elif match:
                tip = " (did you mean '%s'?)" % match
            ctx.warn(ref.node, 2154,
                     "%s is referenced but not assigned%s." % (name, tip))
        else:
            match = _best_match(name, written)
            if match:
                ctx.info(ref.node, 2153, "Possible misspelling: %s may not"
                         " be assigned. Did you mean %s?" % (name, match))


def _is_env_prefix_assignment(node):
    """FOO=bar somecommand: the assignment is for the command's env."""
    if node.kind != "T_Assignment":
        return False
    parent = node.parent
    if parent is None or parent.kind != "T_SimpleCommand":
        return False
    if node not in parent.assigns or not parent.words:
        return False
    from ..parser import literal_text
    cmd = literal_text(parent.words[0])
    if cmd:
        cmd = cmd.rsplit("/", 1)[-1]
    return cmd not in ("declare", "typeset", "local", "export", "readonly")


def _best_match(var, candidates):
    best = None
    best_score = 99
    for c in candidates:
        if c == var:
            continue
        if c.lower() == var.lower():
            score = 1
        elif abs(len(c) - len(var)) > 2:
            continue
        else:
            score = levenshtein(var, c)
        if score < best_score:
            best, best_score = c, score
    if best is None:
        return None
    if len(best) > 7 and best_score <= 2:
        return best
    if len(best) > 3 and best_score <= 1:
        return best
    return None


# ----------------------------------------------------------------------
# SC2004: $ on arithmetic variables

@node_check("TA_Expansion")
def check_arithmetic_deref(ctx, node):
    if len(node.parts) != 1 or node.parts[0].kind != "T_DollarBraced":
        return
    braced = node.parts[0]
    content = braced.content
    name = braced_reference(content)
    if not NAME_RE.match(name):
        return
    if braced_modifier(content) or content.startswith(("#", "!")):
        return
    if "[" in content:
        return
    if _in_let(node):
        return
    ctx.style(braced, 2004, "$/${} is unnecessary on arithmetic"
              " variables.")


@node_check("T_Assignment")
def check_assignment_index_deref(ctx, node):
    # a[$i]=foo for indexed arrays
    indices = node.get("indices")
    if not indices:
        return
    scan = get_varscan(ctx)
    if node.name in scan.assoc_arrays:
        return
    for idx in indices:
        if isinstance(idx, str) \
                and re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?",
                                 idx.strip()):
            ctx.style(node, 2004, "$/${} is unnecessary on arithmetic"
                      " variables.")


def _in_let(node):
    for a in ancestors(node):
        if a.kind == "T_SimpleCommand":
            name = literal_text(a.words[0]) if a.words else None
            return name == "let"
        if a.kind in ("T_Arithmetic", "T_DollarArithmetic", "T_Script",
                      "T_Condition"):
            return False
    return False


@node_check("T_Arithmetic", "T_DollarArithmetic")
def check_array_index_deref(ctx, node):
    # (( a[$i] )) -- $ on the index variable
    scan = get_varscan(ctx)
    for n in walk(node):
        if n.kind != "TA_Variable":
            continue
        if n.name in scan.assoc_arrays:
            continue
        for idx in n.get("indices", ()):
            if idx.kind == "TA_Expansion" and len(idx.parts) == 1 \
                    and idx.parts[0].kind == "T_DollarBraced":
                content = idx.parts[0].content
                if NAME_RE.match(braced_reference(content)) \
                        and not braced_modifier(content) \
                        and not content.startswith(("#", "!")):
                    ctx.style(idx.parts[0], 2004, "$/${} is unnecessary on"
                              " arithmetic variables.")


# ----------------------------------------------------------------------
# SC2128 / SC2178 / SC2179: arrays used as strings

@tree_check
def check_array_without_index(ctx, root):
    scan = get_varscan(ctx)
    events = []  # (pos, type, name, node)
    for a in scan.assigns:
        if not NAME_RE.match(a.name):
            continue
        node = a.node
        if node.kind == "T_Assignment":
            value = node.get("value")
            is_arr = value is not None and value.kind == "T_Array"
            if node.get("indices"):
                is_arr = True
            events.append((node.end, "array" if is_arr else "string",
                           a.name, node, a.append))
        elif a.is_array:
            events.append((node.end, "array", a.name, node, False))
    for ref in scan.refs:
        node = ref.node
        if node.kind != "T_DollarBraced":
            continue
        content = node.content
        if content != ref.name:
            continue  # only plain $var / ${var}
        events.append((node.pos, "ref", ref.name, node, False))
    events.sort(key=lambda e: e[0])
    arrays = set(INTERNAL_ARRAYS)
    warned = set()
    for pos, etype, name, node, append in events:
        if etype == "array":
            arrays.add(name)
        elif etype == "string":
            if name in arrays:
                if (name, pos) in warned:
                    continue
                warned.add((name, pos))
                if append:
                    ctx.warn(node, 2179, 'Use array+=("item") to append'
                             " items to an array.")
                else:
                    ctx.warn(node, 2178, "Variable was used as an array"
                             " but is now assigned a string.")
                arrays.discard(name)
        else:
            if name in arrays:
                if name in warned:
                    continue
                warned.add(name)
                ctx.warn(node, 2128, "Expanding an array without an index"
                         " only gives the first element.")


# ----------------------------------------------------------------------
# SC2155: declare and assign separately

@node_check("T_SimpleCommand")
def check_masked_returns(ctx, node):
    if not node.words or not node.assigns:
        return
    name = literal_text(node.words[0])
    if name:
        name = name.rsplit("/", 1)[-1]
    if name not in ("declare", "typeset", "local", "readonly", "export"):
        return
    flags = ""
    for w in node.words[1:]:
        t = literal_text(w)
        if t and t.startswith("-"):
            flags += t[1:]
    is_scoped = _in_scoped_function(ctx, node)
    is_local = (name in ("local", "declare", "typeset")
                and "g" not in flags and is_scoped)
    is_readonly = name == "readonly" or "r" in flags
    if is_local and is_readonly:
        return
    from ..astlib import expanded_parts
    for assign in node.assigns:
        value = assign.get("value")
        if value is None:
            continue
        for p in expanded_parts(value):
            if p.kind in ("T_DollarExpansion", "T_Backticked",
                          "T_DollarBraceCommandExpansion"):
                ctx.warn(assign, 2155, "Declare and assign separately to"
                         " avoid masking return values.")
                break
        else:
            continue


def _in_scoped_function(ctx, node):
    for a in ancestors(node):
        if a.kind == "T_BatsTest":
            return True
        if a.kind == "T_Function":
            if ctx.shell == "ksh":
                return a.get("keyword_form", False)
            return True
    return False
