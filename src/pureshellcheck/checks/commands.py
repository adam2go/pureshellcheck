"""Command-specific checks (useless cat, pipe pitfalls, printf, etc.)."""

import re

from ..analyzer import node_check, tree_check
from ..astlib import is_constant, word_parts
from ..parser import literal_text, quoted_literal_text
from ..shast import ancestors, walk
from .quoting import may_become_multiple_args, will_split


def simple_words(ctx, cmd):
    return [literal_text(w) for w in cmd.words]


def first_word_basename(cmd):
    if cmd.kind != "T_SimpleCommand" or not cmd.words:
        return None
    name = literal_text(cmd.words[0])
    return name.rsplit("/", 1)[-1] if name else None


def pipeline_command_names(ctx, pipeline):
    out = []
    for c in pipeline.commands:
        out.append(ctx.command_basename(c) if c.kind == "T_SimpleCommand"
                   else None)
    return out


def word_approx(word):
    """Loose textual rendering of a word (expansions become empty)."""
    parts = word.parts if word.kind in ("T_NormalWord", "T_DoubleQuoted",
                                        "T_DollarDoubleQuoted") \
        else [word]
    out = []
    for p in parts:
        k = p.kind
        if k == "T_Literal":
            out.append(p.text)
        elif k in ("T_SingleQuoted", "T_DollarSingleQuoted"):
            out.append(p.text)
        elif k in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            out.append(word_approx(p))
        elif k == "T_Glob":
            out.append(p.text)
        else:
            out.append("")
    return "".join(out)


def flags_of(ctx, cmd):
    return [f for f, w in ctx.flags(cmd)]


# ----------------------------------------------------------------------
# SC2002: useless cat

@node_check("T_Pipeline")
def check_uuoc(ctx, node):
    first = node.commands[0]
    if first.kind != "T_SimpleCommand":
        return
    if ctx.command_basename(first) != "cat":
        return
    args = ctx.argument_words(first)
    if len(args) != 1:
        return
    word = args[0]
    lit = literal_text(word)
    if lit is not None and lit.startswith("-"):
        return
    if may_become_multiple_args(word):
        return
    # `cat $var` may expand to multiple files or flags; only warn when the
    # argument is a single fixed file
    if any(p.kind not in ("T_Literal", "T_SingleQuoted", "T_DoubleQuoted",
                          "T_DollarSingleQuoted")
           for p in word_parts(word)):
        return
    for p in word_parts(word):
        if p.kind == "T_Literal" and not is_constant(word):
            return
    if not is_constant(word):
        # quoted expansions are fine to warn about, unquoted are not
        quoted = word_parts(word)
        if not all(p.kind in ("T_DoubleQuoted", "T_SingleQuoted",
                              "T_DollarSingleQuoted") for p in quoted):
            return
        for p in quoted:
            if p.kind == "T_DoubleQuoted":
                for q in p.parts:
                    if q.kind == "T_DollarBraced" \
                            and q.content.startswith("!"):
                        return
    ctx.style(word, 2002, "Useless cat. Consider 'cmd < file | ..' or"
              " 'cmd file | ..' instead.")


# ----------------------------------------------------------------------
# SC2009/2010/2011/2012/2038/2126: pipe pitfalls

@node_check("T_Pipeline")
def check_pipe_pitfalls(ctx, node):
    cmds = node.commands
    names = []
    for c in cmds:
        names.append(first_word_basename(c))

    def find_seq(seq):
        hits = []
        for i in range(len(names) - len(seq) + 1):
            if all(s == "?" or names[i + j] == s
                   for j, s in enumerate(seq)):
                hits.append(i)
        return hits

    def args_approx(cmd):
        return [word_approx(w) for w in cmd.words[1:]]

    def has_short(arglist, ch):
        return any(a.startswith("-") and not a.startswith("--") and ch in a
                   for a in arglist)

    def has_long(arglist, name):
        return any(a.lstrip("-").startswith(name) for a in arglist)

    for i in find_seq(["find", "xargs"]):
        find_cmd, xargs_cmd = cmds[i], cmds[i + 1]
        all_args = args_approx(xargs_cmd) + args_approx(find_cmd)
        if not (has_short(all_args, "0") or has_long(all_args, "null")
                or has_long(all_args, "print0")
                or has_long(all_args, "printf")):
            ctx.warn(find_cmd, 2038, "Use 'find .. -print0 | xargs -0 ..'"
                     " or 'find .. -exec .. +' to allow non-alphanumeric"
                     " filenames.")

    for i in find_seq(["ps", "grep"]):
        ps_cmd = cmds[i]
        ps_flags = flags_of(ctx, ps_cmd)
        if not any(f in ("p", "pid", "q", "quick-pid") for f in ps_flags):
            ctx.info(ps_cmd, 2009, "Consider using pgrep instead of"
                     " grepping ps output.")

    for i in find_seq(["grep", "wc"]):
        grep_cmd, wc_cmd = cmds[i], cmds[i + 1]
        grep_flags = flags_of(ctx, grep_cmd)
        wc_flags = flags_of(ctx, wc_cmd)
        if not (any(f in ("l", "files-with-matches", "L",
                          "files-without-matches", "o", "only-matching",
                          "r", "R", "recursive", "A", "after-context",
                          "B", "before-context") for f in grep_flags)
                or any(f in ("m", "chars", "w", "words", "c", "bytes",
                             "L", "max-line-length") for f in wc_flags)
                or not wc_flags):
            ctx.style(grep_cmd, 2126, "Consider using 'grep -c' instead"
                      " of 'grep|wc -l'.")

    did_ls = False
    for i in find_seq(["ls", "grep"]):
        did_ls = True
        ctx.warn(cmds[i], 2010, "Don't use ls | grep. Use a glob or a"
                 " for loop with a condition to allow non-alphanumeric"
                 " filenames.")
    for i in find_seq(["ls", "xargs"]):
        did_ls = True
        ctx.warn(cmds[i], 2011, "Use 'find .. -print0 | xargs -0 ..' or"
                 " 'find .. -exec .. +' to allow non-alphanumeric"
                 " filenames.")
    if not did_ls:
        for i in find_seq(["ls", "?"]):
            if not has_short(args_approx(cmds[i]), "N"):
                ctx.info(cmds[i], 2012, "Use find instead of ls to better"
                         " handle non-alphanumeric filenames.")


# ----------------------------------------------------------------------
# SC2005: echo $(cmd); SC2116: cmd $(echo foo)

@node_check("T_SimpleCommand")
def check_uuoe_cmd(ctx, node):
    if first_word_basename(node) != "echo":
        return
    args = node.words[1:]
    if len(args) != 1:
        return
    if _is_just_command_output(args[0]):
        ctx.style(node, 2005, "Useless echo? Instead of 'echo $(cmd)',"
                  " just use 'cmd'.")


@node_check("T_DollarExpansion", "T_Backticked")
def check_uuoe_var(ctx, node):
    if len(node.commands) != 1:
        return
    cmd = node.commands[0]
    if cmd.kind != "T_SimpleCommand" or cmd.get("redirects"):
        return
    if first_word_basename(cmd) != "echo":
        return
    args = cmd.words[1:]
    if not args:
        return
    lit0 = literal_text(args[0])
    if lit0 is not None and lit0.startswith("-"):
        return
    if len(args) == 1 and _is_just_command_output(args[0]):
        return
    for a in args:
        if not _could_be_optimized(a):
            return
    ctx.style(node, 2116, "Useless echo? Instead of 'cmd $(echo foo)',"
              " just use 'cmd foo'.")


def _could_be_optimized(node):
    k = node.kind
    if k in ("T_Glob", "T_Extglob", "T_BraceExpansion"):
        return False
    if k in ("T_NormalWord", "T_DoubleQuoted"):
        return all(_could_be_optimized(p) for p in node.parts)
    return True


def _is_just_command_output(word):
    parts = word_parts(word)
    if len(parts) != 1:
        return False
    p = parts[0]
    if p.kind == "T_DoubleQuoted" and len(p.parts) == 1:
        p = p.parts[0]
    if p.kind not in ("T_DollarExpansion", "T_Backticked"):
        return False
    return any(_has_words(c) for c in p.commands)


def _has_words(node):
    if node.kind == "T_SimpleCommand":
        return bool(node.words)
    return True


# ----------------------------------------------------------------------
# SC2162: read without -r

@node_check("T_SimpleCommand")
def check_read_without_r(ctx, node):
    if ctx.command_basename(node) != "read":
        return
    flags = ctx.flags(node)
    names = [f for f, w in flags]
    if "r" in names:
        return
    # read -t 0 only checks whether input is available
    args = [literal_text(w) for w in ctx.argument_words(node)]
    for i, a in enumerate(args):
        if a == "-t" and i + 1 < len(args) and args[i + 1] == "0":
            return
        if a and a.startswith("-t") and a[2:] == "0":
            return
    ctx.info(node, 2162, "read without -r will mangle backslashes.")


# ----------------------------------------------------------------------
# SC2164: unchecked cd/pushd/popd

SAFE_DIR_RE = re.compile(r"^/*((\.|\.\.)/+)*(\.|\.\.)?$")
SET_E_SHEBANG_RE = re.compile(r"[ \t]-[^-\s]*e")


def has_set_e(ctx):
    cached = ctx.cache.get("has_set_e")
    if cached is not None:
        return cached
    result = False
    shebang = ctx.root.get("shebang") or ""
    if SET_E_SHEBANG_RE.search(shebang):
        result = True
    else:
        for node in ctx.nodes:
            if node.kind != "T_SimpleCommand" or not node.words:
                continue
            if first_word_basename(node) != "set":
                continue
            words = [literal_text(w) for w in node.words[1:]]
            if any(w == "errexit" for w in words) or \
                    any(w and w.startswith("-") and not w.startswith("--")
                        and "e" in w for w in words):
                result = True
                break
    ctx.cache["has_set_e"] = result
    return result


def is_condition(node):
    """Is this node's exit status checked by a conditional construct?"""
    prev = node
    for a in ancestors(node):
        k = a.kind
        if k == "T_BatsTest":
            return True
        if k in ("T_AndIf", "T_OrIf"):
            if prev is a.left:
                return True
        elif k == "T_IfExpression":
            for cond, _body in a.branches:
                if cond and prev is cond[-1]:
                    return True
        elif k in ("T_WhileExpression", "T_UntilExpression"):
            if a.condition and prev is a.condition[-1]:
                return True
        elif k in ("T_Banged", "T_Pipeline", "T_Timed"):
            pass
        elif k in ("T_Script", "T_SimpleCommand", "T_DollarExpansion",
                   "T_Backticked", "T_Subshell", "T_BraceGroup",
                   "T_Function"):
            return False
        prev = a
    return False


@node_check("T_SimpleCommand")
def check_unchecked_cd(ctx, node):
    name = ctx.command_basename(node)
    if name not in ("cd", "pushd", "popd"):
        return
    if has_set_e(ctx):
        return
    args = ctx.argument_words(node)
    flags = [f for f, w in ctx.flags(node)]
    if name in ("pushd", "popd") and "n" in flags:
        return
    non_flag = [literal_text(w) for w in args
                if not (literal_text(w) or "").startswith("-")
                or literal_text(w) is None]
    if len(args) == 1 and len(non_flag) == 1 and non_flag[0] is not None \
            and SAFE_DIR_RE.match(non_flag[0]):
        return
    if is_condition(node):
        return
    if _is_last_command_in_function(node):
        return
    ctx.warn(node, 2164, "Use '%s ... || exit' or '%s ... || return' in"
             " case %s fails." % (name, name, name))


def _is_last_command_in_function(node):
    prev = node
    for a in ancestors(node):
        if a.kind == "T_BraceGroup":
            parent = a.parent
            if parent is not None and parent.kind == "T_Function":
                cmds = a.commands
                return bool(cmds) and cmds[-1] is prev
        if a.kind in ("T_Script", "T_Subshell", "T_DollarExpansion"):
            return False
        prev = a
    return False


# ----------------------------------------------------------------------
# SC2059 / SC2182 / SC2183: printf

PRINTF_FORMAT_RE = re.compile(
    r"#?-?\+? ?0?(\*|\d*)\.?(\d*|\*)(?:hh|h|ll|l|q|L|j|z|Z|t)?"
    r"([diouxXfFeEgGaAcsbqQSC])")


def printf_formats(string):
    out = []
    i = 0
    n = len(string)
    while i < n:
        c = string[i]
        if c != "%":
            i += 1
            continue
        if string[i + 1:i + 2] == "%":
            i += 2
            continue
        if string[i + 1:i + 2] == "(":
            end = string.find(")", i + 2)
            if end == -1 or end + 1 >= n:
                return "".join(out) if end == -1 else "".join(out)
            out.append(string[end + 1])
            i = end + 2
            continue
        m = PRINTF_FORMAT_RE.match(string, i + 1)
        if m:
            if m.group(1) == "*":
                out.append("*")
            if m.group(2) == "*":
                out.append("*")
            out.append(m.group(3))
            i = m.end()
        else:
            if i + 1 < n:
                out.append(string[i + 1])
            i += 2
    return "".join(out)


@node_check("T_SimpleCommand")
def check_printf_var(ctx, node):
    if ctx.command_basename(node) != "printf":
        return
    args = list(ctx.argument_words(node))
    while args:
        lit = literal_text(args[0])
        if lit == "--":
            args = args[1:]
        elif lit == "-v":
            args = args[2:]
        elif lit and lit.startswith("-v"):
            args = args[1:]
        else:
            break
    if not args:
        return
    fmt, params = args[0], args[1:]
    lit = quoted_literal_text(fmt)
    if lit is not None:
        formats = printf_formats(lit)
        fcount, acount = len(formats), len(params)
        if acount == 0 and fcount == 0:
            pass
        elif fcount == 0 and acount > 0:
            ctx.err(fmt, 2182, "This printf format string has no variables."
                    " Other arguments are ignored.")
        elif any(may_become_multiple_args(p) or not is_constant(p)
                 and _has_glob_part(p) for p in params):
            pass
        elif acount < fcount and all(c == "T" for c in formats[acount:]):
            pass
        elif acount > 0 and acount % fcount == 0:
            pass
        elif any(_has_glob_part(p) for p in params):
            pass
        else:
            ctx.warn(fmt, 2183, "This format string has %d %s, but is"
                     " passed %d %s."
                     % (fcount, "variable" if fcount == 1 else "variables",
                        acount,
                        "argument" if acount == 1 else "arguments"))
    approx = word_approx(fmt)
    if "%" not in approx and not is_constant(fmt):
        ctx.info(fmt, 2059, "Don't use variables in the printf format"
                 " string. Use printf '..%s..' \"$foo\".")


def _has_glob_part(word):
    return any(p.kind in ("T_Glob", "T_Extglob", "T_BraceExpansion")
               for p in word_parts(word))


# ----------------------------------------------------------------------
# SC2181: checking $? indirectly

@node_check("TC_Binary", "TA_Binary", "TA_Unary", "TA_Sequence")
def check_return_against_zero(ctx, node):
    k = node.kind

    def is_exit_code(t):
        if t is None:
            return False
        if t.kind == "TA_Expansion":
            return len(t.parts) == 1 \
                and t.parts[0].kind == "T_DollarBraced" \
                and t.parts[0].content == "?"
        from ..astlib import expanded_parts
        parts = expanded_parts(t) if t.kind == "T_NormalWord" else []
        return len(parts) == 1 and parts[0].kind == "T_DollarBraced" \
            and parts[0].content == "?"

    def is_zero(t):
        if t is None:
            return False
        if t.kind == "TA_Literal":
            return t.value == "0"
        return quoted_literal_text(t) == "0"

    target = None
    for_success = True
    if k == "TC_Binary":
        if is_zero(node.rhs) and is_exit_code(node.lhs):
            target = node.lhs
            for_success = node.op not in ("-gt", "-ne", "!=")
        elif is_zero(node.lhs) and is_exit_code(node.rhs):
            target = node.rhs
            for_success = node.op not in ("-ne", "!=")
    elif k == "TA_Binary":
        if node.op in (">", "<", ">=", "<=", "==", "!="):
            if is_zero(node.right) and is_exit_code(node.left):
                target = node.left
                for_success = node.op not in (">", "!=")
            elif is_zero(node.left) and is_exit_code(node.right):
                target = node.right
                for_success = node.op != "!="
    elif k == "TA_Unary":
        if node.op == "!" and is_exit_code(node.operand):
            target = node.operand
            for_success = False
    elif k == "TA_Sequence":
        return  # handled via T_Arithmetic below
    if target is None:
        return
    if not _is_only_test_in_command(node):
        return
    if _is_first_command_in_function(ctx, node):
        return
    ctx.style(target, 2181, "Check exit code directly with e.g. 'if %smycmd;',"
              " not indirectly with $?." % ("" if for_success else "! "))


@node_check("T_Arithmetic")
def check_bare_exit_code(ctx, node):
    # (( $? )) and (( ! $? ))
    expr = node.expr
    while expr is not None and expr.kind in ("TA_Parenthesis",):
        expr = expr.expr
    inverted = False
    while expr is not None and expr.kind == "TA_Unary" and expr.op == "!":
        inverted = not inverted
        expr = expr.operand
        while expr is not None and expr.kind == "TA_Parenthesis":
            expr = expr.expr
    if expr is not None and expr.kind == "TA_Expansion" \
            and len(expr.parts) == 1 \
            and expr.parts[0].kind == "T_DollarBraced" \
            and expr.parts[0].content == "?":
        if _is_first_command_in_function(ctx, node):
            return
        ctx.style(expr, 2181, "Check exit code directly with e.g."
                  " 'if %smycmd;', not indirectly with $?."
                  % ("" if inverted else "! "))


def _is_only_test_in_command(node):
    prev = node
    for a in ancestors(node):
        k = a.kind
        if k == "T_Condition":
            return True
        if k == "T_Arithmetic":
            return True
        if k in ("TC_Unary", "TA_Unary"):
            if a.op.lstrip("|") != "!":
                return False
            prev = a
            continue
        if k in ("TC_Group", "TA_Parenthesis"):
            prev = a
            continue
        if k == "TA_Sequence":
            if len(a.exprs) != 1:
                return False
            prev = a
            continue
        return False
    return False


def _is_first_command_in_function(ctx, node):
    func = None
    for a in ancestors(node):
        if a.kind == "T_Function":
            func = a
            break
        if a.kind == "T_Script":
            return False
    if func is None:
        return False
    cmd = None
    for a in [node] + list(ancestors(node)):
        if a.kind in ("T_Condition", "T_Arithmetic"):
            cmd = a
            break
    first = _first_command_in(func.body)
    return first is not None and cmd is not None and first is cmd


def _first_command_in(node):
    k = node.kind
    if k in ("T_BraceGroup", "T_Subshell"):
        return _first_command_in(node.commands[0]) if node.commands else None
    if k in ("T_AndIf", "T_OrIf"):
        return _first_command_in(node.left)
    if k == "T_Pipeline":
        return _first_command_in(node.commands[0])
    if k in ("T_Banged", "T_Timed"):
        return _first_command_in(node.command)
    if k == "T_IfExpression":
        cond = node.branches[0][0]
        return _first_command_in(cond[0]) if cond else node
    return node


# ----------------------------------------------------------------------
# SC2064: trap with prematurely expanded contents

@node_check("T_SimpleCommand")
def check_trap_quotes(ctx, node):
    if ctx.command_basename(node) != "trap":
        return
    args = ctx.argument_words(node)
    if len(args) < 2:
        return
    word = args[0]
    for p in word_parts(word):
        if p.kind == "T_DoubleQuoted":
            for q in p.parts:
                if q.kind in ("T_DollarBraced", "T_DollarExpansion",
                              "T_Backticked", "T_DollarArithmetic"):
                    ctx.warn(q, 2064, "Use single quotes, otherwise this"
                             " expands now rather than when signalled.")
                    return


# ----------------------------------------------------------------------
# SC2065: test redirects

@node_check("T_SimpleCommand")
def check_test_redirects(ctx, node):
    if ctx.command_basename(node) != "test":
        return
    for r in node.get("redirects", ()):
        op = r.op
        if isinstance(op, str) or op.kind != "T_IoFile":
            continue
        if r.get("fd") == "2":
            continue
        if op.op in (">", "<"):
            ctx.warn(r, 2065, "This is interpreted as a shell file"
                     " redirection, not a comparison.")


# ----------------------------------------------------------------------
# SC2114 / SC2115: catastrophic rm

IMPORTANT_PATH_BASES = [
    "", "/bin", "/etc", "/home", "/mnt", "/usr", "/usr/share", "/usr/local",
    "/var", "/lib", "/dev", "/media", "/boot", "/lib64", "/usr/bin",
]
IMPORTANT_PATHS = frozenset(
    base + suffix
    for base in IMPORTANT_PATH_BASES
    for suffix in ("", "/", "/*", "/*/*")
    if base + suffix
)


@node_check("T_SimpleCommand")
def check_catastrophic_rm(ctx, node):
    if ctx.command_basename(node) != "rm":
        return
    if not any(f in ("r", "R", "recursive", "f" "r")
               for f in flags_of(ctx, node)):
        if not any(f in ("r", "R", "recursive")
                   for f in flags_of(ctx, node)):
            return
    for word in ctx.argument_words(node):
        lit = literal_text(word)
        if lit is not None and lit.startswith("-"):
            continue
        for variant, is_literal in _rm_paths(word):
            if variant is None:
                continue
            path = _fix_path(variant)
            if path in IMPORTANT_PATHS:
                if is_literal:
                    ctx.warn(word, 2114, "Warning: deletes a system"
                             " directory.")
                else:
                    ctx.warn(word, 2115, 'Use "${var:?}" to ensure this'
                             " never expands to %s ." % path)
                break


def _fix_path(path):
    path = re.sub(r"/+", "/", path)
    path = re.sub(r"\*+", "*", path)
    if path != "/":
        path = path.rstrip("/")
    return path


def _rm_paths(word, depth=0):
    """Yield (potential_path, is_fully_literal) for each brace variant.

    potential_path is None for variants containing a :?-guarded expansion.
    """
    parts = word.parts if word.kind in ("T_NormalWord", "T_DoubleQuoted",
                                        "T_DollarDoubleQuoted") \
        else [word]
    variants = [("", True)]
    for p in parts:
        k = p.kind
        add = None
        if k in ("T_Literal", "T_SingleQuoted", "T_DollarSingleQuoted"):
            add = [(p.text, True)]
        elif k in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            sub = list(_rm_paths(p, depth + 1))
            add = sub
        elif k == "T_Glob":
            add = [(p.text, False)]
        elif k == "T_DollarBraced":
            content = p.content
            if any(g in content for g in (":?", ":-", ":=")):
                add = [(None, False)]
            else:
                add = [("", False)]
        elif k == "T_BraceExpansion":
            if depth > 3:
                add = [("", False)]
            else:
                alts = []
                for alt_text in _expand_brace_text(p.text):
                    from ..parser import Parser, ParseError
                    try:
                        sub = Parser(alt_text)
                        w = sub.read_word()
                        if w is not None and sub.at_end():
                            alts.extend(_rm_paths(w, depth + 1))
                        else:
                            alts.append((alt_text, True))
                    except ParseError:
                        alts.append((alt_text, True))
                add = alts or [("", False)]
        else:
            add = [("", False)]
        new = []
        for base, base_lit in variants:
            for text, lit in add:
                if base is None or text is None:
                    new.append((None, False))
                else:
                    new.append((base + text, base_lit and lit))
                if len(new) >= 64:
                    break
            if len(new) >= 64:
                break
        variants = new
    return variants


def _expand_brace_text(text):
    inner = text[1:-1]
    items = []
    depth = 0
    start = 0
    for i, c in enumerate(inner):
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == "," and depth == 0:
            items.append(inner[start:i])
            start = i + 1
    items.append(inner[start:])
    if len(items) == 1 and ".." in items[0]:
        items = items[0].split("..")[:2]
    return items


# ----------------------------------------------------------------------
# SC2174: mkdir -pm

@node_check("T_SimpleCommand")
def check_mkdir_dash_pm(ctx, node):
    if ctx.command_basename(node) != "mkdir":
        return
    flags = ctx.flags(node)
    names = [f for f, w in flags]
    if not ("p" in names or "parents" in names):
        return
    mode_word = None
    for f, w in flags:
        if f in ("m", "mode"):
            mode_word = w
    if mode_word is None:
        return
    args = ctx.argument_words(node)
    safe_re = re.compile(r"^(\.\.?/)+[^/]+$")
    for w in args[1:]:
        lit = literal_text(w)
        if lit is None:
            could = True
        else:
            could = "/" in lit and not safe_re.match(lit)
        if could:
            ctx.warn(mode_word, 2174, "When used with -p, -m only applies"
                     " to the deepest directory.")
            return


# ----------------------------------------------------------------------
# SC2188 / SC2189: redirection without a command

@node_check("T_SimpleCommand")
def check_redirected_nowhere(ctx, node):
    if node.words or node.assigns:
        return
    redirects = node.get("redirects", ())
    if not redirects:
        return
    parent = node.parent
    # var=$(< file) idiom
    if parent is not None and parent.kind in ("T_DollarExpansion",
                                              "T_Backticked") \
            and len(parent.commands) == 1:
        if all(not isinstance(r.op, str) and r.op.kind == "T_IoFile"
               and r.op.op == "<" for r in redirects):
            return
    in_pipeline = parent is not None and parent.kind == "T_Pipeline"
    if in_pipeline:
        ctx.err(node, 2189, "You can't have | between this redirection"
                " and the command it should apply to.")
    else:
        ctx.warn(node, 2188, "This redirection doesn't have a command."
                 " Move to its command (or use 'true' as no-op).")


# ----------------------------------------------------------------------
# SC2148 (+2187, 2239, 2246): shebang

@tree_check
def check_shebang(ctx, root):
    shebang = root.get("shebang")
    has_shell_directive = any(d.kind == "shell" for d in ctx.directives)
    if shebang is None or not shebang.startswith("#!"):
        if not has_shell_directive and ctx.explicit_shell is None:
            f_pos = 0
            ctx.report(root, 2148, "error",
                       "Tips depend on target shell and yours is unknown."
                       " Add a shebang or a 'shell' directive.",
                       pos=f_pos, end=min(1, len(ctx.source)))
        return
    m = re.match(r"#!\s*(\S+)(\s+(\S+))?", shebang)
    if not m:
        return
    interpreter = m.group(1)
    basename = interpreter.rsplit("/", 1)[-1]
    if basename == "env" and m.group(3):
        basename = m.group(3).rsplit("/", 1)[-1]
    elif basename == "busybox" and m.group(3):
        return  # busybox sh/ash handled as ash without warnings
    if interpreter.endswith("/"):
        ctx.report(root, 2246, "error",
                   "This shebang specifies a directory. Ensure the"
                   " interpreter is a file.",
                   pos=0, end=len(shebang))
        return
    if not interpreter.startswith("/") and basename == interpreter \
            not in ("env",):
        if "/" in interpreter and not has_shell_directive:
            pass
    if not interpreter.startswith("/") and "/" in interpreter \
            and not has_shell_directive:
        ctx.report(root, 2239, "error",
                   "Ensure the shebang uses an absolute path to the"
                   " interpreter.", pos=0, end=len(shebang))
    if basename == "ash" and not has_shell_directive:
        ctx.report(root, 2187, "info",
                   "Ash scripts will be checked as Dash. Add"
                   " '# shellcheck shell=dash' to silence.",
                   pos=0, end=len(shebang))


# ----------------------------------------------------------------------
# SC2003: expr is antiquated

EXPR_EXCEPTIONS = frozenset({":", "<", ">", "<=", ">=",
                             "match", "length", "substr", "index"})

EXPR_OP_MSG = {
    "match": "'expr match' has unspecified results. Prefer"
             " 'expr str : regex'.",
    "length": "'expr length' has unspecified results. Prefer ${#var}.",
    "substr": "'expr substr' has unspecified results. Prefer 'cut' or"
              " ${var#???}.",
    "index": "'expr index' has unspecified results. Prefer"
             " x=${var%%[chars]*}; $((${#x}+1)).",
}


@node_check("T_SimpleCommand")
def check_expr(ctx, node):
    if ctx.command_basename(node) != "expr":
        return
    args = list(ctx.argument_words(node))
    lits = [quoted_literal_text(w) for w in args]
    raw_lits = [literal_text(w) for w in args]

    if all(lit is None or lit not in EXPR_EXCEPTIONS for lit in raw_lits):
        ctx.style(node, 2003, "expr is antiquated. Consider rewriting this"
                  " using $((..)), ${} or [[ ]].")

    def check_op(word):
        lit = literal_text(word)
        if lit in EXPR_OP_MSG:
            ctx.warn(word, 2308, EXPR_OP_MSG[lit])

    if len(args) == 3:
        lhs, op, rhs = args
        check_op(lhs)
        op_parts = word_parts(op)
        if len(op_parts) == 1 and op_parts[0].kind == "T_Glob" \
                and op_parts[0].text == "*":
            ctx.err(op, 2304, "* must be escaped to multiply: \\*."
                    " Modern $((x * y)) avoids this issue.")
        elif literal_text(op) == ":" and _has_glob_part(rhs):
            ctx.warn(rhs, 2305, "Quote regex argument to expr to avoid"
                     " it expanding as a glob.")
    elif len(args) == 1:
        if not will_split(args[0]) \
                and not may_become_multiple_args(args[0]):
            ctx.warn(args[0], 2307, "'expr' expects 3+ arguments but sees"
                     " 1. Make sure each operator/operand is a separate"
                     " argument, and escape <>&|.")
    elif len(args) == 2:
        if raw_lits[0] != "length" and not will_split(args[0]) \
                and not will_split(args[1]) \
                and not any(may_become_multiple_args(a) for a in args):
            check_op(args[0])
            ctx.warn(node, 2307, "'expr' expects 3+ arguments, but sees 2."
                     " Make sure each operator/operand is a separate"
                     " argument, and escape <>&|.")
        else:
            check_op(args[0])
            for w in args[1:]:
                if _has_glob_part(w):
                    ctx.warn(w, 2306, "Escape glob characters in arguments"
                             " to expr to avoid pathname expansion.")
    elif args:
        check_op(args[0])
        for w in args[1:]:
            if _has_glob_part(w):
                ctx.warn(w, 2306, "Escape glob characters in arguments"
                         " to expr to avoid pathname expansion.")


# ----------------------------------------------------------------------
# SC2015: shorthand if

@node_check("T_OrIf")
def check_shorthand_if(ctx, node):
    left = node.left
    if left.kind != "T_AndIf":
        return
    # A && B || C
    if _is_ok_shorthand(node.right) or is_condition(node):
        return
    if _is_test_like(left.right):
        return
    ctx.info(node, 2015, "Note that A && B || C is not if-then-else."
             " C may run when A is true.")


def _is_test_like(node):
    k = node.kind
    if k in ("T_Condition", "T_Arithmetic"):
        return True
    if k in ("T_Banged", "T_Timed"):
        return _is_test_like(node.command)
    if k == "T_SimpleCommand":
        return first_word_basename(node) == "test"
    return False


def _is_ok_shorthand(node):
    if node.kind == "T_SimpleCommand":
        if not node.words and node.assigns:
            return True
        name = first_word_basename(node)
        return name in ("echo", "exit", "return", "printf", "true", ":")
    return False


# ----------------------------------------------------------------------
# SC2050 / SC2193: constant conditions

ARITH_TEST_OPS = frozenset({"-eq", "-ne", "-lt", "-le", "-gt", "-ge"})


@node_check("TC_Binary")
def check_constant_conditions(ctx, node):
    cond = None
    for a in ancestors(node):
        if a.kind == "T_Condition":
            cond = a
            break
        if a.kind in ("T_SimpleCommand", "T_Script"):
            break
    if cond is None:
        return
    # in [[ ]], arithmetic comparisons evaluate names as variables
    if node.op in ARITH_TEST_OPS and not cond.single:
        return
    if node.op in ("-nt", "-ot", "-ef"):
        return
    if is_constant(node.lhs) and is_constant(node.rhs):
        ctx.warn(node, 2050, "This expression is constant. Did you forget"
                 " the $ on a variable?")
