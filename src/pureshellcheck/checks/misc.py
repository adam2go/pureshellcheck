"""Assorted smaller checks."""

import re

from ..analyzer import node_check
from ..astlib import word_parts
from ..parser import literal_text, quoted_literal_text
from ..shast import ancestors, walk
from .commands import first_word_basename, is_condition, word_approx


# SC2007: deprecated $[..]

@node_check("T_DollarArithmetic")
def check_dollar_brackets(ctx, node):
    if node.get("deprecated"):
        ctx.style(node, 2007, "Use $((..)) instead of deprecated $[..].")


# SC2035: glob that may become an option

@node_check("T_SimpleCommand")
def check_globs_as_options(ctx, node):
    if len(node.words) < 2:
        return
    name = first_word_basename(node)
    if name in ("echo", "printf"):
        return
    for w in node.words[1:]:
        approx = word_approx(w)
        if approx in ("--", ":::", "::::"):
            break
        parts = word_parts(w)
        if parts and parts[0].kind == "T_Glob" \
                and parts[0].text in ("*", "?"):
            ctx.info(parts[0], 2035, "Use ./*glob* or -- *glob* so names"
                     " with dashes won't become options.")


# SC2103: cd there and back

def command_sequences(node):
    """Statement lists where consecutive-command checks apply."""
    f = node.fields
    if node.kind in ("T_Script", "T_BraceGroup", "T_Subshell"):
        yield f.get("commands", [])
    elif node.kind in ("T_WhileExpression", "T_UntilExpression",
                       "T_ForIn", "T_ForArithmetic", "T_SelectIn"):
        yield f.get("body", [])
    elif node.kind == "T_IfExpression":
        for _cond, body in node.branches:
            yield body
        yield node.else_body


SEQUENCE_KINDS = ("T_Script", "T_BraceGroup", "T_Subshell",
                  "T_WhileExpression", "T_UntilExpression", "T_ForIn",
                  "T_ForArithmetic", "T_SelectIn", "T_IfExpression")


@node_check(*SEQUENCE_KINDS)
def check_cd_and_back(ctx, node):
    from .commands import has_set_e
    if has_set_e(ctx):
        return
    for commands in command_sequences(node):
        candidates = []
        for cmd in commands:
            if cmd.kind == "T_SimpleCommand" \
                    and first_word_basename(cmd) == "cd":
                candidates.append(cmd)
        for a, b in zip(candidates, candidates[1:]):
            if _is_cd_revert(b) and not _is_cd_revert(a):
                ctx.info(b, 2103, "Use a ( subshell ) to avoid having to"
                         " cd back.")
                return


def _is_cd_revert(cmd):
    if len(cmd.words) != 2:
        return False
    return word_approx(cmd.words[1]) in ("..", "-")


# SC2093: exec that won't be the last command

CLEANUP_COMMANDS = frozenset({":", "echo", "exit", "printf", "return"})


def _has_execfail(ctx):
    cached = ctx.cache.get("execfail")
    if cached is None:
        cached = False
        if ctx.shell in ("sh", "dash", "ash"):
            ctx.cache["execfail"] = False
            return False
        for n in ctx.nodes:
            if n.kind == "T_SimpleCommand" and \
                    first_word_basename(n) == "shopt":
                if any(word_approx(w) == "execfail" for w in n.words[1:]):
                    cached = True
                    break
        ctx.cache["execfail"] = cached
    return cached


@node_check(*SEQUENCE_KINDS)
def check_spurious_exec(ctx, node):
    if _has_execfail(ctx):
        return
    in_loop = node.kind in ("T_WhileExpression", "T_UntilExpression",
                            "T_ForIn", "T_ForArithmetic", "T_SelectIn")
    for commands in command_sequences(node):
        cmds = list(commands)
        while cmds and _is_cleanup(cmds[-1]):
            cmds.pop()
        check_until = len(cmds) if in_loop else len(cmds) - 1
        for cmd in cmds[:max(check_until, 0)]:
            if cmd.kind == "T_SimpleCommand" and len(cmd.words) >= 2 \
                    and literal_text(cmd.words[0]) == "exec":
                ctx.warn(cmd, 2093, 'Remove "exec " if script should'
                         " continue after this command.")


def _is_cleanup(cmd):
    if cmd.kind != "T_SimpleCommand":
        return False
    if not cmd.words:
        return bool(cmd.assigns)
    return first_word_basename(cmd) in CLEANUP_COMMANDS


# SC2094: reading and writing the same file in a pipeline

@node_check("T_Pipeline", "T_SimpleCommand")
def check_redirect_to_same(ctx, node):
    if node.kind == "T_SimpleCommand":
        if node.parent is not None and node.parent.kind == "T_Pipeline":
            return
        commands = [node]
    else:
        commands = node.commands
    reads = {}
    writes = {}
    for cmd in commands:
        for r, target, is_write in _redirect_files(ctx, cmd):
            d = writes if is_write else reads
            d.setdefault(target, r)
        if cmd.kind == "T_SimpleCommand" \
                and first_word_basename(cmd) not in ("echo", "printf"):
            for w in cmd.words[1:]:
                text = _file_word_text(w)
                if text:
                    reads.setdefault(text, w)
    for target, r in writes.items():
        if target in reads and target not in ("/dev/null", "/dev/stdin",
                                              "/dev/stdout", "/dev/tty"):
            ctx.info(r, 2094, "Make sure not to read and write the same"
                     " file in the same pipeline.")
            other = reads[target]
            ctx.info(other, 2094, "Make sure not to read and write the"
                     " same file in the same pipeline.")
            return


def _redirect_files(ctx, cmd):
    for r in cmd.get("redirects", ()) or ():
        op = r.op
        if isinstance(op, str) or op.kind != "T_IoFile":
            continue
        text = _file_word_text(op.file)
        if not text:
            continue
        yield r, text, op.op in (">", ">>", "&>", "&>>", ">|")


def _file_word_text(word):
    text = word_approx(word)
    if not text or text.startswith("-"):
        return None
    if "\0" in text:
        return None
    from ..astlib import has_expansions
    if has_expansions(word):
        # render expansions textually so $file == $file matches
        out = []
        for p in word_parts(word):
            if p.kind == "T_DollarBraced":
                out.append("${%s}" % p.content)
            elif p.kind == "T_Literal":
                out.append(p.text)
            elif p.kind in ("T_SingleQuoted", "T_DollarSingleQuoted"):
                out.append(p.text)
            elif p.kind in ("T_DoubleQuoted",):
                for q in p.parts:
                    if q.kind == "T_Literal":
                        out.append(q.text)
                    elif q.kind == "T_DollarBraced":
                        out.append("${%s}" % q.content)
                    else:
                        return None
            else:
                return None
        return "".join(out)
    return text


# SC2028: echo with escape sequences

ECHO_ESCAPE_RE = re.compile(r"\\[ntrabceEfv]|\\x[0-9a-fA-F]|\\[0-7]")


@node_check("T_SimpleCommand")
def check_unused_echo_escapes(ctx, node):
    if first_word_basename(node) != "echo":
        return
    args = node.words[1:]
    if args:
        lit = literal_text(args[0])
        if lit and lit.startswith("-") and "e" in lit:
            return
    for w in args:
        for p in word_parts(w):
            text = None
            if p.kind == "T_SingleQuoted":
                text = p.text
            elif p.kind == "T_DoubleQuoted":
                text = "".join(q.text for q in p.parts
                               if q.kind == "T_Literal")
            if text and ECHO_ESCAPE_RE.search(text):
                ctx.info(p, 2028, "echo may not expand escape sequences."
                         " Use printf.")
                return
