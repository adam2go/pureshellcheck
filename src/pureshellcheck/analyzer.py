"""Analysis framework: finding model, AST helpers, check registry, driver."""

import re

from .shast import Positions, ancestors, iter_children, set_parents, walk
from .parser import (ParseError, Parser, literal_text, quoted_literal_text)

SEVERITIES = ("error", "warning", "info", "style")


class Finding:
    __slots__ = ("code", "severity", "message", "pos", "end",
                 "line", "column", "end_line", "end_column")

    def __init__(self, code, severity, message, pos, end):
        self.code = code
        self.severity = severity
        self.message = message
        self.pos = pos
        self.end = end
        self.line = self.column = self.end_line = self.end_column = 0

    def locate(self, positions):
        self.line, self.column = positions.line_col(self.pos)
        self.end_line, self.end_column = positions.line_col(self.end)

    def __repr__(self):
        return "SC%d:%d:%d %s" % (self.code, self.line, self.column,
                                  self.message)


NODE_CHECKS = {}
TREE_CHECKS = []
# Checks that are opt-in in shellcheck 0.11 (quote-safe-variables,
# require-variable-braces, useless-use-of-cat, ...)
OPTIONAL_CODES = frozenset({2002, 2248, 2250, 2312})


def node_check(*kinds):
    def deco(fn):
        for k in kinds:
            NODE_CHECKS.setdefault(k, []).append(fn)
        return fn
    return deco


def tree_check(fn):
    TREE_CHECKS.append(fn)
    return fn


SHEBANG_RE = re.compile(r"#!\s*(\S+)(\s+(\S+))?")
KNOWN_SHELLS = {"bash", "sh", "dash", "ash", "ksh", "ksh93", "mksh",
                "busybox", "bats", "zsh"}


def shell_from_shebang(shebang):
    if not shebang:
        return None
    m = SHEBANG_RE.match(shebang)
    if not m:
        return None
    base = m.group(1).rsplit("/", 1)[-1]
    if base == "env" and m.group(3):
        base = m.group(3).rsplit("/", 1)[-1]
    if base in ("busybox",):
        return "ash"
    if base in KNOWN_SHELLS:
        return "ksh" if base == "ksh93" else base
    return None


class Context:
    """Shared state and helpers available to every check."""

    def __init__(self, source, root, shell, include_optional=False):
        self.source = source
        self.root = root
        self.shell = shell
        self.include_optional = include_optional
        self.positions = Positions(source)
        self.findings = []
        self.cache = {}
        self.nodes = None  # doc-order node list, set by run_checks

    # -- emission ------------------------------------------------------

    def report(self, node, code, severity, message, pos=None, end=None):
        if code in OPTIONAL_CODES and not self.include_optional:
            return
        f = Finding(code, severity, message,
                    node.pos if pos is None else pos,
                    node.end if end is None else end)
        self.findings.append(f)

    def err(self, node, code, message):
        self.report(node, code, "error", message)

    def warn(self, node, code, message):
        self.report(node, code, "warning", message)

    def info(self, node, code, message):
        self.report(node, code, "info", message)

    def style(self, node, code, message):
        self.report(node, code, "style", message)

    # -- shell flavor ----------------------------------------------------

    @property
    def is_bashlike(self):
        return self.shell in ("bash", "ksh", "bats", "zsh")

    # -- command helpers -------------------------------------------------

    WRAPPER_COMMANDS = frozenset({
        "sudo", "nice", "nohup", "time", "timeout", "env", "doas",
        "command", "builtin", "exec", "stdbuf", "busybox", "run",
    })
    WRAPPER_ARG_FLAGS = {
        "exec": {"a"},
        "stdbuf": {"o", "e", "i"},
        "timeout": {"k", "s"},
        "env": {"u", "C", "S"},
    }

    def command_resolution(self, cmd):
        """(name_word, index, wrapper_names) after skipping wrappers."""
        cached = cmd.fields.get("_cmdres")
        if cached is not None:
            return cached
        result = self._command_resolution(cmd)
        cmd.fields["_cmdres"] = result
        return result

    def _command_resolution(self, cmd):
        if cmd.kind != "T_SimpleCommand" or not cmd.words:
            return None, -1, []
        words = cmd.words
        wrappers = []
        idx = 0
        while idx < len(words):
            name = literal_text(words[idx])
            if name is None:
                return words[idx], idx, wrappers
            base = name.rsplit("/", 1)[-1]
            if base in self.WRAPPER_COMMANDS:
                wrappers.append(base)
                arg_flags = self.WRAPPER_ARG_FLAGS.get(base, set())
                idx += 1
                while idx < len(words):
                    text = literal_text(words[idx])
                    if text is None:
                        break
                    if text.startswith("-"):
                        idx += 1
                        if text[1:] in arg_flags and idx < len(words):
                            idx += 1
                    elif base == "env" and "=" in text:
                        idx += 1
                    else:
                        break
                if base == "timeout" and idx < len(words):
                    idx += 1  # the duration argument
                continue
            return words[idx], idx, wrappers
        return None, -1, wrappers

    def command_name_word(self, cmd):
        """The word holding the command name, skipping wrapper commands."""
        return self.command_resolution(cmd)[0]

    def command_basename(self, cmd):
        word = self.command_name_word(cmd)
        if word is None:
            return None
        name = literal_text(word)
        if name is None:
            return None
        return name.rsplit("/", 1)[-1]

    def is_command(self, cmd, name):
        return self.command_basename(cmd) == name

    def argument_words(self, cmd):
        """Argument words after the (wrapper-skipped) command name."""
        word = self.command_name_word(cmd)
        if word is None:
            return []
        words = cmd.words
        for i, w in enumerate(words):
            if w is word:
                return words[i + 1:]
        return []

    def flags(self, cmd):
        """[(flagname, word)] for '-x'/'--foo' arguments; '' for others."""
        out = []
        args = self.argument_words(cmd)
        for w in args:
            text = literal_text(w)
            if text == "--":
                break
            if text and text.startswith("--"):
                out.append((text[2:].split("=", 1)[0], w))
            elif text and text.startswith("-") and len(text) > 1:
                for ch in text[1:]:
                    out.append((ch, w))
            else:
                out.append(("", w))
        return out

    # -- quoting / context helpers ----------------------------------------

    def is_quote_free(self, node):
        """True if node is in an unquoted context (command subs reset)."""
        for a in ancestors(node):
            k = a.kind
            if k in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
                return False
            if k in ("T_DollarExpansion", "T_Backticked", "T_ProcSub",
                     "T_DollarBraceCommandExpansion", "T_Script"):
                return True
            if k == "T_HereDoc":
                return False
        return True

    def parent_word(self, node):
        """The outermost T_NormalWord containing node, within this context."""
        word = node if node.kind == "T_NormalWord" else None
        for a in ancestors(node):
            if a.kind == "T_NormalWord":
                word = a
            elif a.kind in ("T_DollarExpansion", "T_Backticked",
                            "T_ProcSub", "T_Script"):
                break
        return word

    def word_role(self, node):
        """How the word containing node is used: (role, holder).

        Roles: 'command-word', 'argument', 'assign-value', 'condition',
        'arith', 'case-word', 'for-words', 'redirect-target', 'herestring',
        'heredoc', 'case-pattern', 'array-element', 'braced-arg', 'other'.
        """
        prev = node
        for a in ancestors(node):
            k = a.kind
            if k == "T_SimpleCommand":
                words = a.words
                if words and (prev is words[0]):
                    return "command-word", a
                return "argument", a
            if k == "T_Assignment":
                if prev is a.get("value"):
                    return "assign-value", a
                return "other", a
            if k == "T_IndexedElement":
                return "assign-value", a
            if k == "T_Array":
                return "array-element", a
            if k == "T_Condition":
                return "condition", a
            if k in ("T_DollarArithmetic", "T_Arithmetic", "TA_Expansion"):
                return "arith", a
            if k == "T_CaseExpression":
                if prev is a.word:
                    return "case-word", a
                return "case-pattern", a
            if k == "T_CaseItem":
                if prev in a.patterns:
                    return "case-pattern", a
            if k in ("T_ForIn", "T_SelectIn"):
                if prev in a.words:
                    return "for-words", a
            if k == "T_IoFile":
                return "redirect-target", a
            if k == "T_HereString":
                return "herestring", a
            if k == "T_HereDoc":
                return "heredoc", a
            if k == "T_DollarBraced":
                return "braced-arg", a
            if k in ("T_DollarExpansion", "T_Backticked", "T_Script",
                     "T_ProcSub"):
                return "other", a
            prev = a
        return "other", None


STATEMENT_CONTAINER_KINDS = frozenset({
    "T_Script", "T_BraceGroup", "T_Subshell", "T_WhileExpression",
    "T_UntilExpression", "T_ForIn", "T_ForArithmetic", "T_SelectIn",
    "T_IfExpression", "T_CaseItem", "T_DollarExpansion", "T_Backticked",
    "T_ProcSub", "T_DollarBraceCommandExpansion", "T_CoProc", "T_BatsTest",
})


def statement_lists(nodes):
    """Yield every list of statement nodes in the tree."""
    container = STATEMENT_CONTAINER_KINDS
    for node in nodes:
        if node.kind not in container:
            continue
        f = node.fields
        for key in ("commands", "body", "condition", "else_body"):
            v = f.get(key)
            if type(v) is list and v:
                yield v
        branches = f.get("branches")
        if branches:
            for cond, body in branches:
                yield cond
                yield body


def apply_directives(findings, directives, nodes, source, positions):
    """Filter findings according to `# shellcheck disable=` directives."""
    if not directives:
        return findings
    # statements eligible as directive targets, sorted by position
    statements = []
    seen = set()
    for lst in statement_lists(nodes):
        for node in lst:
            if id(node) not in seen:
                seen.add(id(node))
                statements.append(node)
    statements.sort(key=lambda n: n.pos)

    disabled_ranges = []  # (start, end, set_of_codes)
    first_cmd_pos = statements[0].pos if statements else len(source)
    for d in directives:
        if d.kind != "disable":
            continue
        codes = set()
        for v in d.values:
            m = re.match(r"^(?:SC)?(\d+)$", v)
            if m:
                codes.add(int(m.group(1)))
            elif v == "all":
                codes.add(-1)
            else:
                m = re.match(r"^(?:SC)?(\d+)-(?:SC)?(\d+)$", v)
                if m:
                    codes.update(range(int(m.group(1)),
                                       int(m.group(2)) + 1))
        if not codes:
            continue
        if d.pos <= first_cmd_pos:
            disabled_ranges.append((0, len(source) + 1, codes))
        elif d.line_has_code:
            # trailing directive: applies to the statement on this line
            target = None
            for s in statements:
                if s.pos <= d.pos and s.end >= d.pos - 1:
                    target = s
            if target is not None:
                disabled_ranges.append((target.pos, target.end, codes))
        else:
            target = None
            for s in statements:
                if s.pos >= d.pos:
                    target = s
                    break
            if target is not None:
                disabled_ranges.append((target.pos, target.end, codes))
    if not disabled_ranges:
        return findings
    out = []
    for f in findings:
        suppressed = False
        for start, end, codes in disabled_ranges:
            if start <= f.pos < end and (f.code in codes or -1 in codes):
                suppressed = True
                break
        if not suppressed:
            out.append(f)
    return out


def run_checks(source, shell=None, include_optional=False,
               filename="<stdin>"):
    """Parse and analyze a script. Returns (findings, parse_error|None)."""
    parser = Parser(source)
    try:
        root = parser.parse()
    except ParseError as e:
        f = Finding(e.code, "error",
                    e.message[0].upper() + e.message[1:] + ".",
                    min(e.pos, max(len(source) - 1, 0)),
                    min(e.pos + 1, len(source)))
        f.locate(Positions(source))
        return [f], e
    nodes = set_parents(root)

    detected = shell_from_shebang(root.get("shebang"))
    directives = parser.directives
    for d in directives:
        if d.kind == "shell" and d.values:
            detected = d.values[0]
    effective_shell = shell or detected or "bash"

    ctx = Context(source, root, effective_shell,
                  include_optional=include_optional)
    ctx.detected_shell = detected
    ctx.explicit_shell = shell
    ctx.directives = directives
    ctx.nodes = nodes

    get_checks = NODE_CHECKS.get
    for node in nodes:
        fns = get_checks(node.kind)
        if fns:
            for fn in fns:
                fn(ctx, node)
    for fn in TREE_CHECKS:
        fn(ctx, root)

    findings = apply_directives(ctx.findings, directives, nodes, source,
                                ctx.positions)
    findings.sort(key=lambda f: (f.pos, f.code))
    for f in findings:
        f.locate(ctx.positions)
    return findings, None
