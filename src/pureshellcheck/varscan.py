"""Whole-script variable reference/assignment collection.

Approximates ShellCheck's getReferencedVariables/getModifiedVariables
"variable flow" used by SC2034 (unused), SC2154/SC2153 (unassigned), and
the array checks.
"""

import re

from .astlib import braced_modifier, braced_reference
from .parser import ParseError, Parser, literal_text, quoted_literal_text
from .shast import walk

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SQ_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

DECLARING = {"declare", "typeset", "local", "export", "readonly"}

READ_ARG_FLAGS = set("dinNptu")
MAPFILE_ARG_FLAGS = set("CcdnOsu")


class Ref:
    __slots__ = ("name", "node", "kind")

    def __init__(self, name, node, kind="normal"):
        self.name = name
        self.node = node
        self.kind = kind  # normal | guarded | index-of-other | prefix


class Assign:
    __slots__ = ("name", "node", "exported", "is_array", "append", "kind")

    def __init__(self, name, node, exported=False, is_array=False,
                 append=False, kind="var"):
        self.name = name
        self.node = node
        self.exported = exported
        self.is_array = is_array
        self.append = append
        self.kind = kind  # var | checked | declare


class VarScan:
    def __init__(self, root, shell="bash", nodes=None):
        self.refs = []
        self.assigns = []
        self.assoc_arrays = set()
        self._suppressed = set()
        self.root = root
        self.shell = shell
        self.nodes = nodes if nodes is not None else list(walk(root))
        self._prescan_assoc()
        self._scan()

    def _prescan_assoc(self):
        """Find `declare -A name` declarations before the main scan."""
        for node in self.nodes:
            if node.kind != "T_SimpleCommand" or not node.words:
                continue
            cmd = literal_text(node.words[0])
            if cmd not in ("declare", "typeset", "local"):
                continue
            lits = [literal_text(w) for w in node.words[1:]]
            if not any(t and t.startswith("-") and "A" in t for t in lits):
                continue
            for t in lits:
                if t and not t.startswith(("-", "+")) \
                        and NAME_RE.match(t.split("[", 1)[0]):
                    self.assoc_arrays.add(t.split("[", 1)[0])
            for a in node.assigns:
                self.assoc_arrays.add(a.name)

    # ------------------------------------------------------------------

    _METHOD_CACHE = {}

    def _scan(self):
        methods = self._METHOD_CACHE
        cls = type(self)
        for node in self.nodes:
            k = node.kind
            method = methods.get(k, False)
            if method is False:
                method = getattr(cls, "_scan_" + k, None)
                methods[k] = method
            if method is not None:
                method(self, node)

    def _ref(self, name, node, kind="normal"):
        self.refs.append(Ref(name, node, kind))

    def _assign(self, name, node, **kw):
        self.assigns.append(Assign(name, node, **kw))

    # -- expansions --------------------------------------------------------

    def _scan_T_DollarBraced(self, node):
        content = node.content
        name = braced_reference(content)
        if not name:
            return
        kind = "normal"
        if content.startswith("!") and len(content) > 1:
            # indirection ${!name} or prefix match ${!pre*}
            if content.endswith("*") or content.endswith("@"):
                self._ref(name, node, "prefix")
                return
        # enclosed in a different variable's ${...}? => index, not a ref
        parent = node.parent
        while parent is not None:
            if parent.kind == "T_DollarBraced":
                if braced_reference(parent.content) != name:
                    kind = "index-of-other"
                break
            if parent.kind in ("T_SimpleCommand", "T_Script"):
                break
            parent = parent.parent
        mod = braced_modifier(content)
        if re.match(r"^(\[.*\])?:?[-?]", mod):
            kind = "guarded"
        if mod.startswith("+") or mod.startswith(":+"):
            kind = "guarded"
        if mod.startswith("=") or mod.startswith(":="):
            self._assign(name, node)
        self._ref(name, node, kind)
        # ${a:offset:length} -- offset/length are arithmetic
        if mod.startswith(":") and not mod[1:2] in ("-", "=", "?", "+"):
            self._arith_text_refs(mod[1:], node)
        # indices are arithmetic for non-associative arrays; bare names in
        # them count as uses but not as warnable unassigned references
        idx = _braced_index_text(content)
        if idx is not None and name not in self.assoc_arrays:
            self._arith_text_refs(idx, node, kind="index-of-other")
        elif idx is not None:
            # associative array: bare names in the index are string keys
            for sub in node.get("indices", ()):
                for d in walk(sub):
                    if d.kind == "TA_Variable":
                        self._suppressed.add(id(d))

    def _arith_text_refs(self, text, node, kind="normal",
                         with_dollar=False):
        if not text or (not with_dollar and "$" in text):
            return  # $-refs inside are collected by the normal walk
        try:
            sub = Parser(text)
            expr = sub.read_arith_seq()
            if not sub.at_end():
                return
        except (ParseError, RecursionError):
            return
        self._collect_arith(expr, node, kind)

    def _collect_arith(self, expr, origin, kind="normal"):
        skip = set()
        for n in walk(expr):
            if n.kind == "TA_Variable":
                if id(n) not in skip:
                    self._ref(n.name, origin, kind)
            elif n.kind == "TA_Assignment" and n.left.kind == "TA_Variable":
                self._assign(n.left.name, origin)
                if n.op == "=":
                    skip.add(id(n.left))
            elif n.kind == "T_DollarBraced":
                name = braced_reference(n.content)
                if name:
                    self._ref(name, origin, kind)

    # -- arithmetic --------------------------------------------------------

    def _scan_TA_Variable(self, node):
        if id(node) in self._suppressed:
            return
        self._ref(node.name, node)
        if node.name in self.assoc_arrays:
            for idx in node.get("indices", ()):
                for d in walk(idx):
                    if d.kind == "TA_Variable":
                        self._suppressed.add(id(d))

    def _scan_TA_Assignment(self, node):
        left = node.left
        if left.kind == "TA_Variable":
            self._assign(left.name, node)
            if node.op != "=":
                self._ref(left.name, node)
            else:
                self._suppressed.add(id(left))

    def _scan_TA_Unary(self, node):
        if node.op.lstrip("|") in ("++", "--") \
                and node.operand.kind == "TA_Variable":
            self._assign(node.operand.name, node)
            self._ref(node.operand.name, node)

    # -- conditions --------------------------------------------------------

    def _scan_TC_Unary(self, node):
        op = node.op
        if op in ("-v", "-R"):
            text = _literal_prefix(node.operand)
            name = text.split("[", 1)[0]
            if NAME_RE.match(name):
                self._ref(name, node)
                self._assign(name, node, kind="checked")
            full = quoted_literal_text(node.operand)
            if full and "[" in full and name not in self.assoc_arrays:
                idx = full.split("[", 1)[1].rstrip("]")
                self._arith_text_refs(idx, node, kind="index-of-other")
        elif op in ("-n", "-z"):
            self._mark_checked(node.operand)

    def _scan_TC_Nullary(self, node):
        self._mark_checked(node.word)

    ARITH_TEST_OPS = frozenset({"-eq", "-ne", "-lt", "-le", "-gt", "-ge"})

    def _scan_TC_Binary(self, node):
        if node.op not in self.ARITH_TEST_OPS:
            return
        cond = node.parent
        while cond is not None and cond.kind not in ("T_Condition",
                                                     "T_SimpleCommand",
                                                     "T_Script"):
            cond = cond.parent
        if cond is None or cond.kind != "T_Condition" or cond.single:
            return
        # in [[ ]], arithmetic comparisons evaluate bare names as variables
        for side in (node.lhs, node.rhs):
            text = quoted_literal_text(side)
            if text:
                self._arith_text_refs(text, side)

    def _mark_checked(self, word):
        if word is None:
            return
        for n in walk(word):
            if n.kind == "T_DollarBraced":
                name = braced_reference(n.content)
                if name and NAME_RE.match(name):
                    self._assign(name, n, kind="checked")

    # -- commands ----------------------------------------------------------

    def _scan_T_Assignment(self, node):
        parent = node.parent
        exported = False
        is_decl_arg = False
        flags = ""
        if parent is not None and parent.kind == "T_SimpleCommand":
            if node in parent.assigns and parent.words:
                cmd = literal_text(parent.words[0])
                cmd = cmd.rsplit("/", 1)[-1] if cmd else None
                if cmd in DECLARING:
                    is_decl_arg = True
                    for w in parent.words[1:]:
                        t = literal_text(w)
                        if t and t.startswith("-"):
                            flags += t[1:]
                    if cmd == "export" or "x" in flags:
                        exported = True
                    if "A" in flags:
                        self.assoc_arrays.add(node.name)
        value = node.get("value")
        is_array = value is not None and value.kind == "T_Array"
        self._assign(node.name, node, exported=exported, is_array=is_array,
                     append=node.get("append", False))
        for idx in node.get("indices", ()):
            if node.name not in self.assoc_arrays and isinstance(idx, str):
                self._arith_text_refs(idx, node, with_dollar=True)
        if is_array:
            for el in value.elements:
                if el.kind == "T_IndexedElement" \
                        and node.name not in self.assoc_arrays \
                        and isinstance(el.index, str):
                    self._arith_text_refs(el.index, el, with_dollar=True)

    def _scan_T_SimpleCommand(self, node):
        if not node.words:
            return
        cmd = literal_text(node.words[0])
        if cmd is None:
            return
        cmd = cmd.rsplit("/", 1)[-1]
        if cmd in ("builtin", "command"):
            rest = node.words[1:]
            if rest:
                inner = literal_text(rest[0])
                if inner in DECLARING:
                    cmd = inner
                    node = _Shifted(node, 1)
        args = node.words[1:]
        lits = [literal_text(w) for w in args]
        if cmd in DECLARING:
            flags = "".join(t[1:] for t in lits
                            if t and t.startswith("-") and "=" not in t)
            if "f" in flags or "F" in flags:
                return  # function operations
            for w, t in zip(args, lits):
                if not t or t.startswith("-") or t.startswith("+") \
                        or "=" in t:
                    continue
                if not NAME_RE.match(t.split("[", 1)[0]):
                    continue
                name = t.split("[", 1)[0]
                if "A" in flags:
                    self.assoc_arrays.add(name)
                if "p" in flags:
                    self._ref(name, w)
                    continue
                exported = cmd == "export" or "x" in flags
                if cmd == "readonly" and "=" not in t:
                    # readonly without value: marks existing var
                    self._ref(name, w)
                self._assign(name, w, exported=exported,
                             is_array="a" in flags or "A" in flags,
                             kind="declare")
                if exported or cmd in ("export", "readonly"):
                    self._ref(name, w, "guarded" if False else "normal")
        elif cmd == "read":
            self._scan_read(node, args, lits)
        elif cmd in ("mapfile", "readarray"):
            skip = False
            for w, t in zip(args, lits):
                if skip:
                    skip = False
                    continue
                if t and t.startswith("--"):
                    continue
                if t and t.startswith("-"):
                    if t[-1] in MAPFILE_ARG_FLAGS:
                        skip = True
                    continue
                if t and NAME_RE.match(t):
                    self._assign(t, w, is_array=True)
                    break
        elif cmd == "getopts":
            if len(args) >= 2:
                t = lits[1]
                if t and NAME_RE.match(t):
                    self._assign(t, args[1])
        elif cmd == "printf":
            qlits = [quoted_literal_text(w) for w in args]
            for i, t in enumerate(qlits):
                name = None
                if t == "-v" and i + 1 < len(qlits):
                    name = qlits[i + 1]
                elif t and t.startswith("-v") and len(t) > 2:
                    name = t[2:]
                if name:
                    name = name.split("[", 1)[0]
                    if NAME_RE.match(name):
                        self._assign(name, node)
                    break
        elif cmd == "wait":
            for i, t in enumerate(lits):
                if t == "-p" and i + 1 < len(lits) and lits[i + 1]:
                    name = lits[i + 1]
                    if NAME_RE.match(name):
                        self._assign(name, args[i + 1])
        elif cmd == "let":
            for w, t in zip(args, lits):
                text = quoted_literal_text(w)
                if text:
                    try:
                        sub = Parser(text)
                        expr = sub.read_arith_seq()
                        if sub.at_end():
                            self._collect_arith(expr, w)
                    except (ParseError, RecursionError):
                        pass
        elif cmd == "unset":
            for w, t in zip(args, lits):
                if t and not t.startswith("-"):
                    name = t.split("[", 1)[0]
                    if NAME_RE.match(name):
                        self._ref(name, w, "guarded")
        elif cmd in ("trap", "alias"):
            self._scan_quoted_refs(args)
        elif cmd.startswith("DEFINE_") and cmd[7:] in (
                "string", "boolean", "integer", "float"):
            if lits and lits[0] and NAME_RE.match(lits[0]):
                self._assign("FLAGS_" + lits[0], node)

    def _scan_read(self, node, args, lits):
        names = []
        skip = False
        is_array = False
        for w, t in zip(args, lits):
            if skip:
                skip = False
                continue
            if t and t.startswith("-") and len(t) > 1:
                rest = t[1:]
                for j, ch in enumerate(rest):
                    if ch == "a":
                        is_array = True
                    elif ch in READ_ARG_FLAGS:
                        if j == len(rest) - 1:
                            skip = True  # argument is the next word
                        break  # attached argument: rest is consumed
                continue
            if t and NAME_RE.match(t.split("[", 1)[0]):
                names.append((t.split("[", 1)[0], w))
        if not names:
            self._assign("REPLY", node)
        for name, w in names:
            self._assign(name, w, is_array=is_array and
                         (name, w) == names[-1])

    def _scan_quoted_refs(self, words):
        for w in words:
            for n in walk(w):
                if n.kind == "T_SingleQuoted":
                    for m in SQ_REF_RE.finditer(n.text):
                        self._ref(m.group(1), n)

    def _scan_T_ForIn(self, node):
        self._assign(node.variable, node)

    _scan_T_SelectIn = _scan_T_ForIn

    def _scan_T_CoProc(self, node):
        name = node.get("name") or "COPROC"
        self._assign(name, node, is_array=True)

    def _scan_T_FdRedirect(self, node):
        fd = node.get("fd")
        if fd and fd.startswith("{") and fd.endswith("}"):
            name = fd[1:-1]
            op = node.op
            closing = (not isinstance(op, str)
                       and op.kind == "T_IoDuplicate"
                       and op.target == "-")
            if closing:
                self._ref(name, node)
            else:
                self._assign(name, node)

    def _scan_T_SingleQuoted(self, node):
        # references in PS1='...$var...' and friends
        parent = node.parent
        seen = 0
        while parent is not None and seen < 3:
            if parent.kind == "T_Assignment" and parent.name in (
                    "PS1", "PS2", "PS3", "PS4", "PROMPT_COMMAND"):
                for m in SQ_REF_RE.finditer(node.text):
                    self._ref(m.group(1), node)
                return
            parent = parent.parent
            seen += 1


class _Shifted:
    """View of a simple command with the first word removed."""

    def __init__(self, node, n):
        self.kind = node.kind
        self.words = node.words[n:]
        self.parent = node.parent
        self.pos = node.pos
        self.end = node.end

    def get(self, *a, **k):
        return None


def _literal_prefix(word):
    """Concatenated literal text of leading constant parts of a word."""
    if word is None:
        return ""
    parts = word.parts if word.kind in ("T_NormalWord",) else [word]
    out = []
    for p in parts:
        if p.kind == "T_Literal":
            out.append(p.text)
        elif p.kind in ("T_SingleQuoted", "T_DollarSingleQuoted"):
            out.append(p.text)
        elif p.kind in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            for q in p.parts:
                if q.kind == "T_Literal":
                    out.append(q.text)
                else:
                    return "".join(out)
        else:
            break
    return "".join(out)


def _braced_index_text(content):
    m = re.match(r"[!#]?(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)\[(.*?)\]",
                 content)
    return m.group(1) if m else None


def _flag_arg_attached(flag):
    return False


def levenshtein(a, b, cap=3):
    """Banded edit distance: O(len * cap), returns `cap` once unbeatable."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) >= cap:
        return cap
    if la > lb:
        a, b, la, lb = b, a, lb, la
    if la == 0:
        return lb if lb < cap else cap
    band = cap - 1
    INF = cap + 1
    prev = [j if j <= band else INF for j in range(la + 1)]
    for i in range(1, lb + 1):
        cb = b[i - 1]
        lo = max(1, i - band)
        hi = min(la, i + band)
        cur = [INF] * (la + 1)
        if lo == 1:
            cur[0] = i if i <= band else INF
        best = INF
        for j in range(lo, hi + 1):
            c = min(prev[j] + 1, cur[j - 1] + 1,
                    prev[j - 1] + (a[j - 1] != cb))
            cur[j] = c
            if c < best:
                best = c
        if best >= cap:
            return cap
        prev = cur
    d = prev[la]
    return d if d < cap else cap
