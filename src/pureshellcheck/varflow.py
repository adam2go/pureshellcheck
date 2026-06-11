"""Execution-order variable flow engine.

Walks the AST in rough execution order, tracking each variable's "space
status" (EMPTY / CLEAN / DIRTY) and integer attribute, calling a callback at
every parameter expansion with the state at that point. This is a pragmatic
reimplementation of the value tracking ShellCheck performs on its CFG; it
handles straight-line code, branches (worst-case merge), loops (single pass),
subshell isolation, function definitions/calls with dynamic scoping and
`local`, and branch-exit pruning (`if x; then v='a b'; exit; fi`).
"""

from .astlib import (
    CLEAN, DIRTY, EMPTY, SPECIAL_INTEGER_VARIABLES,
    VARIABLES_WITHOUT_SPACES, braced_reference, join_status,
    literal_space_status, merge_status,
)
from .parser import literal_text
from .shast import walk

EXIT_COMMANDS = {"exit", "return"}

DECLARING_COMMANDS = {"declare", "typeset", "local", "export", "readonly"}


def VarInfo(status, integer=False):
    """Variable state as an immutable (status, integer) tuple."""
    return (status, integer)


class Scope:
    """One level of variable scope (global or function-local)."""

    __slots__ = ("vars",)

    def __init__(self, vars=None):
        self.vars = vars if vars is not None else {}


class FuncDef:
    __slots__ = ("node", "conditional", "walked")

    def __init__(self, node, conditional):
        self.node = node
        self.conditional = conditional
        self.walked = False


class VarFlow:
    """on_reference(braced_node, name, status, integer) is called for every
    T_DollarBraced in execution order."""

    def __init__(self, on_reference=None, shell="bash", on_assign=None):
        self.on_reference = on_reference or (lambda *a: None)
        self.on_assign = on_assign or (lambda *a: None)
        self.shell = shell
        self.scopes = [Scope()]
        self.functions = {}
        self.call_stack = []
        self.conditional_depth = 0

    # -- scope management ------------------------------------------------

    def lookup(self, name):
        for scope in reversed(self.scopes):
            info = scope.vars.get(name)
            if info is not None:
                return info
        return None

    def assign(self, name, status, integer=None, local=False, global_=False):
        if global_:
            scope = self.scopes[0]
        elif local:
            scope = self.scopes[-1]
        else:
            scope = self.scopes[0]
            for s in reversed(self.scopes):
                if name in s.vars:
                    scope = s
                    break
        old = scope.vars.get(name)
        if integer is None:
            integer = old[1] if old is not None else False
        elif self.conditional_depth:
            # attribute only maybe applied: keep the weaker assumption
            integer = integer and (old[1] if old is not None else False)
        if integer and status == DIRTY:
            status = CLEAN
        if self.conditional_depth and old is not None:
            status = merge_status(old[0], status)
        elif self.conditional_depth and old is None:
            status = DIRTY
        scope.vars[name] = (status, integer)

    def snapshot(self):
        return [dict(s.vars) for s in self.scopes]

    def restore(self, snap):
        for scope, vars_ in zip(self.scopes, snap):
            scope.vars = vars_

    def merge_snapshots(self, snaps):
        """Merge variable states from multiple branches (worst case)."""
        merged = []
        for level in range(len(self.scopes)):
            dicts = [snap[level] for snap in snaps]
            if len(dicts) == 2:
                d1, d2 = dicts
                if d1 == d2:
                    merged.append(dict(d1))
                    continue
                vars_ = {}
                for name, i1 in d1.items():
                    i2 = d2.get(name)
                    if i2 is None:
                        vars_[name] = (merge_status(i1[0], DIRTY), False)
                    elif i1 == i2:
                        vars_[name] = i1
                    else:
                        vars_[name] = (merge_status(i1[0], i2[0]),
                                       i1[1] and i2[1])
                for name, i2 in d2.items():
                    if name not in d1:
                        vars_[name] = (merge_status(i2[0], DIRTY), False)
                merged.append(vars_)
                continue
            allnames = set()
            for d in dicts:
                allnames.update(d)
            vars_ = {}
            for name in allnames:
                status = None
                integer = True
                for d in dicts:
                    info = d.get(name)
                    s = info[0] if info is not None else DIRTY
                    i = info[1] if info is not None else False
                    status = s if status is None else merge_status(status, s)
                    integer = integer and i
                vars_[name] = (status, integer)
            merged.append(vars_)
        self.restore(merged)

    # -- value evaluation --------------------------------------------------

    def ref_status(self, name):
        if name in SPECIAL_INTEGER_VARIABLES:
            return CLEAN, True
        if name in VARIABLES_WITHOUT_SPACES:
            return CLEAN, False
        if name in ("@", "*") or name.isdigit():
            return DIRTY, False
        info = self.lookup(name)
        if info is None:
            return DIRTY, False
        if info[1]:
            return CLEAN, True
        return info[0], False

    def word_status(self, word):
        """SpaceStatus of a word's value (assignment RHS semantics)."""
        if word is None:
            return EMPTY
        total = EMPTY
        for part in self._value_parts(word):
            total = join_status(total, self._part_status(part))
        return total

    def _value_parts(self, word):
        if word.kind == "T_NormalWord":
            return word.parts
        return [word]

    def _part_status(self, part):
        k = part.kind
        if k == "T_Literal":
            return literal_space_status(part.text)
        if k in ("T_SingleQuoted", "T_DollarSingleQuoted"):
            return literal_space_status(part.text) if part.text else EMPTY
        if k in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            total = EMPTY
            for q in part.parts:
                total = join_status(total, self._part_status(q))
            return total
        if k == "T_DollarBraced":
            content = part.content
            name = braced_reference(content)
            if content.startswith("#"):
                return CLEAN
            status, _ = self.ref_status(name)
            return status
        if k in ("T_DollarExpansion", "T_Backticked",
                 "T_DollarBraceCommandExpansion"):
            return DIRTY
        if k == "T_DollarArithmetic":
            return CLEAN
        if k in ("T_Glob", "T_Extglob", "T_BraceExpansion"):
            return DIRTY
        if k == "T_ProcSub":
            return CLEAN
        return DIRTY

    # -- main walk ---------------------------------------------------------

    def run(self, root):
        self.process_statements(root.commands)
        # walk function bodies that were never called, with the final state
        for name, fd in sorted(self.functions.items()):
            if not fd.walked:
                self.call_function(fd, simulate_only=True)

    def process_statements(self, statements):
        """Returns True if execution definitely exits within the block."""
        for i, stmt in enumerate(statements):
            if self.process(stmt):
                return True
        return False

    def process(self, node):
        """Process one statement; returns True if it definitely exits."""
        k = node.kind
        method = getattr(self, "_do_" + k, None)
        if method is not None:
            return method(node)
        # generic: walk children as statements/expressions
        self.visit_word(node)
        return False

    # each _do_ method returns exits:bool

    def _do_T_SimpleCommand(self, node):
        cmd_name = None
        if node.words:
            cmd_name = literal_text(node.words[0])
            if cmd_name:
                cmd_name = cmd_name.rsplit("/", 1)[-1]
        is_declaring = cmd_name in DECLARING_COMMANDS
        flags = ""
        unflags = ""
        if is_declaring:
            for w in node.words[1:]:
                t = literal_text(w)
                if t and t.startswith("-"):
                    flags += t[1:]
                elif t and t.startswith("+"):
                    unflags += t[1:]
        in_function = len(self.scopes) > 1
        is_local = (cmd_name in ("local", "declare", "typeset")
                    and in_function and "g" not in flags)
        integer = True if "i" in flags else (False if "i" in unflags
                                             else None)

        for assign in node.assigns:
            self.visit_word(assign.get("value"))
            for idx in assign.get("indices", ()):
                self.visit_word(idx)
            value = assign.get("value")
            if value is not None and value.kind == "T_Array":
                status = EMPTY
                for el in value.elements:
                    v = el.value if el.kind == "T_IndexedElement" else el
                    status = merge_status(status, self.word_status(v)) \
                        if status != EMPTY else self.word_status(v)
            else:
                status = self.word_status(value)
            if assign.get("append"):
                old = self.lookup(assign.name)
                if old is not None:
                    status = join_status(old[0], status)
            self.assign(assign.name, status, integer=integer,
                        local=is_local, global_="g" in flags)
            self.on_assign(assign.name, value, assign)

        for w in node.words:
            self.visit_word(w)
        for r in node.get("redirects", ()):
            self.visit_word(r)
            self._apply_redirect_assign(r)

        if is_declaring:
            # bare names: declare -x NAME / local NAME
            for w in node.words[1:]:
                t = literal_text(w)
                if t and not t.startswith("-") and not t.startswith("+") \
                        and "=" not in t and t.isidentifier():
                    if is_local:
                        self.assign(t, EMPTY, integer=integer, local=True)
                    elif cmd_name in ("export", "readonly") or "x" in flags:
                        self.assign(t, DIRTY, integer=integer)
                    elif integer is not None:
                        old = self.lookup(t)
                        self.assign(t, old[0] if old else EMPTY,
                                    integer=integer)
        elif cmd_name == "read":
            self._apply_read(node)
        elif cmd_name in ("mapfile", "readarray"):
            args = [literal_text(w) for w in node.words[1:]]
            names = [a for a in args if a and not a.startswith("-")]
            if names:
                self.assign(names[-1], DIRTY)
        elif cmd_name == "getopts":
            args = [w for w in node.words[1:]]
            if len(args) >= 2:
                t = literal_text(args[1])
                if t:
                    self.assign(t, CLEAN)
        elif cmd_name == "wait":
            args = [literal_text(w) for w in node.words[1:]]
            for i, a in enumerate(args):
                if a == "-p" and i + 1 < len(args) and args[i + 1]:
                    self.assign(args[i + 1], CLEAN, integer=True)
        elif cmd_name == "printf":
            args = [literal_text(w) for w in node.words[1:]]
            for i, a in enumerate(args):
                if a == "-v" and i + 1 < len(args) and args[i + 1]:
                    self.assign(args[i + 1], DIRTY)
        elif cmd_name == "unset":
            for w in node.words[1:]:
                t = literal_text(w)
                if t and not t.startswith("-"):
                    self.assign(t.split("[", 1)[0], DIRTY)
        elif cmd_name in EXIT_COMMANDS:
            return True
        elif cmd_name == "exec" and len(node.words) > 1:
            return True
        elif cmd_name in self.functions:
            self.call_function(self.functions[cmd_name])
        return False

    def _apply_read(self, node):
        names = []
        args = node.words[1:]
        skip_next = False
        for i, w in enumerate(args):
            t = literal_text(w)
            if skip_next:
                skip_next = False
                if t:
                    names.append(t)
                continue
            if t and t.startswith("-"):
                for opt in ("a", "d", "i", "n", "N", "p", "t", "u"):
                    if t.endswith(opt):
                        skip_next = opt == "a"
                        break
                if t.endswith("-a"):
                    skip_next = True
                continue
            if t:
                names.append(t)
        if not names:
            names = ["REPLY"]
        for n in names:
            self.assign(n.split("[", 1)[0], DIRTY)

    def _apply_redirect_assign(self, redirect):
        fd = redirect.get("fd")
        if fd and fd.startswith("{") and fd.endswith("}"):
            self.assign(fd[1:-1], CLEAN, integer=True)

    def _do_T_Pipeline(self, node):
        for cmd in node.commands:
            snap = self.snapshot()
            self.process(cmd)
            self.restore(snap)
        return False

    def _do_T_Banged(self, node):
        return self.process(node.command)

    def _do_T_Timed(self, node):
        return self.process(node.command)

    def _do_T_Backgrounded(self, node):
        snap = self.snapshot()
        self.process(node.command)
        self.restore(snap)
        return False

    def _do_T_AndIf(self, node):
        self.process(node.left)
        self.conditional_depth += 1
        try:
            self.process(node.right)
        finally:
            self.conditional_depth -= 1
        return False

    _do_T_OrIf = _do_T_AndIf

    def _do_T_IfExpression(self, node):
        snaps = []
        for cond, body in node.branches:
            self.process_statements(cond)
            snap_before = self.snapshot()
            exited = self.process_statements(body)
            if not exited:
                snaps.append(self.snapshot())
            self.restore(snap_before)
        else_body = node.else_body
        if else_body:
            snap_before = self.snapshot()
            exited = self.process_statements(else_body)
            if not exited:
                snaps.append(self.snapshot())
            self.restore(snap_before)
        else:
            snaps.append(self.snapshot())
        if snaps:
            self.merge_snapshots(snaps)
            return False
        return True  # all branches exited and else missing? keep current

    def _do_T_WhileExpression(self, node):
        self.process_statements(node.condition)
        before = self.snapshot()
        self.process_statements(node.body)
        self.merge_snapshots([before, self.snapshot()])
        return False

    _do_T_UntilExpression = _do_T_WhileExpression

    def _do_T_ForIn(self, node):
        status = None
        for w in node.words:
            self.visit_word(w)
            s = self.word_status(w)
            status = s if status is None else merge_status(status, s)
        if not node.has_in or status is None:
            status = DIRTY  # implicit "$@"
        self.assign(node.variable, status)
        before = self.snapshot()
        self.process_statements(node.body)
        self.merge_snapshots([before, self.snapshot()])
        return False

    _do_T_SelectIn = _do_T_ForIn

    def _do_T_ForArithmetic(self, node):
        self.visit_arith(node.init)
        self.visit_arith(node.condition)
        before = self.snapshot()
        self.process_statements(node.body)
        self.visit_arith(node.update)
        self.merge_snapshots([before, self.snapshot()])
        return False

    def _do_T_CaseExpression(self, node):
        self.visit_word(node.word)
        snaps = [self.snapshot()]
        for item in node.items:
            for p in item.patterns:
                self.visit_word(p)
            before = self.snapshot()
            exited = self.process_statements(item.body)
            if not exited:
                snaps.append(self.snapshot())
            self.restore(before)
        self.merge_snapshots(snaps)
        return False

    def _do_T_BraceGroup(self, node):
        return self.process_statements(node.commands)

    def _do_T_Subshell(self, node):
        snap = self.snapshot()
        self.process_statements(node.commands)
        self.restore(snap)
        return False

    def _do_T_Condition(self, node):
        self.visit_word(node.expr)
        return False

    def _do_T_Arithmetic(self, node):
        self.visit_arith(node.expr)
        return False

    def _do_T_Function(self, node):
        conditional = self.conditional_depth > 0
        self.functions[node.name] = FuncDef(node, conditional)
        return False

    def _do_T_BatsTest(self, node):
        self.assign("status", CLEAN, integer=True)
        self.assign("output", DIRTY)
        self.assign("lines", DIRTY)
        self.assign("stderr", DIRTY)
        snap = self.snapshot()
        self.scopes.append(Scope())
        try:
            self.process_statements(node.body.commands)
        finally:
            self.scopes.pop()
            self.restore(snap)
        return False

    def _do_T_CoProc(self, node):
        snap = self.snapshot()
        self.process(node.command)
        self.restore(snap)
        return False

    def call_function(self, fd, simulate_only=False):
        if fd.node in [f for f in self.call_stack]:
            return
        fd.walked = True
        self.call_stack.append(fd.node)
        snap = self.snapshot() if (fd.conditional or simulate_only) else None
        self.scopes.append(Scope())
        try:
            body = fd.node.body
            if body.kind == "T_BraceGroup":
                self.process_statements(body.commands)
            else:
                self.process(body)
        finally:
            self.scopes.pop()
            self.call_stack.pop()
            if snap is not None:
                if fd.conditional and not simulate_only:
                    self.merge_snapshots([snap, self.snapshot()])
                else:
                    self.restore(snap)

    # -- expression-level walking ------------------------------------------

    def visit_word(self, node):
        """Walk any non-statement subtree, processing references and nested
        command substitutions."""
        if node is None or isinstance(node, str):
            return
        k = node.kind
        if k == "T_Literal" or k == "T_SingleQuoted" or k == "T_Glob":
            return
        if k == "T_NormalWord":
            for p in node.parts:
                kp = p.kind
                if kp != "T_Literal" and kp != "T_SingleQuoted" \
                        and kp != "T_Glob":
                    self.visit_word(p)
            return
        if k == "T_DoubleQuoted":
            for p in node.parts:
                kp = p.kind
                if kp != "T_Literal":
                    self.visit_word(p)
            return
        if k == "T_DollarBraced":
            name = braced_reference(node.content)
            status, integer = self.ref_status(name)
            self.on_reference(node, name, status, integer)
            for p in node.get("arg_parts", ()):
                self.visit_word(p)
            for idx in node.get("indices", ()):
                self.visit_word(idx)
            return
        if k in ("T_DollarExpansion", "T_Backticked", "T_ProcSub",
                 "T_DollarBraceCommandExpansion"):
            snap = self.snapshot()
            self.process_statements(node.commands)
            self.restore(snap)
            return
        if k in ("T_DollarArithmetic",):
            self.visit_arith(node.expr)
            return
        if k in ("TA_Sequence", "TA_Assignment", "TA_Binary", "TA_Unary",
                 "TA_Trinary", "TA_Variable", "TA_Parenthesis",
                 "TA_Expansion", "TA_Literal", "TA_Empty"):
            self.visit_arith(node)
            return
        if k == "T_FdRedirect":
            op = node.op
            if isinstance(op, str):
                return
            self.visit_word(op)
            self._apply_redirect_assign(node)
            return
        children = node.children
        if children is None:
            from .shast import iter_children
            children = iter_children(node)
        for c in children:
            self.visit_word(c)

    def visit_arith(self, node):
        if node is None:
            return
        k = node.kind
        if k == "TA_Variable":
            for idx in node.get("indices", ()):
                self.visit_word(idx)
            return
        if k == "TA_Assignment":
            self.visit_arith(node.right)
            left = node.left
            if left.kind == "TA_Variable":
                self.assign(left.name, CLEAN)
            else:
                self.visit_arith(left)
            return
        if k == "TA_Unary":
            op = node.op.lstrip("|")
            operand = node.operand
            if op in ("++", "--") and operand.kind == "TA_Variable":
                self.assign(operand.name, CLEAN)
            else:
                self.visit_arith(operand)
            return
        if k == "TA_Expansion":
            for p in node.parts:
                self.visit_word(p)
            return
        children = node.children
        if children is None:
            from .shast import iter_children
            children = iter_children(node)
        for c in children:
            if c.kind.startswith("TA_"):
                self.visit_arith(c)
            else:
                self.visit_word(c)
