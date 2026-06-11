"""AST node model for shell scripts.

Node kinds mirror ShellCheck's AST constructors (T_SimpleCommand,
T_DollarBraced, ...) so that check logic ports naturally. Nodes are generic
objects with a `kind` tag plus per-kind fields stored in a dict and exposed
as attributes.

Positions `pos`/`end` are absolute character offsets into the source; use
`Positions` to translate to 1-based (line, column).
"""

import bisect


class Node:
    __slots__ = ("kind", "pos", "end", "parent", "fields")

    def __init__(self, kind, pos, end, **fields):
        self.kind = kind
        self.pos = pos
        self.end = end
        self.parent = None
        self.fields = fields

    def __getattr__(self, name):
        try:
            return self.fields[name]
        except KeyError:
            raise AttributeError("%s node has no field %r" % (self.kind, name))

    def get(self, name, default=None):
        return self.fields.get(name, default)

    def __repr__(self):
        inner = ", ".join(
            "%s=%r" % (k, v) for k, v in self.fields.items() if k != "parent"
        )
        return "%s(%s)" % (self.kind, inner)


# Children traversal: every node field that may hold Node or [Node] or
# [[Node]] is walked generically.

def iter_children(node):
    for value in node.fields.values():
        if isinstance(value, Node):
            yield value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, Node):
                    yield item
                elif isinstance(item, list):
                    for sub in item:
                        if isinstance(sub, Node):
                            yield sub
                elif isinstance(item, tuple):
                    for sub in item:
                        if isinstance(sub, Node):
                            yield sub
                        elif isinstance(sub, list):
                            for s2 in sub:
                                if isinstance(s2, Node):
                                    yield s2
        elif isinstance(value, tuple):
            for item in value:
                if isinstance(item, Node):
                    yield item


def walk(node):
    """Yield node and all descendants in document order."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        children = list(iter_children(n))
        children.reverse()
        stack.extend(children)


def set_parents(root):
    for n in walk(root):
        for c in iter_children(n):
            c.parent = n


def ancestors(node):
    n = node.parent
    while n is not None:
        yield n
        n = n.parent


class Positions:
    """Translate absolute offsets to 1-based (line, col)."""

    def __init__(self, source):
        self.line_starts = [0]
        idx = source.find("\n")
        while idx != -1:
            self.line_starts.append(idx + 1)
            idx = source.find("\n", idx + 1)

    def line_col(self, offset):
        line = bisect.bisect_right(self.line_starts, offset)
        return line, offset - self.line_starts[line - 1] + 1
