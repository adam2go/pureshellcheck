"""Recursive-descent parser for bash scripts.

Produces the Node AST defined in shast.py. The parser is deliberately
lenient: it aims to parse anything bash would accept (plus a few common
near-miss constructs) so that analysis can run on real-world scripts.
"""

import re

from .shast import Node

KEYWORDS = {
    "if", "then", "elif", "else", "fi", "while", "until", "for", "do",
    "done", "case", "esac", "select", "in", "function", "{", "}", "!",
    "[[", "]]", "time", "coproc",
}

END_KEYWORDS = {
    "then", "elif", "else", "fi", "do", "done", "esac", "}", "]]", "in",
}

# Characters that terminate an unquoted word.
METACHARS = " \t\n;&|<>()"

UNQUOTED_RUN = re.compile(r"""[^\\'"$`*?\[\](){}<>|&;\s!#~]+""")
DQUOTE_RUN = re.compile(r'[^"\\$`]+')
SQUOTE_END = re.compile(r"'")
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(\[|\+?=)")
DIGITS_RE = re.compile(r"[0-9]+")
SPECIAL_PARAMS = set("@*#?$!-0123456789_")
HEREDOC_LINE = re.compile(r".*\n|.+$")

BINARY_TEST_OPS = {
    "==", "!=", "=", "=~", "<", ">", "\\<", "\\>", "<=", ">=",
    "-eq", "-ne", "-lt", "-le", "-gt", "-ge", "-nt", "-ot", "-ef",
}
UNARY_TEST_OPS = {
    "-a", "-b", "-c", "-d", "-e", "-f", "-g", "-h", "-k", "-n", "-o",
    "-p", "-r", "-s", "-t", "-u", "-v", "-w", "-x", "-z", "-G", "-L",
    "-N", "-O", "-R", "-S",
}

ARITH_ASSIGN_OPS = (
    "<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=", "=",
)


class QuotedOp(str):
    """A test operator that appeared quoted, e.g. '>' in [ $a '>' $b ]."""

    def __new__(cls, text, width):
        self = str.__new__(cls, text)
        self.width = width
        return self


def quoted_literal_text(word):
    """Literal text of a word allowing quoted parts; None if it expands."""
    if word is None or word.kind != "T_NormalWord":
        return None
    out = []
    for p in word.parts:
        if p.kind in ("T_Literal", "T_SingleQuoted", "T_DollarSingleQuoted"):
            out.append(p.text)
        elif p.kind == "T_DoubleQuoted":
            for q in p.parts:
                if q.kind != "T_Literal":
                    return None
                out.append(q.text)
        else:
            return None
    return "".join(out)


class ParseError(Exception):
    def __init__(self, message, pos, code=1073):
        super().__init__(message)
        self.message = message
        self.pos = pos
        self.code = code


class Directive:
    """A `# shellcheck key=value` comment."""

    __slots__ = ("pos", "line_has_code", "kind", "values")

    def __init__(self, pos, line_has_code, kind, values):
        self.pos = pos
        self.line_has_code = line_has_code
        self.kind = kind
        self.values = values


DIRECTIVE_RE = re.compile(r"^#\s*shellcheck\s+(.*)$")


class Parser:
    def __init__(self, source):
        self.src = source
        self.n = len(source)
        self.i = 0
        self.pending_heredocs = []
        self.directives = []
        self.line_had_command = False

    # ------------------------------------------------------------------
    # Low-level helpers

    def peek(self, offset=0):
        i = self.i + offset
        return self.src[i] if i < self.n else ""

    def at_end(self):
        return self.i >= self.n

    def error(self, message, pos=None):
        raise ParseError(message, self.i if pos is None else pos)

    def skip_inline_ws(self):
        src, n = self.src, self.n
        i = self.i
        while i < n:
            c = src[i]
            if c == " " or c == "\t" or c == "\r":
                i += 1
            elif c == "\\" and i + 1 < n and src[i + 1] == "\n":
                i += 2
            else:
                break
        self.i = i

    def consume_comment(self):
        """Consume a comment starting at '#'. Records directives."""
        start = self.i
        end = self.src.find("\n", start)
        if end == -1:
            end = self.n
        text = self.src[start:end]
        self.i = end
        m = DIRECTIVE_RE.match(text)
        if m:
            for field in m.group(1).split():
                if "=" in field:
                    kind, _, value = field.partition("=")
                    if kind in ("disable", "enable", "shell", "source",
                                "source-path", "external-sources"):
                        self.directives.append(Directive(
                            start, self.line_had_command, kind,
                            value.split(",")))

    def consume_newline(self):
        """Consume a newline character, then any pending heredoc bodies."""
        assert self.peek() == "\n"
        self.i += 1
        self.line_had_command = False
        if self.pending_heredocs:
            self.read_heredoc_bodies()

    def skip_ws_and_newlines(self):
        while True:
            self.skip_inline_ws()
            c = self.peek()
            if c == "#":
                self.consume_comment()
            elif c == "\n":
                self.consume_newline()
            else:
                return

    def peek_literal_word(self):
        """Return the purely-literal word starting at i, or "".

        Used for keyword detection at command position; keywords are always
        unquoted literals.
        """
        src, n = self.src, self.n
        i = self.i
        j = i
        while j < n and src[j] not in " \t\r\n;&|<>()'\"\\$`#":
            j += 1
        return src[i:j]

    def at_keyword(self, kw):
        word = self.peek_literal_word()
        if word != kw:
            return False
        return True

    # ------------------------------------------------------------------
    # Script / lists

    def parse(self):
        shebang = None
        if self.src.startswith("#!"):
            end = self.src.find("\n")
            if end == -1:
                end = self.n
            shebang = self.src[:end]
            self.i = end
        commands = self.read_list(set())
        self.skip_ws_and_newlines()
        if not self.at_end():
            self.error("unexpected token %r" % self.peek())
        node = Node("T_Script", 0, self.n, shebang=shebang, commands=commands)
        return node

    def read_list(self, end_keywords, stop_case_seps=False):
        """Read commands until EOF, a closing token, or an end keyword."""
        commands = []
        while True:
            self.skip_ws_and_newlines()
            if self.at_end():
                break
            c = self.peek()
            if c == ")":
                break
            if stop_case_seps and c == ";" and self.peek(1) == ";":
                break
            if c == ";" and self.peek(1) == "&":
                break
            word = self.peek_literal_word()
            if word in END_KEYWORDS and word in end_keywords:
                break
            if word in END_KEYWORDS and word != "in":
                # Unexpected closer ('}' etc.): stop and let caller decide.
                break
            cmd = self.read_and_or()
            if cmd is None:
                break
            sep = self.read_separator()
            if sep == "&":
                cmd = Node("T_Backgrounded", cmd.pos, self.i, command=cmd)
            commands.append(cmd)
            if sep is None:
                break
        return commands

    def read_separator(self):
        self.skip_inline_ws()
        if self.peek() == "#":
            self.consume_comment()
        c = self.peek()
        if c == ";":
            if self.peek(1) == ";" or self.peek(1) == "&":
                return None  # case separator, not consumed here
            self.i += 1
            return ";"
        if c == "&":
            if self.peek(1) in (">", "&"):
                return None
            self.i += 1
            return "&"
        if c == "\n":
            self.consume_newline()
            return "\n"
        return None

    def read_and_or(self):
        left = self.read_pipeline()
        if left is None:
            return None
        while True:
            self.skip_inline_ws()
            two = self.src[self.i:self.i + 2]
            if two == "&&":
                kind = "T_AndIf"
            elif two == "||":
                kind = "T_OrIf"
            else:
                break
            self.i += 2
            self.skip_ws_and_newlines()
            right = self.read_pipeline()
            if right is None:
                self.error("expected a command after %s" % two)
            left = Node(kind, left.pos, right.end, left=left, right=right)
        return left

    def read_pipeline(self):
        self.skip_inline_ws()
        start = self.i
        banged = False
        timed = False
        while True:
            word = self.peek_literal_word()
            if word == "!" and not banged:
                banged = True
                self.i += 1
                self.skip_inline_ws()
            elif word == "time":
                timed = True
                self.i += len(word)
                self.skip_inline_ws()
                # consume time flags like -p
                while self.peek() == "-":
                    w = self.peek_literal_word()
                    if not w.startswith("-"):
                        break
                    self.i += len(w)
                    self.skip_inline_ws()
            else:
                break
        cmd = self.read_command()
        if cmd is None:
            if banged or timed:
                # `time` or `!` with no command
                return Node("T_SimpleCommand", start, self.i,
                            assigns=[], words=[], redirects=[])
            return None
        cmds = [cmd]
        seps = []
        while True:
            self.skip_inline_ws()
            c = self.peek()
            if c == "|" and self.peek(1) != "|":
                op = "|&" if self.peek(1) == "&" else "|"
                self.i += len(op)
                seps.append(op)
                self.skip_ws_and_newlines()
                nxt = self.read_command()
                if nxt is None:
                    self.error("expected a command after |")
                cmds.append(nxt)
            else:
                break
        if len(cmds) > 1:
            result = Node("T_Pipeline", cmds[0].pos, cmds[-1].end,
                          commands=cmds, separators=seps)
        else:
            result = cmds[0]
        if timed:
            result = Node("T_Timed", start, result.end, command=result)
        if banged:
            result = Node("T_Banged", start, result.end, command=result)
        return result

    # ------------------------------------------------------------------
    # Commands

    def read_command(self):
        self.skip_inline_ws()
        if self.at_end():
            return None
        c = self.peek()
        if c == "#":
            return None
        if c == "(":
            if self.peek(1) == "(":
                node = self.read_arithmetic_command()
            else:
                node = self.read_subshell()
            return self.attach_redirects(node)
        word = self.peek_literal_word()
        if word == "[[":
            node = self.read_condition(False)
            return self.attach_redirects(node)
        if word == "[":
            save = self.i
            heredocs = list(self.pending_heredocs)
            try:
                node = self.read_condition(True)
                return self.attach_redirects(node)
            except ParseError:
                # not valid test syntax; fall back to a plain command
                self.i = save
                self.pending_heredocs = heredocs
            return self.read_simple_command()
        if word == "{":
            nxt = self.peek(1)
            if nxt in " \t\n(":
                node = self.read_brace_group()
                return self.attach_redirects(node)
        if word == "@test":
            return self.read_bats_test()
        if word in ("if", "while", "until", "for", "case", "select",
                    "function", "coproc"):
            method = {
                "if": self.read_if,
                "while": self.read_while,
                "until": self.read_until,
                "for": self.read_for,
                "case": self.read_case,
                "select": self.read_select,
                "function": self.read_function_kw,
                "coproc": self.read_coproc,
            }[word]
            node = method()
            return self.attach_redirects(node)
        return self.read_simple_command()

    def expect_keyword(self, kw):
        self.skip_ws_and_newlines()
        word = self.peek_literal_word()
        if word != kw:
            self.error("expected %r, found %r" % (kw, word or self.peek()))
        self.i += len(kw)

    def attach_redirects(self, node):
        redirects = node.get("redirects")
        if redirects is None:
            redirects = []
            node.fields["redirects"] = redirects
        while True:
            self.skip_inline_ws()
            r = self.maybe_read_redirect()
            if r is None:
                break
            redirects.append(r)
            node.end = self.i
        return node

    def read_subshell(self):
        start = self.i
        self.i += 1  # (
        cmds = self.read_list(set())
        self.skip_ws_and_newlines()
        if self.peek() != ")":
            self.error("expected ) to close subshell")
        self.i += 1
        return Node("T_Subshell", start, self.i, commands=cmds)

    def read_brace_group(self):
        start = self.i
        self.i += 1  # {
        cmds = self.read_list({"}"})
        self.skip_ws_and_newlines()
        if self.peek_literal_word() != "}":
            self.error("expected } to close brace group")
        self.i += 1
        return Node("T_BraceGroup", start, self.i, commands=cmds)

    def read_arithmetic_command(self):
        start = self.i
        save = self.i
        self.i += 2  # ((
        try:
            expr = self.read_arith_seq()
            self.skip_inline_ws()
            if self.src[self.i:self.i + 2] != "))":
                self.error("expected ))")
            self.i += 2
            return Node("T_Arithmetic", start, self.i, expr=expr)
        except ParseError:
            self.i = save
            return self.read_subshell()

    def read_if(self):
        start = self.i
        self.i += 2  # if
        branches = []
        cond = self.read_list({"then"})
        self.expect_keyword("then")
        body = self.read_list({"elif", "else", "fi"})
        branches.append((cond, body))
        else_body = []
        while True:
            self.skip_ws_and_newlines()
            word = self.peek_literal_word()
            if word == "elif":
                self.i += 4
                cond = self.read_list({"then"})
                self.expect_keyword("then")
                body = self.read_list({"elif", "else", "fi"})
                branches.append((cond, body))
            elif word == "else":
                self.i += 4
                else_body = self.read_list({"fi"})
            elif word == "fi":
                self.i += 2
                break
            else:
                self.error("expected fi, found %r"
                           % (word or self.peek()))
        return Node("T_IfExpression", start, self.i,
                    branches=branches, else_body=else_body)

    def read_do_group(self):
        self.skip_ws_and_newlines()
        word = self.peek_literal_word()
        if word == "do":
            self.i += 2
            body = self.read_list({"done"})
            self.expect_keyword("done")
            return body
        if word == "{":
            # Not POSIX but accepted by some shells for for-loops; be lenient.
            group = self.read_brace_group()
            return group.commands
        self.error("expected 'do', found %r" % (word or self.peek()))

    def read_while(self):
        start = self.i
        self.i += 5
        cond = self.read_list({"do"})
        body = self.read_do_group()
        return Node("T_WhileExpression", start, self.i,
                    condition=cond, body=body)

    def read_until(self):
        start = self.i
        self.i += 5
        cond = self.read_list({"do"})
        body = self.read_do_group()
        return Node("T_UntilExpression", start, self.i,
                    condition=cond, body=body)

    def read_for(self):
        start = self.i
        self.i += 3
        self.skip_inline_ws()
        if self.peek() == "(" and self.peek(1) == "(":
            self.i += 2
            init = self.read_arith_seq(allow_empty=True)
            self.expect_char(";")
            cond = self.read_arith_seq(allow_empty=True)
            self.expect_char(";")
            update = self.read_arith_seq(allow_empty=True)
            self.skip_inline_ws()
            if self.src[self.i:self.i + 2] != "))":
                self.error("expected )) in arithmetic for loop")
            self.i += 2
            self.skip_inline_ws()
            if self.peek() == ";":
                self.i += 1
            body = self.read_do_group()
            return Node("T_ForArithmetic", start, self.i, init=init,
                        condition=cond, update=update, body=body)
        return self.read_for_in("T_ForIn", start)

    def read_select(self):
        start = self.i
        self.i += 6
        return self.read_for_in("T_SelectIn", start)

    def read_for_in(self, kind, start):
        self.skip_inline_ws()
        m = NAME_RE.match(self.src, self.i)
        if not m:
            self.error("expected a variable name in for loop")
        name = m.group(0)
        name_pos = self.i
        self.i = m.end()
        self.skip_ws_and_newlines()
        words = []
        has_in = False
        if self.peek_literal_word() == "in":
            has_in = True
            self.i += 2
            while True:
                self.skip_inline_ws()
                c = self.peek()
                if c in ("", ";", "\n", "#"):
                    break
                word = self.read_word()
                if word is None:
                    break
                words.append(word)
        self.skip_inline_ws()
        if self.peek() == ";":
            self.i += 1
        body = self.read_do_group()
        return Node(kind, start, self.i, variable=name, var_pos=name_pos,
                    has_in=has_in, words=words, body=body)

    def read_case(self):
        start = self.i
        self.i += 4
        self.skip_inline_ws()
        word = self.read_word()
        if word is None:
            self.error("expected a word after 'case'")
        self.expect_keyword("in")
        items = []
        while True:
            self.skip_ws_and_newlines()
            if self.peek_literal_word() == "esac":
                self.i += 4
                break
            if self.at_end():
                self.error("expected esac")
            if self.peek() == "(":
                self.i += 1
                self.skip_inline_ws()
            patterns = []
            while True:
                pat = self.read_word()
                if pat is None:
                    self.error("expected a case pattern")
                patterns.append(pat)
                self.skip_inline_ws()
                if self.peek() == "|":
                    self.i += 1
                    self.skip_inline_ws()
                else:
                    break
            if self.peek() != ")":
                self.error("expected ) after case pattern")
            self.i += 1
            body = self.read_list({"esac"}, stop_case_seps=True)
            self.skip_ws_and_newlines()
            sep = ";;"
            two = self.src[self.i:self.i + 2]
            if two == ";;":
                if self.peek(2) == "&":
                    sep = ";;&"
                    self.i += 3
                else:
                    self.i += 2
            elif two == ";&":
                sep = ";&"
                self.i += 2
            items.append(Node("T_CaseItem", patterns[0].pos, self.i,
                              patterns=patterns, body=body, separator=sep))
        return Node("T_CaseExpression", start, self.i, word=word, items=items)

    def read_function_kw(self):
        start = self.i
        self.i += 8  # function
        self.skip_inline_ws()
        j = self.i
        while j < self.n and self.src[j] not in " \t\n;&|<>()'\"`$\\":
            j += 1
        name = self.src[self.i:j]
        if not name:
            self.error("expected a function name")
        self.i = j
        self.skip_inline_ws()
        if self.peek() == "(" and self.peek(1) == ")":
            self.i += 2
        return self.finish_function(start, name)

    def finish_function(self, start, name):
        self.skip_ws_and_newlines()
        body = self.read_command()
        if body is None:
            self.error("expected a function body")
        return Node("T_Function", start, self.i, name=name, body=body)

    COMPOUND_STARTERS = {"{", "if", "while", "until", "for", "case",
                         "select", "[["}

    def read_bats_test(self):
        """Parse a bats `@test 'description' { ... }` block."""
        start = self.i
        self.i += 5  # @test
        self.skip_inline_ws()
        desc = self.read_word()
        self.skip_inline_ws()
        if self.peek() != "{":
            self.error("expected { after @test description")
        body = self.read_brace_group()
        return Node("T_BatsTest", start, self.i, description=desc, body=body)

    def read_coproc(self):
        start = self.i
        self.i += 6
        self.skip_inline_ws()
        name = None
        word = self.peek_literal_word()
        if (word and NAME_RE.fullmatch(word)
                and word not in KEYWORDS):
            # could be NAME compound or the command itself; look ahead
            save = self.i
            self.i += len(word)
            self.skip_inline_ws()
            if (self.src[self.i:self.i + 2] == "(("
                    or self.peek() == "("
                    or self.peek_literal_word() in self.COMPOUND_STARTERS):
                name = word
            else:
                self.i = save
        cmd = self.read_command()
        if cmd is None:
            self.error("expected a command after coproc")
        return Node("T_CoProc", start, self.i, name=name, command=cmd)

    def expect_char(self, c):
        self.skip_inline_ws()
        if self.peek() != c:
            self.error("expected %r" % c)
        self.i += 1

    # ------------------------------------------------------------------
    # Simple commands

    DECLARE_COMMANDS = {"declare", "typeset", "local", "export", "readonly"}

    def read_simple_command(self):
        start = self.i
        assigns = []
        words = []
        redirects = []
        is_declare = False
        while True:
            self.skip_inline_ws()
            if self.at_end():
                break
            c = self.peek()
            if c in ";&|\n)#":
                if c == "&" and self.peek(1) in (">",):
                    pass  # &> redirect
                else:
                    break
            r = self.maybe_read_redirect()
            if r is not None:
                redirects.append(r)
                continue
            if not words or is_declare:
                a = self.maybe_read_assignment()
                if a is not None:
                    assigns.append(a)
                    continue
            word = self.read_word()
            if word is None:
                break
            if not words:
                # function definition: name ()
                lit = literal_text(word)
                self.skip_inline_ws()
                if (lit is not None and self.peek() == "("
                        and lit not in KEYWORDS
                        and not assigns and not redirects):
                    save = self.i
                    self.i += 1
                    self.skip_inline_ws()
                    if self.peek() == ")":
                        self.i += 1
                        return self.finish_function(start, lit)
                    self.i = save
                if lit in self.DECLARE_COMMANDS:
                    is_declare = True
            words.append(word)
        if not (assigns or words or redirects):
            return None
        return Node("T_SimpleCommand", start, self.i,
                    assigns=assigns, words=words, redirects=redirects)

    def maybe_read_assignment(self):
        """Parse name=value / name[idx]+=value / name=(...) if present."""
        m = ASSIGN_RE.match(self.src, self.i)
        if not m:
            return None
        start = self.i
        name = m.group(1)
        indices = []
        j = m.end(1)
        # array indices: name[expr]... (only one in bash, but be lenient)
        while j < self.n and self.src[j] == "[":
            depth = 0
            k = j
            while k < self.n:
                ch = self.src[k]
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        break
                elif ch == "\n":
                    return None
                k += 1
            else:
                return None
            indices.append(self.src[j + 1:k])
            j = k + 1
        append = False
        if self.src[j:j + 2] == "+=":
            append = True
            j += 2
        elif self.src[j:j + 1] == "=":
            j += 1
        else:
            return None
        self.i = j
        c = self.peek()
        if c == "(":
            value = self.read_array_literal()
        elif c in METACHARS or c == "":
            value = Node("T_NormalWord", self.i, self.i, parts=[])
        else:
            value = self.read_word()
            if value is None:
                value = Node("T_NormalWord", self.i, self.i, parts=[])
        return Node("T_Assignment", start, self.i, name=name,
                    indices=indices, append=append, value=value)

    def read_array_literal(self):
        start = self.i
        self.i += 1  # (
        elements = []
        while True:
            self.skip_ws_and_newlines()
            if self.peek() == ")":
                self.i += 1
                break
            if self.at_end():
                self.error("expected ) to close array literal")
            if self.peek() == "[":
                # possible [idx]=value element
                elem = self.maybe_read_indexed_element()
                if elem is not None:
                    elements.append(elem)
                    continue
            word = self.read_word()
            if word is None:
                self.error("unexpected token in array literal: %r"
                           % self.peek())
            elements.append(word)
        return Node("T_Array", start, self.i, elements=elements)

    def maybe_read_indexed_element(self):
        start = self.i
        depth = 0
        k = self.i
        while k < self.n:
            ch = self.src[k]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    break
            elif ch == "\n":
                return None
            k += 1
        else:
            return None
        if self.src[k + 1:k + 2] != "=" and self.src[k + 1:k + 3] != "+=":
            return None
        index = self.src[self.i + 1:k]
        self.i = k + 1
        append = False
        if self.src[self.i:self.i + 2] == "+=":
            append = True
            self.i += 2
        else:
            self.i += 1
        if self.peek() in METACHARS or self.at_end():
            value = Node("T_NormalWord", self.i, self.i, parts=[])
        else:
            value = self.read_word()
        return Node("T_IndexedElement", start, self.i, index=index,
                    append=append, value=value)

    # ------------------------------------------------------------------
    # Redirections

    def maybe_read_redirect(self):
        src = self.src
        start = self.i
        i = self.i
        fd = None
        m = DIGITS_RE.match(src, i)
        if m and m.end() < self.n and src[m.end()] in "<>":
            fd = m.group(0)
            i = m.end()
        elif src[i:i + 1] == "{":
            m2 = re.match(r"\{([A-Za-z_][A-Za-z0-9_]*)\}(?=[<>])", src[i:])
            if m2:
                fd = "{" + m2.group(1) + "}"
                i += m2.end()
        c = src[i:i + 1]
        if c == "&" and src[i + 1:i + 2] == ">":
            if src[i + 2:i + 3] == ">":
                op, i = "&>>", i + 3
            else:
                op, i = "&>", i + 2
            self.i = i
            self.skip_inline_ws()
            target = self.read_word()
            if target is None:
                self.error("expected a filename after %s" % op)
            return Node("T_FdRedirect", start, self.i, fd=fd,
                        op=Node("T_IoFile", start, self.i, op=op,
                                file=target))
        if not c or c not in "<>":
            return None
        if c == "<" and src[i + 1:i + 2] == "(" and fd is None:
            return None  # process substitution, not a redirect
        if c == ">" and src[i + 1:i + 2] == "(" and fd is None:
            return None
        if c == "<":
            if src[i + 1:i + 2] == "<":
                if src[i + 2:i + 3] == "<":
                    self.i = i + 3
                    self.skip_inline_ws()
                    word = self.read_word()
                    if word is None:
                        self.error("expected a word after <<<")
                    return Node("T_FdRedirect", start, self.i, fd=fd,
                                op=Node("T_HereString", start, self.i,
                                        word=word))
                dashed = src[i + 2:i + 3] == "-"
                self.i = i + 3 if dashed else i + 2
                return self.read_heredoc_marker(start, fd, dashed)
            if src[i + 1:i + 2] == "&":
                self.i = i + 2
                return self.read_dup(start, fd, "<&")
            if src[i + 1:i + 2] == ">":
                op, self.i = "<>", i + 2
            else:
                op, self.i = "<", i + 1
        else:
            if src[i + 1:i + 2] == ">":
                op, self.i = ">>", i + 2
            elif src[i + 1:i + 2] == "&":
                self.i = i + 2
                return self.read_dup(start, fd, ">&")
            elif src[i + 1:i + 2] == "|":
                op, self.i = ">|", i + 2
            else:
                op, self.i = ">", i + 1
        self.skip_inline_ws()
        target = self.read_word()
        if target is None:
            self.error("expected a filename after %s" % op)
        return Node("T_FdRedirect", start, self.i, fd=fd,
                    op=Node("T_IoFile", start, self.i, op=op, file=target))

    def read_dup(self, start, fd, op):
        self.skip_inline_ws()
        m = re.match(r"[0-9]+-?|-", self.src[self.i:])
        if m:
            target = m.group(0)
            self.i += m.end()
            return Node("T_FdRedirect", start, self.i, fd=fd,
                        op=Node("T_IoDuplicate", start, self.i, op=op,
                                target=target))
        word = self.read_word()
        if word is None:
            self.error("expected a target after %s" % op)
        return Node("T_FdRedirect", start, self.i, fd=fd,
                    op=Node("T_IoFile", start, self.i, op=op, file=word))

    def read_heredoc_marker(self, start, fd, dashed):
        self.skip_inline_ws()
        delim_word = self.read_word()
        if delim_word is None:
            self.error("expected a here document delimiter")
        delimiter, quoted = heredoc_delimiter(delim_word)
        here = Node("T_HereDoc", start, self.i, dashed=dashed,
                    quoted=quoted, delimiter=delimiter, parts=[])
        self.pending_heredocs.append(here)
        return Node("T_FdRedirect", start, self.i, fd=fd, op=here)

    def read_heredoc_bodies(self):
        pending, self.pending_heredocs = self.pending_heredocs, []
        for here in pending:
            lines = []
            content_start = self.i
            while True:
                if self.i >= self.n:
                    break
                line_end = self.src.find("\n", self.i)
                if line_end == -1:
                    line_end = self.n
                line = self.src[self.i:line_end]
                stripped = line.lstrip("\t") if here.dashed else line
                if stripped == here.delimiter:
                    self.i = min(line_end + 1, self.n)
                    break
                lines.append(line)
                self.i = min(line_end + 1, self.n)
            content = "\n".join(lines)
            if lines:
                content += "\n"
            if here.quoted:
                parts = [Node("T_Literal", content_start,
                              content_start + len(content), text=content)]
            else:
                sub = Parser(content)
                sub.read_dquote_like_parts(content_start)
                parts = sub.heredoc_parts
            here.fields["parts"] = parts
            here.end = self.i

    def read_dquote_like_parts(self, base):
        """Parse heredoc content: literal text plus $/`` expansions."""
        parts = []
        src, n = self.src, self.n
        while self.i < n:
            c = src[self.i]
            if c == "$":
                part = self.read_dollar(in_dquote=True)
                if part is not None:
                    parts.append(part)
                    continue
                parts.append(Node("T_Literal", self.i, self.i + 1, text="$"))
                self.i += 1
            elif c == "`":
                parts.append(self.read_backticked())
            elif c == "\\" and self.i + 1 < n and src[self.i + 1] in "$`\\":
                parts.append(Node("T_Literal", self.i, self.i + 2,
                                  text=src[self.i + 1]))
                self.i += 2
            else:
                j = self.i
                while j < n and src[j] not in "$`\\":
                    j += 1
                if j == self.i:
                    j += 1
                parts.append(Node("T_Literal", self.i, j,
                                  text=src[self.i:j]))
                self.i = j
        for p in parts:
            shift_node(p, base)
        self.heredoc_parts = parts

    # ------------------------------------------------------------------
    # Words

    def read_word(self, stop_chars=""):
        """Read a word at the current position; None if no word starts here."""
        start = self.i
        parts = []
        src, n = self.src, self.n
        while self.i < n:
            c = src[self.i]
            if c in METACHARS or c in stop_chars:
                if c in "<>" and src[self.i + 1:self.i + 2] == "(" \
                        and c not in stop_chars:
                    parts.append(self.read_procsub())
                    continue
                break
            if c == "\\":
                nxt = src[self.i + 1:self.i + 2]
                if nxt == "\n":
                    self.i += 2
                    continue
                if nxt == "":
                    parts.append(Node("T_Literal", self.i, self.i + 1,
                                      text="\\"))
                    self.i += 1
                else:
                    parts.append(Node("T_Literal", self.i, self.i + 2,
                                      text=nxt, escaped=True))
                    self.i += 2
            elif c == "'":
                parts.append(self.read_single_quoted())
            elif c == '"':
                parts.append(self.read_double_quoted())
            elif c == "$":
                part = self.read_dollar(in_dquote=False)
                if part is None:
                    parts.append(Node("T_Literal", self.i, self.i + 1,
                                      text="$"))
                    self.i += 1
                else:
                    parts.append(part)
            elif c == "`":
                parts.append(self.read_backticked())
            elif c == "*" or c == "?":
                if src[self.i + 1:self.i + 2] == "(":
                    parts.append(self.read_extglob())
                else:
                    parts.append(Node("T_Glob", self.i, self.i + 1, text=c))
                    self.i += 1
            elif c in "@+!" and src[self.i + 1:self.i + 2] == "(":
                parts.append(self.read_extglob())
            elif c == "[":
                part = self.maybe_read_glob_class()
                parts.append(part)
            elif c == "{":
                part = self.maybe_read_brace_expansion()
                parts.append(part)
            elif c == "}" or c == "]" or c == "!" or c == "#" or c == "~" \
                    or c == "@" or c == "+":
                parts.append(Node("T_Literal", self.i, self.i + 1, text=c))
                self.i += 1
            else:
                m = UNQUOTED_RUN.match(src, self.i)
                if m:
                    parts.append(Node("T_Literal", self.i, m.end(),
                                      text=m.group(0)))
                    self.i = m.end()
                else:
                    parts.append(Node("T_Literal", self.i, self.i + 1,
                                      text=c))
                    self.i += 1
        if not parts:
            return None
        return Node("T_NormalWord", start, self.i, parts=parts)

    def read_single_quoted(self):
        start = self.i
        end = self.src.find("'", self.i + 1)
        if end == -1:
            self.error("unterminated single-quoted string", start)
        self.i = end + 1
        return Node("T_SingleQuoted", start, self.i,
                    text=self.src[start + 1:end])

    def read_double_quoted(self, dollar=False):
        start = self.i
        self.i += 1
        parts = []
        src, n = self.src, self.n
        while True:
            if self.i >= n:
                self.error("unterminated double-quoted string", start)
            c = src[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "$":
                part = self.read_dollar(in_dquote=True)
                if part is None:
                    parts.append(Node("T_Literal", self.i, self.i + 1,
                                      text="$"))
                    self.i += 1
                else:
                    parts.append(part)
            elif c == "`":
                parts.append(self.read_backticked(in_dquote=True))
            elif c == "\\":
                nxt = src[self.i + 1:self.i + 2]
                if nxt in '"$`\\':
                    parts.append(Node("T_Literal", self.i, self.i + 2,
                                      text=nxt, escaped=True))
                    self.i += 2
                elif nxt == "\n":
                    self.i += 2
                else:
                    parts.append(Node("T_Literal", self.i, self.i + 1,
                                      text="\\"))
                    self.i += 1
            else:
                m = DQUOTE_RUN.match(src, self.i)
                parts.append(Node("T_Literal", self.i, m.end(),
                                  text=m.group(0)))
                self.i = m.end()
        kind = "T_DollarDoubleQuoted" if dollar else "T_DoubleQuoted"
        return Node(kind, start, self.i, parts=parts)

    def read_dollar(self, in_dquote):
        """Parse a $-construct at i ('$' itself); None if it's a literal $."""
        src, n = self.src, self.n
        start = self.i
        nxt = src[self.i + 1:self.i + 2]
        if nxt == "(":
            if src[self.i + 2:self.i + 3] == "(":
                # try arithmetic, fall back to command substitution
                save = self.i
                heredocs = list(self.pending_heredocs)
                try:
                    self.i += 3
                    expr = self.read_arith_seq()
                    self.skip_inline_ws()
                    if src[self.i:self.i + 2] != "))":
                        self.error("expected ))")
                    self.i += 2
                    return Node("T_DollarArithmetic", start, self.i,
                                expr=expr)
                except ParseError:
                    self.i = save
                    self.pending_heredocs = heredocs
            self.i += 2
            cmds = self.read_list(set())
            self.skip_ws_and_newlines()
            if self.peek() != ")":
                self.error("expected ) to close $( command substitution")
            self.i += 1
            return Node("T_DollarExpansion", start, self.i, commands=cmds)
        if nxt == "{":
            after = src[self.i + 2:self.i + 3]
            if after in (" ", "\t", "\n", "|"):
                # bash 5.3 / mksh "funsub": ${ commands; } and ${| cmd; }
                self.i += 2
                if self.peek() == "|":
                    self.i += 1
                cmds = self.read_list({"}"})
                self.skip_ws_and_newlines()
                if self.peek_literal_word() != "}":
                    self.error("expected } to close ${ command; }")
                self.i += 1
                return Node("T_DollarBraceCommandExpansion", start, self.i,
                            commands=cmds)
            return self.read_dollar_braced()
        if nxt == "'":
            self.i += 1
            inner = self.read_ansi_quoted()
            inner.pos = start
            return inner
        if nxt == '"':
            self.i += 1
            return self.read_double_quoted(dollar=True)
        if nxt == "[":
            # deprecated $[expr]
            self.i += 2
            expr = self.read_arith_seq()
            self.skip_inline_ws()
            if self.peek() != "]":
                self.error("expected ] to close $[ ]")
            self.i += 1
            return Node("T_DollarArithmetic", start, self.i, expr=expr,
                        deprecated=True)
        m = NAME_RE.match(src, self.i + 1)
        if m:
            self.i = m.end()
            return Node("T_DollarBraced", start, self.i, braced=False,
                        content=m.group(0))
        if nxt and nxt in SPECIAL_PARAMS:
            self.i += 2
            return Node("T_DollarBraced", start, self.i, braced=False,
                        content=nxt)
        return None

    def read_dollar_braced(self):
        start = self.i
        self.i += 2  # ${
        src, n = self.src, self.n
        depth = 1
        j = self.i
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                end = src.find("'", j + 1)
                if end == -1:
                    self.error("unterminated string inside ${}", j)
                j = end + 1
                continue
            if c == '"':
                j += 1
                while j < n and src[j] != '"':
                    if src[j] == "\\":
                        j += 1
                    j += 1
                j += 1
                continue
            if c == "$" and src[j + 1:j + 2] == "{":
                depth += 1
                j += 2
                continue
            if c == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= n:
            self.error("unterminated ${", start)
        content = src[self.i:j]
        node = Node("T_DollarBraced", start, j + 1, braced=True,
                    content=content)
        parse_braced_content(node, content, self.i)
        self.i = j + 1
        return node

    def read_ansi_quoted(self):
        start = self.i
        src, n = self.src, self.n
        j = self.i + 1
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
            elif c == "'":
                break
            else:
                j += 1
        if j >= n:
            self.error("unterminated $' string", start)
        self.i = j + 1
        return Node("T_DollarSingleQuoted", start, self.i,
                    text=src[start + 1:j])

    def read_backticked(self, in_dquote=False):
        start = self.i
        src, n = self.src, self.n
        j = self.i + 1
        escapable = '$`\\"' if in_dquote else "$`\\"
        chars = []
        while j < n:
            c = src[j]
            if c == "\\" and j + 1 < n and src[j + 1] in escapable:
                chars.append(src[j + 1])
                j += 2
            elif c == "`":
                break
            else:
                chars.append(c)
                j += 1
        if j >= n:
            self.error("unterminated backquote", start)
        inner = "".join(chars)
        sub = Parser(inner)
        try:
            script = sub.parse()
            cmds = script.commands
        except ParseError as e:
            raise ParseError(e.message, start + 1 + e.pos, e.code)
        for c in cmds:
            shift_node(c, start + 1)
        self.i = j + 1
        return Node("T_Backticked", start, self.i, commands=cmds)

    def read_procsub(self):
        start = self.i
        op = self.src[self.i]
        self.i += 2  # <( or >(
        cmds = self.read_list(set())
        self.skip_ws_and_newlines()
        if self.peek() != ")":
            self.error("expected ) to close process substitution")
        self.i += 1
        return Node("T_ProcSub", start, self.i, op=op, commands=cmds)

    def read_extglob(self):
        start = self.i
        op = self.src[self.i]
        self.i += 2  # X(
        items = []
        current_start = self.i
        depth = 1
        # Read the raw contents balancing parens, splitting on top-level |
        src, n = self.src, self.n
        j = self.i
        item_starts = [j]
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                end = src.find("'", j + 1)
                if end == -1:
                    break
                j = end + 1
                continue
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            elif c == "|" and depth == 1:
                items.append(src[item_starts[-1]:j])
                item_starts.append(j + 1)
            j += 1
        if j >= n or src[j] != ")":
            self.error("unterminated extglob", start)
        items.append(src[item_starts[-1]:j])
        self.i = j + 1
        return Node("T_Extglob", start, self.i, op=op, items=items)

    def maybe_read_glob_class(self):
        """Parse [...] as a glob character class, else literal '['."""
        src, n = self.src, self.n
        start = self.i
        j = self.i + 1
        if j < n and src[j] in "!^":
            j += 1
        if j < n and src[j] == "]":
            j += 1
        while j < n:
            c = src[j]
            if c == "]":
                self.i = j + 1
                return Node("T_Glob", start, self.i,
                            text=src[start:self.i])
            if c in "\n'\"`$\\" or c in METACHARS:
                break
            if c == "[" and src[j + 1:j + 2] == ":":
                end = src.find(":]", j + 2)
                if end == -1:
                    break
                j = end + 2
                continue
            j += 1
        self.i = start + 1
        return Node("T_Literal", start, self.i, text="[")

    def maybe_read_brace_expansion(self):
        """Parse {a,b} / {1..5} brace expansion, else literal '{'."""
        src, n = self.src, self.n
        start = self.i
        depth = 0
        j = self.i
        has_sep = False
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
                continue
            if c == "'":
                end = src.find("'", j + 1)
                if end == -1:
                    break
                j = end + 1
                continue
            if c in " \t\n;&|<>()" or c == '"' or c == "`":
                break
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            elif depth == 1 and (c == ","
                                 or (c == "." and src[j + 1:j + 2] == ".")):
                has_sep = True
            elif c == "$" and src[j + 1:j + 2] == "{":
                # ${...} inside; skip braced expansion
                k = j + 2
                d2 = 1
                while k < n and d2:
                    if src[k] == "{":
                        d2 += 1
                    elif src[k] == "}":
                        d2 -= 1
                    k += 1
                j = k - 1
            j += 1
        if has_sep and depth == 0 and j > self.i and src[j - 1] == "}":
            text = src[start:j]
            inner = text[1:-1]
            sub = Parser(inner)
            try:
                word = sub.read_word()
                parts = word.parts if word is not None and sub.at_end() \
                    else []
            except ParseError:
                parts = []
            for p in parts:
                shift_node(p, start + 1)
            self.i = j
            return Node("T_BraceExpansion", start, j, text=text,
                        parts=parts)
        self.i = start + 1
        return Node("T_Literal", start, self.i, text="{")

    # ------------------------------------------------------------------
    # Conditions ([ ] and [[ ]])

    def read_condition(self, single):
        start = self.i
        self.i += 1 if single else 2
        self.skip_inline_ws()
        if self.peek() == "\n" and not single:
            self.skip_ws_and_newlines()
        close = "]" if single else "]]"
        if self.cond_at_close(single):
            self.consume_cond_close(single)
            return Node("T_Condition", start, self.i, single=single,
                        expr=Node("TC_Empty", start, self.i))
        expr = self.read_cond_or(single)
        self.skip_inline_ws()
        if not single and self.peek() == "\n":
            self.skip_ws_and_newlines()
        if not self.cond_at_close(single):
            self.error("expected %s" % close)
        self.consume_cond_close(single)
        return Node("T_Condition", start, self.i, single=single, expr=expr)

    def cond_at_close(self, single):
        if single:
            return (self.peek_literal_word() == "]")
        return self.src[self.i:self.i + 2] == "]]" and \
            self.src[self.i + 2:self.i + 3] != "]"

    def consume_cond_close(self, single):
        self.i += 1 if single else 2

    def cond_skip_ws(self, single):
        while True:
            self.skip_inline_ws()
            if not single and self.peek() == "\n":
                self.consume_newline()
            else:
                break

    def read_cond_or(self, single):
        left = self.read_cond_and(single)
        while True:
            self.cond_skip_ws(single)
            if self.src[self.i:self.i + 2] == "||":
                op = "||"
                self.i += 2
            elif self.peek_literal_word() == "-o":
                op = "-o"
                self.i += 2
            else:
                return left
            self.cond_skip_ws(single)
            right = self.read_cond_and(single)
            left = Node("TC_Or", left.pos, right.end, op=op,
                        left=left, right=right)

    def read_cond_and(self, single):
        left = self.read_cond_term(single)
        while True:
            self.cond_skip_ws(single)
            if self.src[self.i:self.i + 2] == "&&":
                op = "&&"
                self.i += 2
            elif self.peek_literal_word() == "-a":
                op = "-a"
                self.i += 2
            else:
                return left
            self.cond_skip_ws(single)
            right = self.read_cond_term(single)
            left = Node("TC_And", left.pos, right.end, op=op,
                        left=left, right=right)

    def read_cond_term(self, single):
        self.cond_skip_ws(single)
        start = self.i
        word = self.peek_literal_word()
        if word == "!":
            self.i += 1
            operand = self.read_cond_term(single)
            return Node("TC_Unary", start, operand.end, op="!",
                        operand=operand)
        if not single and self.peek() == "(":
            self.i += 1
            inner = self.read_cond_or(single)
            self.cond_skip_ws(single)
            if self.peek() != ")":
                self.error("expected ) in [[ ]]")
            self.i += 1
            return Node("TC_Group", start, self.i, expr=inner)
        if single and word == "\\(":
            self.i += 2
            inner = self.read_cond_or(single)
            self.cond_skip_ws(single)
            if self.peek_literal_word() != "\\)":
                self.error("expected \\) in [ ]")
            self.i += 2
            return Node("TC_Group", start, self.i, expr=inner)
        if word in UNARY_TEST_OPS or (
                self.COND_OP_WORD.match(word)
                and word not in ("-a", "-o")
                and word not in BINARY_TEST_OPS):
            self.i += len(word)
            self.cond_skip_ws(single)
            operand = self.read_cond_word(single)
            if operand is None:
                self.error("expected an operand after %s" % word)
            return Node("TC_Unary", start, operand.end, op=word,
                        operand=operand)
        lhs = self.read_cond_word(single)
        if lhs is None:
            self.error("expected a test operand")
        self.cond_skip_ws(single)
        op = self.peek_cond_binary_op(single)
        if op is None:
            return Node("TC_Nullary", start, lhs.end, word=lhs)
        self.i += getattr(op, "width", len(op))
        self.cond_skip_ws(single)
        if op == "=~":
            rhs = self.read_regex_word()
        else:
            rhs = self.read_cond_word(single)
        if rhs is None:
            self.error("expected an operand after %s" % op)
        return Node("TC_Binary", start, rhs.end, op=op, lhs=lhs, rhs=rhs)

    COND_OP_WORD = re.compile(r"-[A-Za-z][A-Za-z0-9]*$")

    def peek_cond_binary_op(self, single):
        src = self.src
        for op in ("=~", "==", "!=", "<=", ">=", "\\<=", "\\>=",
                   "\\<", "\\>"):
            if src.startswith(op, self.i):
                return op
        c = src[self.i:self.i + 1]
        if c in "<>=" and src[self.i + 1:self.i + 2] != "(":
            return c
        word = self.peek_literal_word()
        if word in BINARY_TEST_OPS:
            return word
        if (self.COND_OP_WORD.match(word)
                and word not in UNARY_TEST_OPS
                and not (single and word in ("-a", "-o"))):
            # unknown -xy flags: parse as binary so checks can flag them
            return word
        if single and c in "'\"":
            # quoted operator, e.g. [ $a '>' $b ]
            save = self.i
            try:
                w = self.read_word()
            except ParseError:
                self.i = save
                return None
            self.i = save
            text = quoted_literal_text(w)
            if text in BINARY_TEST_OPS:
                return None if text is None else QuotedOp(text, w.end - save)
        return None

    def read_cond_word(self, single):
        if self.cond_at_close(single):
            return None
        stop = ")" if not single else ""
        word = self.read_word(stop_chars=stop)
        return word

    def read_regex_word(self):
        """Read the right-hand side of =~, where ( ) and | are literal."""
        start = self.i
        parts = []
        src, n = self.src, self.n
        depth = 0
        while self.i < n:
            c = src[self.i]
            if c == "[":
                # bracket expression: ]] inside it is not the closer
                j = self.i + 1
                if j < n and src[j] == "^":
                    j += 1
                if j < n and src[j] == "]":
                    j += 1
                while j < n and src[j] != "]":
                    if src.startswith("[:", j):
                        k = src.find(":]", j + 2)
                        if k == -1:
                            break
                        j = k + 2
                    else:
                        j += 1
                if j < n and src[j] == "]":
                    parts.append(Node("T_Literal", self.i, j + 1,
                                      text=src[self.i:j + 1]))
                    self.i = j + 1
                    continue
            if c in " \t\n" and depth == 0:
                break
            if src.startswith("]]", self.i) and depth == 0:
                break
            if (src.startswith("&&", self.i) or
                    src.startswith("||", self.i)) and depth == 0:
                break
            if c == "(":
                depth += 1
                parts.append(Node("T_Literal", self.i, self.i + 1, text="("))
                self.i += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
                parts.append(Node("T_Literal", self.i, self.i + 1, text=")"))
                self.i += 1
            elif c == "'":
                parts.append(self.read_single_quoted())
            elif c == '"':
                parts.append(self.read_double_quoted())
            elif c == "$":
                part = self.read_dollar(in_dquote=False)
                if part is None:
                    parts.append(Node("T_Literal", self.i, self.i + 1,
                                      text="$"))
                    self.i += 1
                else:
                    parts.append(part)
            elif c == "\\":
                nxt = src[self.i + 1:self.i + 2]
                parts.append(Node("T_Literal", self.i, self.i + 2,
                                  text=nxt, escaped=True))
                self.i += 2
            else:
                parts.append(Node("T_Literal", self.i, self.i + 1, text=c))
                self.i += 1
        if not parts:
            return None
        return Node("T_NormalWord", start, self.i, parts=parts)

    # ------------------------------------------------------------------
    # Arithmetic expressions

    def read_arith_seq(self, allow_empty=False):
        start = self.i
        exprs = [self.read_arith_assignment(allow_empty=allow_empty)]
        while True:
            self.skip_arith_ws()
            if self.peek() == ",":
                self.i += 1
                exprs.append(self.read_arith_assignment())
            else:
                break
        if len(exprs) == 1:
            return exprs[0]
        return Node("TA_Sequence", start, self.i, exprs=exprs)

    def skip_arith_ws(self):
        src, n = self.src, self.n
        i = self.i
        while i < n:
            c = src[i]
            if c in " \t\r\n":
                i += 1
            elif c == "\\" and i + 1 < n and src[i + 1] == "\n":
                i += 2
            else:
                break
        self.i = i

    def read_arith_assignment(self, allow_empty=False):
        self.skip_arith_ws()
        start = self.i
        if allow_empty and (self.peek() in ";)" or
                            self.src[self.i:self.i + 2] == "))"):
            return Node("TA_Empty", start, start)
        left = self.read_arith_ternary()
        self.skip_arith_ws()
        src = self.src
        for op in ARITH_ASSIGN_OPS:
            if src.startswith(op, self.i):
                if op == "=" and src[self.i + 1:self.i + 2] == "=":
                    break
                self.i += len(op)
                right = self.read_arith_assignment()
                return Node("TA_Assignment", start, right.end, op=op,
                            left=left, right=right)
        return left

    def read_arith_ternary(self):
        start = self.i
        cond = self.read_arith_binary(0)
        self.skip_arith_ws()
        if self.peek() == "?":
            self.i += 1
            then = self.read_arith_assignment()
            self.skip_arith_ws()
            if self.peek() != ":":
                self.error("expected : in ternary expression")
            self.i += 1
            otherwise = self.read_arith_assignment()
            return Node("TA_Trinary", start, otherwise.end, cond=cond,
                        then=then, otherwise=otherwise)
        return cond

    ARITH_BINARY_LEVELS = [
        ("||",),
        ("&&",),
        ("|",),
        ("^",),
        ("&",),
        ("==", "!="),
        ("<=", ">=", "<", ">"),
        ("<<", ">>"),
        ("+", "-"),
        ("*", "/", "%"),
    ]

    def read_arith_binary(self, level):
        if level >= len(self.ARITH_BINARY_LEVELS):
            return self.read_arith_power()
        ops = self.ARITH_BINARY_LEVELS[level]
        start = self.i
        left = self.read_arith_binary(level + 1)
        while True:
            self.skip_arith_ws()
            src = self.src
            matched = None
            for op in ops:
                if src.startswith(op, self.i):
                    after = src[self.i + len(op):self.i + len(op) + 1]
                    if op in ("<", ">") and after == op:
                        continue
                    if op in ("<", ">") and after == "=":
                        continue
                    if op == "|" and after == "|":
                        continue
                    if op == "&" and after == "&":
                        continue
                    if op in ("+", "-") and after == op:
                        # ++/-- handled at unary level; but binary a+ +b?
                        # disambiguate: treat as increment only when not
                        # followed by operand... keep simple: binary.
                        pass
                    if op == "=" or (op in ("<<", ">>") and after == "="):
                        continue
                    matched = op
                    break
            if matched is None:
                return left
            if matched in ("+", "-"):
                nxt = src[self.i + 1:self.i + 2]
                if nxt == matched:
                    # could be a++ + b or ++b; if left side just ended with
                    # operand, this is postfix on it
                    pass
            self.i += len(matched)
            right = self.read_arith_binary(level + 1)
            left = Node("TA_Binary", start, right.end, op=matched,
                        left=left, right=right)

    def read_arith_power(self):
        start = self.i
        left = self.read_arith_unary()
        self.skip_arith_ws()
        if self.src.startswith("**", self.i):
            self.i += 2
            right = self.read_arith_power()
            return Node("TA_Binary", start, right.end, op="**", left=left,
                        right=right)
        return left

    def read_arith_unary(self):
        self.skip_arith_ws()
        start = self.i
        src = self.src
        for op in ("++", "--", "!", "~", "+", "-"):
            if src.startswith(op, self.i):
                if op in ("+", "-") and src.startswith(op * 2, self.i):
                    continue
                self.i += len(op)
                operand = self.read_arith_unary()
                kind = "TA_Unary"
                return Node(kind, start, operand.end, op=op, operand=operand)
        return self.read_arith_postfix()

    def read_arith_postfix(self):
        start = self.i
        operand = self.read_arith_primary()
        while True:
            self.skip_arith_ws()
            if self.src.startswith("++", self.i) or \
                    self.src.startswith("--", self.i):
                op = self.src[self.i:self.i + 2]
                self.i += 2
                operand = Node("TA_Unary", start, self.i, op="|" + op,
                               operand=operand, postfix=True)
            else:
                return operand

    def read_arith_primary(self):
        self.skip_arith_ws()
        start = self.i
        src, n = self.src, self.n
        c = self.peek()
        if c == "(":
            self.i += 1
            inner = self.read_arith_seq()
            self.skip_arith_ws()
            if self.peek() != ")":
                self.error("expected ) in arithmetic expression")
            self.i += 1
            return Node("TA_Parenthesis", start, self.i, expr=inner)
        if c == "$":
            part = self.read_dollar(in_dquote=False)
            if part is not None:
                indices = self.maybe_arith_indices()
                return Node("TA_Expansion", start, self.i, parts=[part],
                            indices=indices)
        if c == "`":
            part = self.read_backticked()
            return Node("TA_Expansion", start, self.i, parts=[part],
                        indices=[])
        if c == '"' or c == "'":
            part = (self.read_double_quoted() if c == '"'
                    else self.read_single_quoted())
            return Node("TA_Expansion", start, self.i, parts=[part],
                        indices=[])
        m = re.match(r"0[xX][0-9a-fA-F]+|[0-9]+#[0-9a-zA-Z@_]+|[0-9]+",
                     src[self.i:])
        if m:
            self.i += m.end()
            return Node("TA_Literal", start, self.i, value=m.group(0))
        m = NAME_RE.match(src, self.i)
        if m:
            name = m.group(0)
            self.i = m.end()
            indices = self.maybe_arith_indices()
            return Node("TA_Variable", start, self.i, name=name,
                        indices=indices)
        self.error("unexpected token in arithmetic expression: %r"
                   % (c or "<eof>"))

    def maybe_arith_indices(self):
        indices = []
        src, n = self.src, self.n
        while self.peek() == "[":
            depth = 0
            j = self.i
            while j < n:
                ch = src[j]
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        break
                elif ch == "\\":
                    j += 1
                j += 1
            if j >= n:
                self.error("unterminated array index")
            raw = src[self.i + 1:j]
            inner_pos = self.i + 1
            self.i = j + 1
            indices.append(parse_index(raw, inner_pos))
        return indices


# ----------------------------------------------------------------------
# Helpers

def shift_node(node, offset):
    node.pos += offset
    node.end += offset
    from .shast import iter_children
    for c in iter_children(node):
        shift_node(c, offset)


def literal_text(word):
    """The literal string of a word made only of literal parts, else None."""
    if word is None or word.kind != "T_NormalWord":
        return None
    out = []
    for p in word.parts:
        if p.kind == "T_Literal":
            out.append(p.text)
        else:
            return None
    return "".join(out)


def heredoc_delimiter(word):
    """Extract (delimiter_text, was_quoted) from a heredoc delimiter word."""
    out = []
    quoted = False
    for p in word.parts:
        if p.kind == "T_Literal":
            out.append(p.text)
            if p.get("escaped"):
                quoted = True
        elif p.kind == "T_SingleQuoted":
            out.append(p.text)
            quoted = True
        elif p.kind in ("T_DoubleQuoted", "T_DollarDoubleQuoted"):
            quoted = True
            for q in p.parts:
                if q.kind == "T_Literal":
                    out.append(q.text)
        elif p.kind == "T_DollarSingleQuoted":
            out.append(p.text)
            quoted = True
        else:
            out.append("?")
    return "".join(out), quoted


BRACED_RE = re.compile(
    r"^(?P<bang>[!#]?)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!_-])?"
    r"(?P<index>\[.*?\])*"
)

BRACED_OPS = ("::", ":-", ":=", ":?", ":+", "##", "%%", "//", "/#", "/%",
              "^^", ",,", "@", "-", "=", "?", "+", "#", "%", "/", "^", ",",
              ":")


def parse_braced_content(node, content, base):
    """Decompose ${...} content into name / op / argument word."""
    f = node.fields
    f["prefix"] = ""
    f["op"] = ""
    f["arg_parts"] = []
    f["indices"] = []
    s = content
    if not s:
        f["name"] = ""
        return
    i = 0
    if s[0] in "!#" and len(s) > 1 and (s[1].isalnum() or s[1] in "_@*?$!#-"):
        # ${#var} length, ${!var} indirection -- but ${#} and ${!} are names
        f["prefix"] = s[0]
        i = 1
    m = re.match(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!_-]", s[i:])
    if not m:
        f["name"] = ""
        return
    f["name"] = m.group(0)
    i += m.end()
    # array indices
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
        f["indices"].append(parse_index(s[i + 1:j], base + i + 1))
        i = j + 1
    for op in BRACED_OPS:
        if s.startswith(op, i):
            f["op"] = op
            i += len(op)
            break
    rest = s[i:]
    if rest:
        sub = Parser(rest)
        try:
            word = sub.read_word(stop_chars="")
        except ParseError:
            word = None
        if word is not None and sub.at_end():
            shift_node(word, base + i)
            f["arg_parts"] = word.parts
        else:
            f["arg_parts"] = [Node("T_Literal", base + i,
                                   base + i + len(rest), text=rest)]


def parse_index(raw, pos):
    """Parse an array index as arithmetic when possible, else literal."""
    raw_stripped = raw.strip()
    if raw_stripped in ("@", "*"):
        return Node("T_Literal", pos, pos + len(raw), text=raw_stripped)
    sub = Parser(raw)
    try:
        expr = sub.read_arith_seq()
        sub.skip_arith_ws()
        if sub.at_end():
            shift_node(expr, pos)
            return expr
    except ParseError:
        pass
    sub = Parser(raw)
    try:
        word = sub.read_word()
        if word is not None and sub.at_end():
            shift_node(word, pos)
            return word
    except ParseError:
        pass
    return Node("T_Literal", pos, pos + len(raw), text=raw)


def parse(source):
    """Parse a script, returning its T_Script root node."""
    return Parser(source).parse()
