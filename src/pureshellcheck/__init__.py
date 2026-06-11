"""pureshellcheck: a pure Python reimplementation of ShellCheck's most
common checks.

>>> import pureshellcheck
>>> for finding in pureshellcheck.check('echo $foo'):
...     print(finding.line, finding.column, finding.code, finding.message)
"""

__version__ = "0.1.0"

from .analyzer import Finding, run_checks  # noqa: F401
from .parser import ParseError, parse  # noqa: F401
from . import checks  # noqa: F401  (registers all checks)


def check(source, shell=None, include_optional=False):
    """Analyze a shell script and return a list of Finding objects.

    `shell` overrides shebang detection ("bash", "sh", "dash", "ksh").
    Findings have: code (int), severity, message, line, column, end_line,
    end_column.
    """
    findings, _ = run_checks(source, shell=shell,
                             include_optional=include_optional)
    return findings


def implemented_codes():
    """The set of SC codes this version can emit."""
    from .analyzer import NODE_CHECKS, TREE_CHECKS  # noqa: F401
    return set(_IMPLEMENTED)


# maintained by hand; verified by tests/test_implemented.py
_IMPLEMENTED = set()


def _register_codes(*codes):
    _IMPLEMENTED.update(codes)


_register_codes(
    1073,  # parse errors
    2006, 2016, 2026, 2027, 2041, 2042, 2043, 2046, 2048, 2066, 2068,
    2086, 2089, 2090, 2140, 2145, 2206, 2207, 2223, 2248, 2250, 2258,
)
