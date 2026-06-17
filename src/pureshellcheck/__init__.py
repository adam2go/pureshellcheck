"""pureshellcheck: a pure Python reimplementation of ShellCheck's most
common checks.

>>> import pureshellcheck
>>> for finding in pureshellcheck.check('echo $foo'):
...     print(finding.line, finding.column, finding.code, finding.message)
"""

__version__ = "0.2.2"

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
_register_codes(
    2002, 2003, 2005, 2009, 2010, 2011, 2012, 2015, 2038, 2050, 2059,
    2064, 2065, 2114, 2115, 2116, 2126, 2148, 2162, 2164, 2174, 2181,
    2182, 2183, 2187, 2188, 2189, 2239, 2246, 2304, 2305,
    2306, 2307, 2308,
)
_register_codes(
    2004, 2034, 2128, 2153, 2154, 2155, 2178, 2179,
)
_register_codes(
    2007, 2028, 2035, 2093, 2094, 2103,
)
