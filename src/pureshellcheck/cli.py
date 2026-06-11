"""Command line interface, modeled on shellcheck's."""

import argparse
import json
import sys

from . import __version__, run_checks

SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2, "style": 3}

COLORS = {
    "error": "\x1b[1;31m",
    "warning": "\x1b[1;33m",
    "info": "\x1b[1;32m",
    "style": "\x1b[1;32m",
    "message": "\x1b[1m",
    "source": "",
    "reset": "\x1b[0m",
}


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="pureshellcheck",
        description="Lint shell scripts (pure Python port of ShellCheck's"
                    " most common checks)")
    p.add_argument("files", nargs="+", metavar="FILE",
                   help="script files, or - for stdin")
    p.add_argument("-s", "--shell",
                   choices=["sh", "bash", "dash", "ash", "ksh", "busybox"],
                   help="specify dialect (default: detect from shebang)")
    p.add_argument("-f", "--format", default="tty",
                   choices=["tty", "gcc", "json", "json1"],
                   help="output format (default: tty)")
    p.add_argument("-e", "--exclude", action="append", default=[],
                   metavar="CODE1,CODE2..", help="exclude these checks")
    p.add_argument("-S", "--severity", default="style",
                   choices=["error", "warning", "info", "style"],
                   help="minimum severity to report (default: style)")
    p.add_argument("-o", "--enable", action="append", default=[],
                   metavar="check1,check2..",
                   help="enable optional checks ('all' for every one)")
    p.add_argument("-C", "--color", nargs="?", const="always",
                   default="auto", choices=["auto", "always", "never"],
                   help="use color (default: auto)")
    p.add_argument("--version", action="version",
                   version="pureshellcheck %s" % __version__)
    return p.parse_args(argv)


def parse_excludes(items):
    codes = set()
    for item in items:
        for part in item.split(","):
            part = part.strip()
            if part.upper().startswith("SC"):
                part = part[2:]
            if part.isdigit():
                codes.add(int(part))
    return codes


def check_file(path, args, excluded, min_rank):
    if path == "-":
        source = sys.stdin.read()
        name = "-"
    else:
        with open(path, encoding="utf-8", errors="replace") as f:
            source = f.read()
        name = path
    shell = args.shell if args.shell != "busybox" else "ash"
    include_optional = bool(args.enable)
    findings, _err = run_checks(source, shell=shell,
                                include_optional=include_optional,
                                filename=name)
    findings = [f for f in findings
                if f.code not in excluded
                and SEVERITY_RANK[f.severity] <= min_rank]
    return name, source, findings


def emit_tty(name, source, findings, out, color):
    lines = source.split("\n")
    c = COLORS if color else dict.fromkeys(COLORS, "")
    for f in findings:
        line_text = lines[f.line - 1] if f.line - 1 < len(lines) else ""
        out.write("\n%sIn %s line %d:%s\n"
                  % (c["message"], name, f.line, c["reset"]))
        out.write(line_text + "\n")
        start = f.column - 1
        if f.end_line == f.line and f.end_column > f.column:
            width = f.end_column - f.column
        else:
            width = 1
        marker = "^" if width <= 1 else "^" + "-" * (width - 2) + "^"
        out.write(" " * start + "%s%s SC%d (%s): %s%s\n"
                  % (c[f.severity], marker, f.code, f.severity, f.message,
                     c["reset"]))


def emit_gcc(name, source, findings, out, color):
    sev = {"error": "error", "warning": "warning", "info": "note",
           "style": "note"}
    for f in findings:
        out.write("%s:%d:%d: %s: %s [SC%d]\n"
                  % (name, f.line, f.column, sev[f.severity], f.message,
                     f.code))


def finding_json(name, f):
    return {
        "file": name,
        "line": f.line,
        "endLine": f.end_line,
        "column": f.column,
        "endColumn": f.end_column,
        "level": f.severity,
        "code": f.code,
        "message": f.message,
    }


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    excluded = parse_excludes(args.exclude)
    min_rank = SEVERITY_RANK[args.severity]
    out = sys.stdout
    color = args.color == "always" or (args.color == "auto"
                                       and out.isatty())
    any_findings = False
    had_error = False
    json_items = []
    for path in args.files:
        try:
            name, source, findings = check_file(path, args, excluded,
                                                min_rank)
        except OSError as e:
            sys.stderr.write("pureshellcheck: %s: %s\n"
                             % (path, e.strerror or e))
            had_error = True
            continue
        if findings:
            any_findings = True
        if args.format == "tty":
            emit_tty(name, source, findings, out, color)
        elif args.format == "gcc":
            emit_gcc(name, source, findings, out, color)
        else:
            json_items.extend(finding_json(name, f) for f in findings)
    if args.format == "json":
        json.dump(json_items, out)
        out.write("\n")
    elif args.format == "json1":
        json.dump({"comments": json_items}, out)
        out.write("\n")
    if had_error:
        return 2
    return 1 if any_findings else 0


if __name__ == "__main__":
    sys.exit(main())
