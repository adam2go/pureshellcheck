"""API, CLI, and behavior smoke tests."""

import json
import subprocess
import sys

import pureshellcheck
from pureshellcheck import check


def codes(src, **kw):
    return sorted({f.code for f in check(src, **kw)})


def test_basic_finding():
    findings = check("#!/bin/bash\necho $foo\n")
    assert any(f.code == 2086 for f in findings)
    f = [x for x in findings if x.code == 2086][0]
    assert (f.line, f.column) == (2, 6)
    assert f.severity == "info"
    assert "quote" in f.message.lower()


def test_clean_script():
    assert codes('#!/bin/bash\nset -e\nls -l "$HOME"\n') == []


def test_missing_shebang():
    assert 2148 in codes("echo hello\n")
    assert 2148 not in codes("echo hello\n", shell="bash")


def test_shell_detection_from_shebang():
    # sh splits export assignments, bash does not
    src = "export var=$value\n"
    assert 2086 in codes("#!/bin/sh\n" + src)
    assert 2086 not in codes("#!/bin/bash\n" + src)


def test_directive_disable():
    src = "#!/bin/bash\n# shellcheck disable=SC2086\necho $foo\n"
    assert 2086 not in codes(src)


def test_directive_disable_file_wide():
    src = "# shellcheck disable=SC2086\n#!/bin/bash\necho $a\necho $b\n"
    assert 2086 not in codes(src)


def test_parse_error_reported():
    findings = check("echo 'unterminated\n")
    assert findings and findings[0].code == 1073
    assert findings[0].severity == "error"


def test_optional_checks_off_by_default():
    src = "#!/bin/bash\nx=1; echo $x\n"
    assert 2248 not in codes(src)
    assert 2248 in codes(src, include_optional=True)


def test_implemented_codes():
    impl = pureshellcheck.implemented_codes()
    assert 2086 in impl
    assert len(impl) >= 70


def test_version():
    assert pureshellcheck.__version__


def run_cli(args, stdin=""):
    return subprocess.run(
        [sys.executable, "-m", "pureshellcheck.cli"] + args,
        input=stdin, capture_output=True, text=True)


def test_cli_tty():
    r = run_cli(["-"], stdin="#!/bin/bash\necho $foo\n")
    assert r.returncode == 1
    assert "SC2086" in r.stdout


def test_cli_clean_exit_zero():
    r = run_cli(["-"], stdin='#!/bin/bash\necho "$HOME"\n')
    assert r.returncode == 0


def test_cli_json1():
    r = run_cli(["-f", "json1", "-"], stdin="#!/bin/bash\necho $foo\n")
    data = json.loads(r.stdout)
    assert data["comments"][0]["code"] == 2086
    assert data["comments"][0]["level"] == "info"


def test_cli_gcc_format():
    r = run_cli(["-f", "gcc", "-"], stdin="#!/bin/bash\necho $foo\n")
    assert ":2:6:" in r.stdout and "[SC2086]" in r.stdout


def test_cli_exclude():
    r = run_cli(["-e", "SC2086", "-"], stdin="#!/bin/bash\necho $HOME\n")
    assert r.returncode == 0


def test_cli_severity_filter():
    r = run_cli(["-S", "error", "-"], stdin="#!/bin/bash\necho $foo\n")
    assert r.returncode == 0


def test_cli_shell_flag():
    r = run_cli(["-s", "sh", "-"], stdin="export var=$value\n")
    assert "SC2086" in r.stdout


def test_cli_missing_file():
    r = run_cli(["/nonexistent/file.sh"])
    assert r.returncode == 2


def test_cli_options_after_positional(tmp_path):
    # argparse before Python 3.12 stops parsing options after positionals;
    # the CLI reorders argv so `pureshellcheck file -f gcc` works everywhere
    f = tmp_path / "x.sh"
    f.write_text("#!/bin/bash\necho $foo\n")
    r = run_cli([str(f), "-f", "gcc"])
    assert r.returncode == 1
    assert "[SC2086]" in r.stdout
    r = run_cli([str(f), "-e", "SC2086,SC2154"])
    assert r.returncode == 0


def test_bom_tolerated(tmp_path):
    src = "﻿#!/bin/bash\necho $foo\n"
    assert 2148 not in codes(src)  # shebang still detected behind the BOM
    assert 2086 in codes(src)
    f = tmp_path / "bom.sh"
    f.write_bytes(src.encode("utf-8"))
    r = run_cli(["-f", "gcc", str(f)])
    assert "[SC2086]" in r.stdout and "SC2148" not in r.stdout
