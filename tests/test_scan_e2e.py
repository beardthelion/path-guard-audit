"""End-to-end scan tests against the committed fixture targets.

These drive the real semgrep subprocess through cli.main, so they also
guard the fixture trees under tests/fixtures/ against going stale.
"""

import shutil
from pathlib import Path

import pytest

from path_guard_audit.cli import main

FIXTURES = Path(__file__).parent / "fixtures"

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep binary not on PATH"
)


def test_scan_unguarded_python_reports_p0(capsys):
    code = main(["scan", str(FIXTURES / "p0" / "unguarded-python")])
    assert code == 1
    assert "[P0]" in capsys.readouterr().out


def test_scan_unguarded_typescript_reports_class(capsys):
    code = main(["scan", str(FIXTURES / "p0" / "unguarded-typescript")])
    assert code == 1
    assert "[P0]" in capsys.readouterr().out


def test_scan_complete_guard_python_clean(capsys):
    code = main(["scan", str(FIXTURES / "p0" / "complete-guard-python")])
    out = capsys.readouterr().out
    assert "[P0]" not in out
    assert code == 0


def test_scan_unrecognized_guard(capsys):
    code = main(["scan", str(FIXTURES / "cli" / "unrecognized-guard-python")])
    assert code == 1
    assert "shape unrecognized" in capsys.readouterr().out


def test_scan_empty_dir_reports_no_surface(capsys, tmp_path):
    code = main(["scan", str(tmp_path)])
    assert code == 0
    assert "no path-relevant surface detected" in capsys.readouterr().out


def test_scan_missing_target_fails():
    assert main(["scan", str(FIXTURES / "does-not-exist")]) == 2


def test_scan_vendored_dir_excluded(capsys):
    code = main(["scan", str(FIXTURES / "cli" / "vendored-skip")])
    assert code == 0
    assert "files scanned: 0" in capsys.readouterr().out


def test_scan_target_ignore_files_not_honored(capsys):
    # The fixture ships .gitignore/.semgrepignore contents that would hide
    # server.py; the tool must scan it anyway and surface the files.
    code = main(["scan", str(FIXTURES / "cli" / "ignore-evasion")])
    assert code == 1
    out = capsys.readouterr().out
    assert "ignore files present" in out or ".semgrepignore" in out


def test_scan_nosemgrep_comment_not_honored(capsys, tmp_path):
    # A target file's inline "# nosemgrep" must not suppress the finding:
    # the runner passes --disable-nosem. Without it the sink and probes
    # on that line vanish and the scan reports clean.
    (tmp_path / "server.py").write_text(
        "class Server:\n"
        "    def tool(self, *a, **k):\n"
        "        def deco(fn):\n"
        "            return fn\n"
        "        return deco\n\n"
        "server = Server()\n\n"
        "@server.tool()\n"
        "def read_file(path: str) -> str:\n"
        "    return open(path).read()  # nosemgrep\n"
    )
    code = main(["scan", str(tmp_path)])
    assert code == 1
    assert "[P0]" in capsys.readouterr().out


def test_scan_checklist_fixture_emits_candidates(capsys):
    # unpack_archive on caller paths is a P4 deterministic finding AND a
    # P5 checklist candidate (link-escape audit).
    code = main(["scan", str(FIXTURES / "cli" / "checklist-p5-python")])
    out = capsys.readouterr().out
    assert "Manual-audit checklist" in out
    assert "[P5]" in out
    assert "[P4]" in out
    assert code == 1


def test_scan_dispatch_method_reports_class(capsys):
    code = main(["scan", str(FIXTURES / "cli" / "dispatch-method")])
    out = capsys.readouterr().out
    assert code == 1
    assert "[P0]" in out


def test_scan_sink_outside_handler_in_coverage(capsys):
    # The fixture's sink lives in a non-entry function; it must land
    # on the coverage line, not read as a guarded or empty scan.
    code = main(["scan", str(FIXTURES / "cli" / "sink-outside-entry")])
    out = capsys.readouterr().out
    assert "outside recognized entries" in out
    assert "helper.py" in out
    assert code == 0


def test_scan_excluded_dir_listed_in_coverage(capsys):
    # vendored-skip holds its only code under node_modules: the dir is
    # excluded from scanning but must be visible in coverage.
    code = main(["scan", str(FIXTURES / "cli" / "vendored-skip")])
    out = capsys.readouterr().out
    assert code == 0
    assert "files scanned: 0" in out
    assert "tool-excluded directories present" in out
    assert "node_modules" in out


def test_scan_json_schema(capsys):
    code = main(["scan", str(FIXTURES / "p0" / "unguarded-python"), "--json"])
    assert code == 1
    import json
    d = json.loads(capsys.readouterr().out)
    assert d["schema_version"] == "path-guard-audit/v1"
    assert d["taxonomy_version"] == "p0-p10/v1"
    assert d["ruleset_version"] == "0.1.0"
    assert "semgrep_version" in d
    assert d["findings"]
    assert "checklist" in d and "coverage" in d
