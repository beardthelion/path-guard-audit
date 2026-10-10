# Fixture for rules/site-probes/python-site-probes.yaml.

import os
from pathlib import Path

mcp = None
app = None


# ruleid: path-guard-audit-probe-handler-source-python
@mcp.tool()
def read_file(path: str) -> str:
    # ruleid: path-guard-audit-probe-path-sink-python
    return open(path).read()


# ruleid: path-guard-audit-probe-handler-source-python
@app.get("/static")
def serve(filename):
    # ruleid: path-guard-audit-probe-path-sink-python
    return os.remove(filename)


# ruleid: path-guard-audit-probe-handler-source-python
def plain_path_param(filepath):
    # ruleid: path-guard-audit-probe-path-sink-python
    return filepath.read_text()


# ruleid: path-guard-audit-probe-handler-source-python
def complete_guard_call(path):
    # ruleid: path-guard-audit-probe-complete-guard-python
    checked = safe_join("/base", path)
    # ruleid: path-guard-audit-probe-path-sink-python
    return open(checked).read()


# ruleid: path-guard-audit-probe-handler-source-python
def intervening(path):
    # ruleid: path-guard-audit-probe-intervening-validation-python
    validate_path(path)
    # ruleid: path-guard-audit-probe-path-sink-python
    return open(path).read()


# ruleid: path-guard-audit-probe-handler-source-python
def check_throw(path):
    # ruleid: path-guard-audit-probe-intervening-validation-python
    if not path:
        raise ValueError("empty")
    # ruleid: path-guard-audit-probe-path-sink-python
    return open(path).read()


def no_surface(x):
    # ok: path-guard-audit-probe-handler-source-python
    # ok: path-guard-audit-probe-path-sink-python
    # ok: path-guard-audit-probe-complete-guard-python
    # ok: path-guard-audit-probe-intervening-validation-python
    return len(x)


# ruleid: path-guard-audit-probe-handler-source-python
def canonical_boundary_guarded(dest, member):
    for m in member:
        target = os.path.realpath(os.path.join(dest, m))
        # ruleid: path-guard-audit-probe-canonical-boundary-python
        if not target.startswith(os.path.realpath(dest) + os.sep):
            continue
        # ruleid: path-guard-audit-probe-path-sink-python
        open(target, "wb").write(m.encode())


# ruleid: path-guard-audit-probe-handler-source-python
def canonical_boundary_raise(dest, member):
    resolved = (Path(dest) / member).resolve()
    # ruleid: path-guard-audit-probe-canonical-boundary-python, path-guard-audit-probe-intervening-validation-python
    if not resolved.is_relative_to(Path(dest).resolve()):
        raise ValueError("escape")
    # ruleid: path-guard-audit-probe-path-sink-python
    return resolved.read_bytes()


# ruleid: path-guard-audit-probe-handler-source-python
def startswith_without_separator(dest, member):
    for m in member:
        target = os.path.realpath(os.path.join(dest, m))
        # ok: path-guard-audit-probe-canonical-boundary-python
        if not target.startswith(os.path.realpath(dest)):
            continue
        # ruleid: path-guard-audit-probe-path-sink-python
        open(target, "wb").write(m.encode())


# ruleid: path-guard-audit-probe-handler-source-python
def boundary_check_on_uncanonicalized(dest, member):
    for m in member:
        target = os.path.join(dest, m)
        # ok: path-guard-audit-probe-canonical-boundary-python
        if not target.startswith(dest + os.sep):
            continue
        # ruleid: path-guard-audit-probe-path-sink-python
        open(target, "wb").write(m.encode())


# ruleid: path-guard-audit-probe-handler-source-python
def canonical_boundary_no_reject(dest, member):
    for m in member:
        target = os.path.realpath(os.path.join(dest, m))
        inside = target.startswith(dest + os.sep)
        # ok: path-guard-audit-probe-canonical-boundary-python
        if inside:
            pass
        # ruleid: path-guard-audit-probe-path-sink-python
        open(target, "wb").write(m.encode())


# ruleid: path-guard-audit-probe-handler-source-python
def canonical_boundary_other_var(dest, member):
    for m in member:
        checked = os.path.realpath(os.path.join(dest, m))
        # ruleid: path-guard-audit-probe-canonical-boundary-python
        if not checked.startswith(os.path.realpath(dest) + os.sep):
            continue
        # ruleid: path-guard-audit-probe-path-sink-python
        open(os.path.join(dest, m), "wb").write(m.encode())
