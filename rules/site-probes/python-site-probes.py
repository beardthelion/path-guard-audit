# Fixture for rules/site-probes/python-site-probes.yaml.

import os

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
