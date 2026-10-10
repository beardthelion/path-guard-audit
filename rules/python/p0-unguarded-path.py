# Semgrep test fixture for rules/python/p0-unguarded-path.yaml.
# Annotations are the executable contract (semgrep test). P0 is the raw
# no-guard taint finding; classify.py suppresses or relabels it per the
# layered site resolution.

import os
import shutil
import tarfile
import zipfile
from pathlib import Path

mcp = None
app = None


def read_tool(path: str) -> str:
    # ruleid: path-guard-audit-p0-python
    return open(path).read()


def write_upload(filename):
    # ruleid: path-guard-audit-p0-python
    Path(filename).write_text("x")


def delete_thing(dest):
    # ruleid: path-guard-audit-p0-python
    os.remove(dest)


def move_thing(src_path, dst_path):
    # ruleid: path-guard-audit-p0-python
    shutil.move(src_path, dst_path)


def list_dir(directory):
    # ruleid: path-guard-audit-p0-python
    return os.listdir(directory)


@app.get("/file")
def serve(path):
    # ruleid: path-guard-audit-p0-python
    return open(path, "rb").read()


@mcp.tool()
def read_file(arguments):
    target = arguments["path"]
    # ruleid: path-guard-audit-p0-python
    return open(target).read()


def via_member(member):
    # ruleid: path-guard-audit-p0-python
    return open(os.path.join("/data", member.name), "w")


def via_filename(f):
    # ruleid: path-guard-audit-p0-python
    return open(f.filename, "wb")


def extract_names(zf, dest):
    for name in zf.namelist():
        # ruleid: path-guard-audit-p0-python
        open(os.path.join(dest, name), "wb")


def checked_with_join(base, name):
    joined = os.path.join(base, name)
    # ruleid: path-guard-audit-p0-python
    return open(joined).read()


def request_member(request):
    path = request.args["file"]
    # ruleid: path-guard-audit-p0-python
    return open(path).read()


def sticky_param(path):
    # Parameter stickiness: a check-and-throw on the raw param cannot
    # clear taint at engine level; the site probe resolves this to
    # recognized-complete at classify time.
    assert_under_root(path)
    # ruleid: path-guard-audit-p0-python
    return open(path).read()


def derived_clean(path):
    p = path
    assert_under_root(p)
    # ok: path-guard-audit-p0-python
    return open(p).read()


def complete_return_form(base, name):
    checked = safe_join(base, name)
    # ok: path-guard-audit-p0-python
    return open(checked).read()


def literal_path():
    # ok: path-guard-audit-p0-python
    return open("/etc/motd").read()


def unrelated_args(x):
    # ok: path-guard-audit-p0-python
    return x * 2
