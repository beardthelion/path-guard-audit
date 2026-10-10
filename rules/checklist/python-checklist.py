# Fixture for rules/checklist/python-checklist.yaml. Checklist rules
# enumerate manual-review candidates; every hit is a candidate, not a
# verdict.

import os
import shutil
import tarfile
from pathlib import Path

mcp = None
server = None


# ruleid: path-guard-audit-checklist-p9-python
@mcp.tool()
def extract_backup(path: str) -> str:
    # ruleid: path-guard-audit-checklist-p5-python
    shutil.unpack_archive(path, "/srv/restore")
    return "ok"


# ruleid: path-guard-audit-checklist-p9-python
@app.route("/key")
def serve_key():
    # ruleid: path-guard-audit-checklist-p10-python
    return open("/home/app/.ssh/id_rsa").read()


# ruleid: path-guard-audit-checklist-p9-python
def handle_request(args):
    tf = tarfile.open(args["path"])
    for member in tf.getmembers():
        # ruleid: path-guard-audit-checklist-p5-python
        if member.issym():
            continue
    # ruleid: path-guard-audit-checklist-p5-python
    os.symlink("/x", "/y")


def no_surface(x):
    # ok: path-guard-audit-checklist-p5-python
    # ok: path-guard-audit-checklist-p9-python
    # ok: path-guard-audit-checklist-p10-python
    return len(x)
