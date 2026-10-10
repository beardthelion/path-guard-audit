# Fixture for rules/python/p4-archive-member.yaml.

import os
import shutil
import tarfile
import zipfile


def member_write(zf, dest):
    for member in zf.infolist():
        # ruleid: path-guard-audit-p4-archive-member-python
        open(os.path.join(dest, member.filename), "wb")


def member_extract(zf, member, dest):
    # ruleid: path-guard-audit-p4-archive-member-python
    zf.extract(member, dest)


def member_from_getmember(zf, dest):
    m = zf.getmember("x")
    # ruleid: path-guard-audit-p4-archive-member-python
    zf.extract(m, dest)


def guarded_member(zf, dest):
    for member in zf.infolist():
        name = safe_join(dest, member.filename)
        # ok: path-guard-audit-p4-archive-member-python
        open(name, "wb")
