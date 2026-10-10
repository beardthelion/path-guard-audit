# Fixture for rules/python/p6-platform-quirk.yaml.

import os


def split_posix(path):
    # ruleid: path-guard-audit-p6-platform-quirk-python
    if ".." in path.split("/"):
        return None
    return open(path).read()


def file_scheme(path):
    # ruleid: path-guard-audit-p6-platform-quirk-python
    return path.replace("file://", "")


def colon_split(path):
    # ruleid: path-guard-audit-p6-platform-quirk-python
    return path.split(":")


def splitdrive_only(path):
    # ruleid: path-guard-audit-p6-platform-quirk-python
    return os.path.splitdrive(path)


def generic_check(path):
    # ok: path-guard-audit-p6-platform-quirk-python
    if ".." in path:
        return None
    return open(path).read()
