# Fixture for rules/python/p2-prefix-no-resolve.yaml.

import os


def prefix_check(path, base="/srv/files"):
    # ruleid: path-guard-audit-p2-prefix-no-resolve-python
    if path.startswith(base):
        return open(path).read()
    return ""


def suffix_check(filename):
    # ruleid: path-guard-audit-p2-prefix-no-resolve-python
    if filename.endswith(".jpg"):
        return open(filename, "rb")
    return None


def commonprefix_check(path):
    # ruleid: path-guard-audit-p2-prefix-no-resolve-python
    if os.path.commonprefix([path, "/srv/files"]) == "/srv/files":
        return open(path).read()
    return ""


def relative_to_check(path):
    # ruleid: path-guard-audit-p2-prefix-no-resolve-python
    if path.is_relative_to("/srv/files"):
        return open(path).read()
    return ""


def resolved_prefix_check(base, name):
    full = os.path.realpath(os.path.join(base, name))
    # ok: path-guard-audit-p2-prefix-no-resolve-python
    if full.startswith(base + os.sep):
        return open(full).read()
    return ""
