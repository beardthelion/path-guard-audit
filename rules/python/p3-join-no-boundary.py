# Fixture for rules/python/p3-join-no-boundary.yaml.

import os
from pathlib import Path


def join_then_open(base, name):
    # ruleid: path-guard-audit-p3-join-no-boundary-python
    joined = os.path.join(base, name)
    return joined


def pathlib_join(base, name):
    # ruleid: path-guard-audit-p3-join-no-boundary-python
    p = Path(base) / name
    return p


def pathlib_ctor(base, name):
    # ruleid: path-guard-audit-p3-join-no-boundary-python
    return Path(base, name)


def concat_dir(dir, name):
    # ruleid: path-guard-audit-p3-join-no-boundary-python
    return dir + "/" + name


def join_with_boundary(base, name):
    joined = os.path.join(base, name)
    # ok: path-guard-audit-p3-join-no-boundary-python
    if not os.path.abspath(joined).startswith(base):
        return None
    return open(joined).read()


def join_with_resolved_boundary(base, name):
    joined = os.path.join(base, name)
    real = os.path.realpath(joined)
    # ok: path-guard-audit-p3-join-no-boundary-python
    if not real.startswith(os.path.realpath(base) + os.sep):
        return None
    return open(real).read()
