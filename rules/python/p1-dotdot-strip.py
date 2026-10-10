# Fixture for rules/python/p1-dotdot-strip.yaml.

import os
import re
from werkzeug.utils import secure_filename


def strip_dotdot(name):
    # ruleid: path-guard-audit-p1-python
    cleaned = name.replace("..", "")
    return cleaned


def strip_slashes(filename):
    # ruleid: path-guard-audit-p1-python
    return filename.replace("/", "_")


def sub_regex(path):
    # ruleid: path-guard-audit-p1-python
    return re.sub(r"\.\.+", "", path)


def split_dots(name):
    # ruleid: path-guard-audit-p1-python
    parts = name.split("..")
    return parts[0]


def basename_only(path):
    # ruleid: path-guard-audit-p1-python
    return os.path.basename(path)


def secure_only(filename):
    # ruleid: path-guard-audit-p1-python
    return secure_filename(filename)


def strip_then_resolve(base, name):
    cleaned = name.replace("..", "")
    full = os.path.realpath(os.path.join(base, cleaned))
    # ok: path-guard-audit-p1-python
    return full
