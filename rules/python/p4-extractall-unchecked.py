# Fixture for rules/python/p4-extractall-unchecked.yaml.

import os
import shutil
import tarfile
import zipfile


def extract_all_zip(zf, dest):
    # ruleid: path-guard-audit-p4-extractall-unchecked-python
    zf.extractall(dest)


def extract_all_tar(tf, dest):
    # ruleid: path-guard-audit-p4-extractall-unchecked-python
    tf.extractall(dest)


def unpack(filename, dest):
    # ruleid: path-guard-audit-p4-extractall-unchecked-python
    shutil.unpack_archive(filename, dest)


def checked_extract(zf, dest):
    # ok: path-guard-audit-p4-extractall-unchecked-python
    for m in zf.infolist():
        target = os.path.realpath(os.path.join(dest, m.filename))
        if not target.startswith(os.path.realpath(dest) + os.sep):
            raise ValueError("unsafe member")
    zf.extractall(dest)


def filtered_extract(tf, dest):
    # ok: path-guard-audit-p4-extractall-unchecked-python
    tf.extractall(dest, filter="data")
