# Fixture for rules/python/p8-unanchored-regex.yaml.

import re


def regex_search(path):
    # ruleid: path-guard-audit-p8-unanchored-regex-python
    if re.search(r"[A-Za-z0-9]+", path):
        return open(path).read()
    return None


def regex_match_unanchored(path):
    # ruleid: path-guard-audit-p8-unanchored-regex-python
    if re.match(r"/srv/files", path):
        return open(path).read()
    return None


def regex_match_anchored(path):
    # ok: path-guard-audit-p8-unanchored-regex-python
    if re.match(r"/srv/files/[a-z]+$", path):
        return open(path).read()
    return None
