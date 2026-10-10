# Fixture for rules/python/p7-decoded-path.yaml.

import urllib.parse
import urllib.request


def unquoted(url):
    # ruleid: path-guard-audit-p7-decoded-path-python
    p = urllib.parse.unquote(url)
    return open(p).read()


def unquote_bare(url):
    # ruleid: path-guard-audit-p7-decoded-path-python
    return unquote(url)


def urlparsed(url):
    # ruleid: path-guard-audit-p7-decoded-path-python
    return urllib.parse.urlparse(url).path


def url_to_path(url):
    # ruleid: path-guard-audit-p7-decoded-path-python
    return urllib.request.url2pathname(url)


def no_decode(path):
    # ok: path-guard-audit-p7-decoded-path-python
    return open(path).read()
