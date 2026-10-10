from werkzeug.utils import safe_join


def serve(path: str) -> str:
    checked = safe_join("/srv/static", path)
    if checked is None:
        return "not found"
    return open(checked).read()
