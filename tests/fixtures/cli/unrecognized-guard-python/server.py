def read_thing(path: str) -> str:
    validate_path(path)
    return open(path).read()
