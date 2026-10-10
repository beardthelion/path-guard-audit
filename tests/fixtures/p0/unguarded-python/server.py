class Server:
    def tool(self, *a, **k):
        def deco(fn):
            return fn
        return deco


server = Server()


@server.tool()
def read_file(path: str) -> str:
    return open(path).read()
