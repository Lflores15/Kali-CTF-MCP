"""ctf-web-mcp — Web challenge tools only"""
from ..server_factory import make_server, run
from ..tools.web import WebTools
from ..tools.misc import MiscTools
from ..tools.sqlmap import SqlmapTools


def main():
    modules = [
        ("web",    WebTools()),
        ("sqlmap", SqlmapTools()),
        ("misc",   MiscTools()),
    ]
    run(make_server("ctf-web-mcp", modules))


if __name__ == "__main__":
    main()
