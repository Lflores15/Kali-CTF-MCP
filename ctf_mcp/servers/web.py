"""ctf-web-mcp — Web challenge tools only (~38 tools)"""
from ..server_factory import make_server, run
from ..tools.web import WebTools
from ..tools.misc import MiscTools


def main():
    modules = [
        ("web",  WebTools()),
        ("misc", MiscTools()),
    ]
    run(make_server("ctf-web-mcp", modules))


if __name__ == "__main__":
    main()
