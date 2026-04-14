"""ctf-reverse-mcp — Reverse engineering tools only (~10 tools)"""
from ..server_factory import make_server, run
from ..tools.reverse import ReverseTools
from ..tools.misc import MiscTools


def main():
    modules = [
        ("reverse", ReverseTools()),
        ("misc",    MiscTools()),
    ]
    run(make_server("ctf-reverse-mcp", modules))


if __name__ == "__main__":
    main()
