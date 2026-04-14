"""ctf-pwn-mcp — Binary exploitation tools only (~22 tools)"""
from ..server_factory import make_server, run
from ..tools.pwn import PwnTools
from ..tools.reverse import ReverseTools
from ..tools.misc import MiscTools


def main():
    modules = [
        ("pwn",     PwnTools()),
        ("reverse", ReverseTools()),
        ("misc",    MiscTools()),
    ]
    run(make_server("ctf-pwn-mcp", modules))


if __name__ == "__main__":
    main()
