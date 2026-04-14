"""ctf-crypto-mcp — Crypto challenge tools only (~52 tools)"""
from ..server_factory import make_server, run
from ..tools.crypto import CryptoTools
from ..tools.misc import MiscTools


def main():
    modules = [
        ("crypto", CryptoTools()),
        ("misc",   MiscTools()),
    ]
    run(make_server("ctf-crypto-mcp", modules))


if __name__ == "__main__":
    main()
