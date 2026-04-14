#!/usr/bin/env python3
"""
CTF-MCP Server — full server with all tools (ctf-mcp entry point).
For focused servers with fewer tools, use the category-specific entry points:
  ctf-crypto-mcp, ctf-web-mcp, ctf-pwn-mcp, ctf-reverse-mcp, ctf-forensics-mcp
"""

import logging

from .server_factory import make_server, run
from .tools.crypto import CryptoTools
from .tools.web import WebTools
from .tools.pwn import PwnTools
from .tools.reverse import ReverseTools
from .tools.forensics import ForensicsTools
from .tools.misc import MiscTools
from .tools.hashcat import CrackingTools
from .tools.network import NetworkTools
from .tools.memory import MemoryTools
from .tools.pcap import PcapTools
from .tools.sqlmap import SqlmapTools

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def main():
    modules = [
        ("crypto",    CryptoTools()),
        ("web",       WebTools()),
        ("sqlmap",    SqlmapTools()),
        ("pwn",       PwnTools()),
        ("reverse",   ReverseTools()),
        ("forensics", ForensicsTools()),
        ("misc",      MiscTools()),
        ("cracking",  CrackingTools()),
        ("network",   NetworkTools()),
        ("memory",    MemoryTools()),
        ("pcap",      PcapTools()),
    ]
    app = make_server("ctf-mcp", modules, include_orchestrator=True)
    run(app)


if __name__ == "__main__":
    main()
