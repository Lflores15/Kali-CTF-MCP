#!/usr/bin/env python3
"""
SSE transport wrapper — run any ctf-mcp category server over HTTP/SSE.

Usage:
    python3 sse_server.py                  # full server (all tools), port 8000
    python3 sse_server.py crypto           # crypto only,             port 8000
    python3 sse_server.py web    8001      # web only,                port 8001
    python3 sse_server.py forensics 8002   # forensics only,          port 8002

Available categories: crypto, web, pwn, reverse, forensics, full
"""

import sys
import logging
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route, Mount
import uvicorn

from ctf_mcp.server_factory import make_server

logging.basicConfig(level=logging.INFO)


def build_app(category: str):
    """Build the MCP app for a given category."""
    from ctf_mcp.tools.misc import MiscTools

    misc = MiscTools()

    if category == "crypto":
        from ctf_mcp.tools.crypto import CryptoTools
        modules = [("crypto", CryptoTools()), ("misc", misc)]

    elif category == "web":
        from ctf_mcp.tools.web import WebTools
        modules = [("web", WebTools()), ("misc", misc)]

    elif category == "pwn":
        from ctf_mcp.tools.pwn import PwnTools
        from ctf_mcp.tools.reverse import ReverseTools
        modules = [("pwn", PwnTools()), ("reverse", ReverseTools()), ("misc", misc)]

    elif category == "reverse":
        from ctf_mcp.tools.reverse import ReverseTools
        modules = [("reverse", ReverseTools()), ("misc", misc)]

    elif category == "forensics":
        from ctf_mcp.tools.forensics import ForensicsTools
        from ctf_mcp.tools.memory import MemoryTools
        from ctf_mcp.tools.pcap import PcapTools
        modules = [
            ("forensics", ForensicsTools()),
            ("memory",    MemoryTools()),
            ("pcap",      PcapTools()),
            ("misc",      misc),
        ]

    else:  # full
        from ctf_mcp.tools.crypto import CryptoTools
        from ctf_mcp.tools.web import WebTools
        from ctf_mcp.tools.pwn import PwnTools
        from ctf_mcp.tools.reverse import ReverseTools
        from ctf_mcp.tools.forensics import ForensicsTools
        from ctf_mcp.tools.hashcat import CrackingTools
        from ctf_mcp.tools.network import NetworkTools
        from ctf_mcp.tools.memory import MemoryTools
        from ctf_mcp.tools.pcap import PcapTools
        modules = [
            ("crypto",    CryptoTools()),
            ("web",       WebTools()),
            ("pwn",       PwnTools()),
            ("reverse",   ReverseTools()),
            ("forensics", ForensicsTools()),
            ("misc",      misc),
            ("cracking",  CrackingTools()),
            ("network",   NetworkTools()),
            ("memory",    MemoryTools()),
            ("pcap",      PcapTools()),
        ]
        return make_server(f"ctf-mcp", modules, include_orchestrator=True)

    return make_server(f"ctf-{category}-mcp", modules)


def main():
    category = sys.argv[1] if len(sys.argv) > 1 else "full"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000

    valid = {"crypto", "web", "pwn", "reverse", "forensics", "full"}
    if category not in valid:
        print(f"Unknown category '{category}'. Choose from: {', '.join(sorted(valid))}")
        sys.exit(1)

    mcp_app = build_app(category)
    sse = SseServerTransport("/messages")

    async def handle_sse(request):
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as streams:
            await mcp_app.run(
                streams[0],
                streams[1],
                mcp_app.create_initialization_options(),
            )

    starlette_app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages", app=sse.handle_post_message),
        ]
    )

    print(f"Starting ctf-{category}-mcp SSE server on http://0.0.0.0:{port}/sse")
    uvicorn.run(starlette_app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
