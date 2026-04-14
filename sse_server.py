#!/usr/bin/env python3
"""
HTTP server wrapper — run any ctf-mcp category server over HTTP.

Supports three MCP transports:
  sse        Legacy SSE (GET /sse + POST /messages)  — broadest client support
  streamable Streamable HTTP (POST /mcp)             — current MCP spec, recommended
  stdio      Standard I/O                            — pipe directly, no HTTP

Usage:
    python3 sse_server.py                                   # full, SSE, port 8000
    python3 sse_server.py crypto                            # crypto, SSE, port 8000
    python3 sse_server.py web 8001                          # web, SSE, port 8001
    python3 sse_server.py forensics 8005 --transport sse
    python3 sse_server.py crypto 8001 --transport streamable
    python3 sse_server.py full 8000 --transport stdio

Available categories: crypto, web, pwn, reverse, forensics, full
"""

import argparse
import logging
import sys

import uvicorn
from starlette.applications import Starlette
from starlette.routing import Mount, Route

from ctf_mcp.server_factory import make_server

logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Category → module loader
# ---------------------------------------------------------------------------

def build_app(category: str):
    """Build and return the low-level MCP Server for a given category."""
    from ctf_mcp.tools.misc import MiscTools
    misc = MiscTools()

    if category == "crypto":
        from ctf_mcp.tools.crypto import CryptoTools
        modules = [("crypto", CryptoTools()), ("misc", misc)]

    elif category == "web":
        from ctf_mcp.tools.web import WebTools
        from ctf_mcp.tools.sqlmap import SqlmapTools
        modules = [("web", WebTools()), ("sqlmap", SqlmapTools()), ("misc", misc)]

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
        from ctf_mcp.tools.sqlmap import SqlmapTools
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
            ("sqlmap",    SqlmapTools()),
            ("pwn",       PwnTools()),
            ("reverse",   ReverseTools()),
            ("forensics", ForensicsTools()),
            ("misc",      misc),
            ("cracking",  CrackingTools()),
            ("network",   NetworkTools()),
            ("memory",    MemoryTools()),
            ("pcap",      PcapTools()),
        ]
        return make_server("ctf-mcp", modules, include_orchestrator=True)

    return make_server(f"ctf-{category}-mcp", modules)


# ---------------------------------------------------------------------------
# Transport runners
# ---------------------------------------------------------------------------

def run_sse(mcp_app, host: str, port: int, category: str):
    """Legacy SSE transport — GET /sse  +  POST /messages."""
    from mcp.server.sse import SseServerTransport

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

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages", app=sse.handle_post_message),
        ]
    )

    print(f"[SSE]        ctf-{category}-mcp → http://{host}:{port}/sse")
    uvicorn.run(app, host=host, port=port)


def run_streamable(mcp_app, host: str, port: int, category: str):
    """Streamable HTTP transport — POST /mcp (current MCP spec)."""
    from contextlib import asynccontextmanager
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

    session_manager = StreamableHTTPSessionManager(
        app=mcp_app,
        json_response=False,   # use SSE streams (not JSON polling)
        stateless=False,
        session_idle_timeout=1800,
    )

    @asynccontextmanager
    async def lifespan(app):
        async with session_manager.run():
            yield

    async def handle_mcp(request):
        return await session_manager.handle_request(request)

    app = Starlette(
        lifespan=lifespan,
        routes=[
            Mount("/mcp", app=session_manager.handle_request),
        ],
    )

    print(f"[Streamable] ctf-{category}-mcp → http://{host}:{port}/mcp")
    uvicorn.run(app, host=host, port=port)


def run_stdio(mcp_app, category: str):
    """Standard I/O transport — for direct process pipes (no HTTP)."""
    import asyncio
    from mcp.server.stdio import stdio_server

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await mcp_app.run(
                read_stream,
                write_stream,
                mcp_app.create_initialization_options(),
            )

    print(f"[stdio]      ctf-{category}-mcp started", file=sys.stderr)
    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CTF-MCP HTTP server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "category",
        nargs="?",
        default="full",
        choices=["crypto", "web", "pwn", "reverse", "forensics", "full"],
        help="Tool category to serve (default: full)",
    )
    parser.add_argument(
        "port",
        nargs="?",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000, ignored for stdio)",
    )
    parser.add_argument(
        "--transport",
        choices=["sse", "streamable", "stdio"],
        default="sse",
        help="MCP transport to use (default: sse)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )

    args = parser.parse_args()
    mcp_app = build_app(args.category)

    if args.transport == "sse":
        run_sse(mcp_app, args.host, args.port, args.category)
    elif args.transport == "streamable":
        run_streamable(mcp_app, args.host, args.port, args.category)
    elif args.transport == "stdio":
        run_stdio(mcp_app, args.category)


if __name__ == "__main__":
    main()
