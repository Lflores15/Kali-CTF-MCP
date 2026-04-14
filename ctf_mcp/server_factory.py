"""
MCP Server Factory
Shared logic for building focused category MCP servers.
"""

import asyncio
import inspect
import json
import logging
import re
from typing import Any, get_type_hints, get_origin, get_args, Union

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

logger = logging.getLogger("ctf-mcp")


# ---------------------------------------------------------------------------
# Type → JSON Schema
# ---------------------------------------------------------------------------

def python_type_to_json_schema(py_type: Any) -> dict:
    if py_type is None or py_type is type(None):
        return {"type": "null"}

    origin = get_origin(py_type)
    args = get_args(py_type)

    if origin is Union:
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return python_type_to_json_schema(non_none[0])
        return {"anyOf": [python_type_to_json_schema(a) for a in non_none]}

    if origin is list:
        return {"type": "array", "items": python_type_to_json_schema(args[0])} if args else {"type": "array"}

    if origin is dict:
        return {"type": "object"}

    return {
        str:   {"type": "string"},
        int:   {"type": "integer"},
        float: {"type": "number"},
        bool:  {"type": "boolean"},
        bytes: {"type": "string", "description": "Hex-encoded bytes"},
        list:  {"type": "array"},
        dict:  {"type": "object"},
    }.get(py_type, {"type": "string"})


def generate_input_schema(module: Any, method_name: str) -> dict:
    method = getattr(module, method_name)
    sig = inspect.signature(method)

    try:
        hints = get_type_hints(method)
    except Exception:
        hints = {}

    properties: dict = {}
    required: list = []

    for param_name, param in sig.parameters.items():
        if param_name == "self":
            continue

        schema = python_type_to_json_schema(hints.get(param_name, str))

        doc = method.__doc__ or ""
        m = re.search(rf':param\s+{param_name}:\s*(.+?)(?=\n\s*:|$)', doc, re.DOTALL)
        if m:
            schema["description"] = m.group(1).strip()

        if param.default is not inspect.Parameter.empty:
            schema["default"] = param.default
        else:
            required.append(param_name)

        properties[param_name] = schema

    return {"type": "object", "properties": properties, "required": required}


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------

def make_server(
    server_name: str,
    modules: list[tuple[str, Any]],
    include_orchestrator: bool = False,
) -> Server:
    """
    Create a fully configured MCP server.

    Args:
        server_name: Name shown to MCP clients (e.g. "ctf-crypto-mcp")
        modules: List of (prefix, tool_instance) pairs
        include_orchestrator: Whether to add auto_solve / classify_challenge tools

    Returns:
        Configured Server instance ready to run.
    """
    app = Server(server_name)
    tool_registry: dict[str, tuple[Any, str]] = {}
    tool_schemas: dict[str, Tool] = {}

    # Register category tools
    for prefix, module in modules:
        tools_dict = module.get_tools()
        for tool_name, description in tools_dict.items():
            full_name = f"{prefix}_{tool_name}"

            if not hasattr(module, tool_name):
                logger.warning("Method %s not found in %s, skipping", tool_name, prefix)
                continue

            tool_registry[full_name] = (module, tool_name)

            try:
                input_schema = generate_input_schema(module, tool_name)
            except Exception as e:
                logger.warning("Schema generation failed for %s: %s", full_name, e)
                input_schema = {"type": "object", "properties": {}, "required": []}

            tool_schemas[full_name] = Tool(
                name=full_name,
                description=description,
                inputSchema=input_schema,
            )

    if include_orchestrator:
        _register_orchestrator_tools(tool_registry, tool_schemas)

    logger.info("[%s] Registered %d tools", server_name, len(tool_registry))

    # Bind handlers to this specific app instance
    @app.list_tools()
    async def list_tools() -> list[Tool]:
        return list(tool_schemas.values())

    @app.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        try:
            if name == "auto_solve":
                return await _handle_auto_solve(arguments)
            if name == "classify_challenge":
                return await _handle_classify(arguments)

            if name not in tool_registry:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]

            module, method_name = tool_registry[name]
            if module is None:
                return [TextContent(type="text", text=f"Tool {name} not configured")]

            method = getattr(module, method_name)
            result = method(**arguments)
            if inspect.iscoroutine(result):
                result = await result

            return [TextContent(type="text", text=str(result))]

        except TypeError as e:
            logger.error("Tool %s argument error: %s", name, e)
            return [TextContent(type="text", text=f"Argument error: {e}")]
        except Exception as e:
            logger.error("Tool %s failed: %s", name, e)
            return [TextContent(type="text", text=f"Error: {e}")]

    return app


def run(app: Server) -> None:
    """Run an MCP server on stdio (blocking)."""
    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Orchestrator tools (optional, full server only)
# ---------------------------------------------------------------------------

def _register_orchestrator_tools(
    tool_registry: dict,
    tool_schemas: dict,
) -> None:
    tool_schemas["auto_solve"] = Tool(
        name="auto_solve",
        description="Auto-solve a CTF challenge: classify, plan, and execute strategies.",
        inputSchema={
            "type": "object",
            "properties": {
                "name":        {"type": "string", "description": "Challenge name"},
                "description": {"type": "string", "description": "Challenge description", "default": ""},
                "files":       {"type": "array", "items": {"type": "string"}, "description": "File paths", "default": []},
                "remote":      {"type": "string", "description": "host:port or URL", "default": ""},
                "flag_format": {"type": "string", "description": "Flag regex", "default": "flag\\{[^}]+\\}"},
                "category":    {"type": "string", "description": "Category hint", "default": ""},
                "timeout":     {"type": "number", "description": "Max seconds", "default": 300},
            },
            "required": ["name"],
        },
    )
    tool_registry["auto_solve"] = (None, "_auto_solve")

    tool_schemas["classify_challenge"] = Tool(
        name="classify_challenge",
        description="Classify a CTF challenge type and return confidence scores per category.",
        inputSchema={
            "type": "object",
            "properties": {
                "description": {"type": "string", "default": ""},
                "files":       {"type": "array", "items": {"type": "string"}, "default": []},
                "remote":      {"type": "string", "default": ""},
            },
            "required": [],
        },
    )
    tool_registry["classify_challenge"] = (None, "_classify_challenge")


async def _handle_auto_solve(arguments: dict) -> list[TextContent]:
    from .core.orchestrator import CTFOrchestrator, Challenge
    challenge = Challenge(
        name=arguments.get("name", "unknown"),
        description=arguments.get("description", ""),
        files=arguments.get("files", []),
        remote=arguments.get("remote") or None,
        flag_format=arguments.get("flag_format", r"flag\{[^}]+\}"),
        category_hint=arguments.get("category") or None,
    )
    orchestrator = CTFOrchestrator(timeout=arguments.get("timeout", 300))
    result = await orchestrator.solve(challenge)
    return [TextContent(type="text", text=json.dumps(result.to_dict(), indent=2, ensure_ascii=False))]


async def _handle_classify(arguments: dict) -> list[TextContent]:
    from .core.classifier import ChallengeClassifier
    classifier = ChallengeClassifier()
    result = classifier.classify(
        description=arguments.get("description", ""),
        files=arguments.get("files", []),
        remote=arguments.get("remote") or None,
    )
    return [TextContent(type="text", text=json.dumps(result.to_dict(), indent=2, ensure_ascii=False))]
