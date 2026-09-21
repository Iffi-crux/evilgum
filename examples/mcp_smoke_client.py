"""Initialize and discover tools using the official SDK; does not execute tools.

Install with: python -m pip install -e ".[integration]"
Provide a signed gateway JWT via GATEWAY_TOKEN, never a command-line argument.
"""
import argparse
import asyncio
import os
from datetime import timedelta

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main(url):
    token = os.environ.get("GATEWAY_TOKEN")
    if not token:
        raise SystemExit("Set GATEWAY_TOKEN to an authorized signed JWT first.")
    async with httpx.AsyncClient(headers={"Authorization": "Bearer " + token}, timeout=30) as client:
        async with streamable_http_client(url, http_client=client) as (read, write, get_sid):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=30)) as session:
                result = await session.initialize()
                tools = await session.list_tools()
                print("Protocol:", result.protocolVersion)
                print("Stateless:", get_sid() is None)
                print("Permitted tools:", ", ".join(tool.name for tool in tools.tools) or "(none)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080/mcp")
    asyncio.run(main(parser.parse_args().url))
