# SPDX-License-Identifier: Apache-2.0
"""Canary type: mcp_config - an MCP server configuration with a fake key.

MCP (Model Context Protocol) client configs - the `mcpServers` block in
claude_desktop_config.json, .cursor/mcp.json, .vscode/mcp.json and the like -
put API tokens in plain text next to the command that starts each server, and
they get committed to repos and shared. This type emits such a block with an
inert token, to seed where a real one would sit. If the config later shows up
in public code or a paste, searching for the token finds it, and the ledger
says which seeded location it came from.

The token is INERT, shaped like the real service's token with our 6-hex canary
token woven into its tail (the same shapes as the api_token type). This is a
SEARCH canary (detect=search).

Safety: the `command`/`args` only ever reference MCP server packages that are
actually published on npm under the official @modelcontextprotocol scope. A
config naming an invented package would be dangerous - anyone could later
register that name, and whoever copied the leaked config would then run their
code. Never add an invented or unscoped package name. (Both packages used here
are archived upstream; that matches what many real, older configs contain.)
"""
from __future__ import annotations

import argparse
import json
import secrets
from typing import Iterable

from ..generate import CanaryType, new_token, register_type
from .api_token import _build, _rand

_TEAM_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# server key -> (published npm package, env var holding the token, token shape)
_SERVERS = {
    "github": ("@modelcontextprotocol/server-github",
               "GITHUB_PERSONAL_ACCESS_TOKEN", "github"),
    "slack": ("@modelcontextprotocol/server-slack",
              "SLACK_BOT_TOKEN", "slack"),
}


def _config(server: str, mcp_token: str) -> dict:
    package, env_var, _ = _SERVERS[server]
    env = {env_var: mcp_token}
    if server == "slack":
        # the Slack server also wants the workspace (team) ID
        env["SLACK_TEAM_ID"] = "T" + _rand(_TEAM_ID_ALPHABET, 10)
    return {"mcpServers": {server: {
        "command": "npx",
        "args": ["-y", package],
        "env": env,
    }}}


@register_type
class McpConfigType(CanaryType):
    name = "mcp_config"
    description = "Fake MCP server config (mcpServers block) with an inert token."

    def add_arguments(self, p: argparse.ArgumentParser) -> None:
        p.add_argument("--server", default="github", choices=sorted(_SERVERS),
                       help="Which MCP server's config to mimic (default: github).")
        p.add_argument("--mix", action="store_true",
                       help="Ignore --server and pick a random server per canary.")

    def generate(self, args, count: int) -> Iterable[dict]:
        for _ in range(count):
            server = secrets.choice(sorted(_SERVERS)) if args.mix else args.server
            yield self._one(server)

    def _one(self, server: str) -> dict:
        token = new_token()
        mcp_token = _build(_SERVERS[server][2], token)
        config = _config(server, mcp_token)
        return {
            "record_id": token,
            "mcp_server": server,
            "mcp_token": mcp_token,
            # the JSON to plant, as it would appear in an MCP client config file
            "mcp_config": json.dumps(config, indent=2),
            "_detect": "search",
            "_ledger": {
                "mcp_server": server,
                "mcp_token": mcp_token,
            },
        }
