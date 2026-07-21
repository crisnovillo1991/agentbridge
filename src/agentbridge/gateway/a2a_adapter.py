"""A2A adapter — v0.5.

Scope of the adapter (in order of work):
1. Agent Card generation from the capability registry (below, functional-ish).
2. Task lifecycle mapping: A2A task (submitted → working → completed/failed)
   ⇄ one MCP tools/call. `input-required` maps to MCP elicitation — punt to
   v0.6, reject those upstreams for now.
3. SSE: A2A TaskStatusUpdate events ⇄ MCP progress notifications. This is the
   ~40% of the adapter effort; needs the streaming proxy from gateway/proxy.py.

The card is served at /.well-known/agent-card.json and clearly marked draft
until (2) and (3) land — advertising skills we can't serve as tasks yet would
be exactly the "agent card stuffing" we rant about.
"""
from __future__ import annotations

from ..config import Capability


def build_agent_card(bridge_id: str, caps: dict[str, Capability]) -> dict:
    return {
        "name": "agentbridge gateway",
        "description": "Paid capabilities bridged from MCP. DRAFT: A2A task execution lands in v0.5; use the MCP endpoints meanwhile.",
        "url": bridge_id,
        "preferredTransport": "JSONRPC",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                "id": c.id,
                "name": c.id,
                "description": c.description,
                "tags": ["paid", "x402", f"price:{c.price}", f"network:{c.network}"],
            }
            for c in caps.values()
        ],
    }


async def handle_task(*args, **kwargs):  # pragma: no cover - v0.5
    raise NotImplementedError("A2A task execution ships in v0.5 — see module docstring")
