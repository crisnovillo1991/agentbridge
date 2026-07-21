"""Upstream forwarding: buffered passthrough to a Streamable-HTTP MCP server.

v0 buffers bodies (they get hashed into the receipt anyway). Incremental
hashing + SSE streaming passthrough is the v0.5 upgrade — the interface below
won't change for callers.
"""
from __future__ import annotations

import httpx

from ..config import Capability

_HOP_BY_HOP = {
    "connection", "keep-alive", "transfer-encoding", "te", "trailer",
    "proxy-authenticate", "proxy-authorization", "upgrade", "content-length",
}


class UpstreamClient:
    def __init__(self, client: httpx.AsyncClient | None = None):
        self._client = client or httpx.AsyncClient(timeout=60)

    async def forward(
        self, cap: Capability, body: bytes, content_type: str | None
    ) -> tuple[int, str | None, bytes]:
        headers = {"content-type": content_type or "application/json"}
        if cap.upstream_api_key:
            headers["authorization"] = f"Bearer {cap.upstream_api_key}"
        r = await self._client.post(cap.upstream_url, content=body, headers=headers)
        media_type = (r.headers.get("content-type") or "").split(";")[0] or None
        return r.status_code, media_type, r.content

    async def aclose(self) -> None:
        await self._client.aclose()
