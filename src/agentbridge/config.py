"""Settings (env) and the capability registry (YAML in v0, DB later)."""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class Capability(BaseModel):
    id: str
    description: str = ""
    upstream_url: str  # Streamable-HTTP MCP endpoint (or any JSON POST API)
    upstream_api_key: str | None = None  # sent as Bearer; v0 auth passthrough
    price: str  # atomic units, decimal string ("0" = free, no 402)
    network: str = "base-sepolia"
    asset: str = "USDC"
    pay_to: str = ""
    provider_id: str | None = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    bridge_private_key: str  # base64 of a 32-byte Ed25519 seed (scripts/keygen.py)
    bridge_id: str = "https://bridge.local"
    data_dir: str = "./data"
    capabilities_file: str = "./capabilities.yaml"
    facilitator: str = "mock"  # "mock" | "http"
    facilitator_url: str = ""


def load_capabilities(path: str | Path) -> dict[str, Capability]:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    caps = [Capability(**c) for c in raw.get("capabilities", [])]
    return {c.id: c for c in caps}
