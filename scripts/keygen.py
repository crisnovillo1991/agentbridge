#!/usr/bin/env python3
"""Generate a bridge Ed25519 keypair. Paste the private line into .env."""
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sk = Ed25519PrivateKey.generate()
seed = sk.private_bytes_raw()
pub = sk.public_key().public_bytes_raw()

print("BRIDGE_PRIVATE_KEY=" + base64.b64encode(seed).decode())
print("# public key (publish this, e.g. at /.well-known/): " + base64.b64encode(pub).decode())
