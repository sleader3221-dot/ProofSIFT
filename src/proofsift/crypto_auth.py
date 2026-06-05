from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any

from .integrity import canonical_json, sha256_json


AUTH_VERSION = "proofsift-ephemeral-mcp-auth-v1"


@dataclass(frozen=True)
class AuthorizationEnvelope:
    version: str
    nonce: str
    issued_at_utc: str
    expires_at_utc: str
    tool_name: str
    payload_hash: str
    signature: str

    def public(self) -> dict[str, str]:
        return {
            "version": self.version,
            "nonce": self.nonce,
            "issued_at_utc": self.issued_at_utc,
            "expires_at_utc": self.expires_at_utc,
            "tool_name": self.tool_name,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
        }


class EphemeralToolAuthorizer:
    """One-time cryptographic authorization for typed MCP tool calls."""

    def __init__(self, secret: bytes | None = None, ttl_seconds: int = 30):
        self.secret = secret or secrets.token_bytes(32)
        self.ttl_seconds = ttl_seconds
        self._issued: dict[str, AuthorizationEnvelope] = {}
        self._consumed: set[str] = set()

    def issue(self, tool_name: str, arguments: dict[str, Any]) -> AuthorizationEnvelope:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=self.ttl_seconds)
        nonce = secrets.token_hex(16)
        payload_hash = tool_payload_hash(tool_name, arguments)
        envelope_without_signature = {
            "version": AUTH_VERSION,
            "nonce": nonce,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": expires.isoformat(),
            "tool_name": tool_name,
            "payload_hash": payload_hash,
        }
        signature = self._sign(envelope_without_signature)
        envelope = AuthorizationEnvelope(
            version=AUTH_VERSION,
            nonce=nonce,
            issued_at_utc=envelope_without_signature["issued_at_utc"],
            expires_at_utc=envelope_without_signature["expires_at_utc"],
            tool_name=tool_name,
            payload_hash=payload_hash,
            signature=signature,
        )
        self._issued[nonce] = envelope
        return envelope

    def verify_and_consume(self, tool_name: str, arguments: dict[str, Any], authorization: dict[str, Any]) -> tuple[bool, str]:
        nonce = str(authorization.get("nonce", ""))
        if not nonce:
            return False, "missing nonce"
        if nonce in self._consumed:
            return False, "nonce already consumed"
        issued = self._issued.get(nonce)
        if not issued:
            return False, "unknown nonce"
        if issued.tool_name != tool_name:
            return False, "tool name mismatch"
        if issued.payload_hash != tool_payload_hash(tool_name, arguments):
            return False, "payload hash mismatch"
        expires = datetime.fromisoformat(issued.expires_at_utc)
        if datetime.now(timezone.utc) > expires:
            return False, "nonce expired"
        expected = self._sign(
            {
                "version": issued.version,
                "nonce": issued.nonce,
                "issued_at_utc": issued.issued_at_utc,
                "expires_at_utc": issued.expires_at_utc,
                "tool_name": issued.tool_name,
                "payload_hash": issued.payload_hash,
            }
        )
        provided = str(authorization.get("signature", ""))
        if not hmac.compare_digest(expected, provided):
            return False, "signature mismatch"
        self._consumed.add(nonce)
        return True, "authorized"

    def _sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(self.secret, canonical_json(payload).encode("utf-8"), sha256).hexdigest()


def tool_payload_hash(tool_name: str, arguments: dict[str, Any]) -> str:
    return sha256_json({"version": AUTH_VERSION, "tool_name": tool_name, "arguments": arguments})


def nonce_hash(nonce: str) -> str:
    return sha256(nonce.encode("utf-8")).hexdigest()
