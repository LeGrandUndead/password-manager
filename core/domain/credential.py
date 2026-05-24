"""
core/domain/credential.py
=========================
Domain model representing a single stored credential.

This is a pure data structure with NO dependencies on persistence,
cryptography, or presentation layers. It is the innermost ring of the
Clean Architecture and must remain dependency-free.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Credential:
    """
    Represents a single credential entry in the vault.

    Attributes:
        id:          Unique identifier (UUID v4), auto-generated.
        service:     Name of the service or website (e.g. "github.com").
        username:    Login / email for that service.
        password:    Plaintext password — only present in memory after decryption.
                     NEVER written to disk in plaintext.
        notes:       Optional freeform notes.
        created_at:  UTC timestamp of creation.
        updated_at:  UTC timestamp of last modification.
    """

    service: str
    username: str
    password: str
    notes: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def touch(self) -> None:
        """Update the `updated_at` timestamp to now (UTC)."""
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def sanitize(self) -> None:
        """
        Overwrite the in-memory password with null bytes, then clear the reference.

        Call this as soon as the password is no longer needed to minimise the
        window during which plaintext material lives in memory.

        Note: Python's garbage collector is non-deterministic, so this is a
        best-effort measure. For production use, consider a C-extension backed
        SecureString or mlock/mprotect via ctypes.
        """
        if self.password:
            # Overwrite the string object's internal buffer with zeroes
            # CPython stores small strings interned, so we allocate a
            # fresh bytearray to at least clear our local reference.
            _buf = bytearray(self.password.encode())
            for i in range(len(_buf)):
                _buf[i] = 0
            del _buf
        self.password = ""

    def to_dict(self) -> dict:
        """Serialise to a plain dict (password excluded — caller must handle it)."""
        return {
            "id": self.id,
            "service": self.service,
            "username": self.username,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict, password: str = "") -> "Credential":
        """
        Reconstruct a Credential from a serialised dict.

        Args:
            data:     Dict as returned by ``to_dict()``.
            password: Decrypted plaintext password, injected separately.
        """
        return cls(
            id=data["id"],
            service=data["service"],
            username=data["username"],
            password=password,
            notes=data.get("notes", ""),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )
