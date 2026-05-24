"""
core/ports.py
=============
Abstract port interfaces (following Hexagonal / Ports-and-Adapters architecture).

Defining interfaces here in the *core* layer lets the domain depend on
abstractions, not concrete implementations — the Dependency Inversion
Principle (SOLID-D). The concrete adapters live in the ``data`` layer and are
injected at runtime, keeping the domain and security layers fully testable
without touching the filesystem.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from core.domain.credential import Credential
from core.domain.vault_metadata import VaultMetadata


class IVaultRepository(ABC):
    """
    Port: persistence contract that any storage backend must fulfil.

    Concrete adapters (JsonVaultRepository, …) implement this interface and
    are injected into use-cases via the constructor — classic Dependency
    Injection.
    """

    @abstractmethod
    def vault_exists(self) -> bool:
        """Return True if a vault file already exists on disk."""

    @abstractmethod
    def load_metadata(self) -> VaultMetadata:
        """
        Load and return the vault metadata block.

        Raises:
            FileNotFoundError: If no vault has been initialised yet.
        """

    @abstractmethod
    def save_metadata(self, metadata: VaultMetadata) -> None:
        """Persist the vault metadata block."""

    @abstractmethod
    def load_encrypted_entries(self) -> List[dict]:
        """
        Return the list of raw encrypted entry dicts as stored on disk.
        Each dict contains at minimum ``id``, ``ciphertext_hex``, ``iv_hex``,
        ``tag_hex`` (AES-GCM), plus the plaintext metadata fields.
        """

    @abstractmethod
    def save_encrypted_entries(self, entries: List[dict]) -> None:
        """Atomically replace the full list of encrypted entries on disk."""


class ICryptoService(ABC):
    """
    Port: cryptographic contract that any crypto backend must fulfil.

    Keeping this as an interface allows swapping implementations (e.g. a
    hardware-backed HSM adapter) without touching any other layer.
    """

    @abstractmethod
    def derive_key(self, master_password: str, metadata: VaultMetadata) -> bytes:
        """
        Derive a 256-bit AES key from the master password and the KDF
        parameters stored in ``metadata``.

        Args:
            master_password: Plaintext master password.
            metadata:        VaultMetadata carrying the KDF salt and parameters.

        Returns:
            32-byte raw key material.
        """

    @abstractmethod
    def hash_master_password(self, master_password: str, salt_hex: str) -> str:
        """
        Hash the master password for storage-time verification.

        Args:
            master_password: Plaintext master password.
            salt_hex:        Hex-encoded random salt.

        Returns:
            Hex-encoded digest (never the plaintext password).
        """

    @abstractmethod
    def verify_master_password(
        self, master_password: str, stored_hash: str, salt_hex: str
    ) -> bool:
        """Constant-time comparison of the computed hash vs ``stored_hash``."""

    @abstractmethod
    def encrypt(self, plaintext: str, key: bytes) -> dict:
        """
        Encrypt plaintext and return a dict with ``ciphertext_hex``,
        ``iv_hex``, and ``tag_hex`` (for AES-GCM).
        """

    @abstractmethod
    def decrypt(self, encrypted: dict, key: bytes) -> str:
        """Reverse of ``encrypt``. Raises ValueError on authentication failure."""

    @abstractmethod
    def generate_password(self, length: int, use_symbols: bool) -> str:
        """Generate a cryptographically secure random password via CSPRNG."""

    @abstractmethod
    def generate_salt(self, n_bytes: int = 32) -> bytes:
        """Generate ``n_bytes`` of cryptographically secure random bytes."""
