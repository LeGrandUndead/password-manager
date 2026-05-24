"""
core/domain/vault_metadata.py
==============================
Domain model for vault-level metadata (KDF parameters, salt, master-password
hash). Stored in plaintext in vault.json alongside encrypted credentials.

Pure data — no crypto logic, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VaultMetadata:
    """
    Holds the parameters required to derive the encryption key and verify
    the master password on future unlocks.

    Attributes:
        kdf:            Key-derivation function identifier ("argon2id" | "scrypt" | "pbkdf2").
        kdf_salt_hex:   Hex-encoded random salt used during key derivation.
        master_hash:    Hex-encoded SHA-256(salt2 + master_password) used ONLY
                        to verify the master password at unlock time. The actual
                        encryption key is never stored.
        master_hash_salt_hex: Separate salt for the master-password verification hash.
        version:        Vault schema version for future migrations.
    """

    kdf: str
    kdf_salt_hex: str
    master_hash: str
    master_hash_salt_hex: str
    version: int = 1

    # Argon2id parameters (ignored for other KDFs)
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536   # 64 MiB
    argon2_parallelism: int = 4

    # Scrypt parameters (ignored for other KDFs)
    # NOTE: 2**17 = 128 MiB is ideal for production. Some sandboxed/container
    # environments cap memory; lower to 2**14 (16 MiB) only in those contexts.
    scrypt_n: int = 2**17
    scrypt_r: int = 8
    scrypt_p: int = 1

    # PBKDF2 parameters (ignored for other KDFs)
    pbkdf2_iterations: int = 600_000
    pbkdf2_hash: str = "sha256"

    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON persistence."""
        return {
            "version": self.version,
            "kdf": self.kdf,
            "kdf_salt_hex": self.kdf_salt_hex,
            "master_hash": self.master_hash,
            "master_hash_salt_hex": self.master_hash_salt_hex,
            "argon2_time_cost": self.argon2_time_cost,
            "argon2_memory_cost": self.argon2_memory_cost,
            "argon2_parallelism": self.argon2_parallelism,
            "scrypt_n": self.scrypt_n,
            "scrypt_r": self.scrypt_r,
            "scrypt_p": self.scrypt_p,
            "pbkdf2_iterations": self.pbkdf2_iterations,
            "pbkdf2_hash": self.pbkdf2_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VaultMetadata":
        """Reconstruct from a previously serialised dict."""
        return cls(
            version=data.get("version", 1),
            kdf=data["kdf"],
            kdf_salt_hex=data["kdf_salt_hex"],
            master_hash=data["master_hash"],
            master_hash_salt_hex=data["master_hash_salt_hex"],
            argon2_time_cost=data.get("argon2_time_cost", 3),
            argon2_memory_cost=data.get("argon2_memory_cost", 65536),
            argon2_parallelism=data.get("argon2_parallelism", 4),
            scrypt_n=data.get("scrypt_n", 2**17),
            scrypt_r=data.get("scrypt_r", 8),
            scrypt_p=data.get("scrypt_p", 1),
            pbkdf2_iterations=data.get("pbkdf2_iterations", 600_000),
            pbkdf2_hash=data.get("pbkdf2_hash", "sha256"),
        )
