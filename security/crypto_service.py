"""
security/crypto_service.py
===========================
Concrete implementation of ``ICryptoService``.

Responsibilities (and ONLY these):
    - Key derivation via Argon2id (preferred), Scrypt, or PBKDF2.
    - AES-256-GCM authenticated encryption / decryption.
    - Master-password hashing (SHA-256 with a dedicated salt).
    - CSPRNG-backed password generation.
    - Random salt generation.

This layer is completely ignorant of WHERE data is stored (that is the
Repository's concern) and HOW it is displayed (that is the CLI's concern).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.domain.vault_metadata import VaultMetadata
from core.ports import ICryptoService

# Try to import argon2-cffi; fall back gracefully at runtime if absent.
try:
    from argon2.low_level import Type, hash_secret_raw

    _ARGON2_AVAILABLE = True
except ImportError:
    _ARGON2_AVAILABLE = False

# AES-GCM nonce size (96 bits is the standard recommendation)
_GCM_NONCE_BYTES = 12
# AES-256 key size
_KEY_BYTES = 32


class CryptoService(ICryptoService):
    """
    Full cryptographic service implementing the ``ICryptoService`` port.

    KDF selection strategy (Factory Method pattern applied internally):
        1. Argon2id  — preferred; memory-hard, GPU/ASIC-resistant.
        2. Scrypt    — strong alternative if argon2-cffi is unavailable.
        3. PBKDF2    — fallback; always available via stdlib ``hashlib``.

    Encryption:
        AES-256-GCM — provides both confidentiality AND integrity
        (authenticated encryption). A fresh 96-bit IV/nonce is generated for
        every encryption operation (critical: never reuse a nonce with AES-GCM).
    """

    # ------------------------------------------------------------------ #
    # ICryptoService interface                                             #
    # ------------------------------------------------------------------ #

    def generate_salt(self, n_bytes: int = 32) -> bytes:
        """
        Generate cryptographically secure random bytes via ``os.urandom``,
        which maps to the OS CSPRNG (getrandom(2) on Linux, CryptGenRandom
        on Windows).
        """
        return os.urandom(n_bytes)

    def derive_key(self, master_password: str, metadata: VaultMetadata) -> bytes:
        """
        Derive a 32-byte AES key from the master password using the KDF
        specified in ``metadata``.

        Dispatches to the appropriate private helper via a simple strategy
        dictionary — avoids a long if/elif chain (Open/Closed Principle).
        """
        _strategies = {
            "argon2id": self._derive_argon2id,
            "scrypt": self._derive_scrypt,
            "pbkdf2": self._derive_pbkdf2,
        }
        kdf_fn = _strategies.get(metadata.kdf)
        if kdf_fn is None:
            raise ValueError(f"Unsupported KDF: {metadata.kdf!r}")
        salt = bytes.fromhex(metadata.kdf_salt_hex)
        return kdf_fn(master_password, salt, metadata)

    def hash_master_password(self, master_password: str, salt_hex: str) -> str:
        """
        Compute PBKDF2-HMAC-SHA256(master_password, salt, 600_000 iters)
        for master-password *verification* (not key derivation).

        Using a separate salt and a different purpose prevents any theoretical
        cross-protocol attack between the KDF key material and this hash.

        Returns a hex-encoded digest.
        """
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            master_password.encode("utf-8"),
            salt,
            600_000,
            dklen=32,
        )
        return digest.hex()

    def verify_master_password(
        self, master_password: str, stored_hash: str, salt_hex: str
    ) -> bool:
        """
        Constant-time comparison using ``hmac.compare_digest`` to prevent
        timing side-channel attacks.
        """
        computed = self.hash_master_password(master_password, salt_hex)
        return hmac.compare_digest(computed, stored_hash)

    def encrypt(self, plaintext: str, key: bytes) -> dict:
        """
        Encrypt ``plaintext`` with AES-256-GCM.

        A fresh 96-bit nonce is generated for every call.
        AES-GCM appends a 128-bit authentication tag automatically —
        ``cryptography`` bundles it at the end of the ciphertext bytes.

        Returns:
            {
                "iv_hex":         hex-encoded 12-byte nonce,
                "ciphertext_hex": hex-encoded ciphertext + tag,
            }
        """
        nonce = os.urandom(_GCM_NONCE_BYTES)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "iv_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex(),
        }

    def decrypt(self, encrypted: dict, key: bytes) -> str:
        """
        Decrypt and authenticate an AES-256-GCM ciphertext.

        Raises:
            ValueError: If the authentication tag is invalid (tampered data).
        """
        nonce = bytes.fromhex(encrypted["iv_hex"])
        ciphertext = bytes.fromhex(encrypted["ciphertext_hex"])
        aesgcm = AESGCM(key)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise ValueError(
                "Decryption failed: authentication tag mismatch. "
                "Data may have been tampered with, or the master password is wrong."
            ) from exc
        return plaintext_bytes.decode("utf-8")

    def generate_password(self, length: int = 20, use_symbols: bool = True) -> str:
        """
        Generate a cryptographically secure random password.

        Uses ``secrets.choice`` which is backed by the OS CSPRNG
        (``os.urandom``), making it suitable for security-sensitive contexts
        unlike ``random.choice``.

        The generation loop guarantees the password contains at least one
        character from each required category (uppercase, lowercase, digit,
        symbol) before filling the remainder randomly.

        Args:
            length:      Desired password length (minimum 8).
            use_symbols: Whether to include special characters.

        Returns:
            A random password string of exactly ``length`` characters.
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters.")

        alphabet = string.ascii_letters + string.digits
        required: list[str] = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
        ]
        if use_symbols:
            symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            alphabet += symbols
            required.append(secrets.choice(symbols))

        remainder = [secrets.choice(alphabet) for _ in range(length - len(required))]
        password_chars = required + remainder
        # Shuffle with the CSPRNG so mandatory chars are not always at the front
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)

    # ------------------------------------------------------------------ #
    # Private KDF helpers                                                  #
    # ------------------------------------------------------------------ #

    def _derive_argon2id(
        self, password: str, salt: bytes, meta: VaultMetadata
    ) -> bytes:
        if not _ARGON2_AVAILABLE:
            raise RuntimeError(
                "argon2-cffi is not installed. "
                "Run: pip install argon2-cffi   or choose a different KDF."
            )
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=meta.argon2_time_cost,
            memory_cost=meta.argon2_memory_cost,
            parallelism=meta.argon2_parallelism,
            hash_len=_KEY_BYTES,
            type=Type.ID,
        )

    def _derive_scrypt(
        self, password: str, salt: bytes, meta: VaultMetadata
    ) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=meta.scrypt_n,
            r=meta.scrypt_r,
            p=meta.scrypt_p,
            dklen=_KEY_BYTES,
        )

    def _derive_pbkdf2(
        self, password: str, salt: bytes, meta: VaultMetadata
    ) -> bytes:
        return hashlib.pbkdf2_hmac(
            meta.pbkdf2_hash,
            password.encode("utf-8"),
            salt,
            meta.pbkdf2_iterations,
            dklen=_KEY_BYTES,
        )

    # ------------------------------------------------------------------ #
    # Factory helper                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def best_available_kdf() -> str:
        """
        Return the identifier of the strongest KDF available in the current
        environment. Called during vault initialisation.
        """
        if _ARGON2_AVAILABLE:
            return "argon2id"
        return "scrypt"
