"""
core/use_cases.py
=================
Application-level use-cases (a.k.a. "interactors" in Clean Architecture).

Each use-case class receives its dependencies (ICryptoService, IVaultRepository)
via constructor injection — making every use-case trivially unit-testable by
swapping in mock implementations.

This layer orchestrates the domain + security + persistence layers but has
NO knowledge of the CLI. It returns domain objects or raises typed exceptions;
the CLI converts those to user-facing messages.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from core.domain.credential import Credential
from core.domain.vault_metadata import VaultMetadata
from core.ports import ICryptoService, IVaultRepository


# --------------------------------------------------------------------------- #
# Custom exception hierarchy — lets the CLI handle errors gracefully           #
# --------------------------------------------------------------------------- #


class VaultAlreadyExistsError(RuntimeError):
    """Raised when trying to initialise an already-existing vault."""


class VaultNotFoundError(RuntimeError):
    """Raised when attempting to unlock a vault that does not exist."""


class AuthenticationError(RuntimeError):
    """Raised when the master password does not match."""


class DecryptionError(RuntimeError):
    """Raised when a credential's ciphertext fails AES-GCM authentication."""


# --------------------------------------------------------------------------- #
# InitialiseVaultUseCase                                                        #
# --------------------------------------------------------------------------- #


class InitialiseVaultUseCase:
    """
    Creates a new, empty, encrypted vault.

    Collaborators injected via DI:
        crypto:  ICryptoService  — generates salts, hashes the master password.
        repo:    IVaultRepository — persists the vault metadata.
    """

    def __init__(self, crypto: ICryptoService, repo: IVaultRepository) -> None:
        self._crypto = crypto
        self._repo = repo

    def execute(self, master_password: str, kdf: Optional[str] = None) -> None:
        """
        Initialise the vault with the given master password.

        Args:
            master_password: The user-chosen master password (plaintext — only
                             held in memory for the duration of this call).
            kdf:             KDF override (``"argon2id"`` | ``"scrypt"`` |
                             ``"pbkdf2"``). Defaults to the best available.

        Raises:
            VaultAlreadyExistsError: If a vault file already exists.
        """
        if self._repo.vault_exists():
            raise VaultAlreadyExistsError(
                "A vault already exists. Delete it manually if you want to start over."
            )

        from security.crypto_service import CryptoService  # avoid circular import

        selected_kdf = kdf or CryptoService.best_available_kdf()

        kdf_salt = self._crypto.generate_salt(32)
        hash_salt = self._crypto.generate_salt(32)

        master_hash = self._crypto.hash_master_password(
            master_password, hash_salt.hex()
        )

        metadata = VaultMetadata(
            kdf=selected_kdf,
            kdf_salt_hex=kdf_salt.hex(),
            master_hash=master_hash,
            master_hash_salt_hex=hash_salt.hex(),
        )

        self._repo.save_metadata(metadata)
        self._repo.save_encrypted_entries([])

        # Sanitise the password reference from local scope
        _clear(master_password)


# --------------------------------------------------------------------------- #
# UnlockVaultUseCase                                                            #
# --------------------------------------------------------------------------- #


class UnlockVaultUseCase:
    """
    Verifies the master password and derives the session encryption key.

    Returns the 32-byte AES key so the CLI can hold it in memory for the
    duration of the session. The key is NEVER persisted.
    """

    def __init__(self, crypto: ICryptoService, repo: IVaultRepository) -> None:
        self._crypto = crypto
        self._repo = repo

    def execute(self, master_password: str) -> Tuple[bytes, VaultMetadata]:
        """
        Verify the master password and return the session key + metadata.

        Returns:
            (session_key, metadata) on success.

        Raises:
            VaultNotFoundError:  If no vault file exists.
            AuthenticationError: If the master password is incorrect.
        """
        if not self._repo.vault_exists():
            raise VaultNotFoundError("No vault found. Please initialise one first.")

        metadata = self._repo.load_metadata()

        if not self._crypto.verify_master_password(
            master_password, metadata.master_hash, metadata.master_hash_salt_hex
        ):
            raise AuthenticationError("Incorrect master password.")

        session_key = self._crypto.derive_key(master_password, metadata)
        _clear(master_password)
        return session_key, metadata


# --------------------------------------------------------------------------- #
# AddCredentialUseCase                                                          #
# --------------------------------------------------------------------------- #


class AddCredentialUseCase:
    """Encrypt and persist a new credential."""

    def __init__(self, crypto: ICryptoService, repo: IVaultRepository) -> None:
        self._crypto = crypto
        self._repo = repo

    def execute(self, credential: Credential, session_key: bytes) -> Credential:
        """
        Encrypt the credential's password, build the storage dict, append it.

        The ``Credential.password`` field is sanitised after encryption.

        Returns:
            The credential with its ``id`` set.
        """
        encrypted = self._crypto.encrypt(credential.password, session_key)
        credential.sanitize()  # Clear plaintext from memory immediately

        metadata_dict = credential.to_dict()
        entry = {**metadata_dict, **encrypted}

        entries = self._repo.load_encrypted_entries()
        entries.append(entry)
        self._repo.save_encrypted_entries(entries)
        return credential


# --------------------------------------------------------------------------- #
# GetCredentialUseCase                                                          #
# --------------------------------------------------------------------------- #


class GetCredentialUseCase:
    """Decrypt and return a single credential by ID."""

    def __init__(self, crypto: ICryptoService, repo: IVaultRepository) -> None:
        self._crypto = crypto
        self._repo = repo

    def execute(self, credential_id: str, session_key: bytes) -> Credential:
        """
        Decrypt the credential matching ``credential_id``.

        Raises:
            KeyError:        If no entry with that ID exists.
            DecryptionError: If AES-GCM authentication fails.
        """
        entries = self._repo.load_encrypted_entries()
        entry = next((e for e in entries if e["id"] == credential_id), None)
        if entry is None:
            raise KeyError(f"No credential found with id={credential_id!r}")

        try:
            password = self._crypto.decrypt(
                {"iv_hex": entry["iv_hex"], "ciphertext_hex": entry["ciphertext_hex"]},
                session_key,
            )
        except ValueError as exc:
            raise DecryptionError(str(exc)) from exc

        return Credential.from_dict(entry, password=password)


# --------------------------------------------------------------------------- #
# ListCredentialsUseCase                                                        #
# --------------------------------------------------------------------------- #


class ListCredentialsUseCase:
    """Return metadata for all credentials — passwords are never decrypted."""

    def __init__(self, repo: IVaultRepository) -> None:
        self._repo = repo

    def execute(self) -> List[Credential]:
        """
        Return a list of ``Credential`` objects with empty ``password`` fields.
        No decryption is performed — this is safe to call without the session key.
        """
        entries = self._repo.load_encrypted_entries()
        return [Credential.from_dict(e, password="") for e in entries]


# --------------------------------------------------------------------------- #
# SearchCredentialsUseCase                                                      #
# --------------------------------------------------------------------------- #


class SearchCredentialsUseCase:
    """Search credentials by service name (case-insensitive substring match)."""

    def __init__(self, repo: IVaultRepository) -> None:
        self._repo = repo

    def execute(self, query: str) -> List[Credential]:
        """
        Return credentials whose ``service`` or ``username`` contains ``query``.

        Passwords are NOT decrypted; use ``GetCredentialUseCase`` for that.
        """
        query_lower = query.lower()
        entries = self._repo.load_encrypted_entries()
        results = [
            Credential.from_dict(e, password="")
            for e in entries
            if query_lower in e.get("service", "").lower()
            or query_lower in e.get("username", "").lower()
        ]
        return results


# --------------------------------------------------------------------------- #
# GeneratePasswordUseCase                                                       #
# --------------------------------------------------------------------------- #


class GeneratePasswordUseCase:
    """Delegate password generation to the crypto service (CSPRNG-backed)."""

    def __init__(self, crypto: ICryptoService) -> None:
        self._crypto = crypto

    def execute(self, length: int = 20, use_symbols: bool = True) -> str:
        """Return a freshly generated secure random password."""
        return self._crypto.generate_password(length=length, use_symbols=use_symbols)


# --------------------------------------------------------------------------- #
# Utility                                                                       #
# --------------------------------------------------------------------------- #


def _clear(s: str) -> None:  # noqa: ANN001
    """Best-effort memory sanitisation for a string variable."""
    try:
        buf = bytearray(s.encode())
        for i in range(len(buf)):
            buf[i] = 0
        del buf
    except Exception:
        pass
