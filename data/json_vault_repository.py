"""
data/json_vault_repository.py
==============================
Concrete adapter implementing ``IVaultRepository`` using a local JSON file.

Responsibilities (and ONLY these):
    - Serialise / deserialise vault data to/from ``vault.json``.
    - Atomic write via a temp-file + rename pattern to prevent data loss on
      crash mid-write.
    - Set restrictive file permissions (0o600) so only the owner can read the
      vault file.

This adapter knows nothing about cryptography or the CLI. It just persists
whatever bytes or dicts it is given. Swapping to SQLite or an encrypted
binary format would only require a new adapter, with zero changes to any other
layer (Open/Closed Principle).
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import List

from core.domain.vault_metadata import VaultMetadata
from core.ports import IVaultRepository

_DEFAULT_VAULT_NAME = "vault.json"


class JsonVaultRepository(IVaultRepository):
    """
    JSON file-based vault repository.

    File layout of ``vault.json``::

        {
            "metadata": { ...VaultMetadata fields... },
            "entries":  [
                {
                    "id":             "uuid",
                    "service":        "github.com",
                    "username":       "alice",
                    "notes":          "",
                    "created_at":     "2024-01-01T00:00:00+00:00",
                    "updated_at":     "2024-01-01T00:00:00+00:00",
                    "iv_hex":         "...",
                    "ciphertext_hex": "..."
                },
                ...
            ]
        }

    The ``password`` field is NEVER written to disk. The entire field is
    replaced by ``iv_hex`` + ``ciphertext_hex`` (AES-GCM authenticated
    ciphertext). The authentication tag is bundled at the end of
    ``ciphertext_hex`` by the ``cryptography`` library.

    Args:
        vault_path: Path to the vault file. Defaults to ``./vault.json`` in
                    the current working directory. In production you might
                    point this at ``~/.config/pypass/vault.json``.
    """

    def __init__(self, vault_path: Optional[Path] = None) -> None:
        from typing import Optional  # local import to avoid circular at module level
        self._vault_path: Path = Path(vault_path) if vault_path else Path(_DEFAULT_VAULT_NAME)

    # ------------------------------------------------------------------ #
    # IVaultRepository implementation                                      #
    # ------------------------------------------------------------------ #

    def vault_exists(self) -> bool:
        return self._vault_path.exists()

    def load_metadata(self) -> VaultMetadata:
        data = self._read_vault()
        return VaultMetadata.from_dict(data["metadata"])

    def save_metadata(self, metadata: VaultMetadata) -> None:
        data = self._read_vault() if self.vault_exists() else {"entries": []}
        data["metadata"] = metadata.to_dict()
        self._write_vault(data)

    def load_encrypted_entries(self) -> List[dict]:
        data = self._read_vault()
        return data.get("entries", [])

    def save_encrypted_entries(self, entries: List[dict]) -> None:
        data = self._read_vault()
        data["entries"] = entries
        self._write_vault(data)

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    def _read_vault(self) -> dict:
        """
        Read and parse the vault file.

        Raises:
            FileNotFoundError: If the vault file does not exist.
            json.JSONDecodeError: If the file is corrupted / invalid JSON.
        """
        if not self._vault_path.exists():
            raise FileNotFoundError(
                f"Vault not found at {self._vault_path}. "
                "Run the application and choose 'Initialise vault' first."
            )
        with open(self._vault_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _write_vault(self, data: dict) -> None:
        """
        Atomically write ``data`` to the vault file.

        Strategy:
            1. Write to a temporary file in the same directory (ensures same
               filesystem, making ``os.replace`` atomic on POSIX).
            2. Set file permissions to 0o600 (owner read/write only).
            3. Atomically replace the old vault file with ``os.replace``.

        This ensures the vault is never left in a partially-written state.
        """
        parent = self._vault_path.parent
        parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_path = tempfile.mkstemp(dir=parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            # Restrict permissions before moving into place
            os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            os.replace(tmp_path, self._vault_path)
        except Exception:
            # Clean up temp file on failure to avoid leaking partial data
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

        # Ensure the final file also has the correct permissions (os.replace
        # preserves the tmp file's permissions on most POSIX systems, but we
        # set it again for Windows compatibility).
        try:
            os.chmod(self._vault_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # Non-fatal on platforms that don't support Unix permissions
