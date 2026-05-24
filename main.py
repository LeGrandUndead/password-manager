"""
main.py
=======
Composition Root — the single place in the application where all concrete
implementations are instantiated and wired together.

This is the ONLY file that knows about every layer simultaneously. By keeping
wiring logic here and out of every other module, we apply:
    - Dependency Injection: classes receive their collaborators, never create them.
    - Inversion of Control: high-level policy (use-cases) does not depend on
      low-level detail (JSON files, specific KDF implementations).

To swap the storage backend from JSON to SQLite, you only edit THIS file.
"""

from __future__ import annotations

import sys
from pathlib import Path

# --- Infrastructure (adapters) ---
from data.json_vault_repository import JsonVaultRepository
from security.crypto_service import CryptoService

# --- Use-cases (application layer) ---
from core.use_cases import (
    AddCredentialUseCase,
    GeneratePasswordUseCase,
    GetCredentialUseCase,
    InitialiseVaultUseCase,
    ListCredentialsUseCase,
    SearchCredentialsUseCase,
    UnlockVaultUseCase,
)

# --- Presentation (CLI adapter) ---
from cli.controller import CLIController


def build_controller(vault_path: Path | None = None) -> CLIController:
    """
    Factory / composition root: wire all dependencies and return the
    fully constructed ``CLIController``.

    Args:
        vault_path: Override the default vault file location. Useful for
                    tests or a custom ``--vault`` CLI flag.

    Returns:
        A ready-to-run CLIController with all dependencies injected.
    """
    # 1. Infrastructure adapters
    crypto = CryptoService()
    repo = JsonVaultRepository(vault_path=vault_path)

    # 2. Use-cases — each receives only the interfaces it needs
    init_vault_uc       = InitialiseVaultUseCase(crypto=crypto, repo=repo)
    unlock_vault_uc     = UnlockVaultUseCase(crypto=crypto, repo=repo)
    add_credential_uc   = AddCredentialUseCase(crypto=crypto, repo=repo)
    get_credential_uc   = GetCredentialUseCase(crypto=crypto, repo=repo)
    list_credentials_uc = ListCredentialsUseCase(repo=repo)
    search_uc           = SearchCredentialsUseCase(repo=repo)
    gen_password_uc     = GeneratePasswordUseCase(crypto=crypto)

    # 3. CLI controller — receives use-cases only, never raw infra
    return CLIController(
        init_vault_uc=init_vault_uc,
        unlock_vault_uc=unlock_vault_uc,
        add_credential_uc=add_credential_uc,
        get_credential_uc=get_credential_uc,
        list_credentials_uc=list_credentials_uc,
        search_credentials_uc=search_uc,
        generate_password_uc=gen_password_uc,
    )


def main() -> None:
    """Entry point: parse optional --vault flag and start the application."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="pypass",
        description="PyPass — a secure local password manager.",
    )
    parser.add_argument(
        "--vault",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to the vault file (default: ./vault.json)",
    )
    args = parser.parse_args()

    controller = build_controller(vault_path=args.vault)
    try:
        controller.run()
    except KeyboardInterrupt:
        print("\n")
        from cli import display
        display.info("Interrupted. Vault locked. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
