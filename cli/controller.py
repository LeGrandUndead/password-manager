"""
cli/controller.py
=================
CLI controller — the outermost layer of the application.

Responsibilities:
    - Read user input.
    - Call the appropriate use-case with the right parameters.
    - Convert use-case results / exceptions into user-facing messages via
      the ``display`` module.
    - Hold the ephemeral session key in memory and clear it on lock/exit.

The controller knows about use-cases but NOT about the repository or
crypto implementations directly — those are injected by ``main.py``
(Dependency Injection at the composition root).
"""

from __future__ import annotations

from typing import Optional

import cli.display as display
from core.domain.credential import Credential
from core.use_cases import (
    AddCredentialUseCase,
    AuthenticationError,
    DecryptionError,
    GeneratePasswordUseCase,
    GetCredentialUseCase,
    InitialiseVaultUseCase,
    ListCredentialsUseCase,
    SearchCredentialsUseCase,
    UnlockVaultUseCase,
    VaultAlreadyExistsError,
    VaultNotFoundError,
)


class CLIController:
    """
    Interactive CLI controller.

    All use-case instances are injected via the constructor, making this
    class unit-testable without touching the filesystem or real crypto.

    Args:
        init_vault_uc:      InitialiseVaultUseCase
        unlock_vault_uc:    UnlockVaultUseCase
        add_credential_uc:  AddCredentialUseCase
        get_credential_uc:  GetCredentialUseCase
        list_credentials_uc: ListCredentialsUseCase
        search_credentials_uc: SearchCredentialsUseCase
        generate_password_uc:  GeneratePasswordUseCase
    """

    def __init__(
        self,
        init_vault_uc: InitialiseVaultUseCase,
        unlock_vault_uc: UnlockVaultUseCase,
        add_credential_uc: AddCredentialUseCase,
        get_credential_uc: GetCredentialUseCase,
        list_credentials_uc: ListCredentialsUseCase,
        search_credentials_uc: SearchCredentialsUseCase,
        generate_password_uc: GeneratePasswordUseCase,
    ) -> None:
        self._init_vault = init_vault_uc
        self._unlock_vault = unlock_vault_uc
        self._add_credential = add_credential_uc
        self._get_credential = get_credential_uc
        self._list_credentials = list_credentials_uc
        self._search_credentials = search_credentials_uc
        self._generate_password = generate_password_uc

        # Session state — lives only in memory
        self._session_key: Optional[bytes] = None

    # ------------------------------------------------------------------ #
    # Main event loop                                                       #
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        """Start the interactive CLI loop."""
        display.banner()

        while True:
            display.main_menu(vault_unlocked=self._is_unlocked())
            choice = display.prompt("Choice")

            if choice == "0":
                self._cmd_exit()
                break
            elif choice == "1" and not self._is_unlocked():
                self._cmd_init_vault()
            elif choice == "2" and not self._is_unlocked():
                self._cmd_unlock_vault()
            elif choice == "3" and self._is_unlocked():
                self._cmd_add_credential(generate=False)
            elif choice == "4" and self._is_unlocked():
                self._cmd_add_credential(generate=True)
            elif choice == "5" and self._is_unlocked():
                self._cmd_list_credentials()
            elif choice == "6" and self._is_unlocked():
                self._cmd_search()
            elif choice == "7" and self._is_unlocked():
                self._cmd_reveal_password()
            elif choice == "8" and self._is_unlocked():
                self._cmd_lock()
            else:
                display.warning("Invalid choice or action not available in current state.")

    # ------------------------------------------------------------------ #
    # Command handlers                                                      #
    # ------------------------------------------------------------------ #

    def _cmd_init_vault(self) -> None:
        display.section("Initialise New Vault")
        display.info("Choose a strong master password. It cannot be recovered if lost.")

        master_pw = display.secret_prompt("Master password")
        confirm_pw = display.secret_prompt("Confirm master password")

        if master_pw != confirm_pw:
            display.error("Passwords do not match. Vault not created.")
            _wipe(master_pw)
            _wipe(confirm_pw)
            return

        if len(master_pw) < 12:
            display.warning("Password is shorter than 12 characters — consider a longer one.")

        try:
            self._init_vault.execute(master_pw)
            display.success("Vault initialised successfully. Please unlock it.")
        except VaultAlreadyExistsError as exc:
            display.error(str(exc))
        finally:
            _wipe(master_pw)
            _wipe(confirm_pw)

    def _cmd_unlock_vault(self) -> None:
        display.section("Unlock Vault")
        master_pw = display.secret_prompt("Master password")
        try:
            key, _ = self._unlock_vault.execute(master_pw)
            self._session_key = key
            display.success("Vault unlocked. Session key is held in memory.")
        except (VaultNotFoundError, AuthenticationError) as exc:
            display.error(str(exc))
        finally:
            _wipe(master_pw)

    def _cmd_add_credential(self, generate: bool) -> None:
        display.section("Generate & Add Credential" if generate else "Add Credential")

        service = display.prompt("Service (e.g. github.com)")
        username = display.prompt("Username / Email")

        if generate:
            try:
                length_str = display.prompt("Password length [default: 20]")
                length = int(length_str) if length_str else 20
            except ValueError:
                length = 20

            use_sym = display.confirm("Include symbols?")
            password = self._generate_password.execute(length=length, use_symbols=use_sym)
            display.info(f"Generated password: {password}")
            if not display.confirm("Use this password?"):
                display.info("Aborted.")
                return
        else:
            password = display.secret_prompt("Password")

        notes = display.prompt("Notes (optional)")

        cred = Credential(service=service, username=username, password=password, notes=notes)
        try:
            saved = self._add_credential.execute(cred, self._session_key)
            display.success(f"Credential saved (id={saved.id}).")
        except Exception as exc:
            display.error(f"Failed to save credential: {exc}")

    def _cmd_list_credentials(self) -> None:
        display.section("All Credentials (passwords hidden)")
        credentials = self._list_credentials.execute()
        display.print_credential_list(credentials)

    def _cmd_search(self) -> None:
        display.section("Search Credentials")
        query = display.prompt("Search term (service or username)")
        results = self._search_credentials.execute(query)
        if not results:
            display.warning("No credentials match your query.")
        else:
            display.print_credential_list(results)

    def _cmd_reveal_password(self) -> None:
        display.section("Reveal Password")

        # First show the list so the user can pick an ID
        credentials = self._list_credentials.execute()
        if not credentials:
            display.warning("No credentials stored.")
            return
        display.print_credential_list(credentials)

        cred_id = display.prompt("Enter the credential ID to reveal")
        try:
            cred = self._get_credential.execute(cred_id, self._session_key)
            display.print_credential(cred, show_password=True)
            # Sanitise immediately after display
            cred.sanitize()
        except KeyError as exc:
            display.error(str(exc))
        except DecryptionError as exc:
            display.error(f"Decryption failed: {exc}")

    def _cmd_lock(self) -> None:
        if self._session_key:
            # Overwrite key bytes in memory
            key_buf = bytearray(self._session_key)
            for i in range(len(key_buf)):
                key_buf[i] = 0
            del key_buf
            self._session_key = None
        display.success("Vault locked. Session key cleared from memory.")

    def _cmd_exit(self) -> None:
        self._cmd_lock()
        display.info("Goodbye. Stay secure.")

    # ------------------------------------------------------------------ #
    # Helpers                                                               #
    # ------------------------------------------------------------------ #

    def _is_unlocked(self) -> bool:
        return self._session_key is not None


def _wipe(s: str) -> None:
    """Best-effort overwrite of a string value in local scope."""
    try:
        buf = bytearray(s.encode())
        for i in range(len(buf)):
            buf[i] = 0
        del buf
    except Exception:
        pass
