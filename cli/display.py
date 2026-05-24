"""
cli/display.py
==============
Pure presentation helpers: colour output, banners, table formatting.

This module has NO business logic — it only formats and prints.
Keeping it separate from the controller (``cli.py``) respects the
Single Responsibility Principle and makes it easy to swap in a Rich/
Textual-based UI later.
"""

from __future__ import annotations

import os
import sys
from typing import List

from core.domain.credential import Credential

# ANSI colour codes — disabled on Windows if not using Windows Terminal
_SUPPORTS_COLOR = (
    sys.stdout.isatty()
    and os.environ.get("NO_COLOR") is None
    and os.name != "nt"  # disable on legacy Windows cmd
)

_RESET  = "\033[0m"  if _SUPPORTS_COLOR else ""
_BOLD   = "\033[1m"  if _SUPPORTS_COLOR else ""
_DIM    = "\033[2m"  if _SUPPORTS_COLOR else ""
_RED    = "\033[91m" if _SUPPORTS_COLOR else ""
_GREEN  = "\033[92m" if _SUPPORTS_COLOR else ""
_YELLOW = "\033[93m" if _SUPPORTS_COLOR else ""
_CYAN   = "\033[96m" if _SUPPORTS_COLOR else ""
_WHITE  = "\033[97m" if _SUPPORTS_COLOR else ""


# --------------------------------------------------------------------------- #
# Public helpers                                                                #
# --------------------------------------------------------------------------- #


def banner() -> None:
    """Print the application banner."""
    print(
        f"\n{_CYAN}{_BOLD}"
        "╔══════════════════════════════════════╗\n"
        "║        🔐  PyPass — v1.0.0           ║\n"
        "║   Secure Local Password Manager      ║\n"
        "╚══════════════════════════════════════╝"
        f"{_RESET}\n"
    )


def section(title: str) -> None:
    """Print a section separator."""
    width = 42
    print(f"\n{_DIM}{'─' * width}{_RESET}")
    print(f"  {_BOLD}{_WHITE}{title}{_RESET}")
    print(f"{_DIM}{'─' * width}{_RESET}")


def success(msg: str) -> None:
    print(f"  {_GREEN}✔  {msg}{_RESET}")


def error(msg: str) -> None:
    print(f"  {_RED}✖  {msg}{_RESET}")


def warning(msg: str) -> None:
    print(f"  {_YELLOW}⚠  {msg}{_RESET}")


def info(msg: str) -> None:
    print(f"  {_CYAN}ℹ  {msg}{_RESET}")


def prompt(label: str) -> str:
    """Display a styled prompt and return the stripped input."""
    return input(f"  {_BOLD}{_WHITE}{label}:{_RESET} ").strip()


def secret_prompt(label: str) -> str:
    """Display a styled prompt and read input without echo."""
    import getpass
    return getpass.getpass(f"  {_BOLD}{_WHITE}{label}:{_RESET} ")


def confirm(question: str) -> bool:
    """Ask a yes/no question and return True for 'y'."""
    answer = prompt(f"{question} [y/N]")
    return answer.lower() in ("y", "yes")


def print_credential(cred: Credential, show_password: bool = False) -> None:
    """
    Pretty-print a single credential.

    Args:
        cred:          The Credential to display.
        show_password: If True, the plaintext password is printed.
                       Only set this when the caller explicitly requested it.
    """
    section(f"Credential: {cred.service}")
    _field("ID",       cred.id)
    _field("Service",  cred.service)
    _field("Username", cred.username)
    if show_password:
        _field("Password", f"{_YELLOW}{cred.password}{_RESET}", raw=True)
        warning("Clear your terminal history if it logs stdin!")
    else:
        _field("Password", f"{_DIM}[hidden — use 'show password' option]{_RESET}", raw=True)
    if cred.notes:
        _field("Notes",    cred.notes)
    _field("Created",  cred.created_at)
    _field("Updated",  cred.updated_at)


def print_credential_list(credentials: List[Credential]) -> None:
    """
    Print a compact table of credentials (no passwords).

    Args:
        credentials: List of Credential objects (passwords should be empty).
    """
    if not credentials:
        warning("No credentials found.")
        return

    col_w = [36, 22, 22]
    header = (
        f"  {_BOLD}"
        f"{'ID':<{col_w[0]}}  {'SERVICE':<{col_w[1]}}  {'USERNAME':<{col_w[2]}}"
        f"{_RESET}"
    )
    divider = f"  {_DIM}{'─' * sum(col_w)}{_RESET}"

    print()
    print(header)
    print(divider)
    for cred in credentials:
        row = (
            f"  {_DIM}{cred.id:<{col_w[0]}}{_RESET}  "
            f"{_WHITE}{cred.service:<{col_w[1]}}{_RESET}  "
            f"{_CYAN}{cred.username:<{col_w[2]}}{_RESET}"
        )
        print(row)
    print(divider)
    print(f"  {len(credentials)} credential(s) stored.\n")


def main_menu(vault_unlocked: bool) -> None:
    """Print the interactive main menu."""
    section("Main Menu")
    if not vault_unlocked:
        print(f"  {_WHITE}[1]{_RESET}  Initialise a new vault")
        print(f"  {_WHITE}[2]{_RESET}  Unlock existing vault")
    else:
        print(f"  {_WHITE}[3]{_RESET}  Add credential (manual)")
        print(f"  {_WHITE}[4]{_RESET}  Generate & add credential")
        print(f"  {_WHITE}[5]{_RESET}  List all services")
        print(f"  {_WHITE}[6]{_RESET}  Search credentials")
        print(f"  {_WHITE}[7]{_RESET}  Reveal password for a service")
        print(f"  {_WHITE}[8]{_RESET}  Lock vault (clear session key)")
    print(f"  {_WHITE}[0]{_RESET}  Exit\n")


# --------------------------------------------------------------------------- #
# Private helpers                                                               #
# --------------------------------------------------------------------------- #


def _field(label: str, value: str, raw: bool = False) -> None:
    formatted = value if raw else f"{_WHITE}{value}{_RESET}"
    print(f"  {_DIM}{label:<12}{_RESET} {formatted}")
