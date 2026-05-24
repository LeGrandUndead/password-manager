# 🔐 PyPass — Secure Local Password Manager

A **production-grade, locally-stored** password manager written in Python,
following **Clean Architecture** principles and the **SOLID** design principles.

---

## Directory Tree

```
password_manager/
│
├── main.py                          # Composition Root (DI wiring)
├── requirements.txt
│
├── core/                            # ★ DOMAIN LAYER — zero external deps
│   ├── __init__.py
│   ├── ports.py                     # Abstract interfaces (ICryptoService, IVaultRepository)
│   ├── use_cases.py                 # Application use-cases / interactors
│   └── domain/
│       ├── __init__.py
│       ├── credential.py            # Credential model (pure dataclass)
│       └── vault_metadata.py        # VaultMetadata model (pure dataclass)
│
├── security/                        # ★ CRYPTO LAYER — implements ICryptoService
│   ├── __init__.py
│   └── crypto_service.py            # AES-256-GCM + Argon2id/Scrypt/PBKDF2
│
├── data/                            # ★ DATA LAYER — implements IVaultRepository
│   ├── __init__.py
│   └── json_vault_repository.py     # Atomic JSON persistence (vault.json)
│
└── cli/                             # ★ PRESENTATION LAYER — CLI only
    ├── __init__.py
    ├── controller.py                # Interactive CLI event loop
    └── display.py                   # ANSI formatting, prompts, tables
```

---

## Quick Start

```bash
# 1. Create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python main.py

# Optional: use a custom vault path
python main.py --vault ~/.config/pypass/vault.json
```

---

## Architecture Rationale

### Clean Architecture (Concentric Rings)

```
┌──────────────────────────────────────────────────┐
│  CLI / Presentation                (outermost)   │
│  ┌────────────────────────────────────────────┐  │
│  │  Data / Repository                         │  │
│  │  ┌──────────────────────────────────────┐  │  │
│  │  │  Security / Crypto                   │  │  │
│  │  │  ┌────────────────────────────────┐  │  │  │
│  │  │  │  Core / Domain      (innermost) │  │  │  │
│  │  │  └────────────────────────────────┘  │  │  │
│  │  └──────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

**Dependency rule**: all arrows point inward. The domain layer imports nothing.
The CLI imports use-cases but never directly touches crypto or the database.

---

### Design Patterns Used

| Pattern | Where | Why |
|---|---|---|
| **Repository** | `IVaultRepository` → `JsonVaultRepository` | Decouples persistence from business logic. Swapping to SQLite/encrypted-binary requires only a new adapter. |
| **Dependency Injection** | `main.py` composition root | Every class receives its collaborators; none creates them. Enables mocking in tests. |
| **Strategy** | `CryptoService._derive_*` dispatch dict | Selects KDF (Argon2id / Scrypt / PBKDF2) at runtime without if/elif chains. |
| **Factory Method** | `CryptoService.best_available_kdf()` | Selects the strongest available KDF without the caller knowing the names. |
| **Ports & Adapters** (Hexagonal) | `core/ports.py` | Business logic depends only on interfaces, not implementations. |
| **Use-Case / Interactor** | `core/use_cases.py` | Each operation is a self-contained, single-responsibility class. |

---

### Security Decisions

| Concern | Decision |
|---|---|
| **KDF** | Argon2id (t=3, m=64 MiB, p=4) → Scrypt → PBKDF2-600k as fallback |
| **Encryption** | AES-256-GCM — authenticated encryption prevents silent tampering |
| **IV/Nonce** | Fresh 96-bit nonce per encryption — nonce reuse with GCM is catastrophic |
| **Master password verification** | Separate PBKDF2-SHA256 hash (distinct salt, distinct purpose) |
| **Storage** | Password plaintext NEVER written to disk; only `iv_hex + ciphertext_hex` |
| **Memory** | Passwords overwritten with null bytes immediately after use |
| **File permissions** | `vault.json` created with `0o600` (owner read/write only) |
| **Atomic writes** | Temp-file + `os.replace()` prevents half-written vault on crash |
| **Timing attacks** | `hmac.compare_digest` for constant-time master password comparison |
