# Command prompt password manager app

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
├── core/                            # DOMAIN LAYER — zero external deps
│   ├── __init__.py
│   ├── ports.py                     # Abstract interfaces (ICryptoService, IVaultRepository)
│   ├── use_cases.py                 # Application use-cases / interactors
│   └── domain/
│       ├── __init__.py
│       ├── credential.py            # Credential model (pure dataclass)
│       └── vault_metadata.py        # VaultMetadata model (pure dataclass)
│
├── security/                        # CRYPTO LAYER — implements ICryptoService
│   ├── __init__.py
│   └── crypto_service.py            # AES-256-GCM + Argon2id/Scrypt/PBKDF2
│
├── data/                            # DATA LAYER — implements IVaultRepository
│   ├── __init__.py
│   └── json_vault_repository.py     # Atomic JSON persistence (vault.json)
│
└── cli/                             # PRESENTATION LAYER — CLI only
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
