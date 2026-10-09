"""
cloudaudit.config_mgr.key_manager — Secure API Key Management

Features:
  - Normalise pasted keys (whitespace, quotes, "Bearer ", "NAME=value")
  - Detect the provider from the key's shape and catch provider/key mix-ups
  - Validate keys before storing — distinguishing a *rejected* key from an
    exhausted quota or a network problem
  - Encrypt keys at rest using Fernet (AES-128-CBC + HMAC), written atomically
  - Provider-specific troubleshooting guidance
  - CLI subcommand: cloudaudit config --set-api / --test-api / --list-providers / --remove-api

Keys are NEVER logged. The encryption key is derived from a per-installation random salt.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("cloudaudit.config")

# ── Provider metadata for UX guidance ─────────────────────────────────────────
# ``format`` is advisory: a mismatch produces a warning, never a hard failure,
# because providers change key formats without notice.

PROVIDER_INFO = {
    "gemini": {
        "label":   "Google Gemini",
        "get_key": "https://aistudio.google.com/app/apikey",
        "env_var": "GEMINI_API_KEY",
        "format":  r"^(?:AIza[0-9A-Za-z_\-]{35}|AQ\.[0-9A-Za-z_\-]{20,})$",
        "hint":    "Gemini API keys normally start with 'AIza' (39 characters) or 'AQ.'.",
        "troubleshoot": [
            "Create the key in Google AI Studio: https://aistudio.google.com/app/apikey",
            "If the key came from Google Cloud Console, enable the 'Generative Language API' for its project",
            "Check the key has no API restrictions that exclude the Generative Language API",
            "A 429 / quota error means the key is VALID but rate-limited — wait a minute or use a flash model (--model)",
            "Gemini is not available in every region; a 'location is not supported' error is regional, not a key problem",
        ],
    },
    "openai": {
        "label":   "OpenAI",
        "get_key": "https://platform.openai.com/api-keys",
        "env_var": "OPENAI_API_KEY",
        "format":  r"^sk-[A-Za-z0-9_\-]{20,}$",
        "hint":    "OpenAI API keys start with 'sk-' (project keys: 'sk-proj-').",
        "troubleshoot": [
            "Ensure the key starts with 'sk-' and was copied in full (project keys are ~160 characters)",
            "'insufficient_quota' means the key is valid but the account has no credit — add billing at platform.openai.com",
            "Verify the key was not revoked at platform.openai.com/api-keys",
            "Project-scoped keys must have access to the model in use (override with --model)",
        ],
    },
    "claude": {
        "label":   "Anthropic Claude",
        "get_key": "https://console.anthropic.com/settings/keys",
        "env_var": "ANTHROPIC_API_KEY",
        "format":  r"^sk-ant-[A-Za-z0-9_\-]{20,}$",
        "hint":    "Anthropic keys start with 'sk-ant-'.",
        "troubleshoot": [
            "Keys must start with 'sk-ant-'",
            "'credit balance is too low' means the key is valid but the workspace has no credit",
            "Verify the key belongs to the intended workspace at console.anthropic.com",
            "Install the SDK: pip install anthropic",
        ],
    },
    "deepseek": {
        "label":   "DeepSeek AI",
        "get_key": "https://platform.deepseek.com/api_keys",
        "env_var": "DEEPSEEK_API_KEY",
        "format":  r"^sk-[A-Za-z0-9]{20,}$",
        "hint":    "DeepSeek API keys start with 'sk-'.",
        "troubleshoot": [
            "Get your key at platform.deepseek.com/api_keys",
            "'Insufficient Balance' (HTTP 402) means the key is valid but the account needs a top-up",
        ],
    },
    "custom": {
        "label":   "Custom (OpenAI-compatible)",
        "get_key": "your endpoint's documentation",
        "env_var": "CLOUDAUDIT_API_KEY",
        "format":  None,
        "hint":    "Any OpenAI-compatible endpoint. Requires --provider-url; choose a model with --model.",
        "troubleshoot": [
            "Pass the endpoint base URL with --provider-url (usually ending in /v1)",
            "Pass the model name with --model if the endpoint does not list its models",
        ],
    },
    "ollama": {
        "label":    "Ollama (Local)",
        "get_key":  "https://ollama.com",
        "env_var":  "",
        "format":   None,   # No key required
        "hint":     "Ollama runs locally — no API key required.",
        "troubleshoot": [
            "Install Ollama from https://ollama.com",
            "Run 'ollama pull llama3' to download the model",
            "Ensure Ollama is running: 'ollama serve'",
            "Default URL is http://localhost:11434",
        ],
    },
}

# Additional environment variables honoured per provider (checked after env_var).
ALT_ENV_VARS: Dict[str, Tuple[str, ...]] = {
    "gemini":   ("GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY"),
    "claude":   ("CLAUDE_API_KEY",),
    "openai":   (),
    "deepseek": (),
    "custom":   ("OPENAI_API_KEY",),
}

_ALIASES = {"anthropic": "claude", "google": "gemini", "googleai": "gemini", "gpt": "openai", "chatgpt": "openai"}


def canonical_provider(provider: Optional[str]) -> str:
    """Normalise a provider name ('Anthropic' → 'claude', 'Google' → 'gemini')."""
    p = (provider or "").strip().lower()
    return _ALIASES.get(p, p)


# ── Key normalisation / recognition ───────────────────────────────────────────

_INVISIBLE_RE = re.compile(r"[​‌‍⁠﻿ ]")


def normalize_api_key(raw: Optional[str]) -> str:
    """
    Clean up a pasted key.

    Handles the copy/paste accidents that otherwise surface as a baffling
    "invalid API key" from the provider: surrounding whitespace or newlines,
    wrapping quotes, zero-width characters, a leading ``Bearer``, and a whole
    ``NAME=value`` / ``export NAME=value`` line pasted instead of the value.
    """
    if not raw:
        return ""
    key = _INVISIBLE_RE.sub("", str(raw)).strip()
    key = re.sub(r"^(?:export|set|setx)\s+", "", key, flags=re.IGNORECASE)
    m = re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*(.+)$", key)
    if m and re.search(r"(?i)key|token|secret", key.split("=")[0].split(":")[0]):
        key = m.group(1).strip()
    key = key.strip().strip("\"'`").strip()
    key = re.sub(r"^(?:Bearer|Token)\s+", "", key, flags=re.IGNORECASE)
    # A key never contains whitespace — remove line-wrap artefacts.
    return re.sub(r"\s+", "", key)


def detect_provider_from_key(api_key: str) -> Optional[str]:
    """Best-effort provider guess from the key's prefix. None when ambiguous."""
    key = normalize_api_key(api_key)
    if key.startswith("sk-ant-"):
        return "claude"
    if key.startswith(("AIza", "AQ.")):
        return "gemini"
    if key.startswith(("sk-proj-", "sk-svcacct-", "sk-admin-")) or "T3BlbkFJ" in key:
        return "openai"
    return None   # a bare "sk-…" could be OpenAI, DeepSeek or a compatible gateway


def mask_key(api_key: str) -> str:
    """Display form of a key: enough to recognise it, never enough to use it."""
    key = normalize_api_key(api_key)
    if len(key) <= 12:
        return "***"
    return f"{key[:6]}…{key[-4:]} ({len(key)} chars)"


def get_config_dir() -> Path:
    return Path(os.path.expanduser("~/.cloudaudit"))


def get_config_path() -> Path:
    return get_config_dir() / "config.enc"


def get_salt_path() -> Path:
    return get_config_dir() / ".salt"


def _derive_fernet_key(salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a random salt using PBKDF2."""
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        raw_key = kdf.derive(b"cloudaudit-local-key-v1")
        return base64.urlsafe_b64encode(raw_key)
    except ImportError:
        raise RuntimeError(
            "cryptography package required for secure key storage. "
            "Run: pip install cryptography"
        )


def _restrict(path: Path) -> None:
    """Owner-only permissions where the platform supports them (no-op on Windows)."""
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file + rename so a crash can never leave a half-written store."""
    tmp = path.with_name(path.name + f".tmp{os.getpid()}")
    tmp.write_bytes(data)
    _restrict(tmp)
    os.replace(tmp, path)


def _get_or_create_fernet():
    """Load or create the Fernet cipher for config file encryption."""
    from cryptography.fernet import Fernet
    config_dir = get_config_dir()
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    salt_path = get_salt_path()
    salt = salt_path.read_bytes() if salt_path.exists() else b""
    if len(salt) < 16:
        salt = os.urandom(32)
        _atomic_write(salt_path, salt)

    key = _derive_fernet_key(salt)
    return Fernet(key)


class KeyStoreError(Exception):
    """The encrypted key store exists but cannot be read."""


class SecureKeyStore:
    """
    Encrypted local key store.
    Keys stored as: ~/.cloudaudit/config.enc (Fernet-encrypted JSON)
    """

    def _read(self) -> Dict[str, str]:
        """Load the store. Raises KeyStoreError if it exists but cannot be decrypted."""
        config_path = get_config_path()
        if not config_path.exists():
            return {}
        try:
            f = _get_or_create_fernet()
            data = json.loads(f.decrypt(config_path.read_bytes()).decode("utf-8"))
        except Exception as exc:
            raise KeyStoreError(
                f"{config_path} could not be decrypted ({type(exc).__name__}) — the salt file is missing "
                "or the store is corrupt"
            ) from exc
        if not isinstance(data, dict):
            raise KeyStoreError(f"{config_path} has an unexpected structure")
        return {str(k): str(v) for k, v in data.items() if v}

    def load_all(self) -> Dict[str, str]:
        """Load all stored API keys. Returns empty dict on failure."""
        try:
            return self._read()
        except KeyStoreError as exc:
            logger.warning("Stored API keys are unavailable: %s. Re-add them with: cloudaudit config --set-api <provider>", exc)
            return {}
        except Exception as exc:
            logger.debug("Failed to load config: %s", exc)
            return {}

    def _write(self, data: Dict[str, str]) -> None:
        f = _get_or_create_fernet()
        _atomic_write(get_config_path(), f.encrypt(json.dumps(data).encode("utf-8")))

    def save(self, provider: str, api_key: str) -> bool:
        """Encrypt and persist an API key. Returns True on success."""
        provider = canonical_provider(provider)
        api_key = normalize_api_key(api_key)
        if not provider or not api_key:
            return False
        try:
            try:
                data = self._read()
            except KeyStoreError as exc:
                # Never silently overwrite a store we cannot read: an unreadable
                # store used to be treated as empty, so saving one key wiped
                # every other provider's key. Keep the old file aside instead.
                backup = get_config_path().with_name(f"config.enc.unreadable-{int(time.time())}")
                try:
                    os.replace(get_config_path(), backup)
                    logger.warning("%s. The old store was kept as %s and a new one started.", exc, backup.name)
                except OSError:
                    logger.warning("%s. Starting a new store.", exc)
                data = {}
            data[provider] = api_key
            self._write(data)
            return True
        except Exception as exc:
            logger.error("Failed to save API key: %s", exc)
            return False

    def get(self, provider: str) -> Optional[str]:
        key = self.load_all().get(canonical_provider(provider))
        return normalize_api_key(key) or None

    def remove(self, provider: str) -> bool:
        provider = canonical_provider(provider)
        try:
            data = self._read()
            if provider in data:
                del data[provider]
                self._write(data)
                return True
            return False
        except Exception as exc:
            logger.debug("Failed to remove API key: %s", exc)
            return False

    def list_configured(self) -> List[str]:
        return list(self.load_all().keys())


def resolve_api_key(provider: Optional[str], explicit: Optional[str] = None,
                    env_file: str = ".cloudaudit.env") -> Tuple[Optional[str], str]:
    """
    Single source of truth for key lookup. Returns ``(key, source)``.

    Order: explicit value (--api-key) → provider env var → alternate env vars
    → ``.cloudaudit.env`` in the working directory → encrypted key store.
    The value is never logged; ``source`` is safe to display.
    """
    key = normalize_api_key(explicit)
    if key:
        return key, "--api-key"

    provider = canonical_provider(provider)
    if not provider or provider == "ollama":
        return None, ""

    info = PROVIDER_INFO.get(provider, {})
    names = [n for n in (info.get("env_var", ""), *ALT_ENV_VARS.get(provider, ())) if n]
    for name in names:
        key = normalize_api_key(os.environ.get(name))
        if key:
            return key, f"environment variable {name}"

    path = Path(env_file)
    if names and path.is_file():
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k = re.sub(r"^export\s+", "", k.strip())
                if k in names:
                    key = normalize_api_key(v.split(" #")[0])
                    if key:
                        return key, f"{env_file} ({k})"
        except OSError:
            pass

    key = SecureKeyStore().get(provider)
    if key:
        return key, "encrypted key store"
    return None, ""


def validate_key_format(provider: str, api_key: str) -> tuple[bool, str]:
    """
    Check API key format before attempting live validation.
    Returns (is_valid_format, hint_message). A False result is advisory only.
    """
    provider = canonical_provider(provider)
    api_key = normalize_api_key(api_key)
    info = PROVIDER_INFO.get(provider, {})
    fmt  = info.get("format")
    hint = info.get("hint", "")

    guessed = detect_provider_from_key(api_key)
    if guessed and guessed != provider and provider in ("gemini", "openai", "claude", "deepseek"):
        return False, (
            f"This looks like a {PROVIDER_INFO[guessed]['label']} key, not a {info.get('label', provider)} key. "
            f"Did you mean: --provider {guessed}?"
        )

    if fmt is None:
        return True, ""   # No format requirement (e.g. Ollama, custom)

    if re.match(fmt, api_key):
        return True, ""
    return False, hint


def validate_key_detailed(provider: str, api_key: str, base_url: Optional[str] = None,
                          model: Optional[str] = None) -> Dict[str, object]:
    """
    Live key check. Returns ``{"status", "model", "error"}`` where status is:

      - ``valid``      — the provider accepted the key
      - ``quota``      — the key is genuine but the account has no quota/credit
      - ``invalid``    — the provider rejected the key
      - ``unverified`` — the check could not be completed (offline, SDK missing,
                         rate limited); this is NOT evidence that the key is bad
    """
    provider = canonical_provider(provider)
    api_key = normalize_api_key(api_key)
    try:
        from cloudaudit.ai.providers import build_provider_chain
        from cloudaudit.core.exceptions import ProviderAuthError
        try:
            chain = build_provider_chain(provider, api_key, base_url, model=model)
        except ProviderAuthError as exc:
            return {"status": "invalid", "model": None, "error": str(exc)}
        remote = getattr(chain, "_remote", None)
        if remote is None:
            return {"status": "valid", "model": None, "error": ""}
        return remote.check_key()
    except Exception as exc:
        return {"status": "unverified", "model": None, "error": str(exc)[:300]}


def validate_key_live(provider: str, api_key: str) -> tuple[bool, str]:
    """
    Attempt a live API call to confirm the key works.
    Returns (is_valid, error_message). ``is_valid`` is True for a key the
    provider accepted even if the account is out of quota (the message says so).
    """
    res = validate_key_detailed(provider, api_key)
    status = res["status"]
    if status == "valid":
        return True, ""
    if status == "quota":
        return True, f"Key accepted, but the account has no remaining quota/credit: {res['error']}"
    if status == "unverified":
        return False, f"Could not verify the key (this does not mean it is invalid): {res['error']}"
    return False, str(res["error"])


def get_troubleshoot_guide(provider: str) -> list[str]:
    return PROVIDER_INFO.get(canonical_provider(provider), {}).get("troubleshoot", [])


def get_provider_info(provider: str) -> dict:
    return PROVIDER_INFO.get(canonical_provider(provider), {})
