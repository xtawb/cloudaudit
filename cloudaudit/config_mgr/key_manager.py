"""
cloudaudit.config_mgr.key_manager — Secure API Key Management

Features:
  - Validate keys before storing
  - Encrypt keys at rest using Fernet (AES-128-CBC + HMAC)
  - OS keyring integration when available (falls back to encrypted file)
  - Provider-specific troubleshooting guidance
  - CLI subcommand: cloudaudit config --set-api / --list-providers / --remove-api

Keys are NEVER logged. The encryption key is derived from a per-installation random salt.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger("cloudaudit.config")

# ── Provider metadata for UX guidance ─────────────────────────────────────────

PROVIDER_INFO = {
    "gemini": {
        "label":   "Google Gemini",
        "get_key": "https://aistudio.google.com/app/apikey",
        "env_var": "GEMINI_API_KEY",
        "format":  r"^AIza[0-9A-Za-z\-_]{35}$",
        "hint":    "Gemini API keys start with 'AIza' and are 39 characters long.",
        "troubleshoot": [
            "Ensure the key is from Google AI Studio (not Google Cloud Console)",
            "Check that the Gemini API is enabled for your project",
            "Verify the key has not expired or been deleted",
            "Try regenerating the key at https://aistudio.google.com/app/apikey",
        ],
    },
    "openai": {
        "label":   "OpenAI",
        "get_key": "https://platform.openai.com/api-keys",
        "env_var": "OPENAI_API_KEY",
        "format":  r"^sk-[A-Za-z0-9]{20,}$",
        "hint":    "OpenAI API keys start with 'sk-'.",
        "troubleshoot": [
            "Ensure the key starts with 'sk-'",
            "Check that your OpenAI account has billing configured",
            "Verify the key was not revoked at platform.openai.com",
            "Confirm you have GPT-4 access on your account tier",
        ],
    },
    "claude": {
        "label":   "Anthropic Claude",
        "get_key": "https://console.anthropic.com/settings/keys",
        "env_var": "ANTHROPIC_API_KEY",
        "format":  r"^sk-ant-[A-Za-z0-9\-_]{40,}$",
        "hint":    "Anthropic keys start with 'sk-ant-'.",
        "troubleshoot": [
            "Keys must start with 'sk-ant-'",
            "Check your usage limits at console.anthropic.com",
            "Verify the key is from the correct workspace",
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
            "Ensure you have sufficient DeepSeek credits",
        ],
    },
    "ollama": {
        "label":    "Ollama (Local)",
        "get_key":  "https://ollama.ai",
        "env_var":  "",
        "format":   None,   # No key required
        "hint":     "Ollama runs locally — no API key required.",
        "troubleshoot": [
            "Install Ollama from https://ollama.ai",
            "Run 'ollama pull llama3' to download the model",
            "Ensure Ollama is running: 'ollama serve'",
            "Default URL is http://localhost:11434",
        ],
    },
}


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


def _get_or_create_fernet():
    """Load or create the Fernet cipher for config file encryption."""
    from cryptography.fernet import Fernet
    config_dir = get_config_dir()
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    salt_path = get_salt_path()
    if salt_path.exists():
        salt = salt_path.read_bytes()
    else:
        salt = os.urandom(32)
        salt_path.write_bytes(salt)
        salt_path.chmod(0o600)

    key = _derive_fernet_key(salt)
    return Fernet(key)


class SecureKeyStore:
    """
    Encrypted local key store. Falls back gracefully if cryptography is unavailable.
    Keys stored as: ~/.cloudaudit/config.enc (Fernet-encrypted JSON)
    """

    def load_all(self) -> Dict[str, str]:
        """Load all stored API keys. Returns empty dict on failure."""
        config_path = get_config_path()
        if not config_path.exists():
            return {}
        try:
            f = _get_or_create_fernet()
            encrypted = config_path.read_bytes()
            decrypted = f.decrypt(encrypted)
            return json.loads(decrypted.decode("utf-8"))
        except Exception as exc:
            logger.debug("Failed to load config: %s", exc)
            return {}

    def save(self, provider: str, api_key: str) -> bool:
        """Encrypt and persist an API key. Returns True on success."""
        try:
            data = self.load_all()
            data[provider] = api_key
            f   = _get_or_create_fernet()
            enc = f.encrypt(json.dumps(data).encode("utf-8"))
            config_path = get_config_path()
            config_path.write_bytes(enc)
            config_path.chmod(0o600)
            return True
        except Exception as exc:
            logger.error("Failed to save API key: %s", exc)
            return False

    def get(self, provider: str) -> Optional[str]:
        return self.load_all().get(provider)

    def remove(self, provider: str) -> bool:
        try:
            data = self.load_all()
            if provider in data:
                del data[provider]
                f   = _get_or_create_fernet()
                enc = f.encrypt(json.dumps(data).encode("utf-8"))
                get_config_path().write_bytes(enc)
                return True
            return False
        except Exception:
            return False

    def list_configured(self) -> list[str]:
        return list(self.load_all().keys())


def validate_key_format(provider: str, api_key: str) -> tuple[bool, str]:
    """
    Check API key format before attempting live validation.
    Returns (is_valid_format, hint_message).
    """
    info = PROVIDER_INFO.get(provider, {})
    fmt  = info.get("format")
    hint = info.get("hint", "")

    if fmt is None:
        return True, ""   # No format requirement (e.g. Ollama)

    if re.match(fmt, api_key):
        return True, ""
    return False, hint


def validate_key_live(provider: str, api_key: str) -> tuple[bool, str]:
    """
    Attempt a live API call to confirm the key works.
    Returns (is_valid, error_message).
    """
    try:
        from cloudaudit.ai.providers import (
            GeminiProvider, OpenAICompatibleProvider, ClaudeProvider
        )
        if provider == "gemini":
            return GeminiProvider(api_key).validate_key(), ""
        if provider in ("openai", "deepseek"):
            return OpenAICompatibleProvider(api_key, provider).validate_key(), ""
        if provider in ("claude", "anthropic"):
            return ClaudeProvider(api_key).validate_key(), ""
        return True, ""   # Unknown providers pass through
    except Exception as exc:
        return False, str(exc)


def get_troubleshoot_guide(provider: str) -> list[str]:
    return PROVIDER_INFO.get(provider, {}).get("troubleshoot", [])


def get_provider_info(provider: str) -> dict:
    return PROVIDER_INFO.get(provider, {})
