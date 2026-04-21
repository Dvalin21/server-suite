"""
Encrypted secrets storage using Fernet (AES-128-CBC with HMAC).
Includes SecretsVault (v2) and SecretsManager (v1 backward compatibility).
"""
import os
import json
import secrets
import string
import stat
import re
from pathlib import Path
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
import logging

logger = logging.getLogger(__name__)

SECRETS_FILE = "/opt/server-suite/secrets.enc"
KEY_FILE = "/opt/server-suite/.master.key"
SECRETS_DIR_MODE = 0o700
SECRET_FILE_MODE = 0o600


class SecretsVault:
    def __init__(self, tpm_enabled: bool = False):
        self.tpm_enabled = tpm_enabled
        self.key = self._get_or_create_key()
        self.cipher = Fernet(self.key)
        self._data = {}
        self._load()
    
    def _get_or_create_key(self) -> bytes:
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f:
                return f.read()
        
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        os.chmod(KEY_FILE, 0o600)
        logger.info("Generated new master key for secrets vault")
        return key
    
    def _load(self):
        if not os.path.exists(SECRETS_FILE):
            self._data = {}
            return
        try:
            with open(SECRETS_FILE, "rb") as f:
                decrypted = self.cipher.decrypt(f.read())
                self._data = json.loads(decrypted.decode())
        except (InvalidToken, json.JSONDecodeError) as e:
            logger.error(f"Secrets file corrupted: {e}")
            self._data = {}
    
    def save(self):
        encrypted = self.cipher.encrypt(json.dumps(self._data).encode())
        with open(SECRETS_FILE, "wb") as f:
            f.write(encrypted)
        os.chmod(SECRETS_FILE, 0o600)
    
    def get(self, key: str, default=None):
        return self._data.get(key, default)
    
    def set(self, key: str, value):
        self._data[key] = value
        self.save()
    
    def delete(self, key: str):
        if key in self._data:
            del self._data[key]
            self.save()
    
    def export_backup(self, path: str, confirm: bool = False):
        """Export plaintext backup (requires user confirmation)."""
        if not confirm:
            raise ValueError("export_backup requires confirm=True to acknowledge security implications")
        logger.warning(f"SECURITY WARNING: Exporting plaintext secrets to {path}")
        with open(path, "w") as f:
            json.dump(self._data, f, indent=2)
        os.chmod(path, 0o600)

    def import_backup(self, path: str):
        """Import from plaintext backup."""
        with open(path, "r") as f:
            self._data = json.load(f)
        self.save()


class SecretsManager:
    """Backward compatibility wrapper for v1 API."""

    def __init__(self, suite_dir: Path):
        self.suite_dir = Path(suite_dir)
        self.secrets_dir = self.suite_dir / "secrets"
        self._ensure_secrets_dir()
        self._fernet = self._load_or_create_master_key()

    def _ensure_secrets_dir(self):
        self.secrets_dir.mkdir(mode=SECRETS_DIR_MODE, parents=True, exist_ok=True)
        os.chmod(self.secrets_dir, SECRETS_DIR_MODE)

    def _load_or_create_master_key(self) -> Fernet:
        key_path = self.secrets_dir / ".master.key"
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
            os.chmod(key_path, SECRET_FILE_MODE)
        return Fernet(key)

    @staticmethod
    def generate_password(length: int = 32, exclude_special: bool = False) -> str:
        if exclude_special:
            alphabet = string.ascii_letters + string.digits
        else:
            special = "!@#%^&*-_=+"
            alphabet = string.ascii_letters + string.digits + special

        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(c in special for c in password) if not exclude_special else True
            if has_upper and has_lower and has_digit and has_special:
                return password

    def write_env_file(self, service_name: str, variables: dict, encrypt: bool = True) -> Path:
        filename = f".env.{service_name}"
        env_path = self.secrets_dir / filename

        lines = [
            f"# Server Suite - {service_name} secrets",
            f"# Generated: {__import__('datetime').datetime.utcnow().isoformat()}",
            f"# DO NOT SHARE OR COMMIT THIS FILE",
            "",
        ]
        for key, value in variables.items():
            safe_value = str(value).replace('"', '\\"')
            lines.append(f'{key}="{safe_value}"')

        content = "\n".join(lines) + "\n"

        if encrypt:
            encrypted = self._fernet.encrypt(content.encode())
            enc_path = self.secrets_dir / f"{filename}.enc"
            enc_path.write_bytes(encrypted)
            os.chmod(enc_path, SECRET_FILE_MODE)
            env_path.write_text(content)
            os.chmod(env_path, SECRET_FILE_MODE)
        else:
            env_path.write_text(content)
            os.chmod(env_path, SECRET_FILE_MODE)

        return env_path

    def read_env_file(self, service_name: str) -> Optional[dict]:
        filename = f".env.{service_name}"
        env_path = self.secrets_dir / filename

        if not env_path.exists():
            return None

        variables = {}
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').replace('\\"', '"')
            variables[key.strip()] = value

        return variables