"""
Encrypted secrets storage using Fernet (AES-128-CBC with HMAC).
"""
import os
import json
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
import logging

logger = logging.getLogger(__name__)

SECRETS_FILE = "/opt/server-suite/secrets.enc"
KEY_FILE = "/opt/server-suite/.master.key"

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