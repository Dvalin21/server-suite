"""
core/secrets.py
===============
Cryptographically secure secret generation and encrypted .env file management.
No passwords are ever stored in config.json — only references to secret files.
"""

import os
import re
import secrets
import string
import stat
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from rich.console import Console

console = Console()

SECRETS_DIR_MODE = 0o700
SECRET_FILE_MODE = 0o600


class SecretsManager:
    """Manages all generated secrets for services."""

    def __init__(self, suite_dir: Path):
        self.suite_dir = Path(suite_dir)
        self.secrets_dir = self.suite_dir / "secrets"
        self._ensure_secrets_dir()
        self._fernet = self._load_or_create_master_key()

    # -----------------------------------------------------------------------
    # Setup
    # -----------------------------------------------------------------------

    def _ensure_secrets_dir(self):
        self.secrets_dir.mkdir(mode=SECRETS_DIR_MODE, parents=True, exist_ok=True)
        # Ensure permissions are correct even if dir already existed
        os.chmod(self.secrets_dir, SECRETS_DIR_MODE)

    def _load_or_create_master_key(self) -> Fernet:
        """Load or create the master encryption key."""
        key_path = self.secrets_dir / ".master.key"
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
            os.chmod(key_path, SECRET_FILE_MODE)
        return Fernet(key)

    # -----------------------------------------------------------------------
    # Password generation
    # -----------------------------------------------------------------------

    @staticmethod
    def generate_password(length: int = 32, exclude_special: bool = False) -> str:
        """Generate a cryptographically secure password."""
        if exclude_special:
            alphabet = string.ascii_letters + string.digits
        else:
            # Use special chars that are safe in most config files
            special = "!@#%^&*-_=+"
            alphabet = string.ascii_letters + string.digits + special

        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            # Ensure complexity
            has_upper  = any(c.isupper()  for c in password)
            has_lower  = any(c.islower()  for c in password)
            has_digit  = any(c.isdigit()  for c in password)
            has_special = any(c in special for c in password) if not exclude_special else True
            if has_upper and has_lower and has_digit and has_special:
                return password

    @staticmethod
    def generate_token(length: int = 64) -> str:
        """Generate a URL-safe token (for API keys, tokens, etc.)."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_hex_key(length: int = 32) -> str:
        """Generate a hex key (for encryption keys, salts, etc.)."""
        return secrets.token_hex(length)

    # -----------------------------------------------------------------------
    # .env file management
    # -----------------------------------------------------------------------

    def write_env_file(self, service_name: str, variables: dict,
                       encrypt: bool = True) -> Path:
        """
        Write a .env file for a service.
        Variables dict: {"KEY": "value", ...}
        Returns path to the written file.
        """
        filename = f".env.{service_name}"
        env_path = self.secrets_dir / filename

        # Build env content
        lines = [
            f"# Server Suite - {service_name} secrets",
            f"# Generated: {__import__('datetime').datetime.utcnow().isoformat()}",
            f"# DO NOT SHARE OR COMMIT THIS FILE",
            "",
        ]
        for key, value in variables.items():
            # Escape values that contain special characters
            safe_value = str(value).replace('"', '\\"')
            lines.append(f'{key}="{safe_value}"')

        content = "\n".join(lines) + "\n"

        # Write encrypted or plain
        if encrypt:
            encrypted = self._fernet.encrypt(content.encode())
            enc_path = self.secrets_dir / f"{filename}.enc"
            enc_path.write_bytes(encrypted)
            os.chmod(enc_path, SECRET_FILE_MODE)
            # Also write plaintext .env for Docker to read (Docker can't read encrypted)
            env_path.write_text(content)
            os.chmod(env_path, SECRET_FILE_MODE)
        else:
            env_path.write_text(content)
            os.chmod(env_path, SECRET_FILE_MODE)

        return env_path

    def read_env_file(self, service_name: str) -> Optional[dict]:
        """Read and parse a .env file for a service."""
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

    def update_env_file(self, service_name: str, updates: dict):
        """Update specific variables in an existing .env file."""
        existing = self.read_env_file(service_name) or {}
        existing.update(updates)
        self.write_env_file(service_name, existing)

    def delete_env_file(self, service_name: str):
        """Securely delete a service's .env files."""
        for suffix in ["", ".enc"]:
            path = self.secrets_dir / f".env.{service_name}{suffix}"
            if path.exists():
                # Overwrite with zeros before deleting
                size = path.stat().st_size
                path.write_bytes(b'\x00' * size)
                path.unlink()

    # -----------------------------------------------------------------------
    # Service-specific secret generation
    # -----------------------------------------------------------------------

    def generate_service_secrets(self, service: str) -> dict:
        """
        Generate all required secrets for a known service.
        Returns dict of {VAR_NAME: value} and writes the .env file.
        """
        generators = {
            "mailcow":    self._gen_mailcow,
            "nextcloud":  self._gen_nextcloud,
            "matrix":     self._gen_matrix,
            "mariadb":    self._gen_mariadb,
            "postgresql": self._gen_postgresql,
            "redis":      self._gen_redis,
            "wireguard":  self._gen_wireguard,
            "wazuh":      self._gen_wazuh,
            "grafana":    self._gen_grafana,
            "graylog":    self._gen_graylog,
            "mattermost": self._gen_mattermost,
        }

        gen_func = generators.get(service)
        if gen_func:
            secrets_dict = gen_func()
        else:
            # Generic: generate admin password + secret key
            secrets_dict = {
                f"{service.upper()}_ADMIN_PASSWORD": self.generate_password(),
                f"{service.upper()}_SECRET_KEY": self.generate_token(48),
            }

        self.write_env_file(service, secrets_dict)
        return secrets_dict

    def _gen_mailcow(self) -> dict:
        return {
            "DBPASS":            self.generate_password(32, exclude_special=True),
            "DBROOT":            self.generate_password(32, exclude_special=True),
            "MAILCOW_PASS":      self.generate_password(24),
        }

    def _gen_nextcloud(self) -> dict:
        return {
            "NEXTCLOUD_ADMIN_PASSWORD": self.generate_password(24),
            "NEXTCLOUD_DB_PASSWORD":    self.generate_password(32, exclude_special=True),
            "NEXTCLOUD_SECRET":         self.generate_hex_key(32),
        }

    def _gen_matrix(self) -> dict:
        return {
            "MATRIX_REGISTRATION_SECRET": self.generate_token(48),
            "MATRIX_MACAROON_SECRET_KEY": self.generate_token(48),
            "MATRIX_FORM_SECRET":         self.generate_token(32),
            "MATRIX_POSTGRES_PASSWORD":   self.generate_password(32, exclude_special=True),
        }

    def _gen_mariadb(self) -> dict:
        return {
            "MARIADB_ROOT_PASSWORD":   self.generate_password(32, exclude_special=True),
            "MARIADB_ADMIN_PASSWORD":  self.generate_password(24, exclude_special=True),
        }

    def _gen_postgresql(self) -> dict:
        return {
            "POSTGRES_PASSWORD":       self.generate_password(32, exclude_special=True),
            "POSTGRES_ADMIN_PASSWORD": self.generate_password(24, exclude_special=True),
        }

    def _gen_redis(self) -> dict:
        return {
            "REDIS_PASSWORD": self.generate_password(32, exclude_special=True),
        }

    def _gen_wireguard(self) -> dict:
        return {
            "WG_ADMIN_PASSWORD": self.generate_password(24),
            "WG_PEERS_PRESHARED_KEY": self.generate_hex_key(32),
        }

    def _gen_wazuh(self) -> dict:
        return {
            "WAZUH_ADMIN_PASSWORD":    self.generate_password(16),
            "WAZUH_API_PASSWORD":      self.generate_password(16),
            "WAZUH_INDEXER_PASSWORD":  self.generate_password(32, exclude_special=True),
        }

    def _gen_grafana(self) -> dict:
        return {
            "GF_SECURITY_ADMIN_PASSWORD": self.generate_password(24),
            "GF_SECRET_KEY":              self.generate_hex_key(32),
        }

    def _gen_graylog(self) -> dict:
        return {
            "GRAYLOG_PASSWORD_SECRET":  self.generate_hex_key(32),
            "GRAYLOG_ADMIN_PASSWORD":   self.generate_password(24),
            "GRAYLOG_MONGODB_PASSWORD": self.generate_password(32, exclude_special=True),
        }

    def _gen_mattermost(self) -> dict:
        return {
            "MATTERMOST_DB_PASSWORD": self.generate_password(32, exclude_special=True),
            "MATTERMOST_SECRET_KEY":  self.generate_hex_key(32),
        }

    # -----------------------------------------------------------------------
    # Credentials summary (for display in setup UI)
    # -----------------------------------------------------------------------

    def get_credentials_summary(self) -> dict:
        """
        Return all credentials for the final summary page.
        Only called once during setup — summary is then shown to admin.
        """
        summary = {}
        for env_file in self.secrets_dir.glob(".env.*"):
            if env_file.suffix == ".enc":
                continue
            service = env_file.name.replace(".env.", "")
            summary[service] = self.read_env_file(service) or {}
        return summary

    def redact_for_logs(self, data: dict) -> dict:
        """Return a copy of a dict with sensitive values redacted."""
        sensitive_patterns = re.compile(
            r'(password|secret|key|token|pass|credential|auth)',
            re.IGNORECASE
        )
        redacted = {}
        for k, v in data.items():
            if sensitive_patterns.search(k):
                redacted[k] = "***REDACTED***"
            else:
                redacted[k] = v
        return redacted
