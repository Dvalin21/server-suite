"""
core/config_manager.py
======================
Persistent configuration management. Single source of truth for all
suite state, decisions, and credentials. All modules read/write through here.
"""

import json
import shutil
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

console = Console()

CONFIG_VERSION = "1.0.0"


class ConfigManager:
    """Manages the suite's config.json — the single source of truth."""

    def __init__(self, suite_dir: Path):
        self.suite_dir = Path(suite_dir)
        self.config_path = self.suite_dir / "config.json"
        self.backup_dir = self.suite_dir / "config_backups"
        self._config: dict = {}
        self._load()

    # -----------------------------------------------------------------------
    # Load / Save
    # -----------------------------------------------------------------------

    def _load(self):
        """Load config from disk, create defaults if not present."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    self._config = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                console.print(f"[yellow]Warning: Failed to load config: {e}. Starting fresh.[/yellow]")
                self._config = self._default_config()
        else:
            self._config = self._default_config()

    def save(self):
        """Atomically write config to disk."""
        self._config["meta"]["last_modified"] = datetime.now(timezone.utc).isoformat()

        # Write to temp file first, then rename (atomic)
        tmp_path = self.config_path.with_suffix(".tmp")
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp_path, "w") as f:
                json.dump(self._config, f, indent=2, default=str)
            tmp_path.replace(self.config_path)
        except IOError as e:
            console.print(f"[red]Failed to save config: {e}[/red]")
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    def backup(self) -> Path:
        """Create a timestamped backup of the current config."""
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"config_{timestamp}.json"
        if self.config_path.exists():
            shutil.copy2(self.config_path, backup_path)
        return backup_path

    # -----------------------------------------------------------------------
    # Get / Set
    # -----------------------------------------------------------------------

    def get(self, key_path: str, default: Any = None) -> Any:
        """Get a value using dot notation. e.g., 'hardware.cpu.cores'"""
        keys = key_path.split(".")
        val = self._config
        for key in keys:
            if isinstance(val, dict):
                val = val.get(key)
                if val is None:
                    return default
            else:
                return default
        return val

    def set(self, key_path: str, value: Any, autosave: bool = True):
        """Set a value using dot notation. e.g., 'setup.roles_selected'"""
        keys = key_path.split(".")
        target = self._config
        for key in keys[:-1]:
            if key not in target or not isinstance(target[key], dict):
                target[key] = {}
            target = target[key]
        target[keys[-1]] = value
        if autosave:
            self.save()

    def update(self, key_path: str, data: dict, autosave: bool = True):
        """Merge a dict into an existing config section."""
        existing = self.get(key_path) or {}
        if isinstance(existing, dict):
            existing.update(data)
            self.set(key_path, existing, autosave=autosave)
        else:
            self.set(key_path, data, autosave=autosave)

    def get_all(self) -> dict:
        return self._config.copy()

    # -----------------------------------------------------------------------
    # Role management
    # -----------------------------------------------------------------------

    def add_role(self, role_name: str, config: Optional[dict] = None):
        """Register an installed role."""
        roles = self.get("roles") or {}
        roles[role_name] = {
            "installed": True,
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "config": config or {}
        }
        self.set("roles", roles)

    def remove_role(self, role_name: str):
        """Unregister a role."""
        roles = self.get("roles") or {}
        roles.pop(role_name, None)
        self.set("roles", roles)

    def get_role(self, role_name: str) -> Optional[dict]:
        return (self.get("roles") or {}).get(role_name)

    def is_role_installed(self, role_name: str) -> bool:
        role = self.get_role(role_name)
        return bool(role and role.get("installed"))

    def get_installed_roles(self) -> list:
        roles = self.get("roles") or {}
        return [name for name, data in roles.items() if data.get("installed")]

    # -----------------------------------------------------------------------
    # Port registry
    # -----------------------------------------------------------------------

    def register_port(self, port: int, service: str, protocol: str = "tcp",
                      external: bool = False, description: str = ""):
        """Register a port assignment."""
        ports = self.get("ports") or {}
        ports[str(port)] = {
            "service": service,
            "protocol": protocol,
            "external": external,
            "description": description
        }
        self.set("ports", ports)

    def is_port_registered(self, port: int) -> bool:
        return str(port) in (self.get("ports") or {})

    def get_port_registry(self) -> dict:
        return self.get("ports") or {}

    # -----------------------------------------------------------------------
    # Docker network registry
    # -----------------------------------------------------------------------

    def register_docker_network(self, name: str, subnet: str, services: list):
        networks = self.get("docker.networks") or {}
        networks[name] = {"subnet": subnet, "services": services}
        self.set("docker.networks", networks)

    def get_docker_networks(self) -> dict:
        return self.get("docker.networks") or {}

    # -----------------------------------------------------------------------
    # Service URL registry
    # -----------------------------------------------------------------------

    def register_service_url(self, service: str, url: str, description: str = ""):
        urls = self.get("service_urls") or {}
        urls[service] = {"url": url, "description": description}
        self.set("service_urls", urls)

    def get_service_urls(self) -> dict:
        return self.get("service_urls") or {}

    # -----------------------------------------------------------------------
    # Credential storage (references only — actual secrets in secrets/ dir)
    # -----------------------------------------------------------------------

    def register_credential(self, service: str, username: str, secret_file: str):
        """Register that credentials exist for a service (store path, not value)."""
        creds = self.get("credentials") or {}
        creds[service] = {
            "username": username,
            "secret_file": secret_file,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        self.set("credentials", creds)

    # -----------------------------------------------------------------------
    # Setup state
    # -----------------------------------------------------------------------

    def mark_setup_complete(self):
        self.set("setup_complete", True)
        self.set("setup_completed_at", datetime.now(timezone.utc).isoformat())

    def is_setup_complete(self) -> bool:
        return self.get("setup_complete", False)

    # -----------------------------------------------------------------------
    # Export / Import
    # -----------------------------------------------------------------------

    def export_config(self, filepath: str):
        """Export config to a file (credentials paths stripped for security)."""
        export_data = self._config.copy()
        # Strip any sensitive data from export
        export_data.pop("credentials", None)
        export_data["meta"]["exported_at"] = datetime.now(timezone.utc).isoformat()
        export_data["meta"]["exported_from"] = self.get("hardware.hostname", "unknown")

        with open(filepath, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        os.chmod(filepath, 0o600)
        console.print(f"[green]Config exported to {filepath}[/green]")

    def import_config(self, filepath: str) -> dict:
        """Import config from a file."""
        with open(filepath) as f:
            imported = json.load(f)

        # Version check
        imported_version = imported.get("meta", {}).get("version")
        if imported_version != CONFIG_VERSION:
            console.print(f"[yellow]Warning: Config version mismatch ({imported_version} vs {CONFIG_VERSION})[/yellow]")

        # Backup existing config
        if self.config_path.exists():
            backup_path = self.backup()
            console.print(f"[dim]Existing config backed up to {backup_path}[/dim]")

        # Merge — don't overwrite hardware info with imported values
        self._config.update(imported)
        self.save()
        return self._config

    # -----------------------------------------------------------------------
    # Default config structure
    # -----------------------------------------------------------------------

    def _default_config(self) -> dict:
        return {
            "meta": {
                "version": CONFIG_VERSION,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_modified": datetime.now(timezone.utc).isoformat(),
                "suite_dir": str(self.suite_dir)
            },
            "setup_complete": False,
            "setup_completed_at": None,
            "dry_run": os.environ.get("DRY_RUN", "0") == "1",

            # Hardware info (populated by HardwareDetector)
            "hardware": {
                "cpu": {},
                "ram": {},
                "disks": [],
                "network": [],
                "hostname": "",
                "os_disk": ""
            },

            # Preflight results
            "preflight": {},

            # Role selection and configuration
            "roles": {},

            # Network/domain configuration
            "network": {
                "domain": "",
                "hostname": "",
                "public_ip": "",
                "lan_ip": "",
                "reverse_proxy": ""  # "npm" or "traefik"
            },

            # Docker configuration
            "docker": {
                "installed": False,
                "version": "",
                "networks": {},
                "compose_dir": "/opt/server-suite/docker"
            },

            # Port registry
            "ports": {},

            # Service URLs (populated as services are installed)
            "service_urls": {},

            # Credential references (paths to secret files)
            "credentials": {},

            # Email / notification config
            "notifications": {
                "email": "",
                "smtp_configured": False
            },

            # Maintenance schedule
            "maintenance": {
                "smart_scan_day": 1,
                "smart_scan_time": "22:00",
                "defrag_time": "22:00",
                "scrub_day": 8,
            },

            # Security baseline
            "security": {
                "ssh_hardened": False,
                "firewall_configured": False,
                "fail2ban_configured": False,
                "apparmor_enabled": False,
                "auditd_configured": False,
                "unattended_upgrades": False
            }
        }
