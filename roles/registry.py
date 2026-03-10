"""
roles/registry.py
=================
Central registry mapping role IDs to their installer modules.
Used by setup_ui/app.py and management/dashboard.py to dispatch
to the correct installer without hardcoded imports everywhere.
"""

from pathlib import Path
from typing import Optional
from rich.console import Console

console = Console()

# ---------------------------------------------------------------------------
# Role metadata (mirrors setup_ui/app.py ROLES dict but adds installer info)
# ---------------------------------------------------------------------------

ROLE_REGISTRY = {
    "identity": {
        "name":        "Identity & Directory",
        "icon":        "\U0001f3db",
        "description": "FreeIPA (Kerberos+LDAP+CA+DNS) or Samba4 AD DC (Windows GPO/RSAT)",
        "min_ram_mb":  2048,
        "min_cores":   2,
        "module":      "roles.identity",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   ["dns_dhcp"],
        "sub_roles": {
            "freeipa":  ("roles.identity", "Installer"),
            "samba_ad": ("roles.identity", "Installer"),
        },
    },
    "storage": {
        "name":        "Storage & Backup",
        "icon":        "💾",
        "description": "BTRFS RAID, SMART monitoring, BorgBackup, rclone",
        "min_ram_mb":  1024,
        "min_cores":   2,
        "module":      "roles.storage.raid",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   [],
    },
    "web": {
        "name":        "Web / Reverse Proxy",
        "icon":        "🌐",
        "description": "Nginx Proxy Manager or Traefik, OpenLiteSpeed",
        "min_ram_mb":  512,
        "min_cores":   1,
        "module":      "roles.web",
        "installer":   None,  # sub-choice required
        "sub_roles": {
            "npm":           ("roles.web.nginx_npm",    "Installer"),
            "traefik":       ("roles.web.traefik",      "Installer"),
            "openlitespeed": ("roles.web.openlitespeed","Installer"),
        },
        "requires":    [],
        "conflicts":   [],
    },
    "mail": {
        "name":        "Mail Server",
        "icon":        "📧",
        "description": "Mailcow (Postfix+Dovecot+Rspamd+SOGo)",
        "min_ram_mb":  3072,
        "min_cores":   2,
        "module":      "roles.mail.mailcow",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   [],
    },
    "dns_dhcp": {
        "name":        "DNS & DHCP",
        "icon":        "🔍",
        "description": "Technitium DNS + DHCP server",
        "min_ram_mb":  512,
        "min_cores":   1,
        "module":      "roles.dns_dhcp.technitium",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   [],
    },
    "database": {
        "name":        "Database",
        "icon":        "🗄️",
        "description": "MariaDB, PostgreSQL, Redis, Adminer",
        "min_ram_mb":  1024,
        "min_cores":   2,
        "module":      "roles.database.installer",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   [],
    },
    "files": {
        "name":        "Files & Collaboration",
        "icon":        "📁",
        "description": "Nextcloud, Collabora, Samba, NFS, Syncthing",
        "min_ram_mb":  2048,
        "min_cores":   2,
        "module":      "roles.files.installer",
        "installer":   "Installer",
        "requires":    ["database"],
        "conflicts":   [],
    },
    "comms": {
        "name":        "Communications",
        "icon":        "💬",
        "description": "Matrix/Synapse+Element, Mattermost, Mumble",
        "min_ram_mb":  2048,
        "min_cores":   2,
        "module":      "roles.comms.installer",
        "installer":   "Installer",
        "requires":    ["database"],
        "conflicts":   [],
    },
    "vpn": {
        "name":        "VPN",
        "icon":        "🔒",
        "description": "WireGuard (wg-easy) with peer management",
        "min_ram_mb":  256,
        "min_cores":   1,
        "module":      "roles.vpn.wireguard",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   [],
    },
    "security": {
        "name":        "Security Monitoring",
        "icon":        "🛡️",
        "description": "Wazuh SIEM (server or agent mode)",
        "min_ram_mb":  4096,
        "min_cores":   2,
        "module":      "roles.security.wazuh",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   [],
    },
    "logging": {
        "name":        "Logging & Metrics",
        "icon":        "📊",
        "description": "Grafana+Prometheus+Loki  or  Graylog",
        "min_ram_mb":  1024,
        "min_cores":   2,
        "module":      "roles.logging.installer",
        "installer":   "Installer",
        "requires":    [],
        "conflicts":   [],
    },
}


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

class RoleDispatcher:
    """Loads and runs role installers by role ID."""

    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install_role(self, role_id: str, config: dict,
                     sub_role: Optional[str] = None) -> bool:
        """
        Install a role. For roles with sub_roles (like 'web'),
        pass sub_role='npm' or sub_role='traefik'.
        """
        role_meta = ROLE_REGISTRY.get(role_id)
        if not role_meta:
            console.print(f"[red]Unknown role: {role_id}[/red]")
            return False

        # Check dependencies
        missing_deps = self._check_dependencies(role_id, config)
        if missing_deps:
            console.print(f"[yellow]⚠ {role_id} requires these roles to be installed first: "
                         f"{missing_deps}[/yellow]")
            # Don't hard-fail — services may already be running externally

        # Determine module + class
        if role_meta.get("sub_roles"):
            if not sub_role:
                sub_role = self._prompt_sub_role(role_id, role_meta)
            sub_roles = role_meta["sub_roles"]
            if sub_role not in sub_roles:
                console.print(f"[red]Unknown sub-role '{sub_role}' for {role_id}[/red]")
                return False
            module_path, class_name = sub_roles[sub_role]
        else:
            module_path = role_meta["module"]
            class_name  = role_meta["installer"]

        # Dynamic import
        try:
            import importlib
            module    = importlib.import_module(module_path)
            installer = getattr(module, class_name)
        except (ImportError, AttributeError) as e:
            console.print(f"[red]Failed to load installer for {role_id}: {e}[/red]")
            return False

        # Instantiate and run
        try:
            instance = installer(
                config_manager=self.cm,
                secrets_manager=self.sm,
                suite_dir=self.suite_dir
            )
            return instance.install(config)
        except Exception as e:
            console.print(f"[red]Installation error ({role_id}): {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            return False

    def get_ram_requirements(self, role_ids: list) -> int:
        """Sum the minimum RAM for a set of roles."""
        return sum(
            ROLE_REGISTRY.get(rid, {}).get("min_ram_mb", 0)
            for rid in role_ids
        )

    def _check_dependencies(self, role_id: str, config: dict) -> list:
        """Return list of missing required roles."""
        requires    = ROLE_REGISTRY.get(role_id, {}).get("requires", [])
        installed   = set(config.get("roles", {}).keys())
        return [r for r in requires if r not in installed]

    def _prompt_sub_role(self, role_id: str, role_meta: dict) -> str:
        """Prompt user to pick a sub-role."""
        from rich.prompt import Prompt
        sub_roles = role_meta["sub_roles"]
        console.print(f"\n  [bold]{role_meta['name']} — choose engine:[/bold]")
        options = list(sub_roles.keys())
        for i, key in enumerate(options, 1):
            console.print(f"    {i}. {key}")
        choice = Prompt.ask("  Select", choices=[str(i) for i in range(1, len(options) + 1)])
        return options[int(choice) - 1]


# ---------------------------------------------------------------------------
# Resource summary for setup UI
# ---------------------------------------------------------------------------

def get_role_resource_summary() -> dict:
    """Return role resource requirements for the setup UI RAM/CPU meter."""
    return {
        role_id: {
            "min_ram_mb": meta["min_ram_mb"],
            "min_cores":  meta["min_cores"],
        }
        for role_id, meta in ROLE_REGISTRY.items()
    }
