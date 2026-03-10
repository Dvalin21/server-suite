"""
base/ssh_hardening.py
=====================
Production SSH hardening. Disables insecure defaults,
enforces key authentication, and optionally changes the port.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_BACKUP = Path("/etc/ssh/sshd_config.server-suite.bak")

HARDENED_SETTINGS = {
    # Authentication
    "PermitRootLogin":             "no",
    "PasswordAuthentication":      "no",
    "PubkeyAuthentication":        "yes",
    "AuthenticationMethods":       "publickey",
    "PermitEmptyPasswords":        "no",
    "ChallengeResponseAuthentication": "no",
    "KerberosAuthentication":      "no",
    "GSSAPIAuthentication":        "no",
    "UsePAM":                      "yes",
    # Connection limits
    "MaxAuthTries":                "3",
    "MaxSessions":                 "10",
    "LoginGraceTime":              "30",
    "ClientAliveInterval":         "300",
    "ClientAliveCountMax":         "2",
    # Network
    "X11Forwarding":               "no",
    "AllowTcpForwarding":          "yes",
    "AllowAgentForwarding":        "yes",
    "PermitTunnel":                "no",
    "TCPKeepAlive":                "yes",
    # Security
    "StrictModes":                 "yes",
    "UsePrivilegeSeparation":      "sandbox",
    "Compression":                 "delayed",
    "PrintLastLog":                "yes",
    "PrintMotd":                   "no",
    # Logging
    "SyslogFacility":              "AUTH",
    "LogLevel":                    "VERBOSE",
    # Banners
    "Banner":                      "/etc/ssh/banner",
}


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class SSHHardener:
    """Hardens the SSH daemon configuration."""

    def harden(self, custom_port: int = 22, allow_password_auth: bool = False) -> bool:
        """
        Apply SSH hardening.

        Args:
            custom_port: SSH port (22 = keep default)
            allow_password_auth: Allow password auth temporarily (for initial setup)
        """
        console.print("\n[cyan]Hardening SSH configuration...[/cyan]")

        if not SSHD_CONFIG.exists():
            console.print("[red]sshd_config not found — is OpenSSH installed?[/red]")
            return False

        # Backup original
        if not SSHD_BACKUP.exists():
            shutil.copy2(SSHD_CONFIG, SSHD_BACKUP)
            console.print(f"  [dim]Backup saved: {SSHD_BACKUP}[/dim]")

        settings = HARDENED_SETTINGS.copy()

        # Port
        if custom_port != 22:
            settings["Port"] = str(custom_port)
            console.print(f"  [yellow]SSH port will be changed to {custom_port}[/yellow]")
            console.print(f"  [yellow]Update your SSH client to use: ssh -p {custom_port} user@server[/yellow]")

        # Allow password auth if requested (can tighten later)
        if allow_password_auth:
            settings["PasswordAuthentication"] = "yes"
            settings["AuthenticationMethods"] = "publickey,password"
            console.print("  [yellow]Password authentication temporarily enabled — disable after adding SSH keys[/yellow]")

        self._write_hardened_config(settings)
        self._write_banner()
        self._configure_moduli()

        # Validate config
        rc, _, err = _run(["sshd", "-t"])
        if rc != 0:
            console.print(f"[red]sshd config validation failed: {err}[/red]")
            console.print("[yellow]Restoring backup...[/yellow]")
            if SSHD_BACKUP.exists():
                shutil.copy2(SSHD_BACKUP, SSHD_CONFIG)
            return False

        # Reload sshd
        rc, _, err = _run(["systemctl", "reload", "sshd"])
        if rc != 0:
            console.print(f"[yellow]sshd reload failed, trying restart: {err}[/yellow]")
            rc, _, err = _run(["systemctl", "restart", "sshd"])
            if rc != 0:
                console.print(f"[red]sshd restart failed: {err}[/red]")
                return False

        console.print("[green]SSH hardened ✓[/green]")
        console.print("  [dim]Root login: disabled[/dim]")
        console.print("  [dim]Password auth: " + ("enabled (temporary)" if allow_password_auth else "disabled") + "[/dim]")
        console.print("  [dim]Max auth tries: 3[/dim]")
        console.print("  [dim]Logging: VERBOSE to AUTH facility[/dim]")
        return True

    def _write_hardened_config(self, settings: dict):
        """Write the hardened sshd_config."""
        if DRY_RUN:
            console.print("  [dim][DRY RUN] Would write hardened sshd_config[/dim]")
            return

        original = SSHD_CONFIG.read_text()
        lines = original.splitlines()
        new_lines = []
        applied = set()

        for line in lines:
            stripped = line.strip()
            # Skip empty lines and comments that we'll manage
            if stripped.startswith("#") or not stripped:
                new_lines.append(line)
                continue

            # Extract the key
            parts = stripped.split(None, 1)
            if not parts:
                new_lines.append(line)
                continue

            key = parts[0]
            if key in settings:
                new_lines.append(f"{key} {settings[key]}")
                applied.add(key)
            else:
                new_lines.append(line)

        # Add settings not found in original
        missing = set(settings.keys()) - applied
        if missing:
            new_lines.append("")
            new_lines.append("# Server Suite hardened settings")
            new_lines.append(f"# Applied: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            for key in sorted(missing):
                new_lines.append(f"{key} {settings[key]}")

        SSHD_CONFIG.write_text("\n".join(new_lines) + "\n")
        os.chmod(SSHD_CONFIG, 0o600)

    def _write_banner(self):
        """Write an SSH login banner."""
        banner_path = Path("/etc/ssh/banner")
        banner_content = """
╔══════════════════════════════════════════════════════════════╗
║          AUTHORIZED ACCESS ONLY — MONITORED SYSTEM          ║
║                                                              ║
║  All connections are logged and monitored. Unauthorized      ║
║  access is prohibited and will be prosecuted to the full     ║
║  extent of applicable law.                                   ║
╚══════════════════════════════════════════════════════════════╝
"""
        if not DRY_RUN:
            banner_path.write_text(banner_content)

    def _configure_moduli(self):
        """Remove weak DH moduli (< 3071 bits)."""
        moduli_path = Path("/etc/ssh/moduli")
        if not moduli_path.exists():
            return

        if DRY_RUN:
            console.print("  [dim][DRY RUN] Would remove weak DH moduli[/dim]")
            return

        try:
            lines = moduli_path.read_text().splitlines()
            strong = [l for l in lines if l.startswith("#") or (
                len(l.split()) >= 5 and int(l.split()[4]) >= 3071
            )]
            if len(strong) < len(lines):
                moduli_path.write_text("\n".join(strong) + "\n")
                removed = len(lines) - len(strong)
                console.print(f"  [dim]Removed {removed} weak DH moduli[/dim]")
        except (ValueError, IndexError):
            pass

    def verify_key_auth_ready(self) -> bool:
        """
        Check if any SSH keys are configured before disabling password auth.
        Returns False if no keys found — prevents lockout.
        """
        authorized_keys_paths = [
            Path("/root/.ssh/authorized_keys"),
            *Path("/home").glob("*/.ssh/authorized_keys"),
        ]
        for path in authorized_keys_paths:
            if path.exists() and path.stat().st_size > 0:
                return True
        return False

    def add_authorized_key(self, username: str, public_key: str) -> bool:
        """Add an SSH public key for a user."""
        if username == "root":
            ssh_dir = Path("/root/.ssh")
        else:
            rc, home, _ = _run(["getent", "passwd", username])
            if rc != 0:
                return False
            home_dir = Path(home.split(":")[5])
            ssh_dir = home_dir / ".ssh"

        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        auth_keys = ssh_dir / "authorized_keys"

        # Don't add duplicates
        if auth_keys.exists():
            existing = auth_keys.read_text()
            if public_key.strip() in existing:
                return True

        with open(auth_keys, "a") as f:
            f.write(public_key.strip() + "\n")

        os.chmod(auth_keys, 0o600)
        _run(["chown", "-R", f"{username}:{username}", str(ssh_dir)])
        return True
