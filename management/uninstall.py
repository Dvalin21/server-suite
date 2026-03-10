"""
management/uninstall.py
=======================
Clean uninstall of Server Suite. Removes systemd units, Docker stacks,
firewall rules, and suite files. Never touches user data or RAID arrays.
"""

import os
import subprocess
import shutil
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel

console = Console()


def _run(cmd: list, timeout: int = 60) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class Uninstaller:
    """Safely removes Server Suite components."""

    def __init__(self, config: dict, suite_dir: Path):
        self.config    = config
        self.suite_dir = Path(suite_dir)

    def run(self):
        console.print()
        console.print(Panel(
            "[bold red]Uninstall Server Suite[/bold red]\n\n"
            "[yellow]This will remove:[/yellow]\n"
            "  • All systemd timers and service units\n"
            "  • All Docker containers and networks (images kept)\n"
            "  • UFW rules added by Server Suite\n"
            "  • Suite files in /opt/server-suite\n\n"
            "[green]This will NOT remove:[/green]\n"
            "  • Your BTRFS RAID array or any data\n"
            "  • fstab entries (RAID mount preserved)\n"
            "  • SSH keys or user accounts\n"
            "  • Docker itself\n"
            "  • System packages installed as dependencies",
            border_style="red",
            padding=(1, 2)
        ))

        if not Confirm.ask("\n  [bold red]Are you sure you want to uninstall?[/bold red]",
                          default=False):
            console.print("[dim]Uninstall cancelled.[/dim]")
            return

        if not Confirm.ask("  [red]Final confirmation — this cannot be undone[/red]",
                          default=False):
            console.print("[dim]Uninstall cancelled.[/dim]")
            return

        console.print()
        self._stop_timers()
        self._stop_docker_stacks()
        self._remove_systemd_units()
        self._remove_firewall_rules()
        self._remove_suite_files()
        self._remove_logrotate()

        console.print()
        console.print("[bold green]Server Suite uninstalled.[/bold green]")
        console.print("[dim]Your data, RAID array, and fstab entries are untouched.[/dim]")
        console.print("[dim]To reinstall, run the install.sh script again.[/dim]")

    def _stop_timers(self):
        console.print("[cyan]Stopping systemd timers...[/cyan]")
        rc, out, _ = _run(["systemctl", "list-units", "--all",
                           "server-suite-*", "--no-legend", "--no-pager"])
        if rc == 0:
            for line in out.splitlines():
                unit = line.split()[0] if line.split() else ""
                if unit:
                    _run(["systemctl", "stop",    unit])
                    _run(["systemctl", "disable", unit])
        console.print("  [dim]Timers stopped ✓[/dim]")

    def _stop_docker_stacks(self):
        console.print("[cyan]Stopping Docker stacks...[/cyan]")
        docker_dirs = (self.suite_dir / "docker").glob("*/docker-compose.yml")
        for compose_file in docker_dirs:
            console.print(f"  [dim]Stopping {compose_file.parent.name}...[/dim]")
            _run(["docker", "compose", "-f", str(compose_file), "down"], timeout=120)

        # Remove suite Docker networks
        rc, out, _ = _run(["docker", "network", "ls", "--format", "{{.Name}}"])
        if rc == 0:
            suite_networks = [n for n in out.splitlines()
                             if any(n.startswith(p) for p in
                                   ["proxy_network", "db_network", "mail_network",
                                    "identity_network", "monitor_network", "storage_network",
                                    "comms_network", "vpn_network", "logging_network"])]
            for net in suite_networks:
                _run(["docker", "network", "rm", net])
        console.print("  [dim]Docker stacks stopped ✓[/dim]")

    def _remove_systemd_units(self):
        console.print("[cyan]Removing systemd units...[/cyan]")
        systemd_dir = Path("/etc/systemd/system")
        for unit_file in systemd_dir.glob("server-suite-*"):
            unit_file.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        console.print("  [dim]Systemd units removed ✓[/dim]")

    def _remove_firewall_rules(self):
        console.print("[cyan]Removing firewall rules...[/cyan]")
        # Remove rules added for suite ports
        suite_ports = [7070, 9090, 51820, 1194, 8448, 3478, 10000]
        for port in suite_ports:
            _run(["ufw", "delete", "allow", f"{port}/tcp"])
            _run(["ufw", "delete", "allow", f"{port}/udp"])
        _run(["ufw", "reload"])
        console.print("  [dim]Firewall rules cleaned ✓[/dim]")

    def _remove_suite_files(self):
        console.print("[cyan]Removing suite files...[/cyan]")

        # Remove symlink
        symlink = Path("/usr/local/bin/server-suite")
        if symlink.exists() or symlink.is_symlink():
            symlink.unlink()

        # Remove suite directory (preserve secrets as backup)
        secrets_backup = Path("/root/server-suite-secrets-backup")
        secrets_src = self.suite_dir / "secrets"
        if secrets_src.exists():
            shutil.copytree(str(secrets_src), str(secrets_backup), dirs_exist_ok=True)
            console.print(f"  [yellow]Credentials backed up to: {secrets_backup}[/yellow]")

        if self.suite_dir.exists():
            shutil.rmtree(str(self.suite_dir))
        console.print("  [dim]Suite files removed ✓[/dim]")

    def _remove_logrotate(self):
        Path("/etc/logrotate.d/server-suite").unlink(missing_ok=True)
        console.print("  [dim]Logrotate config removed ✓[/dim]")
