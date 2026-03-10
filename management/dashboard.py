"""
management/dashboard.py
=======================
Post-install management menu. Shown when server-suite is run
on an already-configured server. Handles add roles, status,
update, and re-run maintenance tasks.
"""

import os
import subprocess
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.columns import Columns
from rich import print as rprint

console = Console()


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class ManagementMenu:
    """Main management interface for a configured server."""

    def __init__(self, config: dict, suite_dir: Path):
        self.config    = config
        self.suite_dir = Path(suite_dir)

    def run(self):
        while True:
            self._print_status_bar()
            choice = self._show_menu()
            if choice is None or choice == "exit":
                break
            self._handle_choice(choice)

    def _print_status_bar(self):
        """Print a concise server status summary at the top."""
        from core.config_manager import ConfigManager
        cm = ConfigManager(self.suite_dir)

        hostname = cm.get("hardware.hostname") or "unknown"
        roles    = cm.get_installed_roles()
        setup_at = cm.get("setup_completed_at", "unknown")

        console.print()
        console.print(Panel(
            f"[bold cyan]Server Suite — Management Console[/bold cyan]\n"
            f"[dim]Host:[/dim] [white]{hostname}[/white]   "
            f"[dim]Roles:[/dim] [white]{len(roles)} installed[/white]   "
            f"[dim]Setup completed:[/dim] [white]{str(setup_at)[:10]}[/white]",
            border_style="cyan",
            padding=(0, 2)
        ))
        console.print()

    def _show_menu(self) -> str:
        options = {
            "1": ("📊", "Service Status",        "View all service health and URLs"),
            "2": ("➕", "Add Role",               "Install additional server roles"),
            "3": ("🔄", "Update Services",        "Pull latest Docker images / update packages"),
            "4": ("🛡️", "Security Audit",         "Run Lynis security audit"),
            "5": ("🔧", "Run Maintenance",        "Trigger SMART scan, defrag, or health check"),
            "6": ("📧", "Test Email",             "Send a test notification email"),
            "7": ("💾", "Export Config",          "Export configuration to file"),
            "8": ("🔑", "View Credentials",       "Show stored service credentials"),
            "9": ("🚫", "Uninstall Suite",        "Remove Server Suite (data preserved)"),
            "i": ("🏛️",  "Identity / FreeIPA",    "Manage users, groups, HBAC, DNS, certs"),
            "r": ("🔁",  "IPA Replica",            "Set up or check FreeIPA replica"),
            "0": ("↩️",  "Exit",                  "Return to terminal"),
        }

        table = Table(show_header=False, box=None, padding=(0, 2))
        for key, (icon, name, desc) in options.items():
            table.add_row(
                f"  [bold cyan]{key}[/bold cyan]",
                f"{icon}  [bold]{name}[/bold]",
                f"[dim]{desc}[/dim]"
            )
        console.print(table)
        console.print()

        valid = list(options.keys())
        choice = Prompt.ask(
            "  Select option",
            choices=valid,
            default="0"
        )
        return choice

    def _handle_choice(self, choice: str):
        handlers = {
            "1": self._show_service_status,
            "2": self._add_role,
            "3": self._update_services,
            "4": self._run_security_audit,
            "5": self._run_maintenance,
            "6": self._test_email,
            "7": self._export_config,
            "8": self._view_credentials,
            "9": self._uninstall,
            "i": self._freeipa_management,
            "r": self._freeipa_replica,
            "0": lambda: None,
        }
        fn = handlers.get(choice)
        if fn:
            fn()

    def _show_service_status(self):
        console.print("\n[bold cyan]Service Status[/bold cyan]\n")

        # Systemd timers
        timer_table = Table("Timer", "Status", "Next Run", show_header=True,
                            header_style="bold magenta", border_style="dim")

        rc, out, _ = _run(["systemctl", "list-timers", "--all", "server-suite-*",
                           "--no-legend", "--no-pager"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 8:
                    next_run = " ".join(parts[:3])
                    unit     = parts[7] if len(parts) > 7 else "—"
                    status   = "[green]active[/green]"
                    timer_table.add_row(unit, status, next_run)
        console.print(timer_table)

        # Docker containers
        console.print()
        rc, out, _ = _run(["docker", "ps", "--format",
                           "table {{.Names}}\t{{.Status}}\t{{.Ports}}"])
        if rc == 0 and out:
            console.print("[bold]Docker Containers:[/bold]")
            console.print(out)

        # Service URLs
        from core.config_manager import ConfigManager
        cm = ConfigManager(self.suite_dir)
        urls = cm.get_service_urls()
        if urls:
            console.print()
            url_table = Table("Service", "URL", show_header=True,
                             header_style="bold magenta", border_style="dim")
            for svc, data in urls.items():
                url_table.add_row(svc, f"[cyan]{data.get('url', '—')}[/cyan]")
            console.print(url_table)

        Prompt.ask("\n  Press Enter to continue", default="")

    def _add_role(self):
        console.print("\n[bold cyan]Add Server Role[/bold cyan]")
        console.print("[dim]This will install an additional role on this server.[/dim]\n")

        from setup_ui.app import ROLES, get_local_ip
        from core.config_manager import ConfigManager
        from core.firewall import FirewallManager

        cm = ConfigManager(self.suite_dir)
        installed = set(cm.get_installed_roles())

        available = {k: v for k, v in ROLES.items() if k not in installed}
        if not available:
            console.print("[yellow]All available roles are already installed.[/yellow]")
            Prompt.ask("\n  Press Enter to continue", default="")
            return

        for key, role in available.items():
            console.print(f"  [cyan]{key:15}[/cyan] {role['icon']}  {role['name']} — {role['description'][:60]}")

        console.print()
        choice = Prompt.ask("  Enter role ID to install (or 'cancel')", default="cancel")
        if choice == "cancel" or choice not in available:
            return

        if Confirm.ask(f"  Install {available[choice]['name']}?", default=True):
            console.print(f"\n[cyan]Installing {available[choice]['name']}...[/cyan]")
            # Re-use the setup UI installer
            from setup_ui.app import _install_role
            from core.secrets import SecretsManager
            sm = SecretsManager(self.suite_dir)
            config = cm.get_all()
            success = _install_role(choice, config, cm, sm)
            if success:
                fw = FirewallManager()
                fw.add_role_rules(choice)
                fw.reload()
                console.print(f"[green]{available[choice]['name']} installed ✓[/green]")
            else:
                console.print(f"[red]Installation failed — check /var/log/server-suite/install.log[/red]")

        Prompt.ask("\n  Press Enter to continue", default="")

    def _update_services(self):
        console.print("\n[bold cyan]Updating Services[/bold cyan]\n")

        if Confirm.ask("  Pull latest Docker images for all services?", default=True):
            rc, out, err = _run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                               timeout=10)
            if rc == 0:
                images = [i for i in out.splitlines() if not i.endswith(":latest")]
                for image in images:
                    console.print(f"  [dim]Pulling {image}...[/dim]")
                    _run(["docker", "pull", image], timeout=300)
            console.print("[green]Docker images updated ✓[/green]")

        if Confirm.ask("  Run apt security updates?", default=True):
            _run(["apt-get", "update", "-qq"])
            rc, out, _ = _run(["apt-get", "-s", "upgrade"], timeout=60)
            if "0 upgraded" not in out:
                _run(["apt-get", "upgrade", "-y", "-qq"], timeout=600)
                console.print("[green]System packages updated ✓[/green]")
            else:
                console.print("[dim]System packages already up to date[/dim]")

        Prompt.ask("\n  Press Enter to continue", default="")

    def _run_security_audit(self):
        console.print("\n[bold cyan]Running Lynis Security Audit[/bold cyan]")
        console.print("[dim]This may take a few minutes...[/dim]\n")

        _run(["apt-get", "install", "-y", "-qq", "lynis"])
        rc, out, _ = _run(
            ["lynis", "audit", "system", "--quiet"],
            timeout=600
        )
        console.print(out[-3000:] if len(out) > 3000 else out)
        console.print(f"\n[dim]Full report: /var/log/lynis.log[/dim]")
        Prompt.ask("\n  Press Enter to continue", default="")

    def _run_maintenance(self):
        console.print("\n[bold cyan]Run Maintenance Task[/bold cyan]\n")
        options = {
            "1": ("SMART long scan",    "/opt/server-suite/scripts/smart-scan.sh"),
            "2": ("BTRFS defrag",       "/opt/server-suite/scripts/btrfs-defrag.sh"),
            "3": ("BTRFS scrub",        "/opt/server-suite/scripts/btrfs-scrub.sh"),
            "4": ("Health check",       "/opt/server-suite/scripts/health-check.sh"),
        }
        for k, (name, _) in options.items():
            console.print(f"  [cyan]{k}[/cyan]  {name}")

        choice = Prompt.ask("\n  Select task", choices=list(options.keys()),
                           default="4")
        name, script = options[choice]

        if Confirm.ask(f"\n  Run {name} now?", default=True):
            console.print(f"\n[cyan]Running {name}...[/cyan]")
            rc, out, err = _run(["bash", script], timeout=86400)
            if rc == 0:
                console.print(f"[green]{name} completed ✓[/green]")
            else:
                console.print(f"[yellow]{name} completed with warnings (exit {rc})[/yellow]")
            if out:
                console.print(f"\n[dim]{out[-2000:]}[/dim]")

        Prompt.ask("\n  Press Enter to continue", default="")

    def _test_email(self):
        from core.config_manager import ConfigManager
        from core.notifications import NotificationManager

        cm = ConfigManager(self.suite_dir)
        email = cm.get("notifications.email") or ""
        nm    = NotificationManager(self.suite_dir)

        target = Prompt.ask("  Send test email to", default=email)
        if nm.send_test_email(target):
            console.print(f"[green]Test email sent to {target} ✓[/green]")
        else:
            console.print("[red]Failed to send test email — check SMTP configuration[/red]")

        Prompt.ask("\n  Press Enter to continue", default="")

    def _export_config(self):
        from core.config_manager import ConfigManager
        cm = ConfigManager(self.suite_dir)

        filepath = Prompt.ask(
            "  Export path",
            default=f"/root/server-suite-config-export.json"
        )
        cm.export_config(filepath)
        console.print(f"[green]Config exported to {filepath} ✓[/green]")
        Prompt.ask("\n  Press Enter to continue", default="")

    def _view_credentials(self):
        from core.secrets import SecretsManager
        sm = SecretsManager(self.suite_dir)
        summary = sm.get_credentials_summary()

        if not summary:
            console.print("[yellow]No stored credentials found.[/yellow]")
            Prompt.ask("\n  Press Enter to continue", default="")
            return

        for service, creds in summary.items():
            cred_table = Table(show_header=False, box=None, padding=(0, 2))
            for k, v in creds.items():
                if k.startswith("#") or not k.strip():
                    continue
                cred_table.add_row(f"[dim]{k}[/dim]", f"[cyan]{v}[/cyan]")
            console.print(Panel(cred_table, title=f"[bold]{service}[/bold]",
                               border_style="dim"))

        console.print()
        console.print(f"[dim]Credentials stored at: {self.suite_dir / 'secrets'}[/dim]")
        Prompt.ask("\n  Press Enter to continue", default="")

    def _uninstall(self):
        from management.uninstall import Uninstaller
        u = Uninstaller(self.config, suite_dir=self.suite_dir)
        u.run()


    def _freeipa_management(self):
        """Launch the identity management menu (FreeIPA or Samba AD)."""
        from core.config_manager import ConfigManager
        cm = ConfigManager(self.suite_dir)
        identity_cfg = cm.get("roles.identity")
        if not identity_cfg:
            console.print("\n[yellow]Identity role is not installed on this server.[/yellow]")
            Prompt.ask("\n  Press Enter to continue", default="")
            return
        engine = identity_cfg.get("engine", "freeipa")
        if engine == "samba_ad":
            from roles.identity.samba_management import SambaADManager
            mgr = SambaADManager(suite_dir=self.suite_dir, config_manager=cm)
        else:
            from roles.identity.management import FreeIPAManager
            mgr = FreeIPAManager(suite_dir=self.suite_dir, config_manager=cm)
        mgr.run()

    def _freeipa_replica(self):
        """Set up or check FreeIPA replica (FreeIPA only)."""
        from core.config_manager import ConfigManager
        from core.secrets import SecretsManager
        cm = ConfigManager(self.suite_dir)
        sm = SecretsManager(self.suite_dir)
        identity_cfg = cm.get("roles.identity")
        if not identity_cfg:
            console.print("\n[yellow]Identity role is not installed on this server.[/yellow]")
            Prompt.ask("\n  Press Enter to continue", default="")
            return
        if identity_cfg.get("engine") == "samba_ad":
            console.print("\n[yellow]Replica setup is only available for FreeIPA.\nFor Samba AD, use 'samba-tool domain join' on additional DCs.[/yellow]")
            Prompt.ask("\n  Press Enter to continue", default="")
            return
        from roles.identity.replica import FreeIPAReplicaManager
        replica_mgr = FreeIPAReplicaManager(
            suite_dir=self.suite_dir,
            config_manager=cm,
            secrets_manager=sm,
        )
        console.print("\n[bold]FreeIPA Replica[/bold]")
        console.print("  1. Set up new replica")
        console.print("  2. Check replication status")
        console.print("  0. Back")
        choice = Prompt.ask("  Select", choices=["1", "2", "0"], default="0")
        if choice == "1":
            config = cm.get_all()
            replica_mgr.setup_replica(config)
        elif choice == "2":
            replica_mgr.check_replication_status()
        Prompt.ask("\n  Press Enter to continue", default="")


class StatusDisplay:
    """Quick status display for --status flag."""

    def __init__(self, config: dict):
        self.config = config

    def show(self):
        console.print("\n[bold cyan]Server Suite — Status[/bold cyan]\n")
        rc, out, _ = _run(["systemctl", "list-timers", "server-suite-*",
                           "--no-legend", "--no-pager"])
        if rc == 0:
            console.print("[bold]Active Timers:[/bold]")
            console.print(out or "  No timers active")
        console.print()
        rc, out, _ = _run(["docker", "ps", "--format",
                           "table {{.Names}}\t{{.Status}}"])
        if rc == 0 and out:
            console.print("[bold]Docker Containers:[/bold]")
            console.print(out)
