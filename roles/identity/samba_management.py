"""
roles/identity/samba_management.py
===================================
Day-to-day Samba AD management: users, groups, computers,
GPO listing, DNS records, and password policy.
Accessible from the management dashboard via the 'i' option
when samba_ad engine is configured.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

console = Console()


def _run(cmd: list, timeout: int = 30, input_data: str = None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=input_data
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class SambaADManager:
    """Interactive management menu for Samba AD."""

    def __init__(self, suite_dir: Path, config_manager=None):
        self.suite_dir = Path(suite_dir)
        self.cm = config_manager

    def run(self):
        cfg = self._load_config()
        if not cfg:
            console.print("[red]Samba AD not configured on this server.[/red]")
            return

        while True:
            self._print_header(cfg)
            choice = self._show_menu()
            if choice == "0":
                break
            self._handle(choice, cfg)

    def _print_header(self, cfg: dict):
        console.print()
        console.print(Panel(
            f"[bold cyan]Samba AD Management[/bold cyan]  "
            f"[dim]Domain: {cfg.get('netbios', '?')}  |  "
            f"Realm: {cfg.get('realm', '?')}[/dim]",
            border_style="cyan", padding=(0, 2),
        ))

    def _show_menu(self) -> str:
        items = {
            "1": "👤  User management     (add/list/disable/reset password)",
            "2": "👥  Group management    (add/list/members)",
            "3": "🖥️   Computer accounts   (list/delete)",
            "4": "📋  GPO listing         (list Group Policy Objects)",
            "5": "🌐  DNS records         (add/list A, CNAME, TXT)",
            "6": "🔑  Password policy     (view/update)",
            "7": "📊  Domain info         (DC status, functional level)",
            "8": "🔄  Sync test           (verify replication)",
            "0": "↩️   Back",
        }
        for k, v in items.items():
            console.print(f"  [{'cyan' if k != '0' else 'dim'}]{k}[/] {v}")
        console.print()
        return Prompt.ask("  Select", choices=list(items.keys()), default="0")

    def _handle(self, choice: str, cfg: dict):
        handlers = {
            "1": self._user_management,
            "2": self._group_management,
            "3": self._computer_management,
            "4": self._gpo_listing,
            "5": self._dns_management,
            "6": self._password_policy,
            "7": self._domain_info,
            "8": self._sync_test,
        }
        fn = handlers.get(choice)
        if fn:
            fn(cfg)

    # -----------------------------------------------------------------------
    # Users
    # -----------------------------------------------------------------------

    def _user_management(self, cfg: dict):
        console.print("\n[bold]User Management[/bold]")
        sub = Prompt.ask(
            "  Action", default="list",
            choices=["add", "list", "show", "disable", "enable",
                     "reset-password", "delete"]
        )

        if sub == "add":
            username  = Prompt.ask("  Username (sAMAccountName)")
            firstname = Prompt.ask("  First name")
            lastname  = Prompt.ask("  Last name")
            password  = Prompt.ask("  Password", password=True)
            email     = Prompt.ask(f"  Email", default=f"{username}@{cfg.get('domain','')}")

            rc, out, err = _run([
                "samba-tool", "user", "add", username,
                password,
                f"--given-name={firstname}",
                f"--surname={lastname}",
                f"--mail-address={email}",
                "--use-username-as-cn",
            ], timeout=15)
            if rc == 0:
                console.print(f"[green]User '{username}' created ✓[/green]")
                group = Prompt.ask("  Add to group (Enter to skip)", default="")
                if group:
                    _run(["samba-tool", "group", "addmembers", group, username])
                    console.print(f"  [dim]Added to {group} ✓[/dim]")
            else:
                console.print(f"[red]{err or out}[/red]")

        elif sub == "list":
            rc, out, _ = _run(["samba-tool", "user", "list"])
            if rc == 0 and out:
                users = [u for u in out.splitlines()
                         if u and "krbtgt" not in u.lower() and
                         not u.startswith("DNS-")]
                table = Table("Username", show_header=True,
                             header_style="bold magenta", border_style="dim")
                for u in users:
                    table.add_row(u.strip())
                console.print(table)
            else:
                console.print("[dim]No users or permission denied[/dim]")

        elif sub == "show":
            username = Prompt.ask("  Username")
            rc, out, _ = _run(["samba-tool", "user", "show", username])
            console.print(out or "User not found")

        elif sub == "disable":
            username = Prompt.ask("  Username to disable")
            rc, out, err = _run(["samba-tool", "user", "disable", username])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "enable":
            username = Prompt.ask("  Username to enable")
            rc, out, err = _run(["samba-tool", "user", "enable", username])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "reset-password":
            username = Prompt.ask("  Username")
            new_pass = Prompt.ask("  New password", password=True)
            rc, out, err = _run([
                "samba-tool", "user", "setpassword", username,
                f"--newpassword={new_pass}",
            ])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err or 'Password reset ✓'}[/]")

        elif sub == "delete":
            username = Prompt.ask("  Username to delete")
            if Confirm.ask(f"  Delete user '{username}'?", default=False):
                rc, out, err = _run(["samba-tool", "user", "delete", username])
                console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Groups
    # -----------------------------------------------------------------------

    def _group_management(self, cfg: dict):
        console.print("\n[bold]Group Management[/bold]")
        sub = Prompt.ask(
            "  Action", default="list",
            choices=["add", "list", "show", "addmember", "removemember", "delete"]
        )

        if sub == "add":
            name = Prompt.ask("  Group name")
            rc, out, err = _run(["samba-tool", "group", "add", name])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "list":
            rc, out, _ = _run(["samba-tool", "group", "list"])
            if rc == 0:
                table = Table("Group Name", show_header=True,
                             header_style="bold magenta", border_style="dim")
                for g in out.splitlines():
                    if g.strip():
                        table.add_row(g.strip())
                console.print(table)

        elif sub == "show":
            name = Prompt.ask("  Group name")
            rc, out, _ = _run(["samba-tool", "group", "listmembers", name])
            console.print(f"[bold]Members of {name}:[/bold]")
            console.print(out or "(empty)")

        elif sub == "addmember":
            group  = Prompt.ask("  Group name")
            member = Prompt.ask("  Username to add")
            rc, out, err = _run(["samba-tool", "group", "addmembers", group, member])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "removemember":
            group  = Prompt.ask("  Group name")
            member = Prompt.ask("  Username to remove")
            rc, out, err = _run(["samba-tool", "group", "removemembers", group, member])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "delete":
            name = Prompt.ask("  Group name")
            if Confirm.ask(f"  Delete group '{name}'?", default=False):
                rc, out, err = _run(["samba-tool", "group", "delete", name])
                console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Computers
    # -----------------------------------------------------------------------

    def _computer_management(self, cfg: dict):
        console.print("\n[bold]Computer Accounts[/bold]")
        sub = Prompt.ask("  Action", choices=["list", "show", "delete"], default="list")

        if sub == "list":
            rc, out, _ = _run(["samba-tool", "computer", "list"])
            if rc == 0:
                table = Table("Computer", show_header=True,
                             header_style="bold magenta", border_style="dim")
                for c in out.splitlines():
                    if c.strip():
                        table.add_row(c.strip())
                console.print(table)

        elif sub == "show":
            name = Prompt.ask("  Computer name (without $)")
            rc, out, _ = _run(["samba-tool", "computer", "show", name])
            console.print(out or "Not found")

        elif sub == "delete":
            name = Prompt.ask("  Computer name to delete")
            if Confirm.ask(f"  Remove computer account '{name}'?", default=False):
                rc, out, err = _run(["samba-tool", "computer", "delete", name])
                console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # GPO
    # -----------------------------------------------------------------------

    def _gpo_listing(self, cfg: dict):
        console.print("\n[bold]Group Policy Objects[/bold]")
        rc, out, _ = _run(["samba-tool", "gpo", "listall"], timeout=20)
        if rc == 0 and out:
            console.print(out)
        else:
            console.print("[dim]No GPOs found or samba-tool error.[/dim]")
        console.print(
            "\n[dim]To manage GPOs, use RSAT (Windows) or:\n"
            "  samba-tool gpo create 'Policy Name'\n"
            "  samba-tool gpo setlink <OU> <GPO-GUID>[/dim]"
        )
        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # DNS
    # -----------------------------------------------------------------------

    def _dns_management(self, cfg: dict):
        domain  = cfg.get("domain", "")
        dc_fqdn = cfg.get("fqdn", "127.0.0.1")
        console.print("\n[bold]DNS Records[/bold]")
        sub = Prompt.ask(
            "  Action", choices=["list", "add-a", "add-cname", "add-txt", "delete"],
            default="list"
        )

        if sub == "list":
            rc, out, _ = _run([
                "samba-tool", "dns", "query", dc_fqdn, domain, "@", "ALL",
            ], timeout=15)
            console.print(out or "(empty)")

        elif sub == "add-a":
            name = Prompt.ask("  Record name")
            ip   = Prompt.ask("  IP address")
            rc, out, err = _run([
                "samba-tool", "dns", "add", dc_fqdn,
                domain, name, "A", ip,
            ], timeout=15)
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-cname":
            name   = Prompt.ask("  CNAME name")
            target = Prompt.ask("  Target hostname")
            rc, out, err = _run([
                "samba-tool", "dns", "add", dc_fqdn,
                domain, name, "CNAME", target,
            ], timeout=15)
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-txt":
            name  = Prompt.ask("  Record name")
            value = Prompt.ask("  TXT value")
            rc, out, err = _run([
                "samba-tool", "dns", "add", dc_fqdn,
                domain, name, "TXT", value,
            ], timeout=15)
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "delete":
            name  = Prompt.ask("  Record name")
            rtype = Prompt.ask("  Type (A/CNAME/TXT/MX)")
            value = Prompt.ask("  Value to remove")
            rc, out, err = _run([
                "samba-tool", "dns", "delete", dc_fqdn,
                domain, name, rtype.upper(), value,
            ], timeout=15)
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Password policy
    # -----------------------------------------------------------------------

    def _password_policy(self, cfg: dict):
        console.print("\n[bold]Password Policy[/bold]")
        rc, out, _ = _run(["samba-tool", "domain", "passwordsettings", "show"])
        if rc == 0:
            console.print(out)

        if Confirm.ask("\n  Update password policy?", default=False):
            min_len = Prompt.ask("  Minimum length", default="12")
            max_age = Prompt.ask("  Max password age (days)", default="90")
            lockout = Prompt.ask("  Lockout threshold (attempts)", default="6")
            _run([
                "samba-tool", "domain", "passwordsettings", "set",
                f"--min-pwd-length={min_len}",
                f"--max-pwd-age={max_age}",
                f"--account-lockout-threshold={lockout}",
            ])
            console.print("[green]Password policy updated ✓[/green]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Domain info
    # -----------------------------------------------------------------------

    def _domain_info(self, cfg: dict):
        console.print("\n[bold]Domain Information[/bold]\n")
        rc, out, _ = _run(["samba-tool", "domain", "info", "127.0.0.1"], timeout=15)
        if rc == 0:
            console.print(out)

        console.print()
        rc2, out2, _ = _run(["samba-tool", "domain", "level", "show"], timeout=15)
        if rc2 == 0:
            console.print("[bold]Functional level:[/bold]")
            console.print(out2)

        console.print()
        rc3, out3, _ = _run(["systemctl", "status", "samba-ad-dc", "--no-pager", "-l"])
        console.print("[bold]Service status:[/bold]")
        for line in out3.splitlines()[:8]:
            console.print(f"  [dim]{line}[/dim]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Sync test
    # -----------------------------------------------------------------------

    def _sync_test(self, cfg: dict):
        console.print("\n[bold]Replication / Sync Test[/bold]")
        rc, out, _ = _run(["samba-tool", "drs", "showrepl"], timeout=20)
        if rc == 0:
            console.print(out[:3000])
        else:
            console.print("[dim]Single-DC deployment — no replication partners.[/dim]")
        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _load_config(self) -> Optional[dict]:
        if self.cm:
            return self.cm.get("roles.identity") or {}
        return None
