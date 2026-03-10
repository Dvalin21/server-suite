"""
roles/identity/management.py
============================
Day-to-day FreeIPA management operations.
Used by the management menu to manage users, groups, hosts,
HBAC rules, sudo rules, DNS records, and certificates.

All operations use the `ipa` CLI after a kinit, or the
FreeIPA JSON API for non-interactive scripted operations.
"""

import os
import subprocess
import json
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel

console = Console()


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class IPASession:
    """Manages a Kerberos-authenticated IPA API session."""

    def __init__(self, ipa_fqdn: str, admin_password: str):
        self.ipa_fqdn       = ipa_fqdn
        self.admin_password = admin_password
        self.base_url       = f"https://{ipa_fqdn}/ipa"
        self._cookie        = None

    def __enter__(self):
        self._login()
        return self

    def __exit__(self, *args):
        pass

    def _login(self):
        """Authenticate to the IPA JSON API."""
        try:
            data = urllib.parse.urlencode({
                "user":     "admin",
                "password": self.admin_password,
            }).encode()
            req = urllib.request.Request(
                f"{self.base_url}/session/login_password",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Referer":      f"{self.base_url}/ui/"},
                method="POST",
            )
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                # Extract cookie
                cookie_header = resp.headers.get("Set-Cookie", "")
                if "ipa_session" in cookie_header:
                    for part in cookie_header.split(";"):
                        part = part.strip()
                        if part.startswith("ipa_session="):
                            self._cookie = part
                            break
        except Exception as e:
            console.print(f"  [yellow]IPA API login failed: {e} — falling back to CLI[/yellow]")

    def call(self, method: str, args: list = None, options: dict = None) -> Optional[dict]:
        """Make a JSON-RPC call to the IPA API."""
        if not self._cookie:
            return None
        try:
            payload = json.dumps({
                "method": method,
                "params": [args or [], options or {}],
                "id":     0,
            }).encode()
            req = urllib.request.Request(
                f"{self.base_url}/json",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Referer":      f"{self.base_url}/ui/",
                    "Cookie":       self._cookie,
                },
                method="POST",
            )
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as e:
            console.print(f"  [yellow]API call failed ({method}): {e}[/yellow]")
            return None


class FreeIPAManager:
    """
    Interactive management interface for FreeIPA.
    Accessible from the main management menu.
    """

    def __init__(self, suite_dir: Path, config_manager=None):
        self.suite_dir = Path(suite_dir)
        self.cm        = config_manager

    def run(self):
        """Main management menu loop."""
        cfg = self._load_config()
        if not cfg:
            console.print("[red]FreeIPA is not configured on this server.[/red]")
            return

        while True:
            self._print_header(cfg)
            choice = self._show_menu()
            if choice == "0":
                break
            self._handle(choice, cfg)

    # -----------------------------------------------------------------------
    # Menu
    # -----------------------------------------------------------------------

    def _print_header(self, cfg: dict):
        console.print()
        console.print(Panel(
            f"[bold cyan]FreeIPA Management[/bold cyan]  "
            f"[dim]Realm: {cfg.get('realm', '?')}  |  "
            f"Domain: {cfg.get('domain', '?')}[/dim]",
            border_style="cyan",
            padding=(0, 2),
        ))

    def _show_menu(self) -> str:
        options = {
            "1": "👤  User management      (add/list/disable/reset password)",
            "2": "👥  Group management     (add/list/add member)",
            "3": "🖥️   Host management      (add/list/enroll)",
            "4": "🔐  HBAC rules           (who can log into what)",
            "5": "⚡  Sudo rules           (who can run what as root)",
            "6": "🌐  DNS records          (add/list A, CNAME, MX, TXT)",
            "7": "🔒  Certificates         (issue/list/revoke)",
            "8": "📊  Server status        (services, replication)",
            "9": "📜  Kerberos tickets     (kinit / klist / kdestroy)",
            "0": "↩️   Back",
        }
        for key, label in options.items():
            color = "cyan" if key != "0" else "dim"
            console.print(f"  [{color}]{key}[/{color}]  {label}")
        console.print()
        return Prompt.ask("  Select", choices=list(options.keys()), default="0")

    def _handle(self, choice: str, cfg: dict):
        handlers = {
            "1": self._user_management,
            "2": self._group_management,
            "3": self._host_management,
            "4": self._hbac_management,
            "5": self._sudo_management,
            "6": self._dns_management,
            "7": self._cert_management,
            "8": self._server_status,
            "9": self._kerberos_tickets,
        }
        if choice in handlers:
            handlers[choice](cfg)

    # -----------------------------------------------------------------------
    # User management
    # -----------------------------------------------------------------------

    def _user_management(self, cfg: dict):
        console.print("\n[bold]User Management[/bold]")
        options = {
            "1": "Add user",
            "2": "List users",
            "3": "Disable user",
            "4": "Enable user",
            "5": "Reset password",
            "6": "Show user details",
            "0": "Back",
        }
        for k, v in options.items():
            console.print(f"  [cyan]{k}[/cyan]  {v}")
        choice = Prompt.ask("  Action", choices=list(options.keys()), default="0")

        if choice == "1":
            self._add_user(cfg)
        elif choice == "2":
            self._list_users()
        elif choice == "3":
            uid = Prompt.ask("  Username to disable")
            rc, out, err = _run(["ipa", "user-disable", uid])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")
        elif choice == "4":
            uid = Prompt.ask("  Username to enable")
            rc, out, err = _run(["ipa", "user-enable", uid])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")
        elif choice == "5":
            self._reset_password()
        elif choice == "6":
            uid = Prompt.ask("  Username")
            rc, out, _ = _run(["ipa", "user-show", uid, "--all"])
            console.print(out)

        Prompt.ask("\n  Press Enter to continue", default="")

    def _add_user(self, cfg: dict):
        console.print("\n[bold]Add IPA User[/bold]")
        uid       = Prompt.ask("  Username (login)")
        first     = Prompt.ask("  First name")
        last      = Prompt.ask("  Last name")
        email     = Prompt.ask("  Email", default=f"{uid}@{cfg['domain']}")
        phone     = Prompt.ask("  Phone (optional)", default="")
        shell     = Prompt.ask("  Shell", default="/bin/bash")
        password  = Prompt.ask("  Initial password", password=True)

        cmd = [
            "ipa", "user-add", uid,
            f"--first={first}",
            f"--last={last}",
            f"--email={email}",
            f"--shell={shell}",
            "--password",
        ]
        if phone:
            cmd.append(f"--phone={phone}")

        # Pipe password via stdin
        try:
            result = subprocess.run(
                cmd,
                input=f"{password}\n{password}\n",
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                console.print(f"[green]User '{uid}' created ✓[/green]")
                # Optionally add to group
                group = Prompt.ask("  Add to group (or Enter to skip)", default="")
                if group:
                    _run(["ipa", "group-add-member", group, f"--users={uid}"])
                    console.print(f"  [dim]Added {uid} to {group} ✓[/dim]")
            else:
                console.print(f"[red]Failed: {result.stderr}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def _list_users(self):
        rc, out, _ = _run(["ipa", "user-find", "--all", "--sizelimit=200"])
        if rc == 0:
            # Parse and display as table
            users = self._parse_ipa_find_output(out)
            table = Table("Login", "Full Name", "Email", "Status",
                         show_header=True, header_style="bold magenta",
                         border_style="dim")
            for u in users:
                status = "[green]Active[/green]" if u.get("nsaccountlock", "FALSE") == "FALSE" else "[red]Disabled[/red]"
                table.add_row(
                    u.get("uid", ""),
                    u.get("cn", ""),
                    u.get("mail", ""),
                    status,
                )
            console.print(table)
        else:
            console.print("[yellow]Could not retrieve user list — are you kinited as admin?[/yellow]")

    def _reset_password(self):
        uid      = Prompt.ask("  Username")
        new_pass = Prompt.ask("  New password", password=True)
        try:
            result = subprocess.run(
                ["ipa", "passwd", uid],
                input=f"{new_pass}\n{new_pass}\n",
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                console.print(f"[green]Password reset for {uid} ✓[/green]")
                console.print(f"  [dim]User will be prompted to change on next login[/dim]")
            else:
                console.print(f"[red]{result.stderr}[/red]")
        except Exception as e:
            console.print(f"[red]{e}[/red]")

    # -----------------------------------------------------------------------
    # Group management
    # -----------------------------------------------------------------------

    def _group_management(self, cfg: dict):
        console.print("\n[bold]Group Management[/bold]")
        sub = Prompt.ask("  Action",
                          choices=["add", "list", "show", "add-member", "remove-member"],
                          default="list")

        if sub == "add":
            name = Prompt.ask("  Group name")
            desc = Prompt.ask("  Description", default="")
            rc, out, err = _run(["ipa", "group-add", name, f"--desc={desc}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "list":
            rc, out, _ = _run(["ipa", "group-find", "--sizelimit=200"])
            groups = self._parse_ipa_find_output(out)
            table = Table("Group", "Description", "Members",
                         show_header=True, header_style="bold magenta", border_style="dim")
            for g in groups:
                table.add_row(g.get("cn", ""), g.get("description", ""),
                              str(len(g.get("member_user", []))))
            console.print(table)

        elif sub == "show":
            name = Prompt.ask("  Group name")
            rc, out, _ = _run(["ipa", "group-show", name, "--all"])
            console.print(out)

        elif sub == "add-member":
            group = Prompt.ask("  Group name")
            user  = Prompt.ask("  Username to add")
            rc, out, err = _run(["ipa", "group-add-member", group, f"--users={user}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "remove-member":
            group = Prompt.ask("  Group name")
            user  = Prompt.ask("  Username to remove")
            rc, out, err = _run(["ipa", "group-remove-member", group, f"--users={user}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Host management
    # -----------------------------------------------------------------------

    def _host_management(self, cfg: dict):
        console.print("\n[bold]Host Management[/bold]")
        sub = Prompt.ask("  Action",
                          choices=["add", "list", "show", "enroll-script"],
                          default="list")

        if sub == "add":
            hostname = Prompt.ask(f"  Hostname (FQDN or short — will append .{cfg['domain']})")
            if "." not in hostname:
                hostname = f"{hostname}.{cfg['domain']}"
            ip = Prompt.ask("  IP address (optional)", default="")
            cmd = ["ipa", "host-add", hostname, "--force"]
            if ip:
                cmd.append(f"--ip-address={ip}")
            rc, out, err = _run(cmd)
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "list":
            rc, out, _ = _run(["ipa", "host-find", "--sizelimit=200"])
            hosts = self._parse_ipa_find_output(out)
            table = Table("Hostname", "IP", "OS",
                         show_header=True, header_style="bold magenta", border_style="dim")
            for h in hosts:
                table.add_row(
                    h.get("fqdn", ""),
                    h.get("managedby_host", h.get("l", "")),
                    h.get("nshostlocation", ""),
                )
            console.print(table)

        elif sub == "show":
            host = Prompt.ask("  Hostname")
            rc, out, _ = _run(["ipa", "host-show", host, "--all"])
            console.print(out)

        elif sub == "enroll-script":
            console.print(
                f"\n  [dim]Enrollment script: "
                f"{self.suite_dir / 'scripts' / 'enroll-ipa-client.sh'}[/dim]"
            )
            console.print(
                "  [dim]Copy to target host and run:[/dim]\n"
                "  [cyan]bash enroll-ipa-client.sh <admin-password>[/cyan]"
            )

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # HBAC rules
    # -----------------------------------------------------------------------

    def _hbac_management(self, cfg: dict):
        console.print("\n[bold]HBAC Rules (Host-Based Access Control)[/bold]")
        console.print("[dim]HBAC controls which users/groups can log into which hosts.[/dim]\n")

        sub = Prompt.ask("  Action",
                          choices=["list", "show", "add", "add-user", "add-host",
                                   "enable", "disable"],
                          default="list")

        if sub == "list":
            rc, out, _ = _run(["ipa", "hbacrule-find", "--sizelimit=200"])
            rules = self._parse_ipa_find_output(out)
            table = Table("Rule", "Enabled", "Users/Groups", "Hosts",
                         show_header=True, header_style="bold magenta", border_style="dim")
            for r in rules:
                enabled = "[green]Yes[/green]" if r.get("ipaenabledflag", "TRUE") == "TRUE" else "[red]No[/red]"
                table.add_row(
                    r.get("cn", ""),
                    enabled,
                    ", ".join(r.get("memberuser_group", [])) or "—",
                    r.get("hostcategory", "") or ", ".join(r.get("memberhost_host", [])),
                )
            console.print(table)

        elif sub == "add":
            name    = Prompt.ask("  Rule name")
            desc    = Prompt.ask("  Description")
            hostcat = Confirm.ask("  Apply to ALL hosts?", default=False)
            cmd = ["ipa", "hbacrule-add", name, f"--desc={desc}", "--servicecat=all"]
            if hostcat:
                cmd.append("--hostcat=all")
            rc, out, err = _run(cmd)
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-user":
            rule   = Prompt.ask("  Rule name")
            target = Prompt.ask("  User or group to add")
            is_group = Confirm.ask("  Is this a group?", default=True)
            flag = "--groups" if is_group else "--users"
            rc, out, err = _run(["ipa", "hbacrule-add-user", rule, f"{flag}={target}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-host":
            rule   = Prompt.ask("  Rule name")
            host   = Prompt.ask("  Hostname to add")
            rc, out, err = _run(["ipa", "hbacrule-add-host", rule, f"--hosts={host}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub in ("enable", "disable"):
            rule = Prompt.ask("  Rule name")
            rc, out, err = _run([f"ipa", f"hbacrule-{sub}", rule])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "show":
            rule = Prompt.ask("  Rule name")
            rc, out, _ = _run(["ipa", "hbacrule-show", rule, "--all"])
            console.print(out)

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Sudo rules
    # -----------------------------------------------------------------------

    def _sudo_management(self, cfg: dict):
        console.print("\n[bold]Sudo Rules[/bold]")

        sub = Prompt.ask("  Action", choices=["list", "add", "add-user", "show"],
                          default="list")

        if sub == "list":
            rc, out, _ = _run(["ipa", "sudorule-find", "--sizelimit=200"])
            rules = self._parse_ipa_find_output(out)
            table = Table("Rule", "Users/Groups", "Commands",
                         show_header=True, header_style="bold magenta", border_style="dim")
            for r in rules:
                table.add_row(
                    r.get("cn", ""),
                    ", ".join(r.get("memberuser_group", [])) or "—",
                    r.get("cmdcategory", "") or "custom",
                )
            console.print(table)

        elif sub == "add":
            name     = Prompt.ask("  Rule name")
            desc     = Prompt.ask("  Description")
            all_cmds = Confirm.ask("  Allow ALL commands?", default=True)
            cmd = [
                "ipa", "sudorule-add", name,
                f"--desc={desc}",
                "--hostcat=all",
                "--runasusercat=all",
                "--runasgroupcat=all",
            ]
            if all_cmds:
                cmd.append("--cmdcat=all")
            rc, out, err = _run(cmd)
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-user":
            rule     = Prompt.ask("  Rule name")
            target   = Prompt.ask("  User or group")
            is_group = Confirm.ask("  Is this a group?", default=True)
            flag     = "--groups" if is_group else "--users"
            rc, out, err = _run(["ipa", "sudorule-add-user", rule, f"{flag}={target}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "show":
            rule = Prompt.ask("  Rule name")
            rc, out, _ = _run(["ipa", "sudorule-show", rule, "--all"])
            console.print(out)

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # DNS management
    # -----------------------------------------------------------------------

    def _dns_management(self, cfg: dict):
        if not cfg.get("manage_dns"):
            console.print("[yellow]FreeIPA DNS is not enabled on this server.[/yellow]")
            Prompt.ask("\n  Press Enter to continue", default="")
            return

        console.print("\n[bold]DNS Records[/bold]")
        domain = cfg["domain"]

        sub = Prompt.ask("  Action", choices=["list", "add-a", "add-cname",
                                               "add-txt", "add-mx", "del"],
                          default="list")

        if sub == "list":
            rc, out, _ = _run(["ipa", "dnsrecord-find", domain, "--sizelimit=500"])
            console.print(out)

        elif sub == "add-a":
            name = Prompt.ask("  Record name (hostname, @ for zone apex)")
            ip   = Prompt.ask("  IP address")
            rc, out, err = _run(["ipa", "dnsrecord-add", domain, name,
                                  f"--a-rec={ip}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-cname":
            name  = Prompt.ask("  CNAME name")
            target = Prompt.ask("  Target (FQDN with trailing dot)")
            if not target.endswith("."):
                target += "."
            rc, out, err = _run(["ipa", "dnsrecord-add", domain, name,
                                  f"--cname-rec={target}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-txt":
            name  = Prompt.ask("  TXT record name")
            value = Prompt.ask("  TXT value")
            rc, out, err = _run(["ipa", "dnsrecord-add", domain, name,
                                  f"--txt-rec={value}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "add-mx":
            priority = Prompt.ask("  MX priority", default="10")
            exchange = Prompt.ask("  Mail exchanger (FQDN)")
            if not exchange.endswith("."):
                exchange += "."
            rc, out, err = _run(["ipa", "dnsrecord-add", domain, "@",
                                  f"--mx-rec={priority} {exchange}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        elif sub == "del":
            name = Prompt.ask("  Record name to delete")
            rtype = Prompt.ask("  Record type (a/cname/txt/mx)")
            rc, out, err = _run(["ipa", "dnsrecord-del", domain, name,
                                  f"--{rtype.lower()}-rec="])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Certificate management
    # -----------------------------------------------------------------------

    def _cert_management(self, cfg: dict):
        if not cfg.get("setup_ca"):
            console.print("[yellow]Dogtag CA is not enabled.[/yellow]")
            Prompt.ask("\n  Press Enter to continue", default="")
            return

        console.print("\n[bold]Certificate Management (Dogtag PKI)[/bold]")

        sub = Prompt.ask("  Action", choices=["list", "request", "show", "revoke"],
                          default="list")

        if sub == "list":
            rc, out, _ = _run(["ipa", "cert-find", "--sizelimit=100"])
            console.print(out)

        elif sub == "request":
            subject = Prompt.ask("  Certificate subject (CN=hostname)")
            # Generate key and CSR
            console.print("[dim]Generating key and CSR...[/dim]")
            rc1, _, _ = _run(["openssl", "req", "-new", "-newkey", "rsa:2048",
                               "-nodes", "-keyout", "/tmp/ipa_req.key",
                               "-out", "/tmp/ipa_req.csr",
                               "-subj", f"/{subject}"])
            if rc1 == 0:
                rc2, out, err = _run(["ipa", "cert-request",
                                       "/tmp/ipa_req.csr",
                                       f"--principal={subject}"])
                console.print(f"[{'green' if rc2 == 0 else 'red'}]{out or err}[/]")
            # Clean up
            _run(["rm", "-f", "/tmp/ipa_req.key", "/tmp/ipa_req.csr"])

        elif sub == "show":
            serial = Prompt.ask("  Certificate serial number")
            rc, out, _ = _run(["ipa", "cert-show", serial, "--all"])
            console.print(out)

        elif sub == "revoke":
            serial = Prompt.ask("  Certificate serial number")
            reason = Prompt.ask("  Revocation reason (0=unspecified, 1=keyCompromise, ...)",
                                 default="0")
            rc, out, err = _run(["ipa", "cert-revoke", serial,
                                  f"--revocation-reason={reason}"])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err}[/]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Server status
    # -----------------------------------------------------------------------

    def _server_status(self, cfg: dict):
        console.print("\n[bold]FreeIPA Server Status[/bold]\n")
        rc, out, _ = _run(["ipactl", "status"], timeout=30)
        console.print(out or "Could not retrieve status")
        console.print()

        # Show replication agreements
        rc2, out2, _ = _run(["ipa", "replicationagreement-find"])
        if rc2 == 0 and out2.strip():
            console.print("[bold]Replication Agreements:[/bold]")
            console.print(out2)

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Kerberos
    # -----------------------------------------------------------------------

    def _kerberos_tickets(self, cfg: dict):
        console.print("\n[bold]Kerberos Ticket Management[/bold]")
        sub = Prompt.ask("  Action", choices=["kinit", "klist", "kdestroy"],
                          default="klist")

        if sub == "kinit":
            principal = Prompt.ask("  Principal", default="admin")
            rc, out, err = _run(["kinit", principal])
            console.print(f"[{'green' if rc == 0 else 'red'}]{out or err or 'kinit executed'}[/]")
        elif sub == "klist":
            rc, out, err = _run(["klist", "-v"])
            console.print(out or err or "No tickets")
        elif sub == "kdestroy":
            _run(["kdestroy", "-A"])
            console.print("[green]All tickets destroyed ✓[/green]")

        Prompt.ask("\n  Press Enter to continue", default="")

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _load_config(self) -> Optional[dict]:
        if self.cm:
            return self.cm.get("roles.identity") or {}
        return None

    def _parse_ipa_find_output(self, output: str) -> list:
        """Parse `ipa *-find` output into a list of dicts."""
        entries = []
        current: dict = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("---") or not line:
                if current:
                    entries.append(current)
                    current = {}
                continue
            if ": " in line:
                key, _, val = line.partition(": ")
                key = key.strip().lower().replace(" ", "_").replace("-", "_")
                current[key] = val.strip()
        if current:
            entries.append(current)
        return entries
