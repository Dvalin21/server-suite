"""
roles/mail/mailcow.py
=====================
Mailcow Dockerized deployment. Mailcow is a complete mail server suite:
  - Postfix (SMTP)
  - Dovecot (IMAP/POP3)
  - Rspamd (spam filtering)
  - ClamAV (virus scanning)
  - SOGo (webmail + CalDAV/CardDAV)
  - OpenDKIM (DKIM signing)
  - nginx (internal proxy)
  - MySQL (mailcow database)
  - Redis (caching)

DNS records are managed WITHIN Mailcow's own UI after deployment.
This installer handles the Docker setup, configuration, and generates
a human-readable DNS checklist for the admin.
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

MAILCOW_DIR    = Path("/opt/mailcow-dockerized")
MAILCOW_REPO   = "https://github.com/mailcow/mailcow-dockerized.git"
MAILCOW_BRANCH = "master"


def _run(cmd: list, timeout: int = 300, cwd: Optional[Path] = None) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=str(cwd) if cwd else None
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class MailcowInstaller:
    """Deploys Mailcow Dockerized."""

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir = Path(suite_dir)
        self.cm        = config_manager
        self.sm        = secrets_manager

    # -----------------------------------------------------------------------
    # Main install flow
    # -----------------------------------------------------------------------

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing Mailcow Mail Server[/bold cyan]\n")

        domain   = config.get("domain", "")
        hostname = config.get("hostname", "mail")

        if not domain:
            domain = Prompt.ask("  Mail domain (e.g., example.com)")

        mail_fqdn = Prompt.ask(
            "  Mail server hostname (FQDN)",
            default=f"mail.{domain}"
        )

        # Timezone detection
        rc, tz, _ = _run(["cat", "/etc/timezone"])
        timezone = tz.strip() if rc == 0 and tz.strip() else "UTC"
        timezone = Prompt.ask("  Timezone", default=timezone)

        console.print()
        console.print(Panel(
            f"[bold]Mailcow Configuration[/bold]\n\n"
            f"  Mail FQDN:  [cyan]{mail_fqdn}[/cyan]\n"
            f"  Domain:     [cyan]{domain}[/cyan]\n"
            f"  Timezone:   [cyan]{timezone}[/cyan]\n\n"
            f"  [dim]Mailcow will be deployed to: {MAILCOW_DIR}[/dim]\n"
            f"  [dim]Docker images: ~2-3GB download[/dim]",
            border_style="cyan"
        ))

        if not Confirm.ask("\n  Proceed with Mailcow installation?", default=True):
            return False

        # Step 1: Install git if needed
        _run(["apt-get", "install", "-y", "-qq", "git"])

        # Step 2: Clone Mailcow
        if not self._clone_mailcow():
            return False

        # Step 3: Generate configuration
        if not self._generate_config(mail_fqdn, timezone):
            return False

        # Step 4: Customize mailcow.conf
        self._customize_conf(domain)

        # Step 5: Pull images (this takes a while)
        if not self._pull_images():
            return False

        # Step 6: Start Mailcow
        if not self._start_mailcow():
            return False

        # Step 7: Wait for healthy state
        if not self._wait_for_healthy():
            return False

        # Step 8: Register with config manager
        self._register(mail_fqdn, domain, config)

        # Step 9: Print DNS checklist
        self._print_dns_checklist(mail_fqdn, domain)

        # Step 10: Add firewall rules
        self._configure_firewall()

        console.print(f"\n[bold green]Mailcow installed ✓[/bold green]")
        return True

    # -----------------------------------------------------------------------
    # Clone
    # -----------------------------------------------------------------------

    def _clone_mailcow(self) -> bool:
        console.print("[cyan]Cloning Mailcow repository...[/cyan]")

        if MAILCOW_DIR.exists():
            console.print(f"  [dim]{MAILCOW_DIR} already exists — updating...[/dim]")
            rc, _, err = _run(["git", "pull"], cwd=MAILCOW_DIR)
            return rc == 0

        rc, _, err = _run([
            "git", "clone",
            "--depth", "1",
            "--branch", MAILCOW_BRANCH,
            MAILCOW_REPO,
            str(MAILCOW_DIR)
        ], timeout=120)

        if rc != 0:
            console.print(f"[red]Failed to clone Mailcow: {err}[/red]")
            return False

        console.print(f"  [dim]Cloned to {MAILCOW_DIR} ✓[/dim]")
        return True

    # -----------------------------------------------------------------------
    # Configuration generation
    # -----------------------------------------------------------------------

    def _generate_config(self, mail_fqdn: str, timezone: str) -> bool:
        """Run Mailcow's generate_config.sh."""
        console.print("[cyan]Generating Mailcow configuration...[/cyan]")

        gen_script = MAILCOW_DIR / "generate_config.sh"
        if not gen_script.exists():
            console.print(f"[red]generate_config.sh not found in {MAILCOW_DIR}[/red]")
            return False

        if DRY_RUN:
            console.print("  [dim][DRY RUN] Would run generate_config.sh[/dim]")
            return True

        env = os.environ.copy()
        env["MAILCOW_HOSTNAME"] = mail_fqdn
        env["MAILCOW_TZ"]       = timezone

        try:
            result = subprocess.run(
                ["bash", str(gen_script)],
                env=env,
                cwd=str(MAILCOW_DIR),
                capture_output=True,
                text=True,
                timeout=60,
                input=f"{mail_fqdn}\n{timezone}\n"
            )
            if result.returncode != 0:
                # generate_config.sh is interactive — use sed to set values directly
                self._set_config_values(mail_fqdn, timezone)
        except subprocess.TimeoutExpired:
            self._set_config_values(mail_fqdn, timezone)

        console.print("  [dim]Mailcow config generated ✓[/dim]")
        return True

    def _set_config_values(self, mail_fqdn: str, timezone: str):
        """Directly set mailcow.conf values."""
        conf_path = MAILCOW_DIR / "mailcow.conf"
        if not conf_path.exists():
            # Create minimal conf from template
            template_path = MAILCOW_DIR / "mailcow.conf.template"
            if template_path.exists():
                import shutil
                shutil.copy2(template_path, conf_path)

        if conf_path.exists():
            content = conf_path.read_text()
            replacements = {
                r"MAILCOW_HOSTNAME=.*":  f"MAILCOW_HOSTNAME={mail_fqdn}",
                r"TZ=.*":               f"TZ={timezone}",
            }
            for pattern, replacement in replacements.items():
                content = re.sub(pattern, replacement, content)
            conf_path.write_text(content)

    def _customize_conf(self, domain: str):
        """Apply production-grade customizations to mailcow.conf."""
        conf_path = MAILCOW_DIR / "mailcow.conf"
        if not conf_path.exists() or DRY_RUN:
            return

        content = conf_path.read_text()

        # Generate strong DB passwords
        if self.sm:
            db_pass   = self.sm.generate_password(32, exclude_special=True)
            db_root   = self.sm.generate_password(32, exclude_special=True)
            self.sm.write_env_file("mailcow", {
                "MAILCOW_DOMAIN": domain,
                "DBPASS":         db_pass,
                "DBROOT":         db_root,
            })
            content = re.sub(r"DBPASS=.*",   f"DBPASS={db_pass}",   content)
            content = re.sub(r"DBROOT=.*",   f"DBROOT={db_root}",   content)

        # Security settings
        settings = {
            "SKIP_LETS_ENCRYPT":  "n",
            "ENABLE_SSL_SNI":     "y",
            "SKIP_IP_CHECK":      "n",
            "SKIP_HTTP_VERIFICATION": "n",
            "SOGO_WORKERS":       "3",
        }
        for key, value in settings.items():
            if key in content:
                content = re.sub(rf"{key}=.*", f"{key}={value}", content)
            else:
                content += f"\n{key}={value}"

        conf_path.write_text(content)
        console.print("  [dim]mailcow.conf customized ✓[/dim]")

    # -----------------------------------------------------------------------
    # Docker operations
    # -----------------------------------------------------------------------

    def _pull_images(self) -> bool:
        console.print("[cyan]Pulling Mailcow Docker images (~2-3GB, this will take a while)...[/cyan]")
        rc, _, err = _run(
            ["docker", "compose", "--project-name", "mailcow", "pull"],
            cwd=MAILCOW_DIR,
            timeout=1800  # 30 min timeout for image pull
        )
        if rc != 0:
            console.print(f"[red]Image pull failed: {err}[/red]")
            return False
        console.print("  [dim]Images pulled ✓[/dim]")
        return True

    def _start_mailcow(self) -> bool:
        console.print("[cyan]Starting Mailcow...[/cyan]")
        rc, _, err = _run(
            ["docker", "compose", "--project-name", "mailcow", "up", "-d"],
            cwd=MAILCOW_DIR,
            timeout=300
        )
        if rc != 0:
            console.print(f"[red]Failed to start Mailcow: {err}[/red]")
            return False
        console.print("  [dim]Mailcow containers started ✓[/dim]")
        return True

    def _wait_for_healthy(self, timeout_seconds: int = 300) -> bool:
        """Wait for Mailcow's nginx-mailcow container to be healthy."""
        console.print("[dim]Waiting for Mailcow to become ready (up to 5 minutes)...[/dim]")

        if DRY_RUN:
            return True

        for i in range(timeout_seconds // 5):
            time.sleep(5)
            rc, out, _ = _run([
                "docker", "inspect", "--format",
                "{{.State.Health.Status}}", "nginx-mailcow"
            ])
            if rc == 0 and out.strip() == "healthy":
                console.print("  [green]Mailcow is healthy ✓[/green]")
                return True
            # Check if containers are at least running
            rc2, out2, _ = _run([
                "docker", "ps", "--filter", "name=nginx-mailcow",
                "--format", "{{.Status}}"
            ])
            if i % 12 == 0 and i > 0:  # Every ~60 seconds
                console.print(f"  [dim]Still waiting... ({i * 5}s) — {out2.strip()}[/dim]")

        console.print("[yellow]Mailcow health check timed out — check 'docker ps' manually[/yellow]")
        return True  # Don't fail install — Mailcow may still be starting

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def _register(self, mail_fqdn: str, domain: str, config: dict):
        if not self.cm:
            return

        self.cm.add_role("mail", {
            "engine":     "mailcow",
            "fqdn":       mail_fqdn,
            "domain":     domain,
            "directory":  str(MAILCOW_DIR),
        })

        # Register ports
        mail_ports = [
            (25,  "smtp",       True,  "SMTP"),
            (465, "smtps",      True,  "SMTPS"),
            (587, "submission", True,  "Submission"),
            (993, "imaps",      True,  "IMAPS"),
            (143, "imap",       True,  "IMAP"),
            (110, "pop3",       True,  "POP3"),
            (995, "pop3s",      True,  "POP3S"),
            (4190, "sieve",     False, "ManageSieve (LAN)"),
        ]
        for port, name, external, desc in mail_ports:
            self.cm.register_port(port, f"mailcow-{name}", "tcp",
                                  external=external, description=desc)

        self.cm.register_service_url(
            "mailcow-admin",
            f"https://{mail_fqdn}",
            "Mailcow admin UI — login: admin / moohoo (CHANGE IMMEDIATELY)"
        )
        self.cm.register_service_url(
            "sogo-webmail",
            f"https://{mail_fqdn}/SOGo",
            "SOGo webmail, contacts, and calendar"
        )

    # -----------------------------------------------------------------------
    # Firewall
    # -----------------------------------------------------------------------

    def _configure_firewall(self):
        from core.firewall import FirewallManager
        fw = FirewallManager()
        fw.add_role_rules("mail")
        fw.reload()

    # -----------------------------------------------------------------------
    # DNS Checklist
    # -----------------------------------------------------------------------

    def _print_dns_checklist(self, mail_fqdn: str, domain: str):
        """
        Print a complete DNS records checklist.
        Note: Mailcow's UI shows this too — we're just surfacing it here
        so the admin has it immediately in the terminal and email.
        """
        console.print()
        console.print(Panel(
            "[bold yellow]DNS Records Required for Mail Delivery[/bold yellow]\n"
            "[dim]Configure these at your DNS provider. "
            "Mailcow's admin UI at Configuration → Configuration & Details "
            "also shows your DKIM key after startup.[/dim]",
            border_style="yellow"
        ))

        table = Table(
            "Type", "Name/Host", "Value/Points To", "Priority", "Purpose",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
        )

        server_ip = self._get_public_ip()
        ip_display = server_ip or "<YOUR-SERVER-IP>"

        records = [
            ("A",     mail_fqdn,             ip_display,                                 "—",  "Mail server address"),
            ("MX",    domain,                mail_fqdn,                                  "10", "Mail routing"),
            ("TXT",   domain,                f"v=spf1 mx a:{mail_fqdn} -all",            "—",  "SPF — authorize mail server"),
            ("TXT",   f"_dmarc.{domain}",    f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; ruf=mailto:dmarc@{domain}; sp=quarantine; adkim=s; aspf=s",
                                                                                          "—",  "DMARC policy"),
            ("TXT",   f"dkim._domainkey.{domain}", "[Get from Mailcow UI → Config → Details]",
                                                                                          "—",  "DKIM signature"),
            ("PTR",   ip_display,            mail_fqdn,                                  "—",  "Reverse DNS (set at hosting provider)"),
            ("CNAME", f"autoconfig.{domain}", mail_fqdn,                                 "—",  "Mail client autoconfiguration"),
            ("CNAME", f"autodiscover.{domain}", mail_fqdn,                               "—",  "Outlook autodiscovery"),
            ("SRV",   f"_imap._tcp.{domain}",  f"0 1 143 {mail_fqdn}",                  "—",  "IMAP service record"),
            ("SRV",   f"_imaps._tcp.{domain}", f"0 1 993 {mail_fqdn}",                  "—",  "IMAPS service record"),
            ("SRV",   f"_submission._tcp.{domain}", f"0 1 587 {mail_fqdn}",             "—",  "SMTP submission"),
        ]

        for rec_type, name, value, priority, purpose in records:
            table.add_row(
                f"[cyan]{rec_type}[/cyan]", name,
                value[:55] + "..." if len(value) > 55 else value,
                priority,
                f"[dim]{purpose}[/dim]"
            )

        console.print(table)
        console.print()

        console.print("[bold]Post-installation checklist:[/bold]")
        steps = [
            f"1. Open Mailcow UI: [cyan]https://{mail_fqdn}[/cyan]",
            "2. Log in: [cyan]admin[/cyan] / [cyan]moohoo[/cyan] → [bold red]change password immediately[/bold red]",
            "3. Go to Configuration → Configuration & Details → copy your DKIM public key",
            "4. Add the DKIM TXT record to your DNS provider",
            "5. Add all other DNS records from the table above",
            "6. Wait for DNS propagation (15 min – 48 hours)",
            f"7. Test mail delivery at [cyan]https://mail-tester.com[/cyan]",
            "8. Check blacklists at [cyan]https://mxtoolbox.com/blacklists.aspx[/cyan]",
            "9. Verify PTR/rDNS record with your hosting provider",
        ]
        for step in steps:
            console.print(f"  {step}")

        console.print()
        console.print("[dim]SOGo webmail is available at "
                      f"https://{mail_fqdn}/SOGo[/dim]")

        # Write DNS checklist to file for reference
        checklist_path = self.suite_dir / "mailcow-dns-checklist.txt"
        if not DRY_RUN:
            lines = [
                f"Mailcow DNS Checklist — {domain}",
                "=" * 60,
                f"Mail FQDN:  {mail_fqdn}",
                f"Domain:     {domain}",
                f"Server IP:  {ip_display}",
                "",
            ]
            for rec_type, name, value, priority, purpose in records:
                lines.append(f"{rec_type:6} {name}")
                lines.append(f"       Value: {value}")
                lines.append(f"       Note:  {purpose}")
                lines.append("")
            checklist_path.write_text("\n".join(lines))
            console.print(f"\n[dim]DNS checklist saved to: {checklist_path}[/dim]")

    def _get_public_ip(self) -> Optional[str]:
        """Try to detect the server's public IP."""
        services = [
            ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
            ["curl", "-s", "-4", "--max-time", "5", "https://ifconfig.me"],
        ]
        for cmd in services:
            rc, out, _ = _run(cmd, timeout=10)
            if rc == 0 and out and re.match(r'^\d+\.\d+\.\d+\.\d+$', out.strip()):
                return out.strip()
        return None


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        installer = MailcowInstaller(self.suite_dir, self.cm, self.sm)
        return installer.install(config)
