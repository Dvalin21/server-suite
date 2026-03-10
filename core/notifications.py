"""
core/notifications.py
=====================
Email notification system. Handles SMTP configuration via Postfix
and sends human-readable reports for all monitoring events.
"""

import os
import smtplib
import subprocess
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()

DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    if DRY_RUN:
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class NotificationManager:
    """Manages email configuration and sending."""

    POSTFIX_MAIN_CF = Path("/etc/postfix/main.cf")
    POSTFIX_SASL_PASSWD = Path("/etc/postfix/sasl_passwd")
    POSTFIX_SASL_DIR = Path("/etc/postfix/sasl")

    def __init__(self, suite_dir: Path):
        self.suite_dir = Path(suite_dir)
        self.config_file = self.suite_dir / "secrets" / ".env.smtp"
        self._smtp_config: dict = {}
        self._load_config()

    # -----------------------------------------------------------------------
    # Config management
    # -----------------------------------------------------------------------

    def _load_config(self):
        """Load SMTP config from env file if it exists."""
        if self.config_file.exists():
            for line in self.config_file.read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    self._smtp_config[k.strip()] = v.strip().strip('"')

    def _save_config(self, config: dict):
        """Save SMTP config securely."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Server Suite SMTP Configuration",
            f"# Generated: {datetime.utcnow().isoformat()}",
            "",
        ]
        for k, v in config.items():
            lines.append(f'{k}="{v}"')

        self.config_file.write_text("\n".join(lines) + "\n")
        os.chmod(self.config_file, 0o600)
        self._smtp_config = config

    # -----------------------------------------------------------------------
    # Interactive SMTP setup
    # -----------------------------------------------------------------------

    def interactive_setup(self) -> bool:
        """Walk the user through SMTP configuration."""
        console.print("\n[bold cyan]Email Notification Setup[/bold cyan]")
        console.print("[dim]Configure SMTP for system alerts, scan reports, and maintenance notifications.[/dim]\n")

        # Recipient email
        recipient = Prompt.ask("  Notification email address (where alerts will be sent)")
        if not "@" in recipient:
            console.print("[red]Invalid email address[/red]")
            return False

        # Detect if port 25 might be blocked (cloud VMs)
        port_25_blocked = self._check_port_25_blocked()
        if port_25_blocked:
            console.print("\n  [yellow]⚠ Port 25 outbound appears to be blocked (common on cloud VMs).[/yellow]")
            console.print("  [yellow]  Using port 587 (STARTTLS) is recommended.[/yellow]\n")

        # SMTP provider shortcuts
        console.print("  [dim]Quick setup for common providers:[/dim]")
        console.print("    [cyan]1[/cyan]  Gmail")
        console.print("    [cyan]2[/cyan]  Office 365 / Outlook")
        console.print("    [cyan]3[/cyan]  Fastmail")
        console.print("    [cyan]4[/cyan]  Custom SMTP server")
        console.print()

        provider = Prompt.ask("  Choose provider", choices=["1", "2", "3", "4"], default="4")

        presets = {
            "1": {"host": "smtp.gmail.com",        "port": "587", "security": "STARTTLS",
                  "note": "Use an App Password, not your regular Google password."},
            "2": {"host": "smtp.office365.com",    "port": "587", "security": "STARTTLS",
                  "note": "Use your full email address as the username."},
            "3": {"host": "smtp.fastmail.com",     "port": "587", "security": "STARTTLS",
                  "note": "Use an App Password from Fastmail settings."},
            "4": {"host": "",                      "port": "587", "security": "STARTTLS",
                  "note": ""}
        }

        preset = presets[provider]
        if preset.get("note"):
            console.print(f"\n  [yellow]Note: {preset['note']}[/yellow]")

        smtp_host = Prompt.ask("\n  SMTP host", default=preset["host"])
        smtp_port = Prompt.ask("  SMTP port", default=preset["port"])
        security  = Prompt.ask("  Security", choices=["STARTTLS", "SSL/TLS", "None"],
                               default=preset["security"])
        username  = Prompt.ask("  SMTP username")
        password  = Prompt.ask("  SMTP password", password=True)
        from_addr = Prompt.ask("  From address", default=f"server-suite@{smtp_host.replace('smtp.', '')}")

        config = {
            "SMTP_HOST":      smtp_host,
            "SMTP_PORT":      smtp_port,
            "SMTP_SECURITY":  security,
            "SMTP_USERNAME":  username,
            "SMTP_PASSWORD":  password,
            "SMTP_FROM":      from_addr,
            "NOTIFY_EMAIL":   recipient,
        }

        self._save_config(config)
        console.print("\n[dim]SMTP credentials saved securely.[/dim]")

        # Configure Postfix
        if Confirm.ask("\n  Configure Postfix relay with these settings?", default=True):
            if self.configure_postfix(config):
                console.print("[green]Postfix configured ✓[/green]")
            else:
                console.print("[yellow]Postfix configuration failed — using Python SMTP directly[/yellow]")

        # Send test email
        if Confirm.ask(f"\n  Send a test email to {recipient}?", default=True):
            if self.send_test_email(recipient):
                console.print(f"[green]Test email sent to {recipient} ✓[/green]")
                console.print("[dim]  Check your inbox (and spam folder).[/dim]")
            else:
                console.print("[red]Test email failed — check your SMTP settings.[/red]")
                return False

        return True

    def _check_port_25_blocked(self) -> bool:
        """Check if outbound port 25 is blocked."""
        import socket
        try:
            with socket.create_connection(("smtp.gmail.com", 25), timeout=5):
                return False
        except (socket.timeout, ConnectionRefusedError, OSError):
            return True

    # -----------------------------------------------------------------------
    # Postfix configuration
    # -----------------------------------------------------------------------

    def configure_postfix(self, config: dict) -> bool:
        """Configure Postfix as a relay for outbound email."""
        if DRY_RUN:
            console.print("  [dim][DRY RUN] Would configure Postfix[/dim]")
            return True

        # Install Postfix if needed
        rc, _, _ = _run(["which", "postfix"])
        if rc != 0:
            console.print("  [dim]Installing Postfix...[/dim]")
            _run(["bash", "-c",
                  'DEBIAN_FRONTEND=noninteractive apt-get install -y postfix libsasl2-modules'])

        host     = config["SMTP_HOST"]
        port     = config["SMTP_PORT"]
        username = config["SMTP_USERNAME"]
        password = config["SMTP_PASSWORD"]
        security = config["SMTP_SECURITY"]

        # Determine relay and TLS settings
        relay_host = f"[{host}]:{port}"

        tls_settings = ""
        if security == "STARTTLS":
            tls_settings = (
                "smtp_use_tls = yes\n"
                "smtp_sasl_tls_security_options = noanonymous\n"
                "smtp_tls_security_level = encrypt\n"
            )
        elif security == "SSL/TLS":
            tls_settings = (
                "smtp_tls_wrappermode = yes\n"
                "smtp_sasl_tls_security_options = noanonymous\n"
                "smtp_tls_security_level = encrypt\n"
            )

        # Write main.cf relay config
        relay_config = f"""
# Server Suite SMTP relay configuration
relayhost = {relay_host}
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
{tls_settings}
"""

        # Append to main.cf (remove old suite config first)
        main_cf = self.POSTFIX_MAIN_CF.read_text() if self.POSTFIX_MAIN_CF.exists() else ""
        # Remove any previous suite config
        if "# Server Suite SMTP relay configuration" in main_cf:
            start = main_cf.index("# Server Suite SMTP relay configuration")
            main_cf = main_cf[:start]

        if not DRY_RUN:
            self.POSTFIX_MAIN_CF.write_text(main_cf + relay_config)

        # Write sasl_passwd
        sasl_content = f"{relay_host} {username}:{password}\n"
        if not DRY_RUN:
            self.POSTFIX_SASL_PASSWD.write_text(sasl_content)
            os.chmod(self.POSTFIX_SASL_PASSWD, 0o600)
            _run(["postmap", str(self.POSTFIX_SASL_PASSWD)])
            _run(["systemctl", "restart", "postfix"])

        return True

    # -----------------------------------------------------------------------
    # Email sending
    # -----------------------------------------------------------------------

    def send_test_email(self, recipient: str) -> bool:
        """Send a test email to verify configuration."""
        subject = "Server Suite — Test Email"
        body = self._render_test_email()
        return self._send(recipient, subject, body, html=True)

    def send_report(self, subject: str, body: str,
                    recipient: Optional[str] = None, html: bool = True) -> bool:
        """Send a report email."""
        to = recipient or self._smtp_config.get("NOTIFY_EMAIL")
        if not to:
            console.print("[yellow]No notification email configured — skipping report[/yellow]")
            return False
        return self._send(to, subject, body, html=html)

    def _send(self, to: str, subject: str, body: str, html: bool = True) -> bool:
        """Send an email using configured SMTP."""
        if DRY_RUN:
            console.print(f"  [dim][DRY RUN] Would send email to {to}: {subject}[/dim]")
            return True

        config = self._smtp_config
        if not config:
            console.print("[red]SMTP not configured. Cannot send email.[/red]")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Server Suite] {subject}"
        msg["From"]    = config.get("SMTP_FROM", config.get("SMTP_USERNAME", "server-suite@localhost"))
        msg["To"]      = to

        content_type = "html" if html else "plain"
        msg.attach(MIMEText(body, content_type))

        host     = config.get("SMTP_HOST", "localhost")
        port     = int(config.get("SMTP_PORT", 587))
        username = config.get("SMTP_USERNAME", "")
        password = config.get("SMTP_PASSWORD", "")
        security = config.get("SMTP_SECURITY", "STARTTLS")

        try:
            if security == "SSL/TLS":
                server = smtplib.SMTP_SSL(host, port, timeout=30)
            else:
                server = smtplib.SMTP(host, port, timeout=30)
                if security == "STARTTLS":
                    server.starttls()

            if username and password:
                server.login(username, password)

            server.sendmail(msg["From"], [to], msg.as_string())
            server.quit()
            return True

        except smtplib.SMTPAuthenticationError:
            console.print("[red]SMTP authentication failed — check username/password[/red]")
        except smtplib.SMTPConnectError as e:
            console.print(f"[red]SMTP connection failed: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Email send failed: {e}[/red]")

        return False

    # -----------------------------------------------------------------------
    # Report templates
    # -----------------------------------------------------------------------

    def _render_test_email(self) -> str:
        return self._render_html_report(
            title="Test Email — Server Suite",
            status="SUCCESS",
            status_color="#22c55e",
            summary="Your Server Suite email notifications are working correctly.",
            sections=[{
                "title": "What this means",
                "items": [
                    ("Status", "Email notifications are configured and working"),
                    ("Recipient", self._smtp_config.get("NOTIFY_EMAIL", "—")),
                    ("SMTP Host", self._smtp_config.get("SMTP_HOST", "—")),
                    ("Sent at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                ]
            }]
        )

    def render_smart_report(self, results: list, hostname: str) -> str:
        """Render a human-readable SMART scan report."""
        all_passed = all(r.get("health") == "PASSED" for r in results)
        status = "ALL DRIVES HEALTHY" if all_passed else "⚠ ATTENTION REQUIRED"
        status_color = "#22c55e" if all_passed else "#ef4444"

        sections = []
        for drive in results:
            items = [
                ("Device",               drive.get("device", "—")),
                ("Model",                drive.get("model", "—")),
                ("Type",                 drive.get("type", "—")),
                ("Health",               drive.get("health", "—")),
                ("Temperature",          f"{drive.get('temp', '—')}°C" if drive.get('temp') else "—"),
                ("Power-On Hours",       f"{drive.get('power_on_hours', '—'):,}" if drive.get('power_on_hours') else "—"),
                ("Reallocated Sectors",  str(drive.get("reallocated", 0))),
                ("Pending Sectors",      str(drive.get("pending", 0))),
                ("Uncorrectable Errors", str(drive.get("uncorrectable", 0))),
            ]
            if drive.get("reallocated", 0) > 0:
                items.append(("⚠ Warning", "Reallocated sectors detected — monitor closely"))
            if drive.get("health") == "FAILED":
                items.append(("⚠ CRITICAL", "SMART health test FAILED — replace this drive immediately"))

            sections.append({"title": f"Drive: {drive.get('device', '—')} — {drive.get('model', '—')}", "items": items})

        return self._render_html_report(
            title=f"SMART Scan Report — {hostname}",
            status=status,
            status_color=status_color,
            summary=f"Monthly SMART long scan completed on {datetime.now().strftime('%Y-%m-%d at %H:%M')}. "
                    f"{len(results)} drive(s) scanned.",
            sections=sections
        )

    def render_defrag_report(self, results: list, hostname: str) -> str:
        """Render a BTRFS defrag report."""
        all_ok = all(r.get("status") == "ok" for r in results)
        status = "DEFRAG COMPLETED" if all_ok else "DEFRAG COMPLETED WITH WARNINGS"
        status_color = "#22c55e" if all_ok else "#f59e0b"

        sections = []
        for r in results:
            items = [
                ("Path",        r.get("path", "—")),
                ("Status",      r.get("status", "—")),
                ("Duration",    r.get("duration", "—")),
                ("Files Processed", str(r.get("files_processed", "—"))),
            ]
            if r.get("error"):
                items.append(("Error", r.get("error")))
            sections.append({"title": f"Defrag: {r.get('path', '—')}", "items": items})

        return self._render_html_report(
            title=f"BTRFS Defrag Report — {hostname}",
            status=status,
            status_color=status_color,
            summary=f"Monthly BTRFS defragmentation completed on {datetime.now().strftime('%Y-%m-%d at %H:%M')}.",
            sections=sections
        )

    def render_health_alert(self, alert_type: str, details: dict, hostname: str) -> str:
        """Render an immediate health alert."""
        return self._render_html_report(
            title=f"⚠ Health Alert — {hostname}",
            status=f"ALERT: {alert_type.upper()}",
            status_color="#ef4444",
            summary=f"An automated health check detected an issue on {hostname}.",
            sections=[{
                "title": "Alert Details",
                "items": [(k, str(v)) for k, v in details.items()]
            }]
        )

    def _render_html_report(self, title: str, status: str, status_color: str,
                             summary: str, sections: list) -> str:
        """Render a clean HTML email report."""
        sections_html = ""
        for section in sections:
            rows = ""
            for i, (key, value) in enumerate(section.get("items", [])):
                bg = "#f9fafb" if i % 2 == 0 else "#ffffff"
                rows += f"""
                <tr style="background-color: {bg};">
                    <td style="padding: 8px 16px; font-weight: 600; color: #374151; width: 40%;">{key}</td>
                    <td style="padding: 8px 16px; color: #6b7280;">{value}</td>
                </tr>"""

            sections_html += f"""
            <div style="margin-bottom: 24px;">
                <h3 style="margin: 0 0 8px 0; font-size: 14px; font-weight: 700;
                           color: #1f2937; text-transform: uppercase; letter-spacing: 0.05em;">
                    {section['title']}
                </h3>
                <table style="width: 100%; border-collapse: collapse; border: 1px solid #e5e7eb;
                              border-radius: 8px; overflow: hidden; font-size: 13px;">
                    {rows}
                </table>
            </div>"""

        return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
             background-color: #f3f4f6;">
    <div style="max-width: 600px; margin: 40px auto; background: white;
                border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.07);">

        <!-- Header -->
        <div style="background: #111827; padding: 32px; text-align: center;">
            <div style="font-size: 11px; font-weight: 700; letter-spacing: 0.15em;
                        color: #6b7280; text-transform: uppercase; margin-bottom: 8px;">
                SERVER SUITE
            </div>
            <h1 style="margin: 0; font-size: 20px; font-weight: 700; color: white;">{title}</h1>
        </div>

        <!-- Status badge -->
        <div style="padding: 24px; text-align: center; border-bottom: 1px solid #e5e7eb;">
            <span style="display: inline-block; padding: 8px 24px; border-radius: 100px;
                         background-color: {status_color}; color: white;
                         font-size: 13px; font-weight: 700; letter-spacing: 0.05em;">
                {status}
            </span>
            <p style="margin: 16px 0 0 0; color: #6b7280; font-size: 14px; line-height: 1.6;">
                {summary}
            </p>
        </div>

        <!-- Report sections -->
        <div style="padding: 24px;">
            {sections_html}
        </div>

        <!-- Footer -->
        <div style="padding: 20px 24px; background: #f9fafb; border-top: 1px solid #e5e7eb;
                    text-align: center;">
            <p style="margin: 0; font-size: 12px; color: #9ca3af;">
                Generated by Server Suite on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S UTC')}
            </p>
        </div>
    </div>
</body>
</html>"""
