"""
base/fail2ban.py
================
Fail2Ban setup and jail configuration. Generates jails dynamically
based on installed roles. Reads from journald for all container logs.
"""

import os
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

JAIL_LOCAL = Path("/etc/fail2ban/jail.local")
JAIL_DIR   = Path("/etc/fail2ban/jail.d")
FILTER_DIR = Path("/etc/fail2ban/filter.d")


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    if DRY_RUN:
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


# Per-role jail configurations
ROLE_JAILS = {
    "base": """
[sshd]
enabled  = true
port     = ssh
filter   = sshd
backend  = systemd
maxretry = 3
bantime  = 3600
findtime = 600
""",

    "web": """
[nginx-http-auth]
enabled  = true
filter   = nginx-http-auth
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 1800

[nginx-limit-req]
enabled  = true
filter   = nginx-limit-req
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 10
bantime  = 600
""",

    "mail": """
[postfix]
enabled  = true
port     = smtp,465,submission
filter   = postfix
backend  = systemd
maxretry = 3
bantime  = 3600

[dovecot]
enabled  = true
port     = pop3,pop3s,imap,imaps,submission,465,sieve
filter   = dovecot
backend  = systemd
maxretry = 5
bantime  = 3600

[postfix-sasl]
enabled  = true
port     = smtp,465,submission
filter   = postfix-sasl
backend  = systemd
maxretry = 3
bantime  = 7200
""",

    "nextcloud": """
[nextcloud]
enabled  = true
port     = http,https
filter   = nextcloud
logpath  = /opt/server-suite/docker/nextcloud/logs/nextcloud.log
maxretry = 5
bantime  = 3600
findtime = 900
""",

    "matrix": """
[matrix]
enabled  = true
port     = http,https
filter   = matrix
backend  = systemd
journalmatch = CONTAINER_NAME=matrix-synapse
maxretry = 5
bantime  = 3600
""",

    "sshd_custom": """
[sshd-custom-port]
enabled  = true
port     = {port}
filter   = sshd
backend  = systemd
maxretry = 3
bantime  = 86400
findtime = 600
""",
}


class Fail2BanManager:
    """Manages Fail2Ban installation and jail configuration."""

    def install(self) -> bool:
        rc, _, _ = _run(["which", "fail2ban-server"])
        if rc == 0:
            return True
        console.print("[cyan]Installing Fail2Ban...[/cyan]")
        rc, _, err = _run(["apt-get", "install", "-y", "fail2ban"])
        return rc == 0

    def setup_base(self) -> bool:
        """Set up Fail2Ban with base configuration."""
        console.print("[cyan]Configuring Fail2Ban...[/cyan]")

        if not self.install():
            console.print("[red]Failed to install Fail2Ban[/red]")
            return False

        self._write_jail_local()
        self._add_jail("base", ROLE_JAILS["base"])
        self._configure_nextcloud_filter()

        self.enable_and_start()
        console.print("[green]Fail2Ban configured ✓[/green]")
        return True

    def add_role_jail(self, role: str, ssh_port: int = 22) -> bool:
        """Add jails for a specific role."""
        jail_config = ROLE_JAILS.get(role)
        if not jail_config:
            return True

        if "{port}" in jail_config:
            jail_config = jail_config.replace("{port}", str(ssh_port))

        self._add_jail(role, jail_config)
        self.reload()
        return True

    def _write_jail_local(self):
        """Write the main jail.local with sensible defaults."""
        content = """[DEFAULT]
# Ban IPs for 1 hour by default
bantime  = 3600
# Check 10 minutes of log history
findtime = 600
# Allow 5 failures before banning
maxretry = 5

# Email notifications (uses postfix if configured)
# destemail = root@localhost
# sendername = Fail2Ban
# mta = sendmail
# action = %(action_mwl)s

# Use nftables/iptables backend
banaction = iptables-multiport
banaction_allports = iptables-allports

# Log level
loglevel = INFO
logtarget = SYSTEMD-JOURNAL

# Ignore local IPs
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# Docker networks - never ban
# ignoreip += 172.20.0.0/20
"""
        if not DRY_RUN:
            JAIL_LOCAL.parent.mkdir(parents=True, exist_ok=True)
            JAIL_LOCAL.write_text(content)

    def _add_jail(self, name: str, config: str):
        """Write a jail configuration file."""
        if DRY_RUN:
            console.print(f"  [dim][DRY RUN] Would write jail: {name}[/dim]")
            return
        JAIL_DIR.mkdir(parents=True, exist_ok=True)
        jail_path = JAIL_DIR / f"server-suite-{name}.conf"
        jail_path.write_text(f"# Server Suite - {name} jails\n{config}")

    def _configure_nextcloud_filter(self):
        """Add a Nextcloud-specific Fail2Ban filter."""
        filter_content = (
        "[Definition]\n"
        "failregex = ^.*Login failed: .* [(]Remote IP: '<HOST>'[)]\n"
        "            ^.*remoteAddr.*<HOST>.*Throttler.*\n"
        "ignoreregex =\n"
    )
        if not DRY_RUN:
            FILTER_DIR.mkdir(parents=True, exist_ok=True)
            (FILTER_DIR / "nextcloud.conf").write_text(filter_content)

    def enable_and_start(self) -> bool:
        _run(["systemctl", "enable", "fail2ban"])
        rc, _, err = _run(["systemctl", "restart", "fail2ban"])
        return rc == 0

    def reload(self) -> bool:
        rc, _, _ = _run(["fail2ban-client", "reload"])
        return rc == 0

    def status(self) -> str:
        rc, out, _ = _run(["fail2ban-client", "status"])
        return out if rc == 0 else "Fail2Ban not running"

    def get_banned_ips(self) -> list:
        rc, out, _ = _run(["fail2ban-client", "banned"])
        if rc == 0:
            return out.splitlines()
        return []
