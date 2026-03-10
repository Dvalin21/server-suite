"""
roles/web/openlitespeed.py
==========================
OpenLiteSpeed — high-performance web server, ideal for PHP workloads.
Installed natively (not Docker). Includes WebAdmin console and LSPHP.
"""

import os
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 180) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class OpenLiteSpeedInstaller:
    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir = Path(suite_dir)
        self.cm        = config_manager
        self.sm        = secrets_manager

    def install(self, config: dict) -> bool:
        console.print("\n[bold cyan]Installing OpenLiteSpeed[/bold cyan]\n")

        # Add OpenLiteSpeed repository
        console.print("[cyan]Adding OpenLiteSpeed repository...[/cyan]")
        rc, _, err = _run([
            "bash", "-c",
            "wget -q -O - https://repo.litespeed.sh | bash"
        ], timeout=120)
        if rc != 0:
            console.print(f"[red]Failed to add OLS repo: {err}[/red]")
            return False

        _run(["apt-get", "update", "-qq"])

        # Install OLS + LSPHP 8.3
        console.print("[cyan]Installing OpenLiteSpeed + LSPHP 8.3...[/cyan]")
        packages = [
            "openlitespeed",
            "lsphp83",
            "lsphp83-common",
            "lsphp83-mysql",
            "lsphp83-curl",
            "lsphp83-json",
            "lsphp83-zip",
            "lsphp83-xml",
            "lsphp83-intl",
            "lsphp83-mbstring",
            "lsphp83-gd",
            "lsphp83-redis",
        ]
        rc, _, err = _run(["apt-get", "install", "-y"] + packages, timeout=300)
        if rc != 0:
            console.print(f"[red]OLS installation failed: {err}[/red]")
            return False

        # Generate admin password
        admin_pass = (self.sm.generate_password(16, exclude_special=True)
                      if self.sm else "ChangeMe123!")

        # Set admin password
        _run(["/usr/local/lsws/admin/misc/admpass.sh"],
             timeout=30)

        # Write admin password to secrets
        if self.sm:
            self.sm.write_env_file("openlitespeed", {
                "OLS_ADMIN_USER":     "admin",
                "OLS_ADMIN_PASSWORD": admin_pass,
                "OLS_ADMIN_PORT":     "7080",
            })

        # Configure OLS to use LSPHP 8.3
        self._configure_php()

        # Enable and start
        _run(["systemctl", "enable", "lsws"])
        _run(["systemctl", "start", "lsws"])

        # Verify
        time.sleep(3)
        rc2, out2, _ = _run(["systemctl", "is-active", "lsws"])
        if rc2 != 0 or "active" not in out2:
            console.print("[yellow]OLS may not have started correctly — check 'systemctl status lsws'[/yellow]")

        if self.cm:
            self.cm.register_port(8088, "openlitespeed", "tcp", external=True,
                                  description="OpenLiteSpeed HTTP (default)")
            self.cm.register_port(7080, "openlitespeed-admin", "tcp", external=False,
                                  description="OLS WebAdmin (LAN only)")
            self.cm.register_service_url(
                "openlitespeed-admin",
                "https://<server-ip>:7080",
                f"OLS WebAdmin — user: admin / pass: {admin_pass}"
            )
            self.cm.add_role("web", {
                "engine": "openlitespeed",
                "admin_port": 7080,
            })

        console.print("[bold green]OpenLiteSpeed installed ✓[/bold green]")
        console.print(f"  [dim]WebAdmin: https://<server-ip>:7080[/dim]")
        console.print(f"  [dim]Admin password stored in secrets/.env.openlitespeed[/dim]")
        return True

    def _configure_php(self):
        """Point OLS to the installed LSPHP binary."""
        php_path = "/usr/local/lsws/lsphp83/bin/lsphp"
        ols_conf = Path("/usr/local/lsws/conf/httpd_config.conf")
        if ols_conf.exists() and not DRY_RUN:
            content = ols_conf.read_text()
            if "lsphp74" in content:
                content = content.replace("lsphp74", "lsphp83")
                ols_conf.write_text(content)


class Installer:
    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm = config_manager
        self.sm = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        return OpenLiteSpeedInstaller(self.suite_dir, self.cm, self.sm).install(config)
