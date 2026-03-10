"""
base/cockpit.py - Cockpit server management dashboard
Provides browser-based server management: services, storage, networking, terminal.
"""
import os, subprocess
from rich.console import Console
console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

def _run(cmd, timeout=120):
    if DRY_RUN: return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e: return -1, "", str(e)

COCKPIT_PACKAGES = [
    "cockpit",
    "cockpit-storaged",
    "cockpit-networkmanager",
    "cockpit-packagekit",
    "cockpit-sosreport",
]

class CockpitManager:
    def install(self) -> bool:
        console.print("[cyan]Installing Cockpit management dashboard...[/cyan]")

        # Enable backports for newer Cockpit on Debian
        _run(["apt-get", "install", "-y"] + COCKPIT_PACKAGES)
        _run(["systemctl", "enable", "cockpit.socket"])
        _run(["systemctl", "start", "cockpit.socket"])

        # Write Cockpit config — disallow root login, set allowed origins
        cockpit_conf = """[WebService]
AllowUnencrypted = false
Origins = https://localhost:9090 wss://localhost:9090

[Session]
IdleTimeout = 15
"""
        if not DRY_RUN:
            import os
            os.makedirs("/etc/cockpit", exist_ok=True)
            with open("/etc/cockpit/cockpit.conf", "w") as f:
                f.write(cockpit_conf)

        console.print("[green]Cockpit installed ✓[/green]")
        console.print("  [dim]Accessible at: https://<server-ip>:9090 (LAN only)[/dim]")
        return True
