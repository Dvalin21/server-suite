"""
base/apparmor.py - AppArmor management
"""
import os, subprocess
from rich.console import Console
console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

def _run(cmd, timeout=30):
    if DRY_RUN: return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e: return -1, "", str(e)

class AppArmorManager:
    def enable(self) -> bool:
        console.print("[cyan]Configuring AppArmor...[/cyan]")
        _run(["apt-get", "install", "-y", "apparmor", "apparmor-utils", "apparmor-profiles"])
        _run(["systemctl", "enable", "apparmor"])
        _run(["systemctl", "start", "apparmor"])
        # Enforce key profiles
        profiles = ["usr.sbin.sshd", "usr.sbin.postfix", "usr.sbin.mysqld"]
        for p in profiles:
            _run(["aa-enforce", p])
        console.print("[green]AppArmor enabled ✓[/green]")
        return True
