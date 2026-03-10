"""
base/unattended_upgrades.py - Automatic security patches
"""
import os, subprocess
from pathlib import Path
from rich.console import Console
console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

def _run(cmd, timeout=30):
    if DRY_RUN: return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e: return -1, "", str(e)

class UnattendedUpgradesManager:
    def setup(self) -> bool:
        console.print("[cyan]Configuring automatic security updates...[/cyan]")
        _run(["apt-get", "install", "-y", "unattended-upgrades", "apt-listchanges"])

        config = """Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
"""
        auto_config = """APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
"""
        if not DRY_RUN:
            Path("/etc/apt/apt.conf.d/50unattended-upgrades").write_text(config)
            Path("/etc/apt/apt.conf.d/20auto-upgrades").write_text(auto_config)

        _run(["systemctl", "enable", "unattended-upgrades"])
        _run(["systemctl", "start", "unattended-upgrades"])
        console.print("[green]Automatic security updates enabled ✓[/green]")
        return True
