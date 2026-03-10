"""
base/chrony.py - NTP time synchronization via Chrony
Accurate time is critical for Kerberos (AD), TLS certs, and log correlation.
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

CHRONY_CONF = Path("/etc/chrony/chrony.conf")

class ChronyManager:
    def setup(self) -> bool:
        console.print("[cyan]Configuring NTP (Chrony)...[/cyan]")
        _run(["apt-get", "install", "-y", "chrony"])

        config = """# Server Suite - Chrony NTP Configuration
# Use pool.ntp.org with iburst for fast initial sync
pool 0.pool.ntp.org iburst
pool 1.pool.ntp.org iburst
pool 2.pool.ntp.org iburst
pool 3.pool.ntp.org iburst

# Fallback to local time source
local stratum 10

# Allow step on first start (handles large time offsets)
makestep 1.0 3

# Log tracking
logdir /var/log/chrony
log tracking measurements statistics

# Record the rate at which the system clock gains/loses time.
driftfile /var/lib/chrony/drift

# Security: only localhost can query this server's NTP status
cmdallow 127.0.0.1
cmddeny all
"""
        if not DRY_RUN and CHRONY_CONF.parent.exists():
            CHRONY_CONF.write_text(config)

        _run(["systemctl", "enable", "chrony"])
        _run(["systemctl", "restart", "chrony"])
        # Force immediate sync
        _run(["chronyc", "makestep"])
        console.print("[green]NTP (Chrony) configured ✓[/green]")
        return True
