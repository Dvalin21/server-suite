"""
roles/identity/replica.py
=========================
FreeIPA replica installation and management.
A replica provides HA for authentication — if the primary IPA server
goes down, clients continue to authenticate against the replica.

Replica requires:
  - Another server enrolled as an IPA client
  - Network access to the primary IPA server
  - Same or newer IPA version
  - DNS delegation (if using integrated DNS)
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 300) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


REPLICA_PREP_SCRIPT = """#!/usr/bin/env bash
# =============================================================================
# Server Suite — FreeIPA Replica Preparation
# Run this ON THE PRIMARY IPA SERVER to prepare a replica.
# =============================================================================
set -euo pipefail

REPLICA_HOSTNAME="{replica_fqdn}"
ADMIN_PASSWORD="{admin_password}"

echo "=== Preparing FreeIPA replica for: $REPLICA_HOSTNAME ==="

# Verify replica host exists in IPA
if ! ipa host-show "$REPLICA_HOSTNAME" &>/dev/null; then
    echo "Adding host $REPLICA_HOSTNAME to IPA..."
    ipa host-add "$REPLICA_HOSTNAME" --force
fi

# Grant replica permissions
kinit admin <<< "$ADMIN_PASSWORD"
ipa hostgroup-add-member ipaservers --hosts="$REPLICA_HOSTNAME" 2>/dev/null || true

echo "=== Primary preparation complete ==="
echo "Now run 'ipa-replica-install' on $REPLICA_HOSTNAME"
"""

REPLICA_INSTALL_SCRIPT = """#!/usr/bin/env bash
# =============================================================================
# Server Suite — FreeIPA Replica Installation
# Run this ON THE REPLICA SERVER (must already be enrolled as IPA client).
# =============================================================================
set -euo pipefail

PRIMARY_SERVER="{primary_fqdn}"
ADMIN_PASSWORD="{admin_password}"
SETUP_DNS="{setup_dns}"
SETUP_CA="{setup_ca}"

echo "=== Installing FreeIPA Replica ==="
echo "Primary server: $PRIMARY_SERVER"

# Install replica packages
apt-get update -qq
apt-get install -y freeipa-server{dns_pkg}

# Get admin ticket
echo "$ADMIN_PASSWORD" | kinit admin

# Run replica install
REPLICA_CMD=(
    ipa-replica-install
    --unattended
    --principal=admin
    --admin-password="$ADMIN_PASSWORD"
    --mkhomedir
)

if [[ "$SETUP_DNS" == "true" ]]; then
    REPLICA_CMD+=(--setup-dns --auto-reverse --forwarder=1.1.1.1)
fi

if [[ "$SETUP_CA" == "true" ]]; then
    REPLICA_CMD+=(--setup-ca)
fi

"${{REPLICA_CMD[@]}}"

echo "=== Replica installation complete ==="
echo "Verify with: ipa-replica-manage list"
"""


class FreeIPAReplicaManager:
    """Manages FreeIPA replica setup and monitoring."""

    def __init__(self, suite_dir: Path, config_manager=None, secrets_manager=None):
        self.suite_dir   = Path(suite_dir)
        self.cm          = config_manager
        self.sm          = secrets_manager
        self.scripts_dir = self.suite_dir / "scripts"

    def setup_replica(self, config: dict) -> bool:
        """Generate scripts and instructions for adding a replica."""
        console.print("\n[bold cyan]FreeIPA Replica Setup[/bold cyan]\n")

        ipa_cfg = self.cm.get("roles.identity") if self.cm else {}
        if not ipa_cfg:
            console.print("[red]FreeIPA not configured on this server.[/red]")
            return False

        primary_fqdn    = ipa_cfg.get("fqdn", "")
        realm           = ipa_cfg.get("realm", "")
        setup_dns       = ipa_cfg.get("manage_dns", False)
        setup_ca        = ipa_cfg.get("setup_ca", False)

        console.print(Panel(
            f"[bold]Replica Prerequisites[/bold]\n\n"
            "  • Target server must be running Ubuntu/Debian\n"
            "  • Must be network-reachable from this server\n"
            "  • Must have the same or newer OS version\n"
            "  • Ports 88, 389, 636, 464 must be open between servers\n"
            "  • At least 2GB RAM on the replica",
            border_style="yellow",
        ))

        replica_fqdn = Prompt.ask("\n  Replica server FQDN")
        replica_ip   = Prompt.ask("  Replica server IP")

        if not Confirm.ask(f"\n  Set up replica on {replica_fqdn}?", default=True):
            return False

        admin_password = ""
        if self.sm:
            env_data = self.sm.read_env_file("freeipa")
            admin_password = env_data.get("IPA_ADMIN_PASSWORD", "")
        if not admin_password:
            admin_password = Prompt.ask("  IPA admin password", password=True)

        # Generate prep script (runs on primary)
        prep_script = REPLICA_PREP_SCRIPT.format(
            replica_fqdn=replica_fqdn,
            admin_password=admin_password,
        )

        # Generate install script (runs on replica)
        install_script = REPLICA_INSTALL_SCRIPT.format(
            primary_fqdn=primary_fqdn,
            admin_password=admin_password,
            setup_dns="true" if setup_dns else "false",
            setup_ca="true" if setup_ca else "false",
            dns_pkg=" freeipa-server-dns" if setup_dns else "",
        )

        if not DRY_RUN:
            self.scripts_dir.mkdir(parents=True, exist_ok=True)
            prep_path    = self.scripts_dir / "ipa-replica-prep.sh"
            install_path = self.scripts_dir / "ipa-replica-install.sh"
            prep_path.write_text(prep_script)
            install_path.write_text(install_script)
            os.chmod(prep_path,    0o750)
            os.chmod(install_path, 0o750)

        # Run prep on this (primary) server
        console.print("\n[cyan]Running replica preparation on primary server...[/cyan]")
        rc, out, err = _run(["bash", str(self.scripts_dir / "ipa-replica-prep.sh")])
        if rc != 0:
            console.print(f"[yellow]Prep warning: {err}[/yellow]")

        # Add replica host to /etc/hosts if not in DNS yet
        console.print(f"\n[cyan]Adding {replica_fqdn} to /etc/hosts...[/cyan]")
        if not DRY_RUN:
            hosts = Path("/etc/hosts").read_text()
            if replica_fqdn not in hosts:
                with open("/etc/hosts", "a") as f:
                    f.write(f"\n{replica_ip}\t{replica_fqdn}\n")

        # Print instructions
        console.print()
        console.print(Panel(
            f"[bold]Replica Installation Steps[/bold]\n\n"
            f"  [bold]1.[/bold] Copy the install script to the replica:\n"
            f"  [cyan]scp {self.scripts_dir}/ipa-replica-install.sh "
            f"root@{replica_ip}:/tmp/[/cyan]\n\n"
            f"  [bold]2.[/bold] Copy the client enrollment script first:\n"
            f"  [cyan]scp {self.scripts_dir}/enroll-ipa-client.sh "
            f"root@{replica_ip}:/tmp/[/cyan]\n\n"
            f"  [bold]3.[/bold] On the replica server, enroll as client then install:\n"
            f"  [cyan]bash /tmp/enroll-ipa-client.sh {admin_password}[/cyan]\n"
            f"  [cyan]bash /tmp/ipa-replica-install.sh[/cyan]\n\n"
            f"  [bold]4.[/bold] Verify replication from this server:\n"
            f"  [cyan]ipa-replica-manage list[/cyan]\n"
            f"  [cyan]ipa-replica-manage status {replica_fqdn}[/cyan]",
            border_style="cyan",
            padding=(1, 2),
        ))

        return True

    def check_replication_status(self) -> bool:
        """Check replication status across all replicas."""
        console.print("\n[bold]Replication Status[/bold]\n")
        rc, out, _ = _run(["ipa-replica-manage", "list"], timeout=30)
        if rc == 0 and out:
            replicas = [line.strip() for line in out.splitlines() if line.strip()]
            for replica in replicas:
                console.print(f"  [dim]Checking {replica}...[/dim]")
                rc2, out2, _ = _run(["ipa-replica-manage", "status", replica], timeout=30)
                if "in sync" in (out2 or "").lower():
                    console.print(f"  [green]✓ {replica}: In sync[/green]")
                else:
                    console.print(f"  [yellow]⚠ {replica}: {out2 or 'Unknown status'}[/yellow]")
        else:
            console.print("[dim]No replicas configured or could not connect.[/dim]")
        return True
