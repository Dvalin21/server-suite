"""
core/firewall.py
================
Unified firewall management using nftables as the backend with UFW frontend.
Handles Docker's iptables bypass issue and builds rules dynamically
based on installed roles.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()

DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


# ---------------------------------------------------------------------------
# Port definitions per role
# ---------------------------------------------------------------------------

ROLE_PORTS = {
    "web": {
        "public": [
            (80,  "tcp", "HTTP"),
            (443, "tcp", "HTTPS"),
        ],
        "lan": []
    },
    "mailcow": {
        "public": [
            (25,  "tcp", "SMTP"),
            (465, "tcp", "SMTPS"),
            (587, "tcp", "Submission"),
            (993, "tcp", "IMAPS"),
            (143, "tcp", "IMAP"),
            (110, "tcp", "POP3"),
            (995, "tcp", "POP3S"),
        ],
        "lan": []
    },
    "dns_technitium": {
        "public": [
            (53, "tcp", "DNS"),
            (53, "udp", "DNS"),
        ],
        "lan": [
            (5380, "tcp", "Technitium WebUI"),
        ]
    },
    "dns_bind9": {
        "public": [
            (53, "tcp", "DNS"),
            (53, "udp", "DNS"),
        ],
        "lan": []
    },
    "dhcp": {
        "public": [
            (67, "udp", "DHCP"),
            (68, "udp", "DHCP client"),
        ],
        "lan": []
    },
    "wireguard": {
        "public": [
            (51820, "udp", "WireGuard"),
        ],
        "lan": [
            (51821, "tcp", "WireGuard-UI"),
        ]
    },
    "openvpn": {
        "public": [
            (1194, "udp", "OpenVPN"),
        ],
        "lan": [
            (943, "tcp", "OpenVPN Admin"),
        ]
    },
    "matrix": {
        "public": [
            (8448, "tcp", "Matrix Federation"),
        ],
        "lan": []
    },
    "jitsi": {
        "public": [
            (3478, "udp", "STUN/TURN"),
            (10000, "udp", "Jitsi Media"),
        ],
        "lan": []
    },
    "cockpit": {
        "public": [],
        "lan": [
            (9090, "tcp", "Cockpit"),
        ]
    },
    "wazuh": {
        "public": [],
        "lan": [
            (1514, "tcp", "Wazuh Agent"),
            (1515, "tcp", "Wazuh Registration"),
            (55000, "tcp", "Wazuh API"),
        ]
    },
    "setup_ui": {
        "public": [],
        "lan": [
            (7070, "tcp", "Setup UI (temporary)"),
        ]
    }
}


# ---------------------------------------------------------------------------
# UFW Manager
# ---------------------------------------------------------------------------

class FirewallManager:
    """Manages UFW firewall rules dynamically based on installed roles."""

    def __init__(self):
        self._lan_subnets = self._detect_lan_subnets()

    def _detect_lan_subnets(self) -> list:
        """Detect LAN subnets from network interfaces."""
        subnets = []
        rc, out, _ = _run(["ip", "-o", "-f", "inet", "addr", "show"])
        if rc == 0:
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    iface = parts[1]
                    cidr = parts[3]
                    # Skip loopback and Docker interfaces
                    if not iface.startswith(("lo", "docker", "br-", "veth")):
                        # Extract network address
                        ip = cidr.split("/")[0]
                        prefix = cidr.split("/")[1] if "/" in cidr else "24"
                        # Convert to network address (simplified)
                        octets = ip.split(".")
                        if len(octets) == 4:
                            subnets.append(f"{'.'.join(octets[:3])}.0/{prefix}")
        return subnets or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    # -----------------------------------------------------------------------
    # Installation
    # -----------------------------------------------------------------------

    def install_ufw(self) -> bool:
        """Install UFW if not present."""
        rc, _, _ = _run(["which", "ufw"])
        if rc == 0:
            console.print("[green]UFW already installed ✓[/green]")
            return True

        console.print("[cyan]Installing UFW...[/cyan]")
        rc, _, err = _run(["apt-get", "install", "-y", "ufw"])
        if rc != 0:
            console.print(f"[red]Failed to install UFW: {err}[/red]")
            return False
        return True

    # -----------------------------------------------------------------------
    # Docker + UFW integration
    # -----------------------------------------------------------------------

    def configure_docker_ufw_integration(self) -> bool:
        """
        Prevent Docker from bypassing UFW.
        Docker's daemon.json has iptables=false (set by docker_engine.py).
        This adds the necessary nftables/iptables rules so Docker containers
        can still communicate, but all external traffic goes through UFW.
        """
        console.print("[cyan]Configuring Docker/UFW integration...[/cyan]")

        # Create UFW before.rules addition for Docker
        before_rules_addition = """
# BEGIN Docker UFW rules
# Allow Docker containers to access the internet via NAT
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING ! -o docker+ -s 172.17.0.0/8 -j MASQUERADE
COMMIT

# Allow established Docker connections
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -j RETURN
COMMIT
# END Docker UFW rules
"""
        before_rules_path = Path("/etc/ufw/before.rules")
        if before_rules_path.exists():
            content = before_rules_path.read_text()
            if "BEGIN Docker UFW rules" not in content:
                # Insert before the *filter section
                content = before_rules_addition + content
                if not DRY_RUN:
                    before_rules_path.write_text(content)
                console.print("  [dim]Added Docker NAT rules to UFW before.rules ✓[/dim]")

        # Configure UFW to forward packets (needed for Docker)
        sysctl_conf = Path("/etc/ufw/sysctl.conf")
        if sysctl_conf.exists():
            content = sysctl_conf.read_text()
            if "net/ipv4/ip_forward=1" not in content:
                if not DRY_RUN:
                    with open(sysctl_conf, "a") as f:
                        f.write("\n# Docker networking\nnet/ipv4/ip_forward=1\n")
                console.print("  [dim]Enabled IP forwarding for Docker ✓[/dim]")

        # Enable UFW forwarding policy
        ufw_default = Path("/etc/default/ufw")
        if ufw_default.exists():
            content = ufw_default.read_text()
            if not DRY_RUN:
                content = content.replace(
                    'DEFAULT_FORWARD_POLICY="DROP"',
                    'DEFAULT_FORWARD_POLICY="ACCEPT"'
                )
                ufw_default.write_text(content)

        console.print("[green]Docker/UFW integration configured ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # Rule management
    # -----------------------------------------------------------------------

    def reset_and_configure_baseline(self) -> bool:
        """Set up baseline UFW configuration."""
        console.print("[cyan]Configuring UFW baseline...[/cyan]")

        commands = [
            # Disable first to configure safely
            ["ufw", "--force", "disable"],
            # Reset all rules
            ["ufw", "--force", "reset"],
            # Set default policies
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
            # Allow SSH (critical — must be before enable)
            ["ufw", "allow", "ssh"],
        ]

        for cmd in commands:
            rc, _, err = _run(cmd)
            if rc != 0:
                console.print(f"[yellow]Warning: {' '.join(cmd)} failed: {err}[/yellow]")

        console.print("[green]UFW baseline configured ✓[/green]")
        return True

    def add_role_rules(self, role: str) -> bool:
        """Add UFW rules for a specific role."""
        role_config = ROLE_PORTS.get(role)
        if not role_config:
            console.print(f"[yellow]No port config for role: {role}[/yellow]")
            return True

        # Public rules
        for port, proto, description in role_config.get("public", []):
            self.allow_port(port, proto, source="any", comment=f"{role}: {description}")

        # LAN-only rules
        for port, proto, description in role_config.get("lan", []):
            for subnet in self._lan_subnets:
                self.allow_port(port, proto, source=subnet,
                                comment=f"{role} (LAN only): {description}")

        return True

    def remove_role_rules(self, role: str) -> bool:
        """Remove UFW rules for a specific role."""
        role_config = ROLE_PORTS.get(role)
        if not role_config:
            return True

        all_ports = role_config.get("public", []) + role_config.get("lan", [])
        for port, proto, _ in all_ports:
            rc, _, err = _run(["ufw", "delete", "allow", f"{port}/{proto}"])
            if rc != 0:
                console.print(f"[yellow]Warning removing port {port}: {err}[/yellow]")

        return True

    def allow_port(self, port: int, proto: str = "tcp",
                   source: str = "any", comment: str = "") -> bool:
        """Add a UFW allow rule."""
        if source == "any":
            cmd = ["ufw", "allow", f"{port}/{proto}"]
        else:
            cmd = ["ufw", "allow", "from", source, "to", "any", "port", str(port), "proto", proto]

        rc, _, err = _run(cmd)
        if rc != 0:
            console.print(f"[yellow]UFW rule failed (port {port}/{proto}): {err}[/yellow]")
            return False

        desc = f"port {port}/{proto}"
        if source != "any":
            desc += f" from {source}"
        if comment:
            desc += f" ({comment})"
        console.print(f"  [dim]✓ Allowed {desc}[/dim]")
        return True

    def deny_port(self, port: int, proto: str = "tcp") -> bool:
        """Add a UFW deny rule."""
        rc, _, err = _run(["ufw", "deny", f"{port}/{proto}"])
        return rc == 0

    def allow_ssh(self, custom_port: Optional[int] = None) -> bool:
        """Allow SSH — critical to not lock yourself out."""
        if custom_port:
            return self.allow_port(custom_port, "tcp", comment="SSH (custom port)")
        rc, _, _ = _run(["ufw", "allow", "ssh"])
        return rc == 0

    def add_temporary_setup_ui(self) -> bool:
        """Temporarily open setup UI port for LAN only."""
        console.print("[cyan]Opening Setup UI port 7070 (LAN only, temporary)...[/cyan]")
        for subnet in self._lan_subnets:
            self.allow_port(7070, "tcp", source=subnet, comment="Setup UI (temporary)")
        return True

    def remove_setup_ui(self) -> bool:
        """Remove the temporary setup UI port after setup completes."""
        console.print("[cyan]Closing temporary Setup UI port 7070...[/cyan]")
        _run(["ufw", "delete", "allow", "7070/tcp"])
        for subnet in self._lan_subnets:
            _run(["ufw", "delete", "allow", "from", subnet, "to", "any", "port", "7070", "proto", "tcp"])
        return True

    # -----------------------------------------------------------------------
    # Enable / disable
    # -----------------------------------------------------------------------

    def enable(self) -> bool:
        """Enable UFW."""
        console.print("[cyan]Enabling UFW...[/cyan]")
        rc, _, err = _run(["ufw", "--force", "enable"])
        if rc != 0:
            console.print(f"[red]Failed to enable UFW: {err}[/red]")
            return False
        console.print("[green]UFW enabled ✓[/green]")
        return True

    def reload(self) -> bool:
        """Reload UFW rules."""
        rc, _, err = _run(["ufw", "reload"])
        return rc == 0

    def status(self) -> str:
        """Get UFW status."""
        rc, out, _ = _run(["ufw", "status", "verbose"])
        return out if rc == 0 else "UFW status unavailable"

    def get_rules_summary(self) -> list:
        """Parse and return current UFW rules as a list."""
        rc, out, _ = _run(["ufw", "status", "numbered"])
        if rc != 0:
            return []
        rules = []
        for line in out.splitlines():
            if line.strip().startswith("["):
                rules.append(line.strip())
        return rules

    # -----------------------------------------------------------------------
    # Full setup
    # -----------------------------------------------------------------------

    def full_setup(self, ssh_port: int = 22) -> bool:
        """Complete firewall setup."""
        console.print("\n[bold cyan]Configuring Firewall (UFW + nftables)[/bold cyan]\n")

        if not self.install_ufw():
            return False

        if not self.configure_docker_ufw_integration():
            return False

        if not self.reset_and_configure_baseline():
            return False

        # Ensure SSH is allowed before enabling
        self.allow_ssh(ssh_port if ssh_port != 22 else None)

        # Add setup UI temporarily
        self.add_temporary_setup_ui()

        if not self.enable():
            return False

        console.print("\n[green]Firewall configured and enabled ✓[/green]")
        console.print("[dim]  Default: deny all inbound, allow all outbound[/dim]")
        console.print("[dim]  SSH: allowed[/dim]")
        console.print("[dim]  Setup UI: allowed from LAN (temporary)[/dim]")
        console.print("[dim]  All other ports: added as roles are installed[/dim]")
        return True
