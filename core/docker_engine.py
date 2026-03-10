"""
core/docker_engine.py
=====================
Docker installation, daemon hardening, network management,
and compose orchestration. Security-first Docker setup.
"""

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

# Hardened Docker daemon configuration
DAEMON_CONFIG = {
    "iptables": False,
    "userland-proxy": False,
    "log-driver": "journald",
    "log-opts": {
        "tag": "docker/{{.Name}}"
    },
    "live-restore": True,
    "no-new-privileges": True,
    "storage-driver": "overlay2",
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    },
    "max-concurrent-downloads": 3,
    "max-concurrent-uploads": 3,
}

# Docker network subnet map
NETWORK_SUBNETS = {
    "proxy_network":    "172.20.0.0/24",
    "db_network":       "172.20.1.0/24",
    "mail_network":     "172.20.2.0/24",
    "identity_network": "172.20.3.0/24",
    "monitor_network":  "172.20.4.0/24",
    "storage_network":  "172.20.5.0/24",
    "comms_network":    "172.20.6.0/24",
    "vpn_network":      "172.20.7.0/24",
    "logging_network":  "172.20.8.0/24",
}


def _run(cmd: list, timeout: int = 300, capture: bool = True) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] Would run: {' '.join(cmd)}[/dim]")
        return 0, "", ""
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


class DockerEngine:
    """Manages Docker installation and configuration."""

    def __init__(self, suite_dir: Path):
        self.suite_dir = Path(suite_dir)

    # -----------------------------------------------------------------------
    # Installation
    # -----------------------------------------------------------------------

    def is_installed(self) -> bool:
        rc, _, _ = _run(["docker", "--version"])
        return rc == 0

    def get_version(self) -> Optional[str]:
        rc, out, _ = _run(["docker", "--version"])
        return out if rc == 0 else None

    def install(self) -> bool:
        """Install Docker Engine from the official Docker repository."""
        if self.is_installed():
            console.print(f"[green]Docker already installed: {self.get_version()}[/green]")
            return True

        console.print("[cyan]Installing Docker Engine...[/cyan]")

        # Detect OS
        with open("/etc/os-release") as f:
            os_info = {}
            for line in f:
                k, _, v = line.partition("=")
                os_info[k.strip()] = v.strip().strip('"')

        os_id = os_info.get("ID", "")
        codename = os_info.get("VERSION_CODENAME", "")

        steps = [
            # Remove old Docker packages
            (["apt-get", "remove", "-y",
              "docker", "docker-engine", "docker.io", "containerd", "runc"],
             "Removing old Docker packages"),

            # Install prerequisites
            (["apt-get", "install", "-y",
              "ca-certificates", "curl", "gnupg", "lsb-release"],
             "Installing prerequisites"),
        ]

        for cmd, description in steps:
            console.print(f"  [dim]{description}...[/dim]")
            rc, _, err = _run(cmd)
            if rc != 0 and "E: " in err:
                console.print(f"  [yellow]Warning: {err}[/yellow]")

        # Add Docker's GPG key
        console.print("  [dim]Adding Docker GPG key...[/dim]")
        Path("/etc/apt/keyrings").mkdir(parents=True, exist_ok=True)
        rc, _, err = _run([
            "bash", "-c",
            "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | "
            "gpg --dearmor -o /etc/apt/keyrings/docker.gpg"
        ])
        if rc != 0:
            console.print(f"[red]Failed to add Docker GPG key: {err}[/red]")
            return False
        os.chmod("/etc/apt/keyrings/docker.gpg", 0o644)

        # Add Docker repository
        console.print("  [dim]Adding Docker repository...[/dim]")
        arch_rc, arch, _ = _run(["dpkg", "--print-architecture"])
        arch = arch.strip() if arch_rc == 0 else "amd64"

        repo_line = (
            f"deb [arch={arch} signed-by=/etc/apt/keyrings/docker.gpg] "
            f"https://download.docker.com/linux/{os_id} {codename} stable"
        )
        with open("/etc/apt/sources.list.d/docker.list", "w") as f:
            f.write(repo_line + "\n")

        # Install Docker
        rc, _, err = _run(["apt-get", "update", "-qq"])
        if rc != 0:
            console.print(f"[red]Failed to update package lists: {err}[/red]")
            return False

        rc, _, err = _run([
            "apt-get", "install", "-y",
            "docker-ce", "docker-ce-cli", "containerd.io",
            "docker-buildx-plugin", "docker-compose-plugin"
        ], timeout=600)

        if rc != 0:
            console.print(f"[red]Failed to install Docker: {err}[/red]")
            return False

        console.print("[green]Docker installed successfully ✓[/green]")
        return True

    def install_compose(self) -> bool:
        """Ensure Docker Compose v2 is available."""
        rc, out, _ = _run(["docker", "compose", "version"])
        if rc == 0:
            console.print(f"[green]Docker Compose available: {out}[/green]")
            return True

        # Try standalone compose
        rc, out, _ = _run(["docker-compose", "--version"])
        if rc == 0:
            console.print(f"[green]Docker Compose available: {out}[/green]")
            return True

        console.print("[yellow]Docker Compose not found, installing...[/yellow]")
        rc, _, err = _run(["apt-get", "install", "-y", "docker-compose-plugin"])
        return rc == 0

    # -----------------------------------------------------------------------
    # Daemon hardening
    # -----------------------------------------------------------------------

    def configure_daemon(self) -> bool:
        """Write hardened daemon.json configuration."""
        daemon_path = Path("/etc/docker/daemon.json")
        daemon_path.parent.mkdir(parents=True, exist_ok=True)

        # Merge with existing config if present
        existing = {}
        if daemon_path.exists():
            try:
                with open(daemon_path) as f:
                    existing = json.load(f)
            except json.JSONDecodeError:
                pass

        # Our hardened config takes precedence
        merged = {**existing, **DAEMON_CONFIG}

        if DRY_RUN:
            console.print(f"  [dim][DRY RUN] Would write daemon.json:[/dim]")
            console.print(f"  [dim]{json.dumps(merged, indent=2)}[/dim]")
            return True

        with open(daemon_path, "w") as f:
            json.dump(merged, f, indent=2)
        os.chmod(daemon_path, 0o644)

        console.print("[green]Docker daemon hardened ✓[/green]")
        console.print("  [dim]iptables=false (UFW/nftables handles all firewall rules)[/dim]")
        console.print("  [dim]no-new-privileges=true[/dim]")
        console.print("  [dim]log-driver=journald (all container logs → systemd journal)[/dim]")

        # Restart Docker to apply
        return self.restart()

    def restart(self) -> bool:
        """Restart Docker daemon."""
        console.print("[cyan]Restarting Docker daemon...[/cyan]")
        rc, _, err = _run(["systemctl", "restart", "docker"])
        if rc != 0:
            console.print(f"[red]Failed to restart Docker: {err}[/red]")
            return False

        # Wait for Docker to be ready
        for _ in range(30):
            rc, _, _ = _run(["docker", "info"])
            if rc == 0:
                console.print("[green]Docker daemon restarted ✓[/green]")
                return True
            time.sleep(1)

        console.print("[red]Docker daemon failed to start[/red]")
        return False

    def enable_service(self) -> bool:
        """Enable Docker to start on boot."""
        rc, _, err = _run(["systemctl", "enable", "docker"])
        if rc != 0:
            console.print(f"[yellow]Warning: Could not enable Docker service: {err}[/yellow]")
            return False
        return True

    # -----------------------------------------------------------------------
    # Network management
    # -----------------------------------------------------------------------

    def get_existing_subnets(self) -> list:
        """Get all subnets currently in use on the host."""
        subnets = []

        # Host network interfaces
        rc, out, _ = _run(["ip", "-j", "addr"])
        if rc == 0:
            try:
                interfaces = json.loads(out)
                for iface in interfaces:
                    for addr in iface.get("addr_info", []):
                        if addr.get("family") == "inet":
                            subnets.append(addr.get("local", ""))
            except json.JSONDecodeError:
                pass

        # Existing Docker networks
        rc, out, _ = _run(["docker", "network", "ls", "--format", "{{.ID}}"])
        if rc == 0:
            for network_id in out.splitlines():
                rc2, detail, _ = _run(["docker", "network", "inspect", network_id.strip()])
                if rc2 == 0:
                    try:
                        data = json.loads(detail)
                        for net in data:
                            for config in net.get("IPAM", {}).get("Config", []):
                                subnet = config.get("Subnet", "")
                                if subnet:
                                    subnets.append(subnet.split("/")[0])
                    except (json.JSONDecodeError, KeyError):
                        pass

        return subnets

    def resolve_subnet_conflicts(self) -> dict:
        """
        Check for subnet conflicts and adjust if needed.
        Returns the final subnet map.
        """
        existing = self.get_existing_subnets()
        resolved = {}
        offset = 0

        for network_name, subnet in NETWORK_SUBNETS.items():
            base_ip = subnet.split("/")[0]
            candidate_subnet = subnet

            # Check for conflict
            while any(base_ip.startswith(e.rsplit(".", 1)[0]) for e in existing if e):
                # Increment the third octet
                parts = base_ip.split(".")
                try:
                    parts[2] = str(int(parts[2]) + 10 + offset)
                    base_ip = ".".join(parts)
                    candidate_subnet = f"{base_ip}/24"
                    offset += 1
                except (ValueError, IndexError):
                    break

            resolved[network_name] = candidate_subnet

        return resolved

    def create_network(self, name: str, subnet: str, internal: bool = True) -> bool:
        """Create a Docker network with specified subnet."""
        # Check if already exists
        rc, out, _ = _run(["docker", "network", "ls", "--format", "{{.Name}}"])
        if rc == 0 and name in out.splitlines():
            console.print(f"  [dim]Network {name} already exists[/dim]")
            return True

        cmd = [
            "docker", "network", "create",
            "--driver", "bridge",
            "--subnet", subnet,
            "--opt", "com.docker.network.bridge.enable_icc=true",
        ]

        if internal:
            cmd.append("--internal")

        cmd.append(name)

        rc, _, err = _run(cmd)
        if rc != 0:
            console.print(f"[red]Failed to create network {name}: {err}[/red]")
            return False

        console.print(f"[green]Network {name} ({subnet}) created ✓[/green]")
        return True

    def create_all_networks(self, subnet_map: Optional[dict] = None) -> bool:
        """Create all required Docker networks."""
        if subnet_map is None:
            subnet_map = self.resolve_subnet_conflicts()

        console.print("\n[cyan]Creating Docker networks...[/cyan]")

        # proxy_network needs external access (not internal)
        for name, subnet in subnet_map.items():
            internal = name != "proxy_network" and name != "vpn_network"
            if not self.create_network(name, subnet, internal=internal):
                return False

        return True

    # -----------------------------------------------------------------------
    # Compose operations
    # -----------------------------------------------------------------------

    def compose_up(self, compose_file: Path, service_name: str = "",
                   timeout: int = 600) -> bool:
        """Bring up a Docker Compose stack."""
        cmd = ["docker", "compose", "-f", str(compose_file), "up", "-d"]
        if service_name:
            cmd.append(service_name)

        console.print(f"[cyan]Starting {compose_file.parent.name}...[/cyan]")
        rc, out, err = _run(cmd, timeout=timeout)
        if rc != 0:
            console.print(f"[red]Failed to start service: {err}[/red]")
            return False

        console.print(f"[green]Service started ✓[/green]")
        return True

    def compose_down(self, compose_file: Path, remove_volumes: bool = False) -> bool:
        """Bring down a Docker Compose stack."""
        cmd = ["docker", "compose", "-f", str(compose_file), "down"]
        if remove_volumes:
            cmd.append("-v")
        rc, _, err = _run(cmd)
        if rc != 0:
            console.print(f"[red]Failed to stop service: {err}[/red]")
            return False
        return True

    def compose_pull(self, compose_file: Path) -> bool:
        """Pull latest images for a compose stack."""
        rc, _, err = _run(
            ["docker", "compose", "-f", str(compose_file), "pull"],
            timeout=600
        )
        if rc != 0:
            console.print(f"[yellow]Warning: Image pull failed: {err}[/yellow]")
            return False
        return True

    def is_service_healthy(self, container_name: str,
                           timeout_seconds: int = 120) -> bool:
        """Wait for a container to report healthy status."""
        console.print(f"  [dim]Waiting for {container_name} to become healthy...[/dim]")

        for elapsed in range(timeout_seconds):
            rc, out, _ = _run([
                "docker", "inspect",
                "--format", "{{.State.Health.Status}}",
                container_name
            ])

            if rc == 0:
                status = out.strip()
                if status == "healthy":
                    console.print(f"  [green]{container_name} is healthy ✓[/green]")
                    return True
                elif status == "unhealthy":
                    console.print(f"  [red]{container_name} is unhealthy[/red]")
                    self._print_container_logs(container_name, lines=20)
                    return False
                # "starting" — keep waiting

            time.sleep(2)
            if elapsed % 20 == 0 and elapsed > 0:
                console.print(f"  [dim]Still waiting... ({elapsed}s)[/dim]")

        console.print(f"  [yellow]Timeout waiting for {container_name}[/yellow]")
        return False

    def _print_container_logs(self, container_name: str, lines: int = 50):
        rc, out, _ = _run(["docker", "logs", "--tail", str(lines), container_name])
        if rc == 0 and out:
            console.print(f"\n[dim]--- {container_name} logs ---[/dim]")
            for line in out.splitlines()[-lines:]:
                console.print(f"  [dim]{line}[/dim]")

    # -----------------------------------------------------------------------
    # System info
    # -----------------------------------------------------------------------

    def get_info(self) -> dict:
        """Get Docker system information."""
        rc, out, _ = _run(["docker", "info", "--format", "{{json .}}"])
        if rc == 0:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                pass
        return {}

    def full_setup(self) -> bool:
        """Complete Docker setup: install, harden, networks, enable."""
        console.print("\n[bold cyan]Setting up Docker Engine[/bold cyan]\n")

        if not self.install():
            return False

        if not self.install_compose():
            console.print("[yellow]Warning: Docker Compose not available[/yellow]")

        if not self.configure_daemon():
            return False

        if not self.enable_service():
            console.print("[yellow]Warning: Could not enable Docker autostart[/yellow]")

        return True
