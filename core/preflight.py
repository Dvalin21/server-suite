"""
core/preflight.py
=================
Pre-flight checks before any installation begins.
Validates OS, kernel, internet, ports, and system state.
"""

import os
import re
import socket
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def _run(cmd: list, timeout: int = 15) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class PreflightChecker:
    """Runs all pre-flight checks and reports results."""

    # Minimum kernel version required
    MIN_KERNEL = (5, 4, 0)

    # Ports that conflict if already in use by non-suite services
    MONITORED_PORTS = [80, 443, 25, 465, 587, 993, 143, 53, 67, 51820, 1194, 389, 636, 88, 9090, 3000, 9000]

    def __init__(self):
        self.results = []   # list of (check_name, passed, message)
        self.warnings = []  # Non-fatal issues
        self.errors = []    # Fatal issues

    def _record(self, name: str, passed: bool, message: str, fatal: bool = True):
        self.results.append((name, passed, message))
        if not passed:
            if fatal:
                self.errors.append(f"{name}: {message}")
            else:
                self.warnings.append(f"{name}: {message}")

    # -----------------------------------------------------------------------
    # Individual checks
    # -----------------------------------------------------------------------

    def check_root(self) -> bool:
        passed = os.geteuid() == 0
        self._record("Root privileges", passed,
                     "Running as root ✓" if passed else "Must run as root — use sudo")
        return passed

    def check_os(self) -> bool:
        if not Path("/etc/os-release").exists():
            self._record("OS Detection", False, "Cannot read /etc/os-release")
            return False

        with open("/etc/os-release") as f:
            os_info = {}
            for line in f:
                k, _, v = line.partition("=")
                os_info[k.strip()] = v.strip().strip('"')

        os_id = os_info.get("ID", "")
        version = os_info.get("VERSION_ID", "")
        name = os_info.get("PRETTY_NAME", f"{os_id} {version}")

        supported = (
            (os_id == "ubuntu" and version in ("20.04", "22.04", "24.04")) or
            (os_id == "debian" and version in ("11", "12"))
        )

        if supported:
            self._record("Operating System", True, f"{name} ✓")
        else:
            self._record("Operating System", False,
                         f"{name} — not officially supported (Ubuntu 20.04/22.04/24.04 or Debian 11/12 required)",
                         fatal=False)
        return supported

    def check_kernel(self) -> bool:
        rc, out, _ = _run(["uname", "-r"])
        if rc != 0:
            self._record("Kernel Version", False, "Cannot determine kernel version")
            return False

        kernel_str = out.split("-")[0]
        try:
            parts = [int(x) for x in kernel_str.split(".")[:3]]
            while len(parts) < 3:
                parts.append(0)
            kernel_tuple = tuple(parts)
        except ValueError:
            self._record("Kernel Version", False, f"Cannot parse kernel version: {out}")
            return False

        if kernel_tuple >= self.MIN_KERNEL:
            self._record("Kernel Version", True,
                         f"{out} (>= {'.'.join(map(str, self.MIN_KERNEL))}) ✓")
            return True
        else:
            self._record("Kernel Version", False,
                         f"{out} — minimum required is {'.'.join(map(str, self.MIN_KERNEL))}")
            return False

    def check_internet(self) -> bool:
        hosts = [("8.8.8.8", 53), ("1.1.1.1", 53), ("9.9.9.9", 53)]
        for host, port in hosts:
            try:
                with socket.create_connection((host, port), timeout=5):
                    self._record("Internet Connectivity", True, f"Connected via {host} ✓")
                    return True
            except (socket.timeout, socket.error, OSError):
                continue

        self._record("Internet Connectivity", False,
                     "No internet access detected — required for package installation")
        return False

    def check_dns_resolution(self) -> bool:
        test_domains = ["archive.ubuntu.com", "github.com", "docker.com"]
        for domain in test_domains:
            try:
                socket.getaddrinfo(domain, 80)
                self._record("DNS Resolution", True, f"{domain} resolved ✓")
                return True
            except socket.gaierror:
                continue
        self._record("DNS Resolution", False,
                     "DNS resolution failing — check /etc/resolv.conf", fatal=False)
        return False

    def check_disk_space(self) -> bool:
        """Ensure enough space in /opt and /var for the suite and packages."""
        checks = [
            ("/opt",  2 * 1024**3,  "2GB for suite installation"),
            ("/var",  5 * 1024**3,  "5GB for packages and Docker images"),
            ("/tmp",  512 * 1024**2, "512MB for temporary files"),
        ]
        all_ok = True
        for path, required, description in checks:
            try:
                stat = os.statvfs(path)
                available = stat.f_bavail * stat.f_frsize
                available_gb = available / (1024**3)
                required_gb = required / (1024**3)
                if available >= required:
                    self._record(f"Disk space ({path})", True,
                                 f"{available_gb:.1f}GB available (need {required_gb:.1f}GB) ✓")
                else:
                    self._record(f"Disk space ({path})", False,
                                 f"Only {available_gb:.1f}GB available — need {required_gb:.1f}GB for {description}",
                                 fatal=False)
                    all_ok = False
            except OSError:
                self._record(f"Disk space ({path})", False,
                             f"Cannot check disk space at {path}", fatal=False)
                all_ok = False
        return all_ok

    def check_port_conflicts(self) -> dict:
        """Check which monitored ports are already in use."""
        conflicts = {}
        for port in self.MONITORED_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex(("127.0.0.1", port))
                    if result == 0:
                        # Port is in use — find what's using it
                        proc = self._find_port_owner(port)
                        conflicts[port] = proc
            except socket.error:
                pass
        return conflicts

    def _find_port_owner(self, port: int) -> str:
        rc, out, _ = _run(["ss", "-tlnp", f"sport = :{port}"])
        if rc == 0 and out:
            # Extract process name from ss output
            match = re.search(r'users:\(\("([^"]+)"', out)
            if match:
                return match.group(1)
        return "unknown process"

    def check_required_commands(self) -> bool:
        commands = [
            ("lsblk",     "util-linux"),
            ("smartctl",  "smartmontools"),
            ("ip",        "iproute2"),
            ("systemctl", "systemd"),
            ("curl",      "curl"),
            ("wget",      "wget"),
            ("apt-get",   "apt"),
        ]
        all_found = True
        for cmd, package in commands:
            rc, _, _ = _run(["which", cmd])
            if rc == 0:
                self._record(f"Command: {cmd}", True, f"{cmd} found ✓")
            else:
                self._record(f"Command: {cmd}", False,
                             f"{cmd} not found — install {package}", fatal=False)
                all_found = False
        return all_found

    def check_systemd(self) -> bool:
        rc, out, _ = _run(["systemctl", "--version"])
        if rc == 0:
            self._record("Systemd", True, "systemd available ✓")
            return True
        self._record("Systemd", False, "systemd not found — required for service management")
        return False

    def check_existing_docker(self) -> Optional[str]:
        """Check if Docker is already installed and its version."""
        rc, out, _ = _run(["docker", "--version"])
        if rc == 0:
            self._record("Docker (existing)", True, f"{out} ✓")
            return out
        return None

    def check_apt_lock(self) -> bool:
        """Check if apt is locked by another process."""
        lock_files = [
            "/var/lib/dpkg/lock-frontend",
            "/var/lib/apt/lists/lock",
            "/var/cache/apt/archives/lock",
        ]
        for lock_file in lock_files:
            rc, _, _ = _run(["fuser", lock_file])
            if rc == 0:
                self._record("APT Lock", False,
                             f"APT is locked by another process ({lock_file}). Wait or resolve before proceeding.")
                return False
        self._record("APT Lock", True, "APT is available ✓")
        return True

    def check_selinux(self) -> bool:
        """Check SELinux status — can interfere with Docker."""
        rc, out, _ = _run(["getenforce"])
        if rc == 0 and out == "Enforcing":
            self._record("SELinux", False,
                         "SELinux is Enforcing — may interfere with Docker. Consider setting to Permissive.",
                         fatal=False)
            return False
        self._record("SELinux", True, "SELinux not enforcing ✓")
        return True

    # -----------------------------------------------------------------------
    # Run all checks
    # -----------------------------------------------------------------------

    def run_all(self) -> bool:
        """Run all preflight checks. Returns True if no fatal errors."""
        console.print(Panel("[bold cyan]Running Pre-flight Checks[/bold cyan]", border_style="cyan"))
        console.print()

        self.check_root()
        self.check_os()
        self.check_kernel()
        self.check_internet()
        self.check_dns_resolution()
        self.check_disk_space()
        self.check_required_commands()
        self.check_systemd()
        self.check_existing_docker()
        self.check_apt_lock()
        self.check_selinux()

        # Port conflict check (informational only at preflight)
        port_conflicts = self.check_port_conflicts()
        if port_conflicts:
            for port, owner in port_conflicts.items():
                self._record(
                    f"Port {port}",
                    False,
                    f"Port {port} already in use by: {owner}",
                    fatal=False
                )

        # Print results table
        self._print_results()

        # Print port conflicts if any
        if port_conflicts:
            console.print()
            console.print("[yellow]Port Conflicts Detected:[/yellow]")
            for port, owner in port_conflicts.items():
                console.print(f"  [yellow]⚠[/yellow]  Port [bold]{port}[/bold] → {owner}")
            console.print("[dim]  Conflicting roles will be flagged during role selection.[/dim]")

        # Print fatal errors
        if self.errors:
            console.print()
            console.print("[bold red]Fatal errors found — cannot continue:[/bold red]")
            for err in self.errors:
                console.print(f"  [red]✗[/red]  {err}")
            return False

        # Print warnings
        if self.warnings:
            console.print()
            console.print("[yellow]Warnings (non-fatal):[/yellow]")
            for w in self.warnings:
                console.print(f"  [yellow]⚠[/yellow]  {w}")

        console.print()
        console.print("[bold green]Pre-flight checks passed. Ready to proceed.[/bold green]")
        console.print()
        return True

    def _print_results(self):
        table = Table(
            "Check", "Result", "Details",
            show_header=True,
            header_style="bold magenta",
            border_style="dim"
        )
        for name, passed, message in self.results:
            status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
            table.add_row(name, status, message)
        console.print(table)

    def get_port_conflicts(self) -> dict:
        """Return current port conflicts for use by role selection."""
        return self.check_port_conflicts()

    def get_summary(self) -> dict:
        """Return a summary dict for config storage."""
        return {
            "passed": len(self.errors) == 0,
            "errors": self.errors,
            "warnings": self.warnings,
            "checks": [
                {"name": n, "passed": p, "message": m}
                for n, p, m in self.results
            ]
        }
