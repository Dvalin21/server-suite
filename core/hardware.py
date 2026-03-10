"""
core/hardware.py
================
Comprehensive hardware detection for CPU, RAM, disks, and network interfaces.
All detection runs before any installation begins.
"""

import os
import re
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

console = Console()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CPUInfo:
    model: str = "Unknown"
    cores_physical: int = 0
    cores_logical: int = 0
    sockets: int = 1
    architecture: str = "Unknown"
    frequency_mhz: float = 0.0
    virtualization: bool = False
    virt_type: str = ""


@dataclass
class RAMInfo:
    total_gb: float = 0.0
    available_gb: float = 0.0
    used_gb: float = 0.0
    swap_total_gb: float = 0.0
    swap_available_gb: float = 0.0


@dataclass
class DiskInfo:
    device: str = ""
    name: str = ""
    model: str = "Unknown"
    serial: str = "Unknown"
    disk_type: str = "Unknown"      # HDD, SSD, NVMe
    size_gb: float = 0.0
    size_bytes: int = 0
    rotational: bool = True
    smart_available: bool = False
    smart_health: str = "Unknown"
    temperature_c: Optional[float] = None
    power_on_hours: Optional[int] = None
    reallocated_sectors: int = 0
    pending_sectors: int = 0
    uncorrectable_errors: int = 0
    filesystem: str = ""
    mount_point: str = ""
    is_os_disk: bool = False
    is_removable: bool = False
    transport: str = ""             # sata, nvme, usb, etc.
    firmware: str = "Unknown"


@dataclass
class NetworkInterface:
    name: str = ""
    mac: str = ""
    ipv4: list = field(default_factory=list)
    ipv6: list = field(default_factory=list)
    speed_mbps: Optional[int] = None
    is_up: bool = False
    is_physical: bool = False
    driver: str = ""


@dataclass
class HardwareInfo:
    cpu: CPUInfo = field(default_factory=CPUInfo)
    ram: RAMInfo = field(default_factory=RAMInfo)
    disks_hdd: list = field(default_factory=list)
    disks_ssd: list = field(default_factory=list)
    disks_nvme: list = field(default_factory=list)
    network_interfaces: list = field(default_factory=list)
    hostname: str = ""
    os_disk: str = ""
    total_disk_count: int = 0
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def all_disks(self) -> list:
        return self.disks_hdd + self.disks_ssd + self.disks_nvme


# ---------------------------------------------------------------------------
# Helper: run a command safely
# ---------------------------------------------------------------------------

def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        return -1, "", str(e)


# ---------------------------------------------------------------------------
# CPU Detection
# ---------------------------------------------------------------------------

class CPUDetector:
    def detect(self) -> CPUInfo:
        info = CPUInfo()
        self._parse_cpuinfo(info)
        self._detect_virt(info)
        return info

    def _parse_cpuinfo(self, info: CPUInfo):
        try:
            import psutil
            info.cores_physical = psutil.cpu_count(logical=False) or 1
            info.cores_logical  = psutil.cpu_count(logical=True)  or 1
            freq = psutil.cpu_freq()
            if freq:
                info.frequency_mhz = round(freq.max or freq.current, 1)
        except ImportError:
            pass

        rc, out, _ = _run(["lscpu"])
        if rc == 0:
            for line in out.splitlines():
                key, _, val = line.partition(":")
                val = val.strip()
                key = key.strip()
                if key == "Model name":
                    info.model = val
                elif key == "Architecture":
                    info.architecture = val
                elif key == "Socket(s)":
                    try:
                        info.sockets = int(val)
                    except ValueError:
                        pass

    def _detect_virt(self, info: CPUInfo):
        rc, out, _ = _run(["systemd-detect-virt"])
        if rc == 0 and out not in ("none", ""):
            info.virtualization = True
            info.virt_type = out


# ---------------------------------------------------------------------------
# RAM Detection
# ---------------------------------------------------------------------------

class RAMDetector:
    def detect(self) -> RAMInfo:
        info = RAMInfo()
        try:
            import psutil
            vm = psutil.virtual_memory()
            sw = psutil.swap_memory()
            info.total_gb     = round(vm.total     / (1024**3), 2)
            info.available_gb = round(vm.available  / (1024**3), 2)
            info.used_gb      = round(vm.used        / (1024**3), 2)
            info.swap_total_gb     = round(sw.total  / (1024**3), 2)
            info.swap_available_gb = round((sw.total - sw.used) / (1024**3), 2)
        except ImportError:
            # Fallback: parse /proc/meminfo
            try:
                with open("/proc/meminfo") as f:
                    mem = {}
                    for line in f:
                        k, _, v = line.partition(":")
                        mem[k.strip()] = v.strip()
                total_kb = int(mem.get("MemTotal", "0").split()[0])
                avail_kb = int(mem.get("MemAvailable", "0").split()[0])
                info.total_gb     = round(total_kb / (1024**2), 2)
                info.available_gb = round(avail_kb / (1024**2), 2)
                info.used_gb      = round((total_kb - avail_kb) / (1024**2), 2)
            except Exception:
                pass
        return info


# ---------------------------------------------------------------------------
# Disk Detection
# ---------------------------------------------------------------------------

class DiskDetector:
    def __init__(self):
        self._os_disk = self._detect_os_disk()

    def detect(self) -> tuple[list, list, list]:
        """Returns (hdd_list, ssd_list, nvme_list)."""
        rc, out, _ = _run([
            "lsblk", "-J", "-o",
            "NAME,TYPE,SIZE,ROTA,MODEL,SERIAL,TRAN,MOUNTPOINT,FSTYPE,RM,VENDOR"
        ])
        if rc != 0:
            return [], [], []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return [], [], []

        hdds, ssds, nvmes = [], [], []

        for device in data.get("blockdevices", []):
            if device.get("type") != "disk":
                continue
            if device.get("rm") == "1" or device.get("rm") is True:
                continue  # Skip removable (USB, etc.)

            disk = self._parse_device(device)
            if disk is None:
                continue

            # Mark OS disk
            if disk.device in self._os_disk or self._os_disk in disk.device:
                disk.is_os_disk = True

            # Get SMART data
            self._enrich_smart(disk)

            # Categorize
            if disk.disk_type == "NVMe":
                nvmes.append(disk)
            elif disk.disk_type == "SSD":
                ssds.append(disk)
            else:
                hdds.append(disk)

        return hdds, ssds, nvmes

    def _parse_device(self, device: dict) -> Optional[DiskInfo]:
        name = device.get("name", "")
        if not name:
            return None

        dev_path = f"/dev/{name}"
        disk = DiskInfo()
        disk.device = dev_path
        disk.name = name
        disk.model = (device.get("model") or "Unknown").strip()

        # Size
        size_str = device.get("size", "0")
        disk.size_bytes = self._parse_size(size_str)
        disk.size_gb = round(disk.size_bytes / (1024**3), 1)

        # Type detection
        disk.rotational = device.get("rota") in ("1", True, 1)
        disk.transport = (device.get("tran") or "").lower()
        disk.is_removable = device.get("rm") in ("1", True, 1)

        if "nvme" in name.lower() or disk.transport == "nvme":
            disk.disk_type = "NVMe"
            disk.rotational = False
        elif not disk.rotational:
            disk.disk_type = "SSD"
        else:
            disk.disk_type = "HDD"

        # Filesystem / mount info
        disk.filesystem = device.get("fstype") or ""
        disk.mount_point = device.get("mountpoint") or ""

        # Check children for mount points
        for child in device.get("children", []):
            if child.get("mountpoint"):
                disk.mount_point = child["mountpoint"]
                disk.filesystem  = child.get("fstype") or disk.filesystem

        return disk

    def _enrich_smart(self, disk: DiskInfo):
        """Run smartctl to get health, temperature, and key attributes."""
        rc, out, _ = _run(["smartctl", "-i", "-H", "-A", disk.device], timeout=15)
        if rc < 0:
            disk.smart_available = False
            return

        disk.smart_available = True
        lines = out.splitlines()

        for line in lines:
            ll = line.lower()

            # Overall health
            if "smart overall-health" in ll or "smart health status" in ll:
                disk.smart_health = "PASSED" if "passed" in ll or "ok" in ll else "FAILED"

            # Model / serial / firmware
            if line.startswith("Device Model") or line.startswith("Model Number"):
                disk.model = line.split(":", 1)[-1].strip()
            elif line.startswith("Serial Number"):
                disk.serial = line.split(":", 1)[-1].strip()
            elif line.startswith("Firmware Version"):
                disk.firmware = line.split(":", 1)[-1].strip()

            # SMART attributes
            if re.match(r'\s*\d+\s+', line):
                parts = line.split()
                if len(parts) >= 10:
                    attr_id = parts[0]
                    raw_val = parts[-1]
                    try:
                        if attr_id == "190" or attr_id == "194":
                            disk.temperature_c = float(raw_val.split()[0])
                        elif attr_id == "9":
                            disk.power_on_hours = int(raw_val)
                        elif attr_id == "5":
                            disk.reallocated_sectors = int(raw_val)
                        elif attr_id == "197":
                            disk.pending_sectors = int(raw_val)
                        elif attr_id == "198":
                            disk.uncorrectable_errors = int(raw_val)
                    except (ValueError, IndexError):
                        pass

        # NVMe uses different output format
        if disk.disk_type == "NVMe":
            for line in lines:
                if "temperature" in line.lower() and ":" in line:
                    try:
                        temp_str = line.split(":")[-1].strip().split()[0]
                        disk.temperature_c = float(temp_str)
                    except (ValueError, IndexError):
                        pass
                elif "power on hours" in line.lower() and ":" in line:
                    try:
                        disk.power_on_hours = int(line.split(":")[-1].strip().replace(",", ""))
                    except ValueError:
                        pass

    def _detect_os_disk(self) -> str:
        """Detect which disk contains the root filesystem."""
        rc, out, _ = _run(["findmnt", "-n", "-o", "SOURCE", "/"])
        if rc == 0 and out:
            # Strip partition number to get disk name
            dev = out.strip()
            # Remove partition suffix (e.g., /dev/sda1 -> /dev/sda, /dev/nvme0n1p1 -> /dev/nvme0n1)
            dev = re.sub(r'p?\d+$', '', dev)
            return dev
        return ""

    @staticmethod
    def _parse_size(size_str: str) -> int:
        """Parse lsblk size string to bytes."""
        if not size_str:
            return 0
        # lsblk -b returns raw bytes, but -J may return human readable
        units = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
        size_str = size_str.strip().upper()
        try:
            for unit, multiplier in units.items():
                if size_str.endswith(unit):
                    return int(float(size_str[:-1]) * multiplier)
            return int(size_str)
        except ValueError:
            return 0


# ---------------------------------------------------------------------------
# Network Detection
# ---------------------------------------------------------------------------

class NetworkDetector:
    def detect(self) -> list:
        interfaces = []
        try:
            import netifaces
            for iface_name in netifaces.interfaces():
                iface = self._parse_interface(iface_name)
                if iface:
                    interfaces.append(iface)
        except ImportError:
            interfaces = self._fallback_detect()
        return interfaces

    def _parse_interface(self, name: str) -> Optional[NetworkInterface]:
        import netifaces
        iface = NetworkInterface()
        iface.name = name

        # Skip loopback
        if name == "lo":
            return None

        addrs = netifaces.ifaddresses(name)

        # MAC
        if netifaces.AF_LINK in addrs:
            iface.mac = addrs[netifaces.AF_LINK][0].get("addr", "")

        # IPv4
        if netifaces.AF_INET in addrs:
            iface.ipv4 = [a.get("addr", "") for a in addrs[netifaces.AF_INET]]

        # IPv6
        if netifaces.AF_INET6 in addrs:
            iface.ipv6 = [a.get("addr", "").split("%")[0] for a in addrs[netifaces.AF_INET6]]

        # State
        state_path = Path(f"/sys/class/net/{name}/operstate")
        if state_path.exists():
            iface.is_up = state_path.read_text().strip() == "up"

        # Speed
        speed_path = Path(f"/sys/class/net/{name}/speed")
        if speed_path.exists():
            try:
                iface.speed_mbps = int(speed_path.read_text().strip())
            except ValueError:
                pass

        # Physical check (not virtual)
        iface.is_physical = not name.startswith(("docker", "br-", "veth", "virbr", "lo", "tun", "tap"))

        # Driver
        driver_path = Path(f"/sys/class/net/{name}/device/driver")
        if driver_path.is_symlink():
            iface.driver = Path(os.readlink(driver_path)).name

        return iface

    def _fallback_detect(self) -> list:
        """Fallback using ip addr if netifaces unavailable."""
        interfaces = []
        rc, out, _ = _run(["ip", "-j", "addr"])
        if rc != 0:
            return interfaces
        try:
            data = json.loads(out)
            for entry in data:
                name = entry.get("ifname", "")
                if name in ("lo",):
                    continue
                iface = NetworkInterface()
                iface.name = name
                iface.is_up = entry.get("operstate", "").upper() == "UP"
                for addr_info in entry.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        iface.ipv4.append(addr_info.get("local", ""))
                    elif addr_info.get("family") == "inet6":
                        iface.ipv6.append(addr_info.get("local", ""))
                interfaces.append(iface)
        except (json.JSONDecodeError, KeyError):
            pass
        return interfaces


# ---------------------------------------------------------------------------
# Main HardwareDetector
# ---------------------------------------------------------------------------

class HardwareDetector:
    def detect_all(self) -> HardwareInfo:
        info = HardwareInfo()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            console=console
        ) as progress:

            task = progress.add_task("Detecting CPU...", total=None)
            info.cpu = CPUDetector().detect()
            progress.update(task, description="[green]✓ CPU detected")
            progress.advance(task)

            task2 = progress.add_task("Detecting RAM...", total=None)
            info.ram = RAMDetector().detect()
            progress.update(task2, description="[green]✓ RAM detected")
            progress.advance(task2)

            task3 = progress.add_task("Scanning disks (SMART data may take a moment)...", total=None)
            dd = DiskDetector()
            info.os_disk = dd._detect_os_disk()
            info.disks_hdd, info.disks_ssd, info.disks_nvme = dd.detect()
            info.total_disk_count = len(info.all_disks())
            progress.update(task3, description="[green]✓ Disks scanned")
            progress.advance(task3)

            task4 = progress.add_task("Detecting network interfaces...", total=None)
            info.network_interfaces = NetworkDetector().detect()
            progress.update(task4, description="[green]✓ Network detected")
            progress.advance(task4)

            task5 = progress.add_task("Reading hostname...", total=None)
            rc, out, _ = _run(["hostname", "-f"])
            info.hostname = out if rc == 0 else "localhost"
            progress.update(task5, description="[green]✓ Hostname read")
            progress.advance(task5)

        # Generate warnings
        info.warnings = self._generate_warnings(info)
        return info

    def _generate_warnings(self, info: HardwareInfo) -> list:
        warnings = []

        if info.cpu.cores_physical < 2:
            warnings.append("Single CPU core detected. Most server roles require 2+ cores.")

        if info.ram.total_gb < 2:
            warnings.append(f"Only {info.ram.total_gb}GB RAM detected. Most roles require 2GB+ minimum.")

        if info.cpu.virtualization:
            warnings.append(f"Running inside a VM ({info.cpu.virt_type}). Some roles (VPN, BTRFS RAID) may have limitations.")

        for disk in info.all_disks():
            if disk.smart_health == "FAILED":
                warnings.append(f"SMART FAILURE on {disk.device} ({disk.model}). Do not use this disk for storage.")
            if disk.reallocated_sectors > 0:
                warnings.append(f"Reallocated sectors on {disk.device}: {disk.reallocated_sectors}. Monitor closely.")
            if disk.temperature_c and disk.temperature_c > 55:
                warnings.append(f"High temperature on {disk.device}: {disk.temperature_c}°C.")

        return warnings

    def print_summary(self, info: HardwareInfo):
        """Print a rich formatted hardware summary."""
        console.print()
        console.print(Panel("[bold cyan]Hardware Summary[/bold cyan]", border_style="cyan"))

        # CPU
        cpu_table = Table(show_header=False, box=None, padding=(0, 2))
        cpu_table.add_row("[dim]Model[/dim]",        info.cpu.model)
        cpu_table.add_row("[dim]Physical Cores[/dim]", str(info.cpu.cores_physical))
        cpu_table.add_row("[dim]Logical Cores[/dim]",  str(info.cpu.cores_logical))
        cpu_table.add_row("[dim]Architecture[/dim]",   info.cpu.architecture)
        if info.cpu.frequency_mhz:
            cpu_table.add_row("[dim]Max Frequency[/dim]", f"{info.cpu.frequency_mhz} MHz")
        if info.cpu.virtualization:
            cpu_table.add_row("[dim]Virtualization[/dim]", f"[yellow]{info.cpu.virt_type}[/yellow]")
        console.print(Panel(cpu_table, title="[bold]CPU[/bold]", border_style="dim"))

        # RAM
        ram_table = Table(show_header=False, box=None, padding=(0, 2))
        ram_table.add_row("[dim]Total[/dim]",     f"{info.ram.total_gb} GB")
        ram_table.add_row("[dim]Available[/dim]", f"{info.ram.available_gb} GB")
        ram_table.add_row("[dim]Swap[/dim]",      f"{info.ram.swap_total_gb} GB")
        console.print(Panel(ram_table, title="[bold]RAM[/bold]", border_style="dim"))

        # Disks
        if info.all_disks():
            disk_table = Table(
                "Device", "Type", "Model", "Size", "Health", "Temp", "OS Disk",
                show_header=True, header_style="bold magenta"
            )
            for disk in info.all_disks():
                health_color = "green" if disk.smart_health == "PASSED" else (
                    "red" if disk.smart_health == "FAILED" else "yellow"
                )
                temp_str = f"{disk.temperature_c:.0f}°C" if disk.temperature_c else "N/A"
                disk_table.add_row(
                    disk.device,
                    f"[cyan]{disk.disk_type}[/cyan]",
                    disk.model[:30],
                    f"{disk.size_gb} GB",
                    f"[{health_color}]{disk.smart_health}[/{health_color}]",
                    temp_str,
                    "[red]YES[/red]" if disk.is_os_disk else "No"
                )
            console.print(Panel(disk_table, title="[bold]Storage[/bold]", border_style="dim"))

        # Network
        if info.network_interfaces:
            net_table = Table("Interface", "IPv4", "Speed", "Status", show_header=True, header_style="bold magenta")
            for iface in info.network_interfaces:
                ipv4_str = ", ".join(iface.ipv4) if iface.ipv4 else "N/A"
                speed_str = f"{iface.speed_mbps} Mbps" if iface.speed_mbps and iface.speed_mbps > 0 else "N/A"
                status = "[green]UP[/green]" if iface.is_up else "[red]DOWN[/red]"
                net_table.add_row(iface.name, ipv4_str, speed_str, status)
            console.print(Panel(net_table, title="[bold]Network[/bold]", border_style="dim"))

        # Warnings
        if info.warnings:
            console.print()
            for warning in info.warnings:
                console.print(f"  [yellow]⚠[/yellow]  {warning}")
        console.print()
