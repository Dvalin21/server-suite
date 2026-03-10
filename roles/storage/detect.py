"""
roles/storage/detect.py
=======================
Interactive drive selection for BTRFS RAID configuration.
Categorizes HDD/SSD/NVMe, warns about OS disks and existing data,
enforces RAID best practices based on drive count and size.
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

console = Console()


def _run(cmd: list, timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


# BTRFS RAID levels with metadata about requirements and recommendations
RAID_LEVELS = {
    "single": {
        "name":        "Single (no redundancy)",
        "min_drives":  1,
        "max_drives":  1,
        "redundancy":  False,
        "description": "No redundancy. Data lost if drive fails. Development/test only.",
        "recommended": False,
        "warning":     "NOT recommended for production. No fault tolerance.",
    },
    "raid0": {
        "name":        "RAID 0 (striping)",
        "min_drives":  2,
        "max_drives":  None,
        "redundancy":  False,
        "description": "Stripes data across drives for performance. No redundancy.",
        "recommended": False,
        "warning":     "NOT recommended for production. Any single drive failure = total data loss.",
    },
    "raid1": {
        "name":        "RAID 1 (mirroring)",
        "min_drives":  2,
        "max_drives":  2,
        "redundancy":  True,
        "description": "Mirrors data across 2 drives. Survives 1 drive failure.",
        "recommended": True,
        "warning":     None,
    },
    "raid10": {
        "name":        "RAID 10 (mirror + stripe)",
        "min_drives":  4,
        "max_drives":  None,
        "redundancy":  True,
        "description": "Mirrors then stripes. Best performance + redundancy balance.",
        "recommended": True,
        "warning":     None,
    },
    "raid5": {
        "name":        "RAID 5 (distributed parity)",
        "min_drives":  3,
        "max_drives":  None,
        "redundancy":  True,
        "description": "Distributed parity. Survives 1 drive failure. Usable = (n-1) drives.",
        "recommended": False,
        "warning":     (
            "BTRFS RAID 5 has known write-hole vulnerabilities. "
            "Rebuild time on large drives risks second failure. "
            "RAID 6 or RAID 10 are safer choices."
        ),
    },
    "raid6": {
        "name":        "RAID 6 (dual parity)",
        "min_drives":  4,
        "max_drives":  None,
        "redundancy":  True,
        "description": "Dual parity. Survives 2 simultaneous drive failures. Usable = (n-2) drives.",
        "recommended": True,
        "warning":     "BTRFS RAID 6 also has write-hole risk. Consider using with UPS.",
    },
}


class DriveSelector:
    """
    Guides the user through selecting drives and RAID level
    for a BTRFS array.
    """

    def __init__(self, hardware_info=None):
        self.hardware_info = hardware_info
        self.selected_drives: list = []
        self.raid_level: str = ""

    # -----------------------------------------------------------------------
    # Main interactive flow
    # -----------------------------------------------------------------------

    def run(self) -> Optional[dict]:
        """
        Run the interactive drive selection wizard.
        Returns config dict or None if cancelled.
        """
        console.print("\n[bold cyan]Storage Configuration[/bold cyan]\n")

        # Get drives from hardware info or re-detect
        if self.hardware_info:
            hdds  = [d.__dict__ if hasattr(d, '__dict__') else d
                     for d in (self.hardware_info.disks_hdd  or [])]
            ssds  = [d.__dict__ if hasattr(d, '__dict__') else d
                     for d in (self.hardware_info.disks_ssd  or [])]
            nvmes = [d.__dict__ if hasattr(d, '__dict__') else d
                     for d in (self.hardware_info.disks_nvme or [])]
        else:
            hdds, ssds, nvmes = self._detect_drives()

        all_drives = hdds + ssds + nvmes

        if not all_drives:
            console.print("[red]No drives detected. Cannot configure storage.[/red]")
            return None

        # Display drives by category
        self._display_drives(hdds, ssds, nvmes)

        # Select drives
        selected = self._select_drives(all_drives)
        if not selected:
            return None

        self.selected_drives = selected

        # Select RAID level
        raid = self._select_raid_level(selected)
        if not raid:
            return None

        self.raid_level = raid

        # Final confirmation
        if not self._confirm_selection(selected, raid):
            return None

        return {
            "drives":      [d["device"] for d in selected],
            "drive_info":  selected,
            "raid_level":  raid,
            "mount_point": "/mnt/data",
            "compress":    "zstd",
            "mount_options": self._build_mount_options(raid),
        }

    # -----------------------------------------------------------------------
    # Drive detection (fallback if no hardware_info)
    # -----------------------------------------------------------------------

    def _detect_drives(self) -> tuple[list, list, list]:
        """Detect and categorize drives directly."""
        import json
        rc, out, _ = _run([
            "lsblk", "-J", "-d", "-o",
            "NAME,SIZE,ROTA,MODEL,SERIAL,TRAN,TYPE,RM"
        ])
        if rc != 0:
            return [], [], []

        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return [], [], []

        hdds, ssds, nvmes = [], [], []

        # Detect OS disk
        rc2, os_dev, _ = _run(["findmnt", "-n", "-o", "SOURCE", "/"])
        import re
        os_disk = re.sub(r'p?\d+$', '', os_dev.strip()) if rc2 == 0 else ""

        for dev in data.get("blockdevices", []):
            if dev.get("type") != "disk":
                continue
            if dev.get("rm") in ("1", True):
                continue

            name     = dev.get("name", "")
            device   = f"/dev/{name}"
            rotional = dev.get("rota") in ("1", True, 1)
            tran     = (dev.get("tran") or "").lower()

            drive = {
                "device":    device,
                "name":      name,
                "model":     (dev.get("model") or "Unknown").strip(),
                "serial":    (dev.get("serial") or "Unknown").strip(),
                "size_gb":   self._parse_size_gb(dev.get("size", "0")),
                "disk_type": "NVMe" if "nvme" in name or tran == "nvme"
                             else "SSD" if not rotional
                             else "HDD",
                "is_os_disk": os_disk and (device == os_disk or os_disk in device),
                "smart_health": self._quick_smart_check(device),
            }

            if drive["disk_type"] == "NVMe":
                nvmes.append(drive)
            elif drive["disk_type"] == "SSD":
                ssds.append(drive)
            else:
                hdds.append(drive)

        return hdds, ssds, nvmes

    def _quick_smart_check(self, device: str) -> str:
        rc, out, _ = _run(["smartctl", "-H", device], timeout=10)
        if rc < 0:
            return "Unknown"
        if "PASSED" in out or "OK" in out:
            return "PASSED"
        if "FAILED" in out:
            return "FAILED"
        return "Unknown"

    @staticmethod
    def _parse_size_gb(size_str: str) -> float:
        units = {"K": 1/1024/1024, "M": 1/1024, "G": 1.0, "T": 1024.0}
        s = str(size_str).strip().upper()
        try:
            for u, mult in units.items():
                if s.endswith(u):
                    return round(float(s[:-1]) * mult, 1)
            return round(float(s) / (1024**3), 1)
        except ValueError:
            return 0.0

    # -----------------------------------------------------------------------
    # Display
    # -----------------------------------------------------------------------

    def _display_drives(self, hdds: list, ssds: list, nvmes: list):
        """Display drives organized by type."""
        categories = [
            ("NVMe Drives", nvmes, "bright_cyan"),
            ("SSD Drives",  ssds,  "bright_green"),
            ("HDD Drives",  hdds,  "bright_yellow"),
        ]

        for category_name, drives, color in categories:
            if not drives:
                continue

            table = Table(
                "#", "Device", "Model", "Size", "SMART", "OS Disk",
                show_header=True,
                header_style="bold magenta",
                border_style="dim",
                title=f"[bold {color}]{category_name}[/bold {color}]",
            )

            for i, d in enumerate(drives):
                health_color = (
                    "green"  if d.get("smart_health") == "PASSED" else
                    "red"    if d.get("smart_health") == "FAILED" else
                    "yellow"
                )
                os_flag = "[bold red]⚠ OS DISK[/bold red]" if d.get("is_os_disk") else "—"

                table.add_row(
                    str(i + 1),
                    f"[{color}]{d['device']}[/{color}]",
                    d["model"][:32],
                    f"{d['size_gb']} GB",
                    f"[{health_color}]{d.get('smart_health', 'Unknown')}[/{health_color}]",
                    os_flag,
                )
            console.print(table)
            console.print()

    # -----------------------------------------------------------------------
    # Drive selection
    # -----------------------------------------------------------------------

    def _select_drives(self, all_drives: list) -> Optional[list]:
        """Let user select which drives to include in the array."""
        console.print("[bold]Drive Selection[/bold]")
        console.print("[dim]Enter drive numbers separated by spaces (e.g., 1 2 3).[/dim]")
        console.print("[dim]OS disks are excluded automatically unless you override.[/dim]\n")

        # List all drives with sequential numbers
        table = Table("#", "Device", "Type", "Model", "Size", "Status",
                      show_header=True, header_style="bold magenta", border_style="dim")
        for i, d in enumerate(all_drives):
            status = ""
            if d.get("is_os_disk"):
                status = "[red]OS DISK[/red]"
            elif d.get("smart_health") == "FAILED":
                status = "[red]SMART FAILED[/red]"
            elif d.get("smart_health") == "PASSED":
                status = "[green]Healthy[/green]"
            else:
                status = "[yellow]Unknown[/yellow]"

            table.add_row(
                str(i + 1),
                d["device"],
                d["disk_type"],
                d["model"][:28],
                f"{d['size_gb']} GB",
                status,
            )
        console.print(table)
        console.print()

        while True:
            selection = Prompt.ask(
                "  Select drives for BTRFS array (numbers, space-separated, or 'all')"
            )

            if selection.lower() == "all":
                indices = list(range(len(all_drives)))
            else:
                try:
                    indices = [int(x) - 1 for x in selection.split()]
                except ValueError:
                    console.print("[red]Invalid input. Enter drive numbers.[/red]")
                    continue

            # Validate indices
            invalid = [i for i in indices if i < 0 or i >= len(all_drives)]
            if invalid:
                console.print(f"[red]Invalid drive numbers: {[i+1 for i in invalid]}[/red]")
                continue

            selected = [all_drives[i] for i in indices]

            # Warn about OS disk
            os_disks = [d for d in selected if d.get("is_os_disk")]
            if os_disks:
                console.print(
                    f"\n[bold red]⚠ WARNING: {[d['device'] for d in os_disks]} "
                    f"contain(s) your OS.[/bold red]"
                )
                console.print(
                    "[red]Including the OS disk in a BTRFS RAID array will "
                    "DESTROY YOUR OPERATING SYSTEM.[/red]"
                )
                if not Confirm.ask("  Are you ABSOLUTELY SURE you want to include OS disk(s)?",
                                   default=False):
                    console.print("[dim]OS disk(s) removed from selection.[/dim]")
                    selected = [d for d in selected if not d.get("is_os_disk")]

            # Warn about SMART failures
            failed = [d for d in selected if d.get("smart_health") == "FAILED"]
            if failed:
                console.print(
                    f"\n[bold red]⚠ SMART FAILURE on: "
                    f"{[d['device'] for d in failed]}[/bold red]"
                )
                console.print("[red]These drives have reported SMART failures and should NOT be used.[/red]")
                if not Confirm.ask("  Include failed drives anyway?", default=False):
                    selected = [d for d in selected if d.get("smart_health") != "FAILED"]

            # Warn about existing data
            self._warn_existing_data(selected)

            if len(selected) == 0:
                console.print("[red]No drives selected. Try again.[/red]")
                continue

            console.print(
                f"\n  Selected [cyan]{len(selected)}[/cyan] drive(s): "
                f"[cyan]{', '.join(d['device'] for d in selected)}[/cyan]"
            )
            console.print(
                f"  Total capacity: [cyan]{sum(d['size_gb'] for d in selected):.1f} GB[/cyan]"
            )
            console.print()

            if Confirm.ask("  Confirm drive selection?", default=True):
                return selected

        return None

    def _warn_existing_data(self, drives: list):
        """Check for existing partitions/data and warn."""
        for d in drives:
            rc, out, _ = _run(["lsblk", "-J", "-o", "NAME,FSTYPE,MOUNTPOINT",
                               d["device"]])
            if rc == 0:
                import json
                try:
                    data = json.loads(out)
                    for dev in data.get("blockdevices", []):
                        children = dev.get("children", [])
                        if children:
                            fs_types = [c.get("fstype") for c in children if c.get("fstype")]
                            if fs_types:
                                console.print(
                                    f"\n  [yellow]⚠ {d['device']} has existing "
                                    f"filesystem(s): {', '.join(fs_types)}[/yellow]"
                                )
                                console.print(
                                    f"  [yellow]  ALL DATA ON {d['device']} WILL BE DESTROYED.[/yellow]"
                                )
                except json.JSONDecodeError:
                    pass

    # -----------------------------------------------------------------------
    # RAID level selection
    # -----------------------------------------------------------------------

    def _select_raid_level(self, drives: list) -> Optional[str]:
        """Present RAID options appropriate for the selected drive count."""
        n = len(drives)
        total_tb = sum(d["size_gb"] for d in drives) / 1024
        large_drives = total_tb > 4  # 4TB+ threshold for extra RAID 5 warning

        console.print(f"\n[bold]RAID Level Selection[/bold]")
        console.print(f"[dim]{n} drives selected | {total_tb:.1f} TB total raw capacity[/dim]\n")

        # Filter to compatible levels
        compatible = {
            k: v for k, v in RAID_LEVELS.items()
            if v["min_drives"] <= n and (v["max_drives"] is None or v["max_drives"] >= n)
        }

        # Build recommendation table
        table = Table(
            "#", "RAID Level", "Usable Space", "Survives", "Recommended",
            show_header=True,
            header_style="bold magenta",
            border_style="dim",
        )

        level_keys = list(compatible.keys())
        for i, (key, info) in enumerate(compatible.items()):
            usable = self._calc_usable_space(drives, key)
            survives = self._calc_fault_tolerance(n, key)
            rec = "[green]✓ Yes[/green]" if info["recommended"] else "[yellow]—[/yellow]"
            name_color = "green" if info["recommended"] else "yellow" if info["redundancy"] else "red"

            table.add_row(
                str(i + 1),
                f"[{name_color}]{info['name']}[/{name_color}]",
                f"{usable:.1f} GB",
                survives,
                rec,
            )

        console.print(table)
        console.print()

        # Print recommendations
        self._print_raid_recommendation(n, large_drives)

        while True:
            choice = Prompt.ask(
                "  Select RAID level",
                choices=[str(i + 1) for i in range(len(level_keys))],
            )
            selected_key = level_keys[int(choice) - 1]
            selected_info = RAID_LEVELS[selected_key]

            # Show warning and require acknowledgment for risky choices
            if selected_info.get("warning"):
                console.print(f"\n  [bold yellow]⚠ Warning:[/bold yellow] {selected_info['warning']}")
                if not selected_info["recommended"]:
                    if not Confirm.ask(
                        f"  I understand the risks of {selected_info['name']}. Proceed?",
                        default=False
                    ):
                        continue

            # Extra warning for RAID 5 with large drives
            if selected_key == "raid5" and large_drives:
                console.print(
                    "\n  [bold red]⚠ Additional risk:[/bold red] Your drives are large "
                    f"({total_tb:.1f} TB total). BTRFS RAID 5 rebuild on large drives can "
                    "take 12-48+ hours during which a second failure = complete data loss."
                )
                if not Confirm.ask("  Proceed with RAID 5 on large drives?", default=False):
                    continue

            console.print(
                f"\n  Selected: [cyan]{selected_info['name']}[/cyan]"
            )
            console.print(
                f"  Usable space: [cyan]{self._calc_usable_space(drives, selected_key):.1f} GB[/cyan]"
            )
            return selected_key

    def _calc_usable_space(self, drives: list, raid_level: str) -> float:
        sizes = sorted(d["size_gb"] for d in drives)
        n = len(sizes)
        if raid_level == "single":
            return sizes[0]
        elif raid_level == "raid0":
            return sum(sizes)
        elif raid_level == "raid1":
            return min(sizes)
        elif raid_level == "raid10":
            return sum(sizes) / 2
        elif raid_level == "raid5":
            return min(sizes) * (n - 1)
        elif raid_level == "raid6":
            return min(sizes) * (n - 2)
        return sum(sizes)

    def _calc_fault_tolerance(self, n: int, raid_level: str) -> str:
        faults = {
            "single": "None",
            "raid0":  "None",
            "raid1":  "1 drive",
            "raid10": "1 per mirror pair",
            "raid5":  "1 drive",
            "raid6":  "2 drives",
        }
        return faults.get(raid_level, "—")

    def _print_raid_recommendation(self, n: int, large_drives: bool):
        """Print a context-aware RAID recommendation."""
        if n == 1:
            console.print(
                "  [dim]1 drive: Single mode only. Consider adding a second "
                "drive for RAID 1 redundancy.[/dim]"
            )
        elif n == 2:
            console.print(
                "  [green]Recommendation:[/green] [dim]RAID 1 (mirroring) — "
                "best choice for 2 drives.[/dim]"
            )
        elif n == 3:
            console.print(
                "  [green]Recommendation:[/green] [dim]RAID 1 with a spare, or RAID 5 "
                "(acknowledge risks). RAID 10 requires 4 drives.[/dim]"
            )
        elif n >= 4:
            if large_drives:
                console.print(
                    "  [green]Recommendation:[/green] [dim]RAID 10 (best performance + safety) "
                    "or RAID 6 (max capacity with dual-fault tolerance). "
                    "RAID 5 not advised on large drives.[/dim]"
                )
            else:
                console.print(
                    "  [green]Recommendation:[/green] [dim]RAID 10 for performance, "
                    "RAID 6 for maximum fault tolerance.[/dim]"
                )
        console.print()

    def _build_mount_options(self, raid_level: str) -> str:
        """Build production-grade BTRFS mount options."""
        base = [
            "defaults",
            "noatime",          # Don't update access times — improves performance
            "compress=zstd:3",  # ZSTD compression level 3 — good balance
            "space_cache=v2",   # Faster space cache
            "autodefrag",       # Auto-defrag small random writes
            "x-systemd.device-timeout=30",  # Don't hang boot if drive slow
        ]
        if raid_level in ("raid5", "raid6"):
            base.append("degraded")  # Allow mount even if one drive missing
        return ",".join(base)

    # -----------------------------------------------------------------------
    # Final confirmation
    # -----------------------------------------------------------------------

    def _confirm_selection(self, drives: list, raid_level: str) -> bool:
        """Show final summary and get confirmation before any destructive action."""
        info = RAID_LEVELS[raid_level]
        usable = self._calc_usable_space(drives, raid_level)

        console.print()
        console.print(Panel(
            f"[bold red]⚠ FINAL CONFIRMATION — THIS WILL DESTROY ALL DATA[/bold red]\n\n"
            f"  RAID Level:    [cyan]{info['name']}[/cyan]\n"
            f"  Drives:        [cyan]{', '.join(d['device'] for d in drives)}[/cyan]\n"
            f"  Usable Space:  [cyan]{usable:.1f} GB[/cyan]\n"
            f"  Mount Point:   [cyan]/mnt/data[/cyan]\n"
            f"  Compression:   [cyan]ZSTD level 3[/cyan]\n\n"
            f"  [bold red]ALL EXISTING DATA ON THE SELECTED DRIVES WILL BE PERMANENTLY ERASED.[/bold red]",
            border_style="red",
            padding=(1, 2),
        ))

        if not Confirm.ask(
            "\n  Type YES to confirm you want to create this array",
            default=False
        ):
            return False

        # Second confirmation — type the word
        confirm_word = Prompt.ask(
            "  Type [bold red]DESTROY[/bold red] to confirm data destruction"
        )
        if confirm_word.strip().upper() != "DESTROY":
            console.print("[yellow]Confirmation not received. Aborted.[/yellow]")
            return False

        return True
