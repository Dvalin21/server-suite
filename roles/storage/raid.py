"""
roles/storage/raid.py
=====================
BTRFS RAID array creation, UUID-based fstab entry, mount management,
snapshot policy, and ongoing health integration.
"""

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"

MOUNT_POINT   = Path("/mnt/data")
FSTAB_PATH    = Path("/etc/fstab")
FSTAB_MARKER  = "# Server Suite BTRFS RAID"


def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "dry-run-uuid-1234-5678", ""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class BTRFSRaid:
    """Creates and manages a BTRFS RAID array."""

    def __init__(self, suite_dir: Path):
        self.suite_dir = Path(suite_dir)

    # -----------------------------------------------------------------------
    # Full setup flow
    # -----------------------------------------------------------------------

    def setup(self, config: dict) -> bool:
        """
        Complete BTRFS RAID setup from a config dict produced by DriveSelector.
        """
        drives      = config["drives"]
        raid_level  = config["raid_level"]
        mount_point = Path(config.get("mount_point", "/mnt/data"))
        compress    = config.get("compress", "zstd")
        mount_opts  = config.get("mount_options",
                                  "defaults,noatime,compress=zstd:3,space_cache=v2")

        console.print(f"\n[bold cyan]Creating BTRFS {raid_level.upper()} Array[/bold cyan]\n")

        # Step 1: Install required packages
        if not self._install_packages():
            return False

        # Step 2: Wipe drives
        if not self._wipe_drives(drives):
            return False

        # Step 3: Create BTRFS array
        uuid = self._create_array(drives, raid_level)
        if not uuid:
            return False

        console.print(f"  [green]Array UUID: {uuid}[/green]")

        # Step 4: Create mount point
        if not DRY_RUN:
            mount_point.mkdir(parents=True, exist_ok=True)
            os.chmod(mount_point, 0o755)

        # Step 5: Write fstab entry
        if not self._write_fstab(uuid, mount_point, mount_opts):
            return False

        # Step 6: Mount the array
        if not self._mount_array(mount_point):
            return False

        # Step 7: Verify mount
        if not self._verify_mount(mount_point):
            return False

        # Step 8: Create standard subvolumes
        self._create_subvolumes(mount_point)

        # Step 9: Set up snapshot directory
        self._setup_snapshot_dir(mount_point)

        console.print(f"\n[bold green]BTRFS {raid_level.upper()} array ready at {mount_point} ✓[/bold green]")
        self._print_array_info(mount_point, uuid, raid_level, drives)

        return True

    # -----------------------------------------------------------------------
    # Package installation
    # -----------------------------------------------------------------------

    def _install_packages(self) -> bool:
        console.print("[cyan]Installing BTRFS tools...[/cyan]")
        packages = ["btrfs-progs", "smartmontools", "hdparm", "util-linux"]
        rc, _, err = _run(["apt-get", "install", "-y", "-qq"] + packages)
        if rc != 0:
            console.print(f"[red]Failed to install packages: {err}[/red]")
            return False
        console.print("  [dim]btrfs-progs, smartmontools installed ✓[/dim]")
        return True

    # -----------------------------------------------------------------------
    # Drive wiping
    # -----------------------------------------------------------------------

    def _wipe_drives(self, drives: list) -> bool:
        """Wipe partition tables and existing filesystems from all drives."""
        console.print(f"[cyan]Wiping {len(drives)} drive(s)...[/cyan]")

        for drive in drives:
            console.print(f"  [dim]Wiping {drive}...[/dim]")

            # Unmount anything on this drive first
            rc, out, _ = _run(["lsblk", "-o", "MOUNTPOINT", "-n", drive])
            if rc == 0:
                for mount in out.splitlines():
                    mount = mount.strip()
                    if mount:
                        _run(["umount", "-f", mount])

            # Wipe filesystem signatures
            rc, _, err = _run(["wipefs", "-a", drive])
            if rc != 0:
                console.print(f"  [yellow]wipefs warning on {drive}: {err}[/yellow]")

            # Zero out the first and last 10MB (clears partition tables and backup GPT)
            _run(["dd", "if=/dev/zero", f"of={drive}",
                  "bs=1M", "count=10", "status=none"])
            # Get drive size in bytes to zero the end
            rc2, size_str, _ = _run(["blockdev", "--getsize64", drive])
            if rc2 == 0:
                try:
                    size_bytes = int(size_str.strip())
                    seek_mb = (size_bytes // (1024 * 1024)) - 10
                    if seek_mb > 0:
                        _run(["dd", "if=/dev/zero", f"of={drive}", "bs=1M",
                              "count=10", f"seek={seek_mb}", "status=none"])
                except ValueError:
                    pass

            # Inform kernel of partition table changes
            _run(["partprobe", drive])

        # Small wait for kernel to settle
        if not DRY_RUN:
            time.sleep(2)

        console.print(f"  [green]{len(drives)} drive(s) wiped ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # Array creation
    # -----------------------------------------------------------------------

    def _create_array(self, drives: list, raid_level: str) -> Optional[str]:
        """
        Create the BTRFS filesystem spanning multiple drives.
        Returns the UUID of the created array.
        """
        console.print(f"[cyan]Creating BTRFS {raid_level.upper()} filesystem...[/cyan]")

        # Map raid level to mkfs.btrfs flags
        # BTRFS uses -d for data profile and -m for metadata profile
        profile_map = {
            "single": ("-d", "single",  "-m", "single"),
            "raid0":  ("-d", "raid0",   "-m", "raid1"),    # metadata always raid1 minimum
            "raid1":  ("-d", "raid1",   "-m", "raid1"),
            "raid10": ("-d", "raid10",  "-m", "raid10"),
            "raid5":  ("-d", "raid5",   "-m", "raid6"),    # metadata raid6 for extra safety
            "raid6":  ("-d", "raid6",   "-m", "raid6"),
        }
        profiles = profile_map.get(raid_level, ("-d", "single", "-m", "single"))

        cmd = [
            "mkfs.btrfs",
            "-f",                  # Force (drive already wiped)
            profiles[0], profiles[1],  # Data profile
            profiles[2], profiles[3],  # Metadata profile
            "-L", "server-suite-data",  # Label
        ] + drives

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(
                f"Creating BTRFS {raid_level.upper()} on {len(drives)} drives...",
                total=None
            )
            rc, out, err = _run(cmd, timeout=300)
            progress.update(task, description="[green]BTRFS created ✓")

        if rc != 0:
            console.print(f"[red]mkfs.btrfs failed: {err}[/red]")
            return None

        # Extract UUID from mkfs output
        uuid = self._extract_uuid(out)
        if not uuid:
            # Fallback: read UUID from blkid
            rc2, blkid_out, _ = _run(["blkid", "-s", "UUID", "-o", "value", drives[0]])
            if rc2 == 0:
                uuid = blkid_out.strip()

        if not uuid:
            console.print("[red]Could not determine array UUID[/red]")
            return None

        return uuid

    def _extract_uuid(self, mkfs_output: str) -> Optional[str]:
        """Extract UUID from mkfs.btrfs output."""
        patterns = [
            r"UUID:\s+([a-f0-9-]{36})",
            r"uuid:\s+([a-f0-9-]{36})",
            r"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
        ]
        for pattern in patterns:
            match = re.search(pattern, mkfs_output, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    # -----------------------------------------------------------------------
    # fstab
    # -----------------------------------------------------------------------

    def _write_fstab(self, uuid: str, mount_point: Path, mount_options: str) -> bool:
        """
        Write UUID-based fstab entry.
        Uses nofail so a missing drive doesn't halt boot.
        """
        console.print("[cyan]Writing fstab entry...[/cyan]")

        fstab_entry = (
            f"\n{FSTAB_MARKER}\n"
            f"# Created by server-suite on {self._timestamp()}\n"
            f"# RAID UUID: {uuid}\n"
            f"UUID={uuid}  {mount_point}  btrfs  "
            f"{mount_options},nofail  0  0\n"
            f"{FSTAB_MARKER} END\n"
        )

        if DRY_RUN:
            console.print(f"  [dim][DRY RUN] Would add to fstab:\n{fstab_entry}[/dim]")
            return True

        # Remove any previous suite fstab entry
        self._remove_fstab_entry()

        with open(FSTAB_PATH, "a") as f:
            f.write(fstab_entry)

        # Verify fstab is valid
        rc, _, err = _run(["findmnt", "--verify", "--verbose"])
        if rc != 0:
            console.print(f"[yellow]fstab verification warning: {err}[/yellow]")

        console.print(f"  [dim]UUID={uuid} → {mount_point} ✓[/dim]")
        return True

    def _remove_fstab_entry(self):
        """Remove any previous Server Suite fstab entries."""
        if not FSTAB_PATH.exists():
            return
        content = FSTAB_PATH.read_text()
        if FSTAB_MARKER not in content:
            return

        lines = content.splitlines(keepends=True)
        new_lines = []
        inside_block = False
        for line in lines:
            if FSTAB_MARKER in line and "END" not in line:
                inside_block = True
            elif FSTAB_MARKER in line and "END" in line:
                inside_block = False
                continue
            if not inside_block:
                new_lines.append(line)

        FSTAB_PATH.write_text("".join(new_lines))

    # -----------------------------------------------------------------------
    # Mount
    # -----------------------------------------------------------------------

    def _mount_array(self, mount_point: Path) -> bool:
        """Mount the BTRFS array using the fstab entry."""
        console.print(f"[cyan]Mounting array at {mount_point}...[/cyan]")
        rc, _, err = _run(["mount", str(mount_point)])
        if rc != 0:
            # Try mounting all new entries
            rc2, _, err2 = _run(["mount", "-a"])
            if rc2 != 0:
                console.print(f"[red]Failed to mount array: {err} | {err2}[/red]")
                return False
        return True

    def _verify_mount(self, mount_point: Path) -> bool:
        """Verify the array is mounted and accessible."""
        if DRY_RUN:
            return True
        rc, out, _ = _run(["findmnt", "-n", "-o", "FSTYPE", str(mount_point)])
        if rc != 0 or "btrfs" not in out.lower():
            console.print(f"[red]Mount verification failed: {mount_point} not mounted as BTRFS[/red]")
            return False

        # Write a test file
        test_file = mount_point / ".server-suite-test"
        try:
            test_file.write_text("ok")
            test_file.unlink()
        except IOError as e:
            console.print(f"[red]Cannot write to mount point: {e}[/red]")
            return False

        console.print(f"  [green]Mount verified: {mount_point} (BTRFS) ✓[/green]")
        return True

    # -----------------------------------------------------------------------
    # Subvolumes
    # -----------------------------------------------------------------------

    def _create_subvolumes(self, mount_point: Path):
        """
        Create a standard subvolume layout.
        Using subvolumes makes snapshot management much cleaner.
        """
        console.print("[cyan]Creating BTRFS subvolumes...[/cyan]")
        subvolumes = [
            ("@data",      "Main data subvolume"),
            ("@backups",   "Local backup storage"),
            ("@snapshots", "Snapshot storage"),
        ]
        for name, description in subvolumes:
            subvol_path = mount_point / name
            if not subvol_path.exists():
                rc, _, err = _run(["btrfs", "subvolume", "create", str(subvol_path)])
                if rc == 0:
                    console.print(f"  [dim]Created subvolume {name} ({description}) ✓[/dim]")
                else:
                    console.print(f"  [yellow]Could not create {name}: {err}[/yellow]")

    def _setup_snapshot_dir(self, mount_point: Path):
        """Create snapshot management structure."""
        snap_dir = mount_point / "@snapshots"
        if not DRY_RUN and snap_dir.exists():
            (snap_dir / "daily").mkdir(exist_ok=True)
            (snap_dir / "weekly").mkdir(exist_ok=True)
            (snap_dir / "monthly").mkdir(exist_ok=True)
        console.print("  [dim]Snapshot directory structure created ✓[/dim]")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _print_array_info(self, mount_point: Path, uuid: str,
                          raid_level: str, drives: list):
        """Print array information summary."""
        console.print()
        rc, out, _ = _run(["btrfs", "filesystem", "show", str(mount_point)])
        if rc == 0:
            console.print(Panel(
                out,
                title="[bold cyan]BTRFS Array Info[/bold cyan]",
                border_style="cyan"
            ))

        rc2, out2, _ = _run(["btrfs", "filesystem", "usage", str(mount_point)])
        if rc2 == 0:
            console.print(Panel(
                out2,
                title="[bold cyan]Filesystem Usage[/bold cyan]",
                border_style="cyan"
            ))

    @staticmethod
    def _timestamp() -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -----------------------------------------------------------------------
    # Snapshot management
    # -----------------------------------------------------------------------

    def create_snapshot(self, mount_point: Path,
                        snapshot_type: str = "manual") -> Optional[Path]:
        """Create a read-only BTRFS snapshot."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snap_dir  = mount_point / "@snapshots" / snapshot_type
        snap_path = snap_dir / f"snap_{timestamp}"

        if not DRY_RUN:
            snap_dir.mkdir(parents=True, exist_ok=True)

        rc, _, err = _run([
            "btrfs", "subvolume", "snapshot", "-r",
            str(mount_point / "@data"),
            str(snap_path)
        ])

        if rc != 0:
            console.print(f"[red]Snapshot failed: {err}[/red]")
            return None

        console.print(f"[green]Snapshot created: {snap_path} ✓[/green]")
        return snap_path

    def prune_snapshots(self, mount_point: Path,
                        keep_daily: int = 7,
                        keep_weekly: int = 4,
                        keep_monthly: int = 6):
        """Delete old snapshots according to retention policy."""
        snap_root = mount_point / "@snapshots"
        policies  = [
            ("daily",   keep_daily),
            ("weekly",  keep_weekly),
            ("monthly", keep_monthly),
        ]

        for snap_type, keep_count in policies:
            snap_dir = snap_root / snap_type
            if not snap_dir.exists():
                continue

            snaps = sorted(snap_dir.iterdir(), reverse=True)
            to_delete = snaps[keep_count:]

            for snap in to_delete:
                rc, _, err = _run(["btrfs", "subvolume", "delete", str(snap)])
                if rc == 0:
                    console.print(f"  [dim]Pruned snapshot: {snap.name}[/dim]")
                else:
                    console.print(f"  [yellow]Failed to prune {snap}: {err}[/yellow]")


class Installer:
    """Role installer interface for setup_ui/app.py dispatch."""

    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm         = config_manager
        self.sm         = secrets_manager
        self.suite_dir  = Path(suite_dir)

    def install(self, config: dict) -> bool:
        from roles.storage.detect import DriveSelector

        selector = DriveSelector()
        storage_config = selector.run()
        if not storage_config:
            return False

        raid = BTRFSRaid(self.suite_dir)
        if not raid.setup(storage_config):
            return False

        # Persist storage config
        self.cm.add_role("storage", storage_config)
        self.cm.register_service_url(
            "btrfs-data",
            str(storage_config.get("mount_point", "/mnt/data")),
            "BTRFS RAID data mount"
        )

        # Register all drives in port registry (just for documentation)
        for drive in storage_config.get("drives", []):
            self.cm.set(f"storage.drives.{drive.replace('/', '_')}", drive)

        # Set up maintenance schedules now that storage exists
        from maintenance.scheduler import MaintenanceScheduler
        scheduler = MaintenanceScheduler(
            suite_dir=self.suite_dir,
            notify_email=self.cm.get("notifications.email", "root")
        )
        scheduler.setup_all(self.cm.get_all())

        return True
