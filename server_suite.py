#!/usr/bin/env python3
"""
Server Suite - Main Entry Point
================================
The all-in-one Linux server deployment and management suite.
"""

import os
import sys
import json
import signal
import argparse
from pathlib import Path

# Ensure we're running from the right directory
SUITE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SUITE_DIR))

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import print as rprint

console = Console()


def check_root():
    """Ensure script is running as root."""
    if os.geteuid() != 0:
        console.print("[bold red]✗ Server Suite must be run as root.[/bold red]")
        console.print("  Use: [cyan]sudo python3 server_suite.py[/cyan] or [cyan]sudo server-suite[/cyan]")
        sys.exit(1)


def print_banner():
    """Print the Server Suite banner."""
    console.clear()
    banner = Text()
    banner.append("  SERVER SUITE\n", style="bold cyan")
    banner.append("  The All-In-One Linux Server Deployment Suite\n", style="white")
    banner.append("  Version 1.0.0", style="dim")

    console.print(Panel(
        Align.center(banner),
        border_style="cyan",
        padding=(1, 4),
    ))
    console.print()


def load_config() -> dict:
    """Load existing configuration if present."""
    config_path = SUITE_DIR / "config.json"
    if config_path.exists():
        try:
            with open(config_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            console.print("[yellow]Warning: config.json is corrupted. Starting fresh.[/yellow]")
    return {}


def is_first_run(config: dict) -> bool:
    """Determine if this is a first-time setup or management mode."""
    return not config.get("setup_complete", False)


def launch_setup(config: dict):
    """Launch the setup wizard (web UI + terminal fallback)."""
    from core.preflight import PreflightChecker
    from core.hardware import HardwareDetector
    from setup_ui.app import SetupWebUI

    console.print("[bold green]Starting setup wizard...[/bold green]\n")

    # Run preflight checks first
    checker = PreflightChecker()
    if not checker.run_all():
        console.print("[red]Preflight checks failed. Please resolve issues above.[/red]")
        sys.exit(1)

    # Detect hardware
    hw = HardwareDetector()
    hardware_info = hw.detect_all()

    # Launch web UI
    ui = SetupWebUI(config, hardware_info, suite_dir=SUITE_DIR)
    ui.start()


def launch_management(config: dict):
    """Launch the management menu for already-configured servers."""
    from management.dashboard import ManagementMenu
    menu = ManagementMenu(config, suite_dir=SUITE_DIR)
    menu.run()


def handle_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Server Suite - Linux Server Deployment & Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo server-suite                  # Auto-detect mode (setup or management)
  sudo server-suite --setup          # Force setup wizard
  sudo server-suite --manage         # Force management menu
  sudo server-suite --dry-run        # Show what would be installed
  sudo server-suite --export-config  # Export current config
  sudo server-suite --import-config  # Import config from file
  sudo server-suite --status         # Show current service status
        """
    )
    parser.add_argument("--setup",         action="store_true", help="Force setup wizard")
    parser.add_argument("--manage",        action="store_true", help="Force management menu")
    parser.add_argument("--dry-run",       action="store_true", help="Show actions without executing")
    parser.add_argument("--export-config", metavar="FILE",      help="Export config to file")
    parser.add_argument("--import-config", metavar="FILE",      help="Import config from file")
    parser.add_argument("--status",        action="store_true", help="Show service status")
    parser.add_argument("--uninstall",     action="store_true", help="Remove Server Suite")
    parser.add_argument("--version",       action="store_true", help="Show version")
    return parser.parse_args()


def handle_export(config: dict, filepath: str):
    """Export configuration to file."""
    from core.config_manager import ConfigManager
    cm = ConfigManager(SUITE_DIR)
    cm.export_config(filepath)
    console.print(f"[green]Config exported to: {filepath}[/green]")
    sys.exit(0)


def handle_import(filepath: str) -> dict:
    """Import configuration from file."""
    from core.config_manager import ConfigManager
    cm = ConfigManager(SUITE_DIR)
    config = cm.import_config(filepath)
    console.print(f"[green]Config imported from: {filepath}[/green]")
    return config


def handle_status(config: dict):
    """Show status of all installed services."""
    from management.dashboard import StatusDisplay
    sd = StatusDisplay(config)
    sd.show()
    sys.exit(0)


def handle_uninstall(config: dict):
    """Uninstall Server Suite."""
    from management.uninstall import Uninstaller
    u = Uninstaller(config, suite_dir=SUITE_DIR)
    u.run()
    sys.exit(0)


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    console.print("\n\n[yellow]Server Suite interrupted. Goodbye.[/yellow]")
    sys.exit(0)


def main():
    """Main entry point."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    check_root()
    print_banner()

    args = handle_args()
    config = load_config()

    # Handle version
    if args.version:
        console.print("Server Suite v1.0.0")
        sys.exit(0)

    # Handle export
    if args.export_config:
        handle_export(config, args.export_config)

    # Handle import
    if args.import_config:
        config = handle_import(args.import_config)

    # Handle status
    if args.status:
        handle_status(config)

    # Handle uninstall
    if args.uninstall:
        handle_uninstall(config)

    # Set dry-run mode globally
    if args.dry_run:
        os.environ["DRY_RUN"] = "1"
        console.print(Panel(
            "[yellow]DRY RUN MODE — No changes will be made to your system[/yellow]",
            border_style="yellow"
        ))
        console.print()

    # Determine mode
    if args.setup or is_first_run(config):
        launch_setup(config)
    elif args.manage or not is_first_run(config):
        launch_management(config)
    else:
        launch_setup(config)


if __name__ == "__main__":
    main()
