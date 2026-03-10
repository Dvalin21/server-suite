"""
roles/identity/__init__.py
==========================
Identity role entry point. Supports both FreeIPA and Samba AD.
The setup UI passes sub_role='freeipa' or sub_role='samba_ad'.
"""

from pathlib import Path


class Installer:
    """Entry point used by roles/registry.py dispatcher."""

    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict, sub_role: str = "freeipa") -> bool:
        if sub_role == "samba_ad":
            from roles.identity.samba_ad import SambaADInstaller
            inst = SambaADInstaller(
                suite_dir=self.suite_dir,
                config_manager=self.cm,
                secrets_manager=self.sm,
            )
        else:
            # Default: FreeIPA
            from roles.identity.freeipa import FreeIPAInstaller
            inst = FreeIPAInstaller(
                suite_dir=self.suite_dir,
                config_manager=self.cm,
                secrets_manager=self.sm,
            )
        return inst.install(config)
