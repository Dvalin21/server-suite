"""
TPM 2.0 integration for hardware-bound secrets.
"""
import subprocess
import os
import tempfile
import shutil
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class TPMSealer:
    PCRS = "0,7"  # BIOS/UEFI firmware and Secure Boot state
    
    @staticmethod
    def is_available() -> bool:
        return Path("/dev/tpm0").exists() or Path("/dev/tpmrm0").exists()
    
    def __init__(self):
        if not self.is_available():
            raise RuntimeError("TPM 2.0 not detected")
    
    def _create_secure_workdir(self) -> Path:
        old_umask = os.umask(0o077)
        try:
            workdir = Path(tempfile.mkdtemp(prefix="tpm_seal_"))
        finally:
            os.umask(old_umask)
        return workdir
    
    def _cleanup_workdir(self, workdir: Path):
        try:
            if workdir.exists():
                shutil.rmtree(workdir)
        except Exception as e:
            logger.warning(f"Failed to cleanup workdir {workdir}: {e}")
    
    def seal(self, data: bytes) -> bytes:
        """Encrypt data with TPM, returning sealed blob."""
        workdir = self._create_secure_workdir()
        try:
            secret_file = workdir / "secret.bin"
            secret_file.write_bytes(data)
            os.chmod(secret_file, 0o600)
            
            subprocess.run([
                "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa",
                "-c", str(workdir / "primary.ctx")
            ], check=True, capture_output=True)
            
            subprocess.run([
                "tpm2_create", "-C", str(workdir / "primary.ctx"),
                "-g", "sha256", "-G", "keyedhash",
                "-i", str(secret_file),
                "-u", str(workdir / "obj.pub"),
                "-r", str(workdir / "obj.priv"),
                f"--pcr-list=sha256:{self.PCRS}"
            ], check=True, capture_output=True)
            
            subprocess.run([
                "tpm2_load", "-C", str(workdir / "primary.ctx"),
                "-u", str(workdir / "obj.pub"),
                "-r", str(workdir / "obj.priv"),
                "-c", str(workdir / "load.ctx")
            ], check=True, capture_output=True)
            
            pub = (workdir / "obj.pub").read_bytes()
            priv = (workdir / "obj.priv").read_bytes()
            
            return pub + priv
        
        finally:
            self._cleanup_workdir(workdir)
    
    def unseal(self, sealed_blob: bytes) -> bytes:
        """Decrypt sealed blob using TPM."""
        split = len(sealed_blob) // 2
        pub = sealed_blob[:split]
        priv = sealed_blob[split:]
        
        workdir = self._create_secure_workdir()
        try:
            (workdir / "obj.pub").write_bytes(pub)
            (workdir / "obj.priv").write_bytes(priv)
            
            subprocess.run([
                "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "rsa",
                "-c", str(workdir / "primary.ctx")
            ], check=True, capture_output=True)
            
            subprocess.run([
                "tpm2_load", "-C", str(workdir / "primary.ctx"),
                "-u", str(workdir / "obj.pub"),
                "-r", str(workdir / "obj.priv"),
                "-c", str(workdir / "load.ctx")
            ], check=True, capture_output=True)
            
            result = subprocess.run([
                "tpm2_unseal", "-c", str(workdir / "load.ctx"),
                f"--pcr-list=sha256:{self.PCRS}"
            ], check=True, capture_output=True)
            
            return result.stdout
        
        finally:
            self._cleanup_workdir(workdir)