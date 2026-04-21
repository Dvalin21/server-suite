"""
Remote execution via SSH with stream multiplexing.
"""
import subprocess
import shlex
import os
from pathlib import Path
from typing import Optional, Generator
import logging

logger = logging.getLogger(__name__)

class RemoteExecutor:
    def __init__(self, target: str, ssh_key: Optional[str] = None, ssh_port: int = 22):
        if not target or "@" not in target:
            raise ValueError("Invalid target format. Expected user@host")
        self.target = target
        self.ssh_key = self._validate_ssh_key(ssh_key) if ssh_key else None
        self.ssh_port = ssh_port
        self.control_path = f"/tmp/ss-{target.replace('@', '_').replace(':', '_')}"
    
    def _validate_ssh_key(self, key_path: str) -> str:
        key_path = os.path.expanduser(key_path)
        path = Path(key_path)
        if not path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")
        if not path.is_file():
            raise ValueError(f"SSH key is not a file: {key_path}")
        stat_info = path.stat()
        if stat_info.st_mode & 0o077:
            raise ValueError(f"SSH key has insecure permissions: {oct(stat_info.st_mode)}")
        return str(path)
    
    def _build_ssh_base(self) -> list:
        cmd = [
            "ssh",
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={self.control_path}",
            "-o", "ControlPersist=60s",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "HashKnownHosts=no",
            "-p", str(self.ssh_port)
        ]
        if self.ssh_key:
            cmd.extend(["-i", self.ssh_key])
        cmd.append(self.target)
        return cmd
    
    def execute(self, command: str, stream: bool = False, timeout: int = 300) -> subprocess.CompletedProcess:
        """Execute a single command remotely."""
        ssh_cmd = self._build_ssh_base() + [command]
        return subprocess.run(ssh_cmd, capture_output=not stream, text=True, timeout=timeout)
    
    def run_server_suite(self, role: str, action: str = "install",
                         args: Optional[list] = None, timeout: int = 600) -> Generator[str, None, int]:
        """Stream local server-suite code to remote and execute."""
        local_main = Path(__file__).parent.parent / "__main__.py"
        with open(local_main, "rb") as f:
            script_content = f.read().decode()

        cmd_parts = [
            f"python3 -c '{script_content}'",
            f"--role {shlex.quote(role)}",
            f"--action {shlex.quote(action)}"
        ]
        if args:
            cmd_parts.extend(shlex.quote(str(a)) for a in args)

        remote_cmd = " ".join(cmd_parts)
        ssh_cmd = self._build_ssh_base() + [remote_cmd]

        process = subprocess.Popen(
            ssh_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        try:
            for line in iter(process.stdout.readline, ''):
                yield line.rstrip('\n')
        finally:
            process.stdout.close()
            process.wait(timeout=timeout)

        return process.returncode

    def copy_file(self, local_path: str, remote_path: str) -> bool:
        """SCP a file to remote host."""
        if not Path(local_path).exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")
        scp_cmd = ["scp", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/dev/null", "-P", str(self.ssh_port)]
        if self.ssh_key:
            scp_cmd.extend(["-i", self.ssh_key])
        scp_cmd.extend([local_path, f"{self.target}:{remote_path}"])
        result = subprocess.run(scp_cmd, capture_output=True, text=True)
        return result.returncode == 0

    def close_master(self):
        """Close the SSH control master connection."""
        ssh_cmd = self._build_ssh_base() + ["-O", "exit"]
        subprocess.run(ssh_cmd, capture_output=True)