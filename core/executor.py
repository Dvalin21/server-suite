"""
Safe command execution module.
Replaces all os.system and subprocess(shell=True) calls.
"""
import subprocess
import shlex
import logging
from typing import List, Union, Optional

logger = logging.getLogger(__name__)

class SafeExecutor:
    """Secure command execution with parameterized arguments."""
    
    @staticmethod
    def run(cmd: Union[List[str], str],
            shell: bool = False,
            check: bool = True,
            capture: bool = True,
            timeout: Optional[int] = 300,
            **kwargs) -> subprocess.CompletedProcess:
        if isinstance(cmd, str) and not shell:
            cmd = shlex.split(cmd)
        
        if shell:
            raise ValueError("shell=True is not allowed for security reasons")
        
        logger.debug(f"Executing: {cmd}")
        
        result = subprocess.run(
            cmd,
            shell=False,
            check=check,
            capture_output=capture,
            text=True,
            timeout=timeout,
            **kwargs
        )
        
        if result.returncode != 0 and check:
            raise subprocess.CalledProcessError(
                result.returncode, cmd,
                output=result.stdout, stderr=result.stderr
            )
        return result
    
    @staticmethod
    def run_streaming(cmd: Union[List[str], str], timeout: Optional[int] = 300):
        """Execute with live output streaming."""
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            shell=False
        )
        try:
            for line in iter(process.stdout.readline, ''):
                yield line.rstrip('\n')
        finally:
            process.stdout.close()
            process.wait()
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, cmd)
        return process.returncode