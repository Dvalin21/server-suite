"""
Configuration drift detection and reconciliation.
"""
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class DriftDetector:
    TRACKED_PATHS = [
        "/opt/server-suite/config.json",
        "/etc/nginx/nginx.conf",
        "/etc/ufw/user.rules",
        "/etc/fail2ban/jail.local"
    ]
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.state_file = Path("/opt/server-suite/desired_state.json")
    
    def capture_state(self):
        """Take snapshot of current system state."""
        try:
            timestamp_result = subprocess.run(["date", "-Iseconds"], capture_output=True, text=True, timeout=10)
            timestamp = timestamp_result.stdout.strip() if timestamp_result.returncode == 0 else "unknown"
        except subprocess.TimeoutExpired:
            logger.warning("Failed to get timestamp: command timed out")
            timestamp = "unknown"
        except FileNotFoundError:
            logger.warning("date command not found")
            timestamp = "unknown"
        
        state = {
            "timestamp": timestamp,
            "config_checksum": self._hash_file("/opt/server-suite/config.json"),
            "ufw_rules": self._get_ufw_rules(),
            "docker_containers": self._get_docker_containers(),
            "installed_roles": self.config.get("installed_roles", []),
            "file_checksums": {path: self._hash_file(path) for path in self.TRACKED_PATHS if Path(path).exists()}
        }
        
        os.makedirs(self.state_file.parent, mode=0o700, exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)
        os.chmod(self.state_file, 0o600)
        logger.info("System state captured")
    
    def detect_drift(self) -> Dict[str, Any]:
        """Compare current state with captured baseline."""
        if not self.state_file.exists():
            return {"error": "No baseline captured. Run 'server-suite capture-state' first."}
        
        try:
            with open(self.state_file) as f:
                baseline = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"State file corrupted: {e}")
            return {"error": "State file corrupted, cannot detect drift"}
        
        try:
            timestamp_result = subprocess.run(["date", "-Iseconds"], capture_output=True, text=True, timeout=10)
            timestamp = timestamp_result.stdout.strip() if timestamp_result.returncode == 0 else "unknown"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            timestamp = "unknown"
        
        current = {
            "timestamp": timestamp,
            "config_checksum": self._hash_file("/opt/server-suite/config.json"),
            "ufw_rules": self._get_ufw_rules(),
            "docker_containers": self._get_docker_containers(),
            "installed_roles": self.config.get("installed_roles", []),
            "file_checksums": {path: self._hash_file(path) for path in self.TRACKED_PATHS if Path(path).exists()}
        }
        
        drift = {}
        for key in baseline:
            if key in ("timestamp", "file_checksums"):
                continue
            if baseline[key] != current.get(key):
                drift[key] = {
                    "baseline": baseline[key],
                    "current": current.get(key)
                }
        
        file_drift = {}
        for path, baseline_hash in baseline.get("file_checksums", {}).items():
            current_hash = current.get("file_checksums", {}).get(path)
            if baseline_hash != current_hash:
                file_drift[path] = {"baseline": baseline_hash, "current": current_hash}
        if file_drift:
            drift["files"] = file_drift
        
        return drift
    
    def _hash_file(self, path: str) -> str:
        p = Path(path)
        if not p.exists():
            return "MISSING"
        hasher = hashlib.sha256()
        try:
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
        except IOError as e:
            logger.warning(f"Failed to hash {path}: {e}")
            return "ERROR"
        return hasher.hexdigest()
    
    def _get_ufw_rules(self) -> List[str]:
        try:
            result = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.warning(f"ufw command failed: {result.stderr}")
                return []
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except subprocess.TimeoutExpired:
            logger.error("ufw command timed out")
            return []
        except FileNotFoundError:
            logger.warning("ufw not installed")
            return []
        except Exception as e:
            logger.error(f"Failed to get ufw rules: {e}")
            return []
    
    def _get_docker_containers(self) -> List[str]:
        try:
            result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.warning(f"docker command failed: {result.stderr}")
                return []
            return [name for name in result.stdout.splitlines() if name.strip()]
        except subprocess.TimeoutExpired:
            logger.error("docker command timed out")
            return []
        except FileNotFoundError:
            logger.warning("docker not installed")
            return []
        except Exception as e:
            logger.error(f"Failed to get docker containers: {e}")
            return []