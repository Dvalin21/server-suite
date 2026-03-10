# Contributing to Server Suite

Thank you for your interest in contributing. This guide covers everything you need: environment setup, adding a new role, writing tests, and the pull request process.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Project Layout Quick Reference](#project-layout-quick-reference)
- [Adding a New Role](#adding-a-new-role)
- [Writing Tests](#writing-tests)
- [Coding Standards](#coding-standards)
- [Pull Request Checklist](#pull-request-checklist)
- [Commit Message Format](#commit-message-format)
- [Reporting Bugs](#reporting-bugs)

---

## Development Setup

No special tools required beyond Python 3.10+. All tests run in `DRY_RUN=1` mode — no root, no system changes.

```bash
git clone https://github.com/your-org/server-suite.git
cd server-suite

# Optional: create a virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Install runtime deps (for IDE support / import resolution)
pip install -r requirements.txt

# Run the test suite
DRY_RUN=1 python3 -c "
import sys
sys.path.insert(0, '.')
import tests.conftest
import unittest
loader = unittest.TestLoader()
suite  = loader.loadTestsFromName('tests.test_suite')
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
sys.exit(0 if result.wasSuccessful() else 1)
"
```

All 80 tests should pass before you begin making changes, and again after.

---

## Project Layout Quick Reference

```
core/           Foundation: config, secrets, hardware, Docker, firewall
base/           Always-installed hardening (SSH, Fail2Ban, auditd, etc.)
roles/          Role installers — one subdirectory per role
setup_ui/       Flask + WebSocket setup wizard
management/     Terminal management console
maintenance/    Scheduled tasks (SMART, BTRFS scrub, health checks)
tests/          80-test integration suite
packaging/      .deb build scripts and metadata
```

The central dispatch table is `roles/registry.py`. The setup wizard's role definitions live in `setup_ui/roles_config.py` (extracted from `app.py` for testability).

---

## Adding a New Role

Follow these steps to add a role called `myservice` as a worked example.

### 1. Create the installer module

```
roles/myservice/__init__.py      (empty or re-exports Installer)
roles/myservice/installer.py     (the actual installer)
```

Every installer must expose this interface:

```python
# roles/myservice/installer.py

import os
from pathlib import Path
from rich.console import Console
from rich.prompt import Prompt, Confirm

console = Console()
DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"


def _run(cmd: list, timeout: int = 120) -> tuple[int, str, str]:
    """Run a shell command. Respects DRY_RUN."""
    if DRY_RUN:
        console.print(f"  [dim][DRY RUN] {' '.join(str(c) for c in cmd)}[/dim]")
        return 0, "dry-run", ""
    import subprocess
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return -1, "", str(e)


class Installer:
    """
    Installs MyService.
    Called by RoleDispatcher with:
        Installer(config_manager=cm, secrets_manager=sm, suite_dir=path)
    """

    def __init__(self, config_manager, secrets_manager, suite_dir: Path):
        self.cm        = config_manager
        self.sm        = secrets_manager
        self.suite_dir = Path(suite_dir)

    def install(self, config: dict) -> bool:
        """
        Main entry point. Return True on success, False on failure.
        config contains values collected by the setup wizard.
        """
        console.print("\n[bold cyan]Installing MyService...[/bold cyan]")

        # 1. Collect any missing config
        port = config.get("port") or Prompt.ask("  Port", default="9999")

        # 2. Pre-flight checks
        if not self._preflight():
            return False

        # 3. Install
        if not self._install_packages():
            return False

        # 4. Configure
        self._configure(port)

        # 5. Register with Server Suite
        self._register(port)

        console.print("[bold green]MyService installed ✓[/bold green]")
        return True

    def _preflight(self) -> bool:
        # Check ports, RAM, etc.
        return True

    def _install_packages(self) -> bool:
        rc, _, err = _run(["apt-get", "install", "-y", "mypackage"])
        if rc != 0 and not DRY_RUN:
            console.print(f"[red]Install failed: {err}[/red]")
            return False
        return True

    def _configure(self, port: str):
        pass  # Write config files, start services, etc.

    def _register(self, port: str):
        """Register the role in config.json and secrets."""
        if self.cm:
            self.cm.add_role("myservice", {"port": port})
            self.cm.register_service_url(
                "myservice", f"http://localhost:{port}", "MyService"
            )
        if self.sm:
            password = self.sm.generate_password(20)
            self.sm.write_env_file("myservice", {
                "MYSERVICE_PORT":     port,
                "MYSERVICE_PASSWORD": password,
            })
```

### 2. Register in `roles/registry.py`

Add an entry to `ROLE_REGISTRY`:

```python
"myservice": {
    "name":        "My Service",
    "icon":        "🔧",
    "description": "Does something useful",
    "min_ram_mb":  512,
    "min_cores":   1,
    "module":      "roles.myservice.installer",
    "installer":   "Installer",
    "requires":    [],       # e.g. ["database"] if you need MariaDB
    "conflicts":   [],
},
```

### 3. Register in `setup_ui/roles_config.py`

Add the same role to the `ROLES` dict in `setup_ui/roles_config.py`. This is the wizard-facing definition (includes UI labels, min_ram_gb for display):

```python
"myservice": {
    "name":        "My Service",
    "icon":        "🔧",
    "description": "Does something useful",
    "min_ram_gb":  0.5,
    "min_cores":   1,
    "requires":    [],
    "port_hints":  [9999],
},
```

Also add the same entry to the `ROLES` dict inside `setup_ui/app.py` to keep them in sync.

### 4. Write tests

Add a test class in `tests/test_suite.py`:

```python
class TestMyServiceRole(unittest.TestCase):

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_import(self):
        from roles.myservice.installer import Installer
        inst = Installer(None, None, self.tmpdir)
        self.assertIsNotNone(inst)

    def test_dry_run_install(self):
        from roles.myservice.installer import Installer
        from core.config_manager import ConfigManager
        from core.secrets import SecretsManager
        cm   = ConfigManager(self.tmpdir)
        sm   = SecretsManager(self.tmpdir)
        inst = Installer(cm, sm, self.tmpdir)
        # DRY_RUN=1 is set globally in test env
        result = inst.install({"port": "9999"})
        self.assertTrue(result)

    def test_registered_in_registry(self):
        from roles.registry import ROLE_REGISTRY
        self.assertIn("myservice", ROLE_REGISTRY)

    def test_registered_in_roles_config(self):
        from setup_ui.roles_config import ROLES
        self.assertIn("myservice", ROLES)
```

Also add `"roles.myservice.installer"` to the `TestRoleImports.MODULES` list.

### 5. Add to management dashboard (optional)

If your role has a management menu, add an option in `management/dashboard.py` and wire it to your management class. Follow the pattern used by `_freeipa_management()`.

---

## Writing Tests

- All tests must pass with `DRY_RUN=1` and without root
- Tests live in `tests/test_suite.py`; the conftest stub system is in `tests/conftest.py`
- If your module imports a third-party lib not in `requirements.txt`, add a stub to `conftest.py`
- Each new module should have at minimum: an import test, a dry-run install test, and a registry registration test
- Use `tempfile.mkdtemp()` for any file I/O in tests — clean up in `tearDown`

---

## Coding Standards

- **Python 3.10+** — f-strings, `match`/`case`, `pathlib.Path` throughout
- **`_run()` pattern** — every subprocess call goes through a local `_run()` function that honours `DRY_RUN`
- **`DRY_RUN` at module level** — `DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"` at the top of every module that calls subprocesses
- **Rich for all output** — use `console.print()` with markup, not bare `print()`
- **No hardcoded passwords** — always generate via `secrets_manager.generate_password()`
- **Idempotent** — check if a service is already installed/running before installing
- **Register everything** — call `config_manager.add_role()` and `config_manager.register_service_url()` at the end of every successful install
- **Type hints on public methods** — `def install(self, config: dict) -> bool:`
- Line length: 100 characters soft limit

---

## Pull Request Checklist

Before opening a PR, confirm:

- [ ] All 80 existing tests still pass (`DRY_RUN=1`)
- [ ] New tests written for new code
- [ ] New role registered in both `roles/registry.py` and `setup_ui/roles_config.py`
- [ ] All subprocess calls go through `_run()` and respect `DRY_RUN`
- [ ] No hardcoded passwords, IPs, or hostnames
- [ ] `_register()` calls `config_manager.add_role()` at minimum
- [ ] `python3 -m py_compile` passes on all changed files
- [ ] PR targets the `develop` branch, not `main`
- [ ] PR description explains what changed and why

---

## Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`

Scopes: `core`, `base`, `roles`, `identity`, `storage`, `web`, `mail`, `dns`, `database`, `files`, `comms`, `vpn`, `security`, `logging`, `ui`, `management`, `packaging`, `tests`

Examples:

```
feat(roles): add Gitea/Forgejo role
fix(identity): handle hostname > 15 chars before Samba provision
docs(readme): add Forgejo self-hosted setup section
test(storage): add BTRFS RAID level calculation tests
chore(packaging): bump version to 1.1.0
```

---

## Reporting Bugs

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.md) issue template. Include:

- OS version and Server Suite version
- Which role was being installed
- The full error output
- Contents of `/var/log/server-suite/` if available

For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do **not** open a public issue.
