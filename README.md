<div align="center">

# 🖥️ Server Suite

**All-in-one Linux server deployment and management suite for Ubuntu/Debian**

[![CI](https://github.com/your-org/server-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/server-suite/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Ubuntu 22.04+](https://img.shields.io/badge/ubuntu-22.04%2B-orange)](https://ubuntu.com/)
[![Debian 12+](https://img.shields.io/badge/debian-12%2B-red)](https://www.debian.org/)

Server Suite is a **role-based server automation tool** that deploys and manages production-grade self-hosted infrastructure. It launches a **browser-based setup wizard** (Flask + WebSocket, port 7070) for first-time configuration, then switches to a **terminal management console** for ongoing administration.

[Quick Start](#-quick-start) · [Roles](#-roles) · [Security Model](#-security-model) · [Architecture](#-architecture) · [Contributing](#-contributing) · [FAQ](#-faq)

</div>

---

## ✨ Features

- **Browser-based setup wizard** — role selection with live RAM/CPU impact meter, streaming progress via WebSocket
- **11 deployable roles** — storage, web, mail, identity, DNS/DHCP, database, files, comms, VPN, security monitoring, logging
- **Dual identity engines** — FreeIPA (Kerberos + LDAP + PKI CA + DNS + HBAC) _or_ Samba4 AD (Windows GPO/RSAT compatible)
- **Hardened Docker networking** — all containers bind to `127.0.0.1` only; single ingress via Nginx Proxy Manager or Traefik
- **Encrypted secrets management** — Fernet-encrypted master key; per-service `.env` files at `chmod 600`
- **TPM 2.0 hardware sealing** — optional hardware-bound key protection
- **Remote execution** — SSH-based remote deployment with key validation
- **Drift detection** — configuration baseline and change detection
- **Idempotent** — safe to re-run; detects existing state before acting
- **Auditd + AppArmor + Fail2Ban** always installed as the base layer
- **80-test integration suite** — runs fully in `DRY_RUN=1` mode, no system changes required
- **Installable as a `.deb`** — `sudo dpkg -i server-suite_2.0.0_all.deb && sudo server-suite`

---

## 📋 Requirements

| Requirement | Minimum | Notes |
|---|---|---|
| OS | Ubuntu 22.04 LTS / Debian 12 | 64-bit only |
| Python | 3.10+ | Usually pre-installed |
| RAM | 1 GB | 2 GB+ recommended; roles have individual minimums |
| Disk | 20 GB free | Storage/mail roles need more |
| Network | LAN + internet | Internet needed during install only |
| Privileges | root | `sudo server-suite` |

> **VM or bare metal required** for the FreeIPA and Samba AD identity roles. Docker containers do not support the kernel features these need (Kerberos socket types, Unix domain sockets for AD).

Per-role RAM minimums enforced at selection time:

| Role | Min RAM |
|---|---|
| VPN | 256 MB |
| Web / DNS | 512 MB |
| Storage / Database | 1 GB |
| Files / Comms / Logging | 2 GB |
| Identity (FreeIPA/Samba AD) | 2 GB |
| Mail (Mailcow) | 3 GB |
| Security (Wazuh server) | 4 GB |

---

## 🚀 Quick Start

### Option 1 — Install from `.deb` (recommended)

Download the latest `.deb` from the [Releases](https://github.com/your-org/server-suite/releases) page, then:

```bash
sudo dpkg -i server-suite_2.0.0_all.deb
sudo apt-get install -f          # resolves any missing dependencies
sudo server-suite                # launches the setup wizard
```

### Option 2 — Bootstrap script (git clone)

```bash
git clone https://github.com/your-org/server-suite.git
cd server-suite
sudo bash install.sh
```

The `install.sh` bootstrap will:
1. Check Python 3.10+ is present (installs it if not)
2. Install Python dependencies from `requirements.txt`
3. Launch `server_suite.py`

### Option 3 — Manual (advanced)

```bash
git clone https://github.com/your-org/server-suite.git
cd server-suite
pip3 install -r requirements.txt --break-system-packages
sudo python3 server_suite.py
```

### First Run

On first run, Server Suite:

1. Scans hardware (CPU, RAM, disks with SMART health, NICs)
2. Opens the setup wizard on **port 7070** (LAN-only, temporary firewall rule)
3. You open `http://<server-ip>:7070` in your browser
4. Select roles, fill in config, watch real-time install progress
5. After install: summary page with all service URLs and credentials (downloadable as JSON)
6. Port 7070 is closed; permanent management via **Cockpit (port 9090)** + `sudo server-suite`

On subsequent runs:

```bash
sudo server-suite     # opens terminal management console
```

---

## 🎛️ Roles

Each role is independently selectable. Some have sub-options (e.g. choose your web engine). Dependencies are enforced (e.g. Files and Comms require Database).

### 🔐 Identity & Directory

The most powerful role — suppresses the standalone DNS/DHCP role when integrated DNS is enabled.

**Path A — FreeIPA** (recommended for Linux-first environments)
- Kerberos 5 KDC + MIT Kerberos
- 389 Directory Server (LDAP)
- Dogtag PKI Certificate Authority — issues TLS certs for internal services
- BIND9 DNS with dynamic updates (optional, replaces Technitium)
- SSSD integration for Linux client domain join
- HBAC rules (who can SSH into which host)
- Sudo policy pushed from the directory
- Replica setup wizard (multi-DC)
- Post-install password policy: min 12 chars, complexity, 90-day max, 6-attempt lockout, anonymous LDAP disabled

**Path B — Samba4 AD DC** (recommended for Windows/mixed environments)
- Full Active Directory Domain Controller
- Kerberos KDC + LDAP (Samba internal LDB)
- DNS: Samba internal or BIND9 DLZ backend
- Group Policy Objects (GPO) — manage via RSAT or `samba-tool gpo`
- Windows and Linux domain join (Linux via `realm join` + SSSD)
- LAPS schema extension (optional)
- AD Recycle Bin (optional)
- Post-install hardening: SMBv2 minimum, NTLMv2-only, lanman disabled, auth audit logging
- Linux client join script generated at `/opt/server-suite/scripts/join-samba-domain.sh`
- Windows PowerShell join snippet generated at `join-samba-domain-windows.ps1`

### 💾 Storage & Backup

- **BTRFS RAID** — interactive drive selection wizard with SMART health gating, RAID level comparison table (RAID0/1/5/10 with usable space calculation), OS-disk protection, typed DESTROY confirmation
- Subvolume layout: `@data`, `@backups`, `@snapshots`
- **BorgBackup** — encrypted, deduplicated local backup with weekly systemd timer and email reports
- **rclone** — offsite sync to any S3-compatible, Backblaze B2, Google Drive, etc. (daily timer)
- Snapshot pruning (configurable retention)

### 🌐 Web / Reverse Proxy

Choose one engine:

- **Nginx Proxy Manager** — GUI proxy manager on :81 (LAN only), SQLite backend, Let's Encrypt
- **Traefik v3** — TOML static + dynamic config, ACME, LAN IP whitelist middleware, security headers, rate limiting
- **OpenLiteSpeed** — high-performance web server, LSPHP 8.3, WebAdmin on :7080

### 📧 Mail Server

- **Mailcow** — the gold standard self-hosted mail stack: Postfix + Dovecot + Rspamd + ClamAV + SOGo webmail
- Full DNS checklist generated post-install: A, MX, SPF, DMARC, DKIM, PTR, autoconfig, SRV records
- DB passwords auto-generated and stored in secrets

### 🔍 DNS & DHCP

*(Suppressed automatically if FreeIPA or Samba AD with integrated DNS is selected)*

- **Technitium DNS** — Docker deployment, REST API configuration, ad-block lists, DHCP scope with lease time, forwarders
- Disables `systemd-resolved` stub on install

### 🗄️ Database

All RAM-tuned based on available system memory:

- **MariaDB 11.4** — InnoDB buffer pool auto-sized
- **PostgreSQL 16.4** — `shared_buffers` auto-sized
- **Redis 7.4** — `maxmemory` auto-sized
- **Adminer** — web-based DB manager (bound to internal network only)

### 📁 Files & Collaboration

- **Nextcloud 29** — with background cron container, CalDAV/CardDAV redirects
- **Collabora Online** (CODE) — embedded in Nextcloud for document editing
- **Syncthing** — P2P file sync
- **Samba** — SMB shares (SMBv2+ only, NTLMv2)
- **NFS** — configurable client CIDR

### 💬 Communications

- **Matrix Synapse + Element Web** — self-hosted Matrix homeserver, PostgreSQL backend, federation port 8448
- **Mattermost** — team messaging, PostgreSQL backend
- **Mumble** — low-latency voice, superuser password generated

### 🔒 VPN

- **WireGuard (wg-easy)** — Docker-based management UI with bcrypt-hashed password, traffic stats, QR codes for peers printed to terminal and saved as PNG
- **Native WireGuard** — kernel module, `wg addconf` live reload
- Interactive peer generation with per-peer IP assignment

### 🛡️ Security Monitoring

- **Wazuh SIEM** — choose between:
  - **Server mode**: Manager + Indexer + OpenSearch + Dashboard (RAM-gated with override)
  - **Agent mode**: registers with an existing Wazuh manager via curl-install script
- TLS certificates auto-generated for inter-component communication
- Firewall rules for all Wazuh ports

### 📊 Logging & Metrics

Choose one stack:

- **Stack A** — Grafana 11 + Prometheus 3 + Loki 3 + Promtail + Node Exporter + cAdvisor. Datasources auto-provisioned.
- **Stack B** — Graylog 6 + OpenSearch + MongoDB. SHA256-hashed root password, `vm.max_map_count` set automatically.

---

## 🔒 Security Model

Security is not an afterthought — it's built into every layer.

### Base Layer (always installed)

Every server gets these regardless of which roles are selected:

| Component | What it does |
|---|---|
| **SSH hardening** | `PasswordAuthentication no`, `PermitRootLogin prohibit-password`, `MaxAuthTries 3`, validated with `sshd -t` before applying |
| **UFW firewall** | Default deny-in; roles register their own rules. Port 7070 opened LAN-only during setup, then removed. |
| **Fail2Ban** | journald backend; SSH, mail, web, and custom jails per role |
| **AppArmor** | Enforcing mode; profiles per service |
| **auditd** | STIG/CIS Level 2 rules: auth events, privilege escalation (setuid/setgid syscalls), file deletions, critical config file access, kernel module loads, Docker socket, secrets directory |
| **Chrony** | NTP time sync — required for Kerberos |
| **unattended-upgrades** | Security patches auto-applied |
| **Cockpit** | Permanent web management on :9090, LAN-only |
| **rkhunter** | Rootkit scanner |

### Docker Hardening

All Docker deployments share this `daemon.json`:

```json
{
  "iptables": false,
  "no-new-privileges": true,
  "log-driver": "journald",
  "userns-remap": "default",
  "live-restore": true,
  "userland-proxy": false
}
```

All container ports bind to `127.0.0.1:PORT:PORT` — **never `0.0.0.0`**. Only the reverse proxy (NPM or Traefik) has external network access.

Docker network segmentation:

| Network | Subnet | Services |
|---|---|---|
| `proxy_network` | 172.20.0.0/24 | NPM/Traefik ↔ public-facing services |
| `db_network` | 172.20.1.0/24 | Databases only |
| `mail_network` | 172.20.2.0/24 | Mailcow internal |
| `identity_network` | 172.20.3.0/24 | FreeIPA / Samba |
| `monitor_network` | 172.20.4.0/24 | Wazuh + Grafana + Prometheus |
| `storage_network` | 172.20.5.0/24 | Nextcloud + storage |
| `comms_network` | 172.20.6.0/24 | Matrix + Jitsi + Mattermost |
| `vpn_network` | 172.20.7.0/24 | WireGuard / OpenVPN |
| `logging_network` | 172.20.8.0/24 | Graylog / Loki |

### Secrets

- Master Fernet key generated on first run, stored in `/opt/server-suite/secrets/`
- Per-service secrets written to `/opt/server-suite/secrets/.env.<service>` (`chmod 600`)
- Secrets directory audited by auditd — any read triggers an audit event
- Passwords never appear in `docker-compose.yml` files — always via `.env` or Docker secrets

---

## 🏗️ Architecture

```
server-suite/
├── server_suite.py          # Entry point — setup wizard or management console
├── install.sh               # Bootstrap: installs Python deps, launches suite
├── requirements.txt
│
├── core/                    # Foundation modules
│   ├── hardware.py          # CPU/RAM/disk/NIC detection, SMART gating
│   ├── config_manager.py    # config.json read/write — single source of truth
│   ├── secrets.py           # Fernet encryption, .env file management (SecretsVault v2)
│   ├── executor.py         # Safe command execution, blocks shell=True
│   ├── remote.py          # SSH remote execution with key validation
│   ├── tpm_seal.py       # TPM 2.0 hardware-bound sealing
│   ├── drift.py          # Configuration drift detection
│   ├── docker_engine.py     # daemon.json hardening, network creation
│   ├── firewall.py          # UFW rule management
│   ├── preflight.py         # System-level pre-flight checks
│   └── notifications.py     # Email/webhook alerts
│
├── base/                    # Always-installed hardening
│   ├── ssh_hardening.py
│   ├── fail2ban.py
│   ├── apparmor.py
│   ├── auditd.py            # STIG/CIS Level 2 audit rules
│   ├── chrony.py
│   ├── cockpit.py
│   └── unattended_upgrades.py
│
├── setup_ui/                # Browser-based setup wizard
│   ├── app.py               # Flask + Socket.IO — 5-step wizard, live progress
│   ├── roles_config.py      # ROLES dict (importable without Flask)
│   └── templates/
│       └── index.html       # Dark-themed single-page wizard UI
│
├── roles/                   # Role installers
│   ├── registry.py          # Central dispatch: RoleDispatcher + ROLE_REGISTRY
│   ├── identity/
│   │   ├── preflight.py     # 11-check FreeIPA pre-flight validator
│   │   ├── freeipa.py       # FreeIPA server installer + post-install hardening
│   │   ├── management.py    # FreeIPA: users, groups, HBAC, DNS, certs, replicas
│   │   ├── replica.py       # FreeIPA replica setup scripts
│   │   ├── samba_ad.py      # Samba4 AD DC installer
│   │   └── samba_management.py  # Samba: users, groups, GPO, DNS, password policy
│   ├── storage/
│   │   ├── detect.py        # Interactive drive selection + SMART gating
│   │   ├── raid.py          # BTRFS RAID creation + subvolumes + snapshots
│   │   └── backup.py        # BorgBackup + rclone timers
│   ├── web/
│   │   ├── nginx_npm.py     # Nginx Proxy Manager
│   │   ├── traefik.py       # Traefik v3
│   │   └── openlitespeed.py
│   ├── mail/
│   │   └── mailcow.py
│   ├── dns_dhcp/
│   │   └── technitium.py
│   ├── database/
│   │   └── installer.py     # MariaDB + PostgreSQL + Redis + Adminer
│   ├── files/
│   │   └── installer.py     # Nextcloud + Collabora + Samba + NFS + Syncthing
│   ├── comms/
│   │   └── installer.py     # Matrix/Synapse + Mattermost + Mumble
│   ├── vpn/
│   │   └── wireguard.py
│   ├── security/
│   │   └── wazuh.py
│   └── logging/
│       └── installer.py
│
├── management/              # Post-install management console
│   ├── dashboard.py         # Main menu — service status, add role, audit, etc.
│   └── uninstall.py         # Clean removal of roles + optional data wipe
│
├── maintenance/
│   └── scheduler.py         # SMART scans, BTRFS scrubs, health-check timers
│
├── tests/
│   ├── conftest.py          # Stub modules for offline testing
│   └── test_suite.py        # 80-test integration suite
│
└── packaging/
    ├── build-deb.sh         # Automated .deb build script
    ├── postinst             # Debian post-install hook
    ├── prerm                # Debian pre-removal hook
    ├── defaults.conf        # /etc/server-suite/defaults.conf template
    └── server-suite.sh      # /usr/bin/server-suite wrapper
```

### How a Role Install Works

```
Browser wizard
    │
    ▼
setup_ui/app.py  ──► RoleDispatcher.install_role("identity", config, sub_role="freeipa")
                           │
                           ├── Check RAM/CPU minimums
                           ├── Check dependencies (e.g. files → database)
                           ├── Dynamic import of roles.identity.freeipa.FreeIPAInstaller
                           └── installer.install(config)
                                    │
                                    ├── preflight checks
                                    ├── package install
                                    ├── configure
                                    ├── harden
                                    ├── register firewall rules
                                    ├── config_manager.add_role(...)
                                    └── secrets_manager.write_env_file(...)
```

---

## 🧪 Running the Tests

The test suite runs entirely in `DRY_RUN=1` mode — no system changes are made, no root required.

```bash
cd server-suite

# Run all 80 tests
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

# Or if pytest is installed
pip3 install pytest
DRY_RUN=1 pytest tests/ -v
```

Test coverage:

| Category | Tests |
|---|---|
| ConfigManager (set/get, persistence, role registration) | 8 |
| SecretsManager (password gen, env files, permissions) | 5 |
| HardwareInfo (CPU, RAM, hostname detection) | 4 |
| Role Registry (dispatch, RAM calc, dependency check) | 7 |
| All 20 role modules import cleanly | 20 |
| FreeIPA preflight logic | 6 |
| Samba AD NetBIOS name validation | 4 |
| Setup UI ROLES dict (structure, no circular deps) | 5 |
| Base modules (SSH, Fail2Ban, AppArmor, auditd rules) | 6 |
| Maintenance scheduler | 3 |
| FirewallManager | 2 |
| Management modules (dashboard, uninstall, identity mgrs) | 5 |
| Docker engine (daemon.json security, unique subnets) | 3 |
| **Total** | **80** |

---

## 📦 Building the `.deb` Package

```bash
# Set version
echo "2.0.0" > VERSION

# Build
bash packaging/build-deb.sh

# Output: dist/server-suite_2.0.0_all.deb
```

Install the built package:

```bash
sudo dpkg -i dist/server-suite_2.0.0_all.deb
sudo apt-get install -f      # fix any missing deps
sudo server-suite
```

---

## 🔁 Management Console

After initial setup, run `sudo server-suite` to open the management console:

```
╔══════════════════════════════════════════════════╗
║          Server Suite — Management               ║
╚══════════════════════════════════════════════════╝

  s  Service status
  a  Add a new role
  u  Update all roles
  l  Run Lynis security audit
  m  Maintenance (SMART scans, BTRFS scrub, health check)
  e  Export config.json
  c  View credentials / service URLs
  i  Identity management (FreeIPA or Samba AD)
  r  FreeIPA replica management
  x  Uninstall a role
  q  Quit
```

The `i` option dispatches to the correct identity management menu based on which engine was installed (`freeipa` or `samba_ad`).

### FreeIPA Management Menu

Users · Groups · Hosts · HBAC rules · Sudo rules · DNS records · Certificate management (Dogtag PKI) · Server status · Replication agreements · Kerberos ticket management

### Samba AD Management Menu

Users (add/list/disable/enable/reset password/delete) · Groups · Computer accounts · GPO listing · DNS records (A/CNAME/TXT) · Password policy · Domain info · Replication sync test

---

## ⬆️ Upgrading

```bash
# From .deb
sudo dpkg -i server-suite_<new-version>_all.deb

# From git
git pull
sudo bash install.sh    # re-runs, detects existing install, updates deps only
```

Your `/opt/server-suite/config.json` and `/opt/server-suite/secrets/` are **never touched** by upgrades. The `/etc/server-suite/defaults.conf` is also preserved (listed in `conffiles`).

---

## 🗑️ Uninstalling

```bash
# Remove a single role (from management console)
sudo server-suite
# → x (uninstall a role)

# Remove the package (preserves /opt/server-suite data)
sudo dpkg -r server-suite

# Full removal including all data, secrets, Docker volumes
sudo dpkg -r server-suite
sudo rm -rf /opt/server-suite /var/log/server-suite
# Then manually stop/remove any Docker containers
docker compose -f /opt/server-suite/... down -v
```

---

## ❓ FAQ

**Q: Can I run this on a VPS?**
A: Yes for most roles. FreeIPA and Samba AD require a real VM (not Docker/LXC) — most VPS providers work. Some providers block ports 88 (Kerberos) and 389 (LDAP) by default; check your provider's firewall.

**Q: Can I run multiple roles on the same server?**
A: Yes. The setup wizard shows a live RAM/CPU impact meter as you select roles. You can run e.g. Web + Database + Files + VPN on an 8 GB server. Wazuh Server + FreeIPA + Mailcow together would need ~12 GB.

**Q: What happens if an install fails halfway through?**
A: Server Suite is idempotent — re-running will detect what's already done and skip or retry. Roles that partially installed will be retried from the last successful step. Check `/var/log/server-suite/` for the specific error.

**Q: Can I use this to manage an existing server?**
A: The management console can be added on top of an existing setup. Installing individual roles (e.g. just `security` for Wazuh) is fully supported via `sudo server-suite --role security`.

**Q: Does this work with Proxmox/LXC?**
A: Most roles work in LXC (privileged containers). FreeIPA and Samba AD require a full VM or privileged LXC with specific kernel features — Server Suite will detect this at pre-flight and warn/block accordingly.

**Q: Where are passwords stored?**
A: All generated passwords are in `/opt/server-suite/secrets/.env.<service>` (owner root, mode 600). The setup wizard's final screen lets you download them as a JSON file. The auditd base layer logs any access to the secrets directory.

**Q: Can I add my own role?**
A: Yes. Create `roles/myservice/installer.py` with an `Installer` class that has `__init__(config_manager, secrets_manager, suite_dir)` and `install(config) -> bool`. Register it in `roles/registry.py` and `setup_ui/roles_config.py`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

**Q: GitHub vs Forgejo — which should I use?**
A: GitHub for maximum visibility/CI minutes. Forgejo (or Gitea) for fully self-hosted — you can run Forgejo itself on a server deployed by Server Suite (via the web role + database role). See the [Publishing to GitHub/Forgejo](#-publishing-to-githubforgejo) section below.

---

## 🌐 Publishing to GitHub/Forgejo

### Publishing to GitHub

**1. Create the repository**

Go to [github.com/new](https://github.com/new):
- Repository name: `server-suite`
- Description: `All-in-one Linux server deployment and management suite`
- Visibility: Public or Private
- **Do not** initialise with README, .gitignore, or licence (you already have them)

**2. Initialise git locally**

```bash
cd /path/to/server-suite    # your local copy of the project

git init
git add .
git commit -m "feat: initial release v1.0.0

- Phase 1: Core foundation (hardware, config, secrets, Docker, firewall, base hardening)
- Phase 2: All role installers (storage, web, mail, DNS, database, files, comms, VPN, security, logging)
- Phase 3: FreeIPA identity role (preflight, installer, management, replica)
- Phase 4: Samba4 AD alternative, 80-test suite, .deb packaging"
```

**3. Add remote and push**

```bash
git remote add origin https://github.com/YOUR-USERNAME/server-suite.git
git branch -M main
git push -u origin main
```

**4. Create a release with the `.deb` attached**

```bash
# Tag the release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

Then on GitHub: **Releases → Draft a new release → choose tag v1.0.0 → upload `server-suite_1.0.0_all.deb`**.

Or using the GitHub CLI:

```bash
gh release create v1.0.0 \
  --title "Server Suite v1.0.0" \
  --notes "Initial release. See CHANGELOG.md for details." \
  dist/server-suite_1.0.0_all.deb
```

**5. Enable branch protection (recommended)**

In **Settings → Branches → Add rule** for `main`:
- ✅ Require pull request reviews before merging
- ✅ Require status checks (CI workflow) to pass
- ✅ Require branches to be up to date
- ✅ Do not allow bypassing the above settings

**6. Set up CI secrets (if needed)**

If you add notification webhooks or signing keys later:
**Settings → Secrets and variables → Actions → New repository secret**

---

### Publishing to Forgejo (Self-Hosted)

Forgejo is a fully self-hosted Git platform (fork of Gitea). You can host it yourself using Server Suite's web + database roles, then push your own project to it.

**1. Set up Forgejo** (if you don't have it already)

On your server:
```bash
# Using Docker (after server-suite has installed the database role):
docker run -d \
  --name forgejo \
  --restart always \
  -p 127.0.0.1:3000:3000 \
  -v /opt/forgejo:/data \
  codeberg.org/forgejo/forgejo:latest
```

Then proxy it through Nginx Proxy Manager or Traefik as `git.yourdomain.com`.

**2. Create the repository in Forgejo**

Visit `https://git.yourdomain.com` → **+ New Repository**:
- Owner: your user or organisation
- Name: `server-suite`
- Leave "Initialise repository" **unchecked**

**3. Add remote and push**

```bash
cd /path/to/server-suite

git init    # if not already a git repo
git add .
git commit -m "feat: initial release v1.0.0"

git remote add origin https://git.yourdomain.com/YOUR-USERNAME/server-suite.git
git branch -M main
git push -u origin main
```

For SSH (recommended for automation):

```bash
# Generate a deploy key if needed
ssh-keygen -t ed25519 -C "server-suite-deploy" -f ~/.ssh/forgejo_deploy

# Add the public key in Forgejo:
# Settings → SSH / GPG Keys → Add Key → paste contents of ~/.ssh/forgejo_deploy.pub

git remote set-url origin git@git.yourdomain.com:YOUR-USERNAME/server-suite.git
git push -u origin main
```

**4. Create a release with the `.deb`**

In Forgejo: **Releases → New Release → Tag: v1.0.0**. Attach `server-suite_1.0.0_all.deb` as a release asset.

Or via the Forgejo API:

```bash
# Create the tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Create release via API
curl -X POST https://git.yourdomain.com/api/v1/repos/YOUR-USERNAME/server-suite/releases \
  -H "Authorization: token YOUR-API-TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tag_name": "v1.0.0",
    "name": "Server Suite v1.0.0",
    "body": "Initial release.",
    "draft": false,
    "prerelease": false
  }'

# Upload the .deb asset (get RELEASE_ID from the response above)
curl -X POST "https://git.yourdomain.com/api/v1/repos/YOUR-USERNAME/server-suite/releases/RELEASE_ID/assets" \
  -H "Authorization: token YOUR-API-TOKEN" \
  -F "attachment=@dist/server-suite_1.0.0_all.deb"
```

**5. Set up Forgejo Actions CI** (same workflow file works)

Forgejo Actions is compatible with GitHub Actions syntax. The `.github/workflows/ci.yml` included in this repo will work as-is. Enable Actions in **Settings → Repository → Enable Repository Actions**.

Runner setup (on your server):

```bash
# Install the Forgejo runner
curl -fsSL https://code.forgejo.org/forgejo/runner/releases/download/v3.3.0/forgejo-runner-3.3.0-linux-amd64 \
  -o /usr/local/bin/forgejo-runner
chmod +x /usr/local/bin/forgejo-runner

# Register the runner (get token from Forgejo: Settings → Actions → Runners)
forgejo-runner register \
  --instance https://git.yourdomain.com \
  --token YOUR-RUNNER-TOKEN \
  --name "server-suite-runner" \
  --labels "ubuntu-22.04"

# Run as a service
forgejo-runner daemon
```

---

### Recommended Branch Strategy

```
main          ← stable, protected, tagged releases only
develop       ← integration branch for new work
feature/*     ← individual features (e.g. feature/nextcloud-30-upgrade)
fix/*         ← bug fixes
release/*     ← release prep (version bumps, changelog)
```

Typical workflow:

```bash
git checkout develop
git checkout -b feature/my-new-role
# ... make changes ...
git push origin feature/my-new-role
# Open pull request → develop
# CI must pass before merge
# When ready to release: merge develop → main, tag
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide including how to add a new role, run tests, and the PR checklist.

**Quick version:**

```bash
# Fork the repo, then:
git clone https://github.com/YOUR-USERNAME/server-suite.git
cd server-suite
git checkout -b feature/my-improvement

# Make changes, run tests
DRY_RUN=1 python3 -c "import sys; sys.path.insert(0,'.'); import tests.conftest; import unittest; unittest.main(module='tests.test_suite', argv=[''], verbosity=2, exit=False)"

git commit -m "feat(roles): add support for ..."
git push origin feature/my-improvement
# Open PR against develop
```

---

## 📄 License

[MIT](LICENSE) — free to use, modify, and distribute.

---

## 🙏 Acknowledgements

Server Suite orchestrates and configures these excellent open-source projects:

[FreeIPA](https://www.freeipa.org/) · [Samba](https://www.samba.org/) · [Mailcow](https://mailcow.email/) · [Nextcloud](https://nextcloud.com/) · [Wazuh](https://wazuh.com/) · [Traefik](https://traefik.io/) · [WireGuard](https://www.wireguard.com/) · [Technitium](https://technitium.com/dns/) · [Grafana](https://grafana.com/) · [Matrix Synapse](https://matrix.org/) · [Mattermost](https://mattermost.com/) · [BorgBackup](https://www.borgbackup.org/) · [Cockpit](https://cockpit-project.org/)
