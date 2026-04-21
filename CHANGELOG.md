# Changelog

All notable changes to Server Suite are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Samba4 AD → FreeIPA migration assistant
- Nextcloud 30 support
- Proxmox LXC privileged container detection improvements
- `server-suite --status` JSON output mode for monitoring integration

---

## [2.0.0] — 2026-04-20

### Added

**Security Hardening**
- `SafeExecutor` — replaces all subprocess calls, explicitly blocks `shell=True`, adds configurable timeouts (default 300s)
- `RemoteExecutor` — SSH key path validation (checks file existence + permissions), strict host key checking, control master multiplexing
- `SecretsVault` — refactored secrets storage with Fernet encryption, `confirm=True` flag on plaintext export
- `TPMSealer` — TPM 2.0 hardware-bound sealing using PCRs 0,7 (BIOS/Secure Boot)
- `DriftDetector` — configuration drift detection with checksums, captures baseline state

**Packaging**
- DEBIAN/ control file with proper dependencies
- build_deb.sh script for .deb package generation

### Security Fixes

- Block command injection via shell=True in executor
- Prevent SSH key path traversal attacks
- Require confirmation for plaintext secret exports
- Secure temp file handling in TPM operations
- State file permissions (0o600)
- Timeout protection on all subprocess calls

---

## [1.0.0] — 2026-03-08

### Added

**Phase 1 — Core Foundation**
- Hardware detection: CPU cores, RAM, disks with SMART health, NIC enumeration
- `ConfigManager` — `config.json` as single source of truth with dot-notation get/set
- `SecretsManager` — Fernet-encrypted master key, per-service `.env` files at `chmod 600`
- `DockerEngine` — `daemon.json` hardening (`iptables=false`, `no-new-privileges`, `userns-remap`, `live-restore`), segmented Docker networks (9 subnets)
- `FirewallManager` — UFW baseline, LAN-only setup wizard port, role-specific rules
- `HardwareInfo` — SMART-gated drive selection for storage role
- Base layer (always installed): SSH hardening (`sshd -t` validated), Fail2Ban (journald backend), AppArmor, Chrony NTP, unattended-upgrades, Cockpit on :9090, rkhunter
- `auditd` — STIG/CIS Level 2 rules: authentication, privilege escalation (setuid/setgid syscalls), privileged commands, critical file access, Docker socket, secrets directory
- Browser-based setup wizard: Flask + Socket.IO, 5-step flow, live RAM/CPU impact meter, WebSocket progress streaming, dark theme
- Maintenance scheduler: SMART scan, BTRFS scrub/defrag, health-check systemd timers with email reports
- Management console: service status, add role, Lynis audit, export config, credentials view, uninstall
- `Uninstaller` — stops timers and Docker stacks, removes systemd units and UFW rules, backs up secrets before removal

**Phase 2 — Role Installers**
- Storage: interactive RAID wizard (SMART gating, OS-disk protection, RAID level comparison, typed DESTROY confirmation), BTRFS array creation with subvolumes (`@data`/`@backups`/`@snapshots`), snapshot pruning, BorgBackup + rclone offsite timers
- Web: Nginx Proxy Manager, Traefik v3 (ACME, LAN whitelist, security headers, rate limiting), OpenLiteSpeed
- Mail: Mailcow (Postfix + Dovecot + Rspamd + ClamAV + SOGo), DNS checklist generation (A/MX/SPF/DMARC/DKIM/PTR/autoconfig/SRV)
- DNS/DHCP: Technitium (Docker, REST API config, DHCP scope, ad-block, disables systemd-resolved stub)
- Database: MariaDB 11.4 + PostgreSQL 16.4 + Redis 7.4 + Adminer, all RAM-tuned
- Files: Nextcloud 29 + Collabora Online + Syncthing + Samba (SMBv2+/NTLMv2) + NFS
- Communications: Matrix Synapse + Element Web + Mattermost + Mumble
- VPN: WireGuard (wg-easy Docker + native), peer QR codes, `wg addconf` live reload
- Security: Wazuh server (Manager + Indexer + Dashboard) or agent-only mode
- Logging: Grafana 11 + Prometheus 3 + Loki 3 + Promtail + Node Exporter + cAdvisor _or_ Graylog 6 + OpenSearch + MongoDB
- `RoleDispatcher` — central dynamic dispatch with RAM/CPU minimums, dependency checking, sub-role routing

**Phase 3 — FreeIPA Identity**
- 11-check FreeIPA pre-flight: RAM, disk, FQDN resolution (no loopback), Kerberos time skew, port conflicts (10 ports), existing Kerberos/LDAP conflicts, SELinux enforcement, systemd-resolved DNS conflict, reverse PTR
- FreeIPA server installer: unattended provision with real-time milestone parsing, common failure detection with actionable hints, post-install hardening (password policy, anonymous LDAP disabled, SSSD, HBAC allow_all disabled → explicit admin rule), initial groups/sudo rules, DNS role suppression, client enrollment script generation
- FreeIPA management: users, groups, hosts, HBAC rules, sudo rules, DNS records (A/CNAME/TXT/MX), certificates (Dogtag PKI), server status, replication agreements, Kerberos tickets
- FreeIPA replica: prep script generation, install script, step-by-step SCP+SSH instructions, replication status check

**Phase 4 — Samba AD + Tests + Packaging**
- Samba4 AD DC installer: FQDN/NetBIOS validation, DNS backend choice (SAMBA_INTERNAL or BIND9_DLZ), `samba-tool domain provision --unattended` with live output, AD functional level 2016, LAPS schema extension, AD Recycle Bin, post-install hardening (SMBv2 min, NTLMv2-only, auth audit logging, password policy), Kerberos client config, Linux + Windows client enrollment scripts, container detection (blocks in Docker/LXC)
- Samba AD management: users, groups, computers, GPO listing, DNS records, password policy, domain info, replication test
- Management dashboard dispatches to correct identity manager based on configured engine
- 80-test integration suite covering all modules, runs fully in `DRY_RUN=1`
- `tests/conftest.py` stub system for offline testing (no network required)
- `.deb` package: `DEBIAN/control`, `postinst`, `prerm`, `conffiles`, man page, `changelog.Debian`
- `packaging/build-deb.sh` automated build script
- `.gitignore`, `.github/workflows/ci.yml` (lint + test + shellcheck + deb build), issue templates, CONTRIBUTING.md, SECURITY.md

[Unreleased]: https://github.com/your-org/server-suite/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/your-org/server-suite/releases/tag/v1.0.0
