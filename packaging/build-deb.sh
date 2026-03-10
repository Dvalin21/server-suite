#!/usr/bin/env bash
# packaging/build-deb.sh
# Builds the server-suite .deb package.
# Usage: bash packaging/build-deb.sh [VERSION]
set -euo pipefail

VERSION="${1:-$(cat VERSION 2>/dev/null || echo '1.0.0')}"
PKGNAME="server-suite_${VERSION}_all"
SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDDIR="$(mktemp -d)"
OUTDIR="${SRCDIR}/dist"

echo "Building server-suite ${VERSION}..."
mkdir -p "${OUTDIR}"

# Create package tree
PKG="${BUILDDIR}/${PKGNAME}"
mkdir -p "${PKG}/DEBIAN"
mkdir -p "${PKG}/usr/lib/server-suite"
mkdir -p "${PKG}/usr/bin"
mkdir -p "${PKG}/usr/share/doc/server-suite"
mkdir -p "${PKG}/usr/share/man/man8"
mkdir -p "${PKG}/etc/server-suite"
mkdir -p "${PKG}/lib/systemd/system"

# Copy source (exclude dev/test artefacts)
cp -r "${SRCDIR}/base"        "${PKG}/usr/lib/server-suite/"
cp -r "${SRCDIR}/core"        "${PKG}/usr/lib/server-suite/"
cp -r "${SRCDIR}/docker"      "${PKG}/usr/lib/server-suite/"
cp -r "${SRCDIR}/maintenance" "${PKG}/usr/lib/server-suite/"
cp -r "${SRCDIR}/management"  "${PKG}/usr/lib/server-suite/"
cp -r "${SRCDIR}/roles"       "${PKG}/usr/lib/server-suite/"
cp -r "${SRCDIR}/setup_ui"    "${PKG}/usr/lib/server-suite/"
cp -r "${SRCDIR}/tests"       "${PKG}/usr/lib/server-suite/"
cp    "${SRCDIR}/server_suite.py" "${PKG}/usr/lib/server-suite/"
cp    "${SRCDIR}/requirements.txt" "${PKG}/usr/lib/server-suite/"
cp    "${SRCDIR}/install.sh"   "${PKG}/usr/lib/server-suite/"

# Remove __pycache__ from package
find "${PKG}" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${PKG}" -name "*.pyc" -delete 2>/dev/null || true

# Packaging metadata
INSTALLED_KB=$(du -sk "${PKG}/usr" | awk '{print $1}')

cat > "${PKG}/DEBIAN/control" << EOF
Package: server-suite
Version: ${VERSION}
Architecture: all
Maintainer: Server Suite <server-suite@localhost>
Installed-Size: ${INSTALLED_KB}
Depends: python3 (>= 3.10), python3-pip, curl, git, ca-certificates, gnupg, lsb-release, ufw, fail2ban, auditd, chrony, cockpit, sudo
Recommends: docker-ce | docker.io, samba, freeipa-server
Suggests: freeipa-server-dns, mailcow, borgbackup
Section: admin
Priority: optional
Homepage: https://github.com/server-suite/server-suite
Description: All-in-one Linux server deployment and management suite
 Server Suite is a comprehensive, role-based server automation tool for
 Ubuntu/Debian. Provides a browser-based setup wizard and terminal console
 for deploying: FreeIPA/Samba AD, storage RAID, mail (Mailcow), web proxy,
 databases, Nextcloud, Matrix, WireGuard VPN, Wazuh SIEM, and more.
 .
 Run 'sudo server-suite' to begin.
EOF

# postinst / prerm
cp "${SRCDIR}/packaging/postinst" "${PKG}/DEBIAN/postinst"
cp "${SRCDIR}/packaging/prerm"    "${PKG}/DEBIAN/prerm"
chmod 755 "${PKG}/DEBIAN/postinst" "${PKG}/DEBIAN/prerm"

# conffiles
echo "/etc/server-suite/defaults.conf" > "${PKG}/DEBIAN/conffiles"

# /etc/server-suite/defaults.conf
cp "${SRCDIR}/packaging/defaults.conf" "${PKG}/etc/server-suite/defaults.conf"

# /usr/bin/server-suite wrapper
cp "${SRCDIR}/packaging/server-suite.sh" "${PKG}/usr/bin/server-suite"
chmod 755 "${PKG}/usr/bin/server-suite"

# Man page
if [ -f "${SRCDIR}/docs/server-suite.8" ]; then
    cp "${SRCDIR}/docs/server-suite.8" "${PKG}/usr/share/man/man8/server-suite.8"
    gzip -9f "${PKG}/usr/share/man/man8/server-suite.8"
fi

# Changelog / copyright
if [ -f "${SRCDIR}/CHANGELOG.md" ]; then
    gzip -9c "${SRCDIR}/CHANGELOG.md" > "${PKG}/usr/share/doc/server-suite/changelog.Debian.gz"
fi
if [ -f "${SRCDIR}/LICENSE" ]; then
    cp "${SRCDIR}/LICENSE" "${PKG}/usr/share/doc/server-suite/copyright"
fi

# Fix permissions
find "${PKG}/usr/lib/server-suite" -name "*.py" -exec chmod 644 {} \;
find "${PKG}/usr/lib/server-suite" -name "*.sh" -exec chmod 755 {} \;
chmod 755 "${PKG}/usr/lib/server-suite/server_suite.py"

# Build
dpkg-deb --build --root-owner-group "${PKG}" "${OUTDIR}/${PKGNAME}.deb"

echo ""
echo "Built: ${OUTDIR}/${PKGNAME}.deb"
dpkg-deb --info "${OUTDIR}/${PKGNAME}.deb" | grep -E "Package|Version|Size"

# Cleanup
rm -rf "${BUILDDIR}"
