#!/bin/bash
# Build Debian package for Server Suite v2.0.0

set -e

VERSION="2.0.0"
PACKAGE_DIR="server-suite_${VERSION}_all"

echo "Building Server Suite v${VERSION}..."

# Clean previous build
rm -rf ${PACKAGE_DIR} *.deb

# Create directory structure
mkdir -p ${PACKAGE_DIR}/opt/server-suite
mkdir -p ${PACKAGE_DIR}/DEBIAN
mkdir -p ${PACKAGE_DIR}/usr/local/bin

# Copy application files
cp -r core roles setup_ui server_suite.py requirements.txt ${PACKAGE_DIR}/opt/server-suite/
cp DEBIAN/* ${PACKAGE_DIR}/DEBIAN/

# Copy scripts
cp scripts/*.sh ${PACKAGE_DIR}/opt/server-suite/ 2>/dev/null || true

# Create wrapper script
cat > ${PACKAGE_DIR}/usr/local/bin/server-suite << 'EOF'
#!/bin/bash
cd /opt/server-suite
exec python3 server_suite.py "$@"
EOF
chmod +x ${PACKAGE_DIR}/usr/local/bin/server-suite

# Set permissions
chmod -R 755 ${PACKAGE_DIR}/opt/server-suite

# Build package
dpkg-deb --build ${PACKAGE_DIR}

echo "Done: ${PACKAGE_DIR}.deb"
echo ""
echo "To install: sudo dpkg -i ${PACKAGE_DIR}.deb"
echo "Or distribute the .deb file to your users."