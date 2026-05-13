#!/bin/bash

# Installer script for ubuntu-security-check
# Downloads security-check.sh and installs it to /usr/local/bin

set -euo pipefail

REPO_URL="https://raw.githubusercontent.com/TheSolyboy/ubuntu-security-check/main"
SCRIPT_NAME="security-check.sh"
INSTALL_PATH="/usr/local/bin/${SCRIPT_NAME}"

echo "🔧 Installing Ubuntu Security Check..."

# Download the script
echo "⬇️  Downloading ${SCRIPT_NAME}..."
if ! curl -fsSL "${REPO_URL}/${SCRIPT_NAME}" -o "/tmp/${SCRIPT_NAME}" 2>/dev/null; then
    echo "⚠️  Retry with alternate URL casing..."
    REPO_URL="https://raw.githubusercontent.com/thesolyboy/ubuntu-security-check/main"
    curl -fsSL "${REPO_URL}/${SCRIPT_NAME}" -o "/tmp/${SCRIPT_NAME}"
fi

# Make it executable
chmod +x "/tmp/${SCRIPT_NAME}"

# Move to system path
echo "📦 Installing to ${INSTALL_PATH}..."
sudo mv "/tmp/${SCRIPT_NAME}" "${INSTALL_PATH}"

# Verify installation
if command -v "${SCRIPT_NAME}" >/dev/null 2>&1; then
    echo "✅ Installation complete!"
    echo ""
    echo "🚀 Running security check..."
    echo ""
    sudo "${SCRIPT_NAME}"
else
    echo "❌ Installation failed. Please check permissions and try again."
    exit 1
fi
