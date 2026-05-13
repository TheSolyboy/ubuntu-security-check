#!/bin/bash

# Installer script for ubuntu-security-check
# Downloads security-check.sh and installs it to /usr/local/bin (or ~/.local/bin)

set -euo pipefail

SCRIPT_NAME="security-check.sh"
TMP_FILE=$(mktemp /tmp/security-check.XXXXXX)
trap 'rm -f "$TMP_FILE"' EXIT

echo "🔧 Installing Ubuntu Security Check..."

# Download with fallback for URL casing
echo "⬇️  Downloading ${SCRIPT_NAME}..."
if ! curl -fsSL "https://raw.githubusercontent.com/TheSolyboy/ubuntu-security-check/main/${SCRIPT_NAME}" -o "$TMP_FILE" 2>/dev/null; then
    echo "⚠️  Primary URL failed, trying alternate casing..."
    if ! curl -fsSL "https://raw.githubusercontent.com/thesolyboy/ubuntu-security-check/main/${SCRIPT_NAME}" -o "$TMP_FILE" 2>/dev/null; then
        echo "❌ Download failed. Please check your internet connection."
        exit 1
    fi
fi

chmod +x "$TMP_FILE"

# Determine install path (system-wide if root/sudo, else user-local)
if [ "$(id -u)" -eq 0 ] || [ -w "/usr/local/bin" ]; then
    INSTALL_PATH="/usr/local/bin/${SCRIPT_NAME}"
    mkdir -p /usr/local/bin
else
    INSTALL_PATH="${HOME}/.local/bin/${SCRIPT_NAME}"
    mkdir -p "${HOME}/.local/bin"

    if [[ ":$PATH:" != *":${HOME}/.local/bin:"* ]]; then
        echo ""
        echo "⚠️  ${HOME}/.local/bin is not in your PATH."
        echo "   Add this to your ~/.bashrc or ~/.zshrc:"
        echo '   export PATH="${HOME}/.local/bin:${PATH}"'
        echo ""
    fi
fi

echo "📦 Installing to ${INSTALL_PATH}..."
mv "$TMP_FILE" "$INSTALL_PATH"

echo "✅ Installation complete!"
echo ""
echo "🚀 Run with: ${INSTALL_PATH}"
