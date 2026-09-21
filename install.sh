#!/usr/bin/env bash
# Universal Installer for Salesforce Specialist Agent Scanner (sf-agent-scan)
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
REPO_URL="https://github.com/cease15/salesforce-agent-scanner.git"
CLONE_DIR="${TMPDIR:-/tmp}/salesforce-agent-scanner-install"

echo "================================================================"
echo "Installing Salesforce Specialist Agent Scanner (sf-agent-scan)"
echo "Target directory: ${INSTALL_DIR}"
echo "================================================================"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required. Please install Python 3.8+." >&2
  exit 1
fi

mkdir -p "${INSTALL_DIR}"

# Clone or pull latest
if [ -d "${CLONE_DIR}" ]; then
  rm -rf "${CLONE_DIR}"
fi

echo "Fetching latest version from ${REPO_URL}..."
git clone --depth 1 "${REPO_URL}" "${CLONE_DIR}"

# Copy package files into destination lib
TARGET_LIB="${INSTALL_DIR}/../lib/sf_agent_scanner"
mkdir -p "${TARGET_LIB}"
cp -R "${CLONE_DIR}/sf_agent_scanner/"* "${TARGET_LIB}/"

# Write standalone launcher script
cat <<'EOF' > "${INSTALL_DIR}/sf-agent-scan"
#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Locate library next to executable or in standard lib
lib_path = Path(__file__).resolve().parent.parent / "lib"
if lib_path.exists():
    sys.path.insert(0, str(lib_path))

from sf_agent_scanner.cli import main

if __name__ == "__main__":
    main()
EOF

chmod +x "${INSTALL_DIR}/sf-agent-scan"
rm -rf "${CLONE_DIR}"

echo "----------------------------------------------------------------"
echo "Installation complete: ${INSTALL_DIR}/sf-agent-scan"
echo "Ensure ${INSTALL_DIR} is in your PATH:"
echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
echo "----------------------------------------------------------------"
"${INSTALL_DIR}/sf-agent-scan" --help | head -n 5
