#!/usr/bin/env bash
# fetch-scripts.sh
# Run at build time to pull the latest setup scripts from ADORSYS-GIS/wazuh-agent

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")/../scripts" && pwd)"
mkdir -p "$SCRIPTS_DIR"

BASE="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent/refs/heads/develop/scripts"

echo "📥 Fetching Unix setup script (Linux/macOS)..."
curl -fsSL "$BASE/setup-agent.sh" -o "$SCRIPTS_DIR/setup-agent.sh"
chmod +x "$SCRIPTS_DIR/setup-agent.sh"

echo "📥 Fetching Windows setup script..."
curl -fsSL "$BASE/windows/setup-agent.ps1" -o "$SCRIPTS_DIR/setup-agent.ps1" || {
  echo "⚠️  setup-agent.ps1 not found at expected path, trying root scripts dir..."
  curl -fsSL "$BASE/setup-agent.ps1" -o "$SCRIPTS_DIR/setup-agent.ps1" || {
    echo "⚠️  setup-agent.ps1 not found, creating placeholder..."
    cat > "$SCRIPTS_DIR/setup-agent.ps1" << 'EOF'
# GuardPost - Windows setup agent placeholder
# Replace this with the real setup-agent.ps1 from ADORSYS-GIS/wazuh-agent
param(
    [string]$SuricataMode = "ids",
    [switch]$InstallSnort,
    [switch]$InstallTrivy
)
Write-Host "Windows agent setup — script not yet available." -ForegroundColor Yellow
exit 1
EOF
  }
}

echo "📥 Fetching shared utilities..."
curl -fsSL "$BASE/shared/utils.sh" -o "$SCRIPTS_DIR/utils.sh" || {
  echo "⚠️  utils.sh not found, skipping."
}

echo "✅ Scripts fetched to $SCRIPTS_DIR"
ls -lh "$SCRIPTS_DIR"
