#!/usr/bin/env bash
# dev-setup.sh - one-shot setup for local development
set -euo pipefail

echo "🛡️  GuardPost dev setup"
echo "========================"

# Check node
if ! command -v node &>/dev/null; then
  echo "❌ Node.js not found. Install from https://nodejs.org"
  exit 1
fi

# Check rust
if ! command -v cargo &>/dev/null; then
  echo "❌ Rust not found. Install from https://rustup.rs"
  exit 1
fi

# Linux deps check
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  echo "📦 Checking Linux build dependencies..."
  MISSING=()
  for pkg in libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libgtk-3-dev; do
    dpkg -s "$pkg" &>/dev/null || MISSING+=("$pkg")
  done
  if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Installing missing packages: ${MISSING[*]}"
    sudo apt-get install -y "${MISSING[@]}"
  fi
fi

echo "📥 Fetching bundled agent scripts..."
bash scripts/fetch-scripts.sh

echo "📦 Installing frontend dependencies..."
npm install

echo ""
echo "✅ Done! Run the app with:"
echo "   npm run tauri dev"
