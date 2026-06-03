#!/bin/bash
set -euo pipefail

REPO="chojuninengu/guardpost"
VERSION="${1:-latest}"

echo "📥 Downloading GuardPost for macOS..."

if [ "$VERSION" = "latest" ]; then
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" \
    | grep browser_download_url | grep dmg | head -1 | cut -d'"' -f4)
else
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/$VERSION" \
    | grep browser_download_url | grep dmg | head -1 | cut -d'"' -f4)
fi

if [ -z "$DL_URL" ]; then
  echo "❌ Could not find macOS DMG in release"
  echo "   Visit https://github.com/$REPO/releases to check available assets"
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$DL_URL" -o "$TMP/GuardPost.dmg"

echo "📦 Installing..."
hdiutil attach "$TMP/GuardPost.dmg" -mountpoint "$TMP/mount" -quiet
cp -R "$TMP/mount/GuardPost.app" /Applications/
hdiutil detach "$TMP/mount" -quiet

echo "🛡️  Removing quarantine attribute..."
xattr -dr com.apple.quarantine /Applications/GuardPost.app

echo "✅ GuardPost installed! You can find it in your Applications folder."
