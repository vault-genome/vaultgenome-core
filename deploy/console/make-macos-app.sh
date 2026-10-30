#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Wraps a vgconsole binary into a macOS application a person double-clicks
# ("Vault Genome.app"), and that opens a .vgpass file when one is
# double-clicked. The bundle holds the binary as it is; its hash stays the one
# on the release's signed list.
#
# Usage: make-macos-app.sh VGCONSOLE-BINARY OUTPUT-DIR
set -euo pipefail
BIN="${1:?usage: make-macos-app.sh VGCONSOLE-BINARY OUTPUT-DIR}"
OUT="${2:?usage: make-macos-app.sh VGCONSOLE-BINARY OUTPUT-DIR}"
APP="$OUT/Vault Genome.app"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/vgconsole"
chmod 0755 "$APP/Contents/MacOS/vgconsole"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Vault Genome</string>
  <key>CFBundleDisplayName</key><string>Vault Genome</string>
  <key>CFBundleIdentifier</key><string>com.vaultgenome.console</string>
  <key>CFBundleExecutable</key><string>vgconsole</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.15</string>
  <key>LSBackgroundOnly</key><true/>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeName</key><string>Vault Genome pass</string>
      <key>CFBundleTypeRole</key><string>Viewer</string>
      <key>CFBundleTypeExtensions</key><array><string>vgpass</string></array>
    </dict>
  </array>
</dict>
</plist>
PLIST
echo "$APP"
