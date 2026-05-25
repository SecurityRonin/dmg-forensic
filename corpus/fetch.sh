#!/usr/bin/env bash
# Generate DMG corpus image using hdiutil (macOS only).
# This script runs on macos-latest in CI (see .github/workflows/ci.yml corpus job).
set -euo pipefail

DEST="$(cd "$(dirname "$0")" && pwd)"
WORK=$(mktemp -d)

# Create a 10 MiB HFS+ DMG
hdiutil create \
  -size 10m \
  -fs HFS+ \
  -volname CorpusDMG \
  -ov \
  "${DEST}/test"

# Also produce a UDZO (zlib-compressed) variant for the compressed block path
hdiutil convert "${DEST}/test.dmg" \
  -format UDZO \
  -ov \
  -o "${DEST}/test_compressed" 2>/dev/null || true

rm -rf "${WORK}"
