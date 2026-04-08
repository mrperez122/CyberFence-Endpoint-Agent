#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# CyberFence Endpoint — Linux / CI MSI builder using wixl (msitools)
#
# Usage:
#   ./installer/scripts/build-wixl.sh
#
# Requirements:
#   - wixl + msitools installed (sudo apt install wixl msitools)
#   - cf-agent.exe cross-compiled to dist/CyberFence-Endpoint-v0.1.0-Windows/
#
# Output:
#   dist/CyberFence-Endpoint-v0.1.0.msi
#
# Note:
#   Uses Product_wixl.wxs (wixl-compatible subset).
#   Full WiX 3 installer with branded UI + VBScript CAs → Product.wxs
#   (requires WiX Toolset 3.11 on Windows, see installer/scripts/build.ps1)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER_DIR="$REPO_ROOT/installer"
WXS_DIR="$INSTALLER_DIR/wix"
DIST_DIR="$REPO_ROOT/dist/CyberFence-Endpoint-v0.1.0-Windows"
OUTPUT_MSI="$REPO_ROOT/dist/CyberFence-Endpoint-v0.1.0.msi"
BUILD_DIR="$INSTALLER_DIR/build"

echo "=================================================="
echo " CyberFence Endpoint — MSI Builder (wixl)"
echo "=================================================="
echo "Repo root   : $REPO_ROOT"
echo "Dist dir    : $DIST_DIR"
echo "Output MSI  : $OUTPUT_MSI"
echo ""

# ── Validate prerequisites ────────────────────────────────────────────────
if ! command -v wixl &>/dev/null; then
    echo "ERROR: wixl not found. Install with: sudo apt install wixl msitools"
    exit 1
fi

if [ ! -f "$DIST_DIR/cf-agent.exe" ]; then
    echo "ERROR: cf-agent.exe not found at $DIST_DIR/cf-agent.exe"
    echo "Build the Windows binary first:"
    echo "  cargo build --release --target x86_64-pc-windows-gnu"
    echo "  cp target/x86_64-pc-windows-gnu/release/cf-agent.exe $DIST_DIR/"
    exit 1
fi

echo "[✓] wixl found: $(which wixl)"
echo "[✓] cf-agent.exe found ($(du -sh "$DIST_DIR/cf-agent.exe" | cut -f1))"

# ── Create build dir ──────────────────────────────────────────────────────
mkdir -p "$BUILD_DIR"
mkdir -p "$(dirname "$OUTPUT_MSI")"

# ── Preprocess: substitute DIST_DIR_PLACEHOLDER with real path ────────────
PREPROCESSED="$BUILD_DIR/Product_wixl_pp.wxs"
sed "s|DIST_DIR_PLACEHOLDER|$DIST_DIR|g" \
    "$WXS_DIR/Product_wixl.wxs" > "$PREPROCESSED"

echo "[✓] WXS preprocessed → $PREPROCESSED"

# ── Build MSI with wixl ───────────────────────────────────────────────────
echo ""
echo "[1/1] Building MSI with wixl..."

wixl \
    --arch x64 \
    --output "$OUTPUT_MSI" \
    "$PREPROCESSED"

if [ $? -eq 0 ] && [ -f "$OUTPUT_MSI" ]; then
    MSI_SIZE=$(du -sh "$OUTPUT_MSI" | cut -f1)
    echo ""
    echo "=================================================="
    echo " ✓ MSI built successfully!"
    echo "   Output : $OUTPUT_MSI"
    echo "   Size   : $MSI_SIZE"
    echo "=================================================="
    echo ""
    echo "Validate with msiinfo:"
    echo "  msiinfo suminfo $OUTPUT_MSI"
    echo "  msiinfo tables  $OUTPUT_MSI"
    echo ""
    echo "Install on Windows:"
    echo "  msiexec /i CyberFence-Endpoint-v0.1.0.msi /l*v install.log"
    echo ""
    echo "Silent install (no UI):"
    echo "  msiexec /i CyberFence-Endpoint-v0.1.0.msi /qn /l*v install.log"
else
    echo "ERROR: wixl failed. Check output above."
    exit 1
fi
