#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
# SPDX-License-Identifier: GPL-3.0-or-later
# ═══════════════════════════════════════════════════════════════════
# GridDown Secure Messenger — Firmware Release Script
#
# Usage:  ./release.sh <version>
# Example: ./release.sh 1.0.1
#
# What it does:
#   1. Builds firmware via PlatformIO (pio run -e tdeck)
#   2. Merges 4 binaries into a single flashable image
#   3. Updates manifest.json with the new version
#   4. Copies release artifacts to the output directory
#
# What it does NOT do:
#   - Git tag/push (do that yourself before or after)
#   - Upload to blackatlas.tech (do that yourself after)
#
# Requirements:
#   - PlatformIO CLI (pio) installed and in PATH
#   - esptool.py installed (pip install esptool)
#   - jq installed (for manifest.json manipulation)
#   - Run from the firmware project root (where platformio.ini lives)
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No color

# ── Config ──
PIO_ENV="tdeck"
CHIP="esp32s3"
FLASH_MODE="dio"
FLASH_FREQ="80m"
FLASH_SIZE="16MB"
OUTPUT_DIR="./release"
MANIFEST_FILE="${OUTPUT_DIR}/manifest.json"
FIRMWARE_URL_BASE="https://blackatlas.tech/firmware/messenger"

# ── PlatformIO build output paths ──
BUILD_DIR=".pio/build/${PIO_ENV}"
BOOTLOADER="${BUILD_DIR}/bootloader.bin"
PARTITIONS="${BUILD_DIR}/partitions.bin"
FIRMWARE="${BUILD_DIR}/firmware.bin"

# ── Functions ──
info()    { echo -e "${CYAN}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── Validate arguments ──
if [ $# -ne 1 ]; then
    echo -e "${BOLD}GridDown Secure Messenger — Firmware Release${NC}"
    echo ""
    echo "Usage: $0 <version>"
    echo "  e.g. $0 1.0.1"
    echo ""
    echo "Run from the firmware project root (where platformio.ini lives)."
    exit 1
fi

VERSION="$1"
OUTPUT_FILE="griddown-messenger-${VERSION}.bin"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_FILE}"

# Validate version format (semver-ish: digits and dots)
if ! echo "${VERSION}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    error "Invalid version format '${VERSION}'. Use semver: X.Y.Z (e.g. 1.0.1)"
fi

echo ""
echo -e "${BOLD}GridDown Secure Messenger — Release v${VERSION}${NC}"
echo "────────────────────────────────────────────────"
echo ""

# ── Pre-flight checks ──
info "Running pre-flight checks..."

# Check we're in the right directory
if [ ! -f "platformio.ini" ]; then
    error "platformio.ini not found. Run this script from the firmware project root."
fi

# Check required tools
command -v pio >/dev/null 2>&1      || error "PlatformIO CLI (pio) not found. Install: pip install platformio"
command -v esptool.py >/dev/null 2>&1 || error "esptool.py not found. Install: pip install esptool"
command -v jq >/dev/null 2>&1       || error "jq not found. Install: brew install jq (macOS) or apt install jq (Linux)"
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || error "sha256sum/shasum not found."

# SHA-256 helper (macOS uses shasum, Linux uses sha256sum)
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Check for clean git state
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        warn "Working directory has uncommitted changes. Consider committing before release."
    else
        success "Git working directory is clean."
    fi

    # Check if version tag exists
    if git tag -l "v${VERSION}" | grep -q "v${VERSION}"; then
        success "Git tag v${VERSION} exists."
    else
        warn "Git tag v${VERSION} not found — remember to tag this release."
    fi
else
    warn "Not a git repository or git not installed. Skipping git checks."
fi

# Check if output already exists
if [ -f "${OUTPUT_PATH}" ]; then
    warn "Output file ${OUTPUT_PATH} already exists. It will be overwritten."
fi

success "Pre-flight checks passed."
echo ""

# ── Step 1: Build ──
info "Building firmware (pio run -e ${PIO_ENV})..."
echo ""

if ! pio run -e "${PIO_ENV}"; then
    error "PlatformIO build failed. Fix build errors and try again."
fi

echo ""
success "Build completed."

# Verify build outputs exist
[ -f "${BOOTLOADER}" ] || error "Bootloader not found at ${BOOTLOADER}"
[ -f "${PARTITIONS}" ] || error "Partition table not found at ${PARTITIONS}"
[ -f "${FIRMWARE}" ]   || error "Firmware not found at ${FIRMWARE}"
success "Build outputs verified."

# ── Find boot_app0.bin ──
# PlatformIO stores this in the framework package — location varies by version.
# Search common locations.
BOOT_APP0=""
SEARCH_PATHS=(
    "${HOME}/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"
    "${HOME}/.platformio/packages/framework-arduinoespressif32@*/tools/partitions/boot_app0.bin"
    "${BUILD_DIR}/../../packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"
)

for pattern in "${SEARCH_PATHS[@]}"; do
    # Use ls to expand glob, take first match
    match=$(ls ${pattern} 2>/dev/null | head -1)
    if [ -n "${match}" ] && [ -f "${match}" ]; then
        BOOT_APP0="${match}"
        break
    fi
done

if [ -z "${BOOT_APP0}" ]; then
    # Last resort: find in platformio packages
    BOOT_APP0=$(find "${HOME}/.platformio" -name "boot_app0.bin" -path "*/partitions/*" 2>/dev/null | head -1)
fi

[ -n "${BOOT_APP0}" ] && [ -f "${BOOT_APP0}" ] || error "boot_app0.bin not found. Check your PlatformIO installation."
success "Found boot_app0.bin: ${BOOT_APP0}"

# Print binary sizes
echo ""
info "Binary sizes:"
echo "    Bootloader:  $(wc -c < "${BOOTLOADER}" | tr -d ' ') bytes"
echo "    Partitions:  $(wc -c < "${PARTITIONS}" | tr -d ' ') bytes"
echo "    boot_app0:   $(wc -c < "${BOOT_APP0}" | tr -d ' ') bytes"
echo "    Application: $(wc -c < "${FIRMWARE}" | tr -d ' ') bytes"
echo ""

# ── Step 2: Merge ──
info "Merging binaries into ${OUTPUT_FILE}..."

mkdir -p "${OUTPUT_DIR}"

esptool.py --chip "${CHIP}" merge_bin \
    -o "${OUTPUT_PATH}" \
    --flash_mode "${FLASH_MODE}" \
    --flash_freq "${FLASH_FREQ}" \
    --flash_size "${FLASH_SIZE}" \
    0x0     "${BOOTLOADER}" \
    0x8000  "${PARTITIONS}" \
    0xe000  "${BOOT_APP0}" \
    0x10000 "${FIRMWARE}"

[ -f "${OUTPUT_PATH}" ] || error "Merge failed — output file not created."

MERGED_SIZE=$(wc -c < "${OUTPUT_PATH}" | tr -d ' ')
MERGED_HASH=$(sha256 "${OUTPUT_PATH}")
MERGED_SIZE_KB=$((MERGED_SIZE / 1024))
MERGED_SIZE_MB=$(echo "scale=2; ${MERGED_SIZE} / 1048576" | bc 2>/dev/null || echo "${MERGED_SIZE_KB}KB")

success "Merged binary created: ${OUTPUT_PATH}"
echo "    Size:   ${MERGED_SIZE} bytes (${MERGED_SIZE_KB} KB)"
echo "    SHA256: ${MERGED_HASH}"
echo ""

# ── Step 3: Update manifest ──
info "Updating manifest.json..."

TODAY=$(date +%Y-%m-%d)
FIRMWARE_URL="${FIRMWARE_URL_BASE}/${OUTPUT_FILE}"

NEW_ENTRY=$(jq -n \
    --arg version "${VERSION}" \
    --arg label "${VERSION} (Stable)" \
    --arg date "${TODAY}" \
    --arg url "${FIRMWARE_URL}" \
    --arg notes "Release v${VERSION}" \
    --arg sha256 "${MERGED_HASH}" \
    '{
        version: $version,
        label: $label,
        date: $date,
        url: $url,
        offset: 0,
        sha256: $sha256,
        notes: $notes
    }')

if [ -f "${MANIFEST_FILE}" ]; then
    # Check for duplicate version
    EXISTING=$(jq -r ".versions[] | select(.version == \"${VERSION}\") | .version" "${MANIFEST_FILE}" 2>/dev/null || echo "")
    if [ -n "${EXISTING}" ]; then
        warn "Version ${VERSION} already exists in manifest. Replacing it."
        # Remove the existing entry, then prepend new one
        UPDATED=$(jq --argjson new "${NEW_ENTRY}" \
            '.versions = [$new] + [.versions[] | select(.version != "'"${VERSION}"'")]' \
            "${MANIFEST_FILE}")
    else
        # Prepend new version (newest first)
        UPDATED=$(jq --argjson new "${NEW_ENTRY}" \
            '.versions = [$new] + .versions' \
            "${MANIFEST_FILE}")
    fi
    echo "${UPDATED}" | jq '.' > "${MANIFEST_FILE}"
else
    # Create new manifest
    jq -n \
        --arg device "T-Deck CYPHER M8K" \
        --arg chip "ESP32-S3FN16R8" \
        --argjson versions "[${NEW_ENTRY}]" \
        '{
            device: $device,
            chip: $chip,
            description: "GridDown Secure Messenger firmware for T-Deck CYPHER M8K",
            versions: $versions
        }' > "${MANIFEST_FILE}"
fi

success "Manifest updated: ${MANIFEST_FILE}"
jq '.versions[0]' "${MANIFEST_FILE}"
echo ""

# ── Summary ──
echo "────────────────────────────────────────────────"
echo -e "${GREEN}${BOLD}Release v${VERSION} ready.${NC}"
echo "────────────────────────────────────────────────"
echo ""
echo "  Release artifacts in: ${OUTPUT_DIR}/"
echo "    ${OUTPUT_FILE}   ($(du -h "${OUTPUT_PATH}" | cut -f1))"
echo "    manifest.json"
echo ""
echo "  SHA256: ${MERGED_HASH}"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo "  1. Upload to blackatlas.tech:"
echo "     ${FIRMWARE_URL_BASE}/${OUTPUT_FILE}"
echo "     ${FIRMWARE_URL_BASE}/manifest.json"
echo ""
echo "  2. Tag the release (if you haven't already):"
echo "     git tag v${VERSION}"
echo "     git push origin v${VERSION}"
echo ""
echo "  3. Users flash via: https://flash.blackatlas.tech"
echo ""
