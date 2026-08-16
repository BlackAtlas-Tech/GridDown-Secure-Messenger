<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->
# GridDown Secure Messenger — Web Flasher

Browser-based firmware flasher for the T-Deck CYPHER M8K (ESP32-S3FN16R8).
Uses Web Serial API + esptool-js v0.5.7 — no software installation required.

## Target Device

- **Board**: LILYGO T-Deck CYPHER M8K
- **Chip**: ESP32-S3FN16R8 (Dual-core LX7, 16MB Flash, 8MB PSRAM)
- **USB**: Native USB CDC (VID 0x303A — Espressif, `ARDUINO_USB_CDC_ON_BOOT=1`)
- **Memory type**: qio_opi (QIO flash, OPI PSRAM)
- **Framework**: Arduino via PlatformIO (espressif32@6.5.0)
- **Filesystem**: LittleFS

## Repository Contents

```
flasher/
    index.html                           ← Web flasher (deploys to flash.blackatlas.tech)
    release.sh                           ← Build + merge + manifest automation script
    firmware/messenger/manifest.json     ← Firmware version catalog
    _headers_for_main_site               ← CORS headers for blackatlas.tech
    README.md                            ← This file
```

## Releasing Firmware

### Prerequisites

Install these tools once:

```bash
pip install platformio esptool
brew install jq          # macOS
# or: apt install jq     # Linux
```

### Release Workflow

From your firmware project root (where `platformio.ini` lives):

```bash
# 1. Commit your changes
git add -A && git commit -m "v1.0.1 — fix channel hopping timing"

# 2. Tag the release
git tag v1.0.1
git push origin main v1.0.1

# 3. Build + merge + update manifest (one command)
./release.sh 1.0.1

# 4. Upload the two files from ./release/ to blackatlas.tech:
#    - griddown-messenger-1.0.1.bin   → /firmware/messenger/
#    - manifest.json                  → /firmware/messenger/
```

That's it. The script handles building, merging all 4 binary parts, computing the SHA-256 hash, and updating the manifest with the new version. Users flash via `flash.blackatlas.tech`.

### What the script does

1. **Validates** — checks for `platformio.ini`, required tools (`pio`, `esptool.py`, `jq`), clean git state, and version tag
2. **Builds** — runs `pio run -e tdeck` (fails fast on build errors)
3. **Finds boot_app0.bin** — auto-detects the OTA partition selector from your PlatformIO installation (location varies between platform versions)
4. **Merges** — combines 4 binaries into a single flashable image:
   - `bootloader.bin` at `0x0`
   - `partitions.bin` at `0x8000`
   - `boot_app0.bin` at `0xE000`
   - `firmware.bin` at `0x10000`
   - Flash config: mode=dio, freq=80m, size=16MB
5. **Hashes** — SHA-256 of the merged binary (stored in manifest for integrity verification)
6. **Updates manifest.json** — prepends the new version entry (newest first), replaces if duplicate

### What the script does NOT do

- Git tag or push (you do this yourself, before or after)
- Upload to blackatlas.tech (you do this yourself)
- Auto-increment version numbers

### Script output

```
release/
    griddown-messenger-1.0.1.bin     ← Merged flashable binary (typically 1.5-3 MB)
    manifest.json                    ← Updated version catalog
```

### Manual merge (without script)

If you prefer to merge manually:

```bash
pio run -e tdeck

esptool.py --chip esp32s3 merge_bin \
    -o griddown-messenger-1.0.1.bin \
    --flash_mode dio \
    --flash_freq 80m \
    --flash_size 16MB \
    0x0     .pio/build/tdeck/bootloader.bin \
    0x8000  .pio/build/tdeck/partitions.bin \
    0xe000  ~/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin \
    0x10000 .pio/build/tdeck/firmware.bin
```

Note: The `boot_app0.bin` path varies by PlatformIO version. The release script auto-detects this.

## Deploying the Web Flasher

### flash.blackatlas.tech (Cloudflare Pages)

1. Create a new Cloudflare Pages project
2. Upload `index.html` (single file — no build needed)
3. Add custom domain: `flash.blackatlas.tech`
4. DNS: CNAME `flash` → Cloudflare Pages

### CORS on blackatlas.tech

The flasher at `flash.blackatlas.tech` fetches firmware from `blackatlas.tech`.
Add these CORS headers to the main site's `_headers` file:

```
/firmware/*
    Access-Control-Allow-Origin: https://flash.blackatlas.tech
    Access-Control-Allow-Methods: GET
    Access-Control-Allow-Headers: Content-Type
```

### Firmware hosting on blackatlas.tech

```
blackatlas.tech/firmware/messenger/
    manifest.json                        ← Version catalog (fetched on page load)
    griddown-messenger-1.0.0.bin         ← Merged binary v1.0.0
    griddown-messenger-1.0.1.bin         ← Merged binary v1.0.1
    ...
```

## Entering Download Mode

The T-Deck uses ESP32-S3 native USB (`ARDUINO_USB_CDC_ON_BOOT=1`), not an external UART bridge.

If the flasher can't connect:

1. Hold **BOOT** button
2. While holding BOOT, press and release **RESET**
3. Release **BOOT**
4. Device is now in download mode — click "Connect Device" in the flasher

The device appears as "USB JTAG/serial debug unit" in the browser's serial port picker (Espressif VID `0x303A`).

## Build Directory Size

After `pio run -e tdeck`, the `.pio/build/tdeck/` directory can be 50-200+ MB due to compiled object files, library caches, and framework binaries. This is normal. The release script only reads 3 small files from the build directory:

| File | Typical Size |
|---|---|
| `bootloader.bin` | ~16 KB |
| `partitions.bin` | ~3 KB |
| `firmware.bin` | 1.5-3 MB |

Plus `boot_app0.bin` (~8 KB) from the PlatformIO framework package. The merged output is typically 1.5-3 MB. The rest of the build directory is ignored.

## Browser Support

- Google Chrome 89+ ✓
- Microsoft Edge 89+ ✓
- Safari ✗ (no Web Serial API)
- Firefox ✗ (no Web Serial API)
- Mobile browsers ✗ (no Web Serial API)

## Flash Configuration Reference

| Parameter | Value | Reason |
|---|---|---|
| Chip | esp32s3 | T-Deck CYPHER M8K SoC |
| Flash mode | dio | Bootloader uses DIO; switches to QIO at runtime (qio_opi memory type) |
| Flash freq | 80m | Matches espressif32@6.5.0 platform defaults for qio_opi |
| Flash size | 16MB | ESP32-S3FN16R8 has 16MB integrated flash |
| Bootloader offset | 0x0 | ESP32-S3 (not 0x1000 like original ESP32) |
| Partition table | 0x8000 | Standard ESP-IDF offset |
| OTA selector | 0xE000 | boot_app0.bin — required for OTA partition switching |
| Application | 0x10000 | Standard app offset (64KB) |
