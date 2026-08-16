<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->
# GridDown Secure Messenger

**Encrypted off-grid radio firmware for the LILYGO T-Deck.**
Firmware v6.70.0 · GPL-3.0-or-later · BlackAtlas LLC

GridDown turns a LILYGO T-Deck CYPHER-M8K into a standalone encrypted handheld
radio that works with no cell network, no internet, and no phone. Text, voice,
and images travel over 900 MHz LoRa, encrypted with AES-256-GCM, across a mesh
that relays for peers out of direct range.

It is built for search-and-rescue teams, emergency managers, and field operators
who need communications that keep working when infrastructure does not.

---

## Contents

**Getting started:** [Read this first](#read-this-first) · [Hardware](#hardware) ·
[Install](#install) · [What it does](#what-it-does) ·
[Known limits](#known-limits-stated-up-front)

**Reference:** [Feature overview](#feature-overview) ·
[Build reference](#build-reference) · [Encryption](#encryption) ·
[Mesh networking](#mesh-networking) · [Drone scanner](#900-mhz-drone-scanner) ·
[UI screens](#ui-screens) · [Keyboard shortcuts](#keyboard-shortcuts) ·
[Serial log prefixes](#serial-log-prefixes) · [Changelog](#changelog)

**Policies:** [SECURITY.md](SECURITY.md) · [PRIVACY.md](PRIVACY.md) ·
[LICENSE](LICENSE) · [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) ·
[EXPORT_CONTROL.md](EXPORT_CONTROL.md) · [TRADEMARK.md](TRADEMARK.md) ·
[CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
[RELEASING.md](RELEASING.md)

---

## Read this first

- **[SECURITY.md](SECURITY.md)** — what this firmware protects and, just as
  importantly, **what it does not**. Packet metadata is unencrypted, transmitting
  radios can be located, and a captured radio means a compromised group key.
  Read it before deploying operationally.
- **[PRIVACY.md](PRIVACY.md)** — what the firmware records, what it transmits, and
  what it never stores. Relevant if you enable Remote ID detection or share
  position data.
- **[EXPORT_CONTROL.md](EXPORT_CONTROL.md)** — this is open-source encryption
  software. You are responsible for the export and sanctions rules that apply to
  you.
- **[TRADEMARK.md](TRADEMARK.md)** — the code is GPL; the name is not. Fork
  freely, please rename your fork.

---

## Hardware

| | |
|---|---|
| **Primary target** | LILYGO T-Deck CYPHER-M8K — ESP32-S3, SX1262 LoRa, 2.8" 320×240 display, physical keyboard, GPS, 8000 mAh |
| **Radio** | Semtech SX1262, 902–928 MHz ISM (FCC Part 15.247), 14 dBm default |
| **Storage** | 16 MB flash (8 MB app + 7.9 MB LittleFS) + microSD |
| **Optional** | Android tablet running the GridDown PWA for map and enhanced situational awareness |

Nothing here requires a phone. The tablet is optional.

---

## Install

**Easiest — browser flasher:** <https://flash.blackatlas.tech>
Binaries there are built by CI from a tagged commit in this repository, and each
release publishes a SHA-256 you can verify yourself (see *Verified builds* below).

**From source:**

```bash
pip install platformio
git clone <this repository>
cd tdeck-radio-scanner-p5-43-50
pio run -e tdeck -t upload
pio device monitor -b 115200
```

A **full erase** is required when upgrading across a partition-table change:
`pio run -e tdeck -t erase`, then upload.

### First run

1. Set a callsign.
2. Set a group passphrase — **minimum 12 characters**, identical on every radio.
3. Compare the 4-character **Key Check Value** shown in Settings across your
   radios. Matching KCVs confirm they derived the same key; differing KCVs mean
   differing passphrases.
4. To connect a tablet: read this radio's **unique** Wi-Fi password from
   Settings → `G`. There is no shared default password.

---

## What it does

Encrypted text messaging with mesh relay and store-and-forward · Codec2 encrypted
voice (three quality modes) · encrypted image transfer over LoRa · GPS-synced
channel rotation · passive 900 MHz drone scanning · acoustic gunshot detection ·
Cursor-on-Target bridge for ATAK/WinTAK · authenticated remote wipe · covert
duress signalling · tactical waypoints · peer health dashboard.

**Experimental in v6.70.0:** Remote ID (ASTM F3411) drone detection over 2.4 GHz —
opt-in (press `D` on the Scan screen), WiFi-only in the default build, and **cooperative detection only**. See
[SECURITY.md](SECURITY.md#remote-id-detection--passive-24-ghz-monitoring-experimental)
for its limits before relying on it.

**On-device help:** the Drone Detection screen has a full key reference — press
**`H`** on that screen to see every binding. Most screens show their key hints in
the footer.

Full detail in the sections below and in [`docs/`](docs/).

---

## Known limits, stated up front

- **Packet metadata is not encrypted.** Contents are protected; the fact, timing,
  and routing of transmissions are observable. Traffic analysis is possible.
- **Channel rotation is congestion avoidance, not jam resistance,** and it
  requires GPS time sync.
- **The group key is recoverable from a radio in an adversary's possession.**
  Treat a lost or captured radio as a compromised cluster key and re-key.
- **Received images are stored unencrypted** on the microSD card.
- **Anyone on the Wi-Fi access point can control the radio.**
- No third-party security audit, FIPS validation, or Common Criteria evaluation.

---

## Feature Overview

### Standalone Operation (No tablet required)
- 10-screen UI: Status, Messages, Compose, Map, Voice, Peers, Debug, Settings, Conversation, Scan
- Two-layer encryption: AES-256-GCM group PSK + per-peer ECDH E2E (P-256)
- PSK key derivation via PBKDF2-HMAC-SHA256 (10,000 iterations), encrypted at rest with device-specific wrapping key
- Ephemeral ECDH key exchange with forward secrecy — session keys auto-established via beacon, no manual pairing
- E2E encryption indicator: cyan "E2E" tag on encrypted messages in both message list and conversation views
- PSK-only fallback for messages exceeding 50-character E2E limit (with serial log notification)
- Signed delivery confirmations: HMAC-SHA256 ACK authentication using per-peer session keys prevents forgery
- Backward-compatible ACK handling: unsigned ACKs accepted from pre-signing firmware
- GPS-synced frequency hopping (FHOP): 30-second slot rotation across 8 channels, PSK-seeded deterministic schedule, requires GPS position lock (not just time)
- Codec2 voice with PTT (push-to-talk) — record, preview, send
- Three voice quality modes: Range (1600bps + 2x redundancy), Balanced (3200bps + 2x redundancy), Clarity (3200bps single pass)
- Cross-mode voice interoperability: receivers auto-detect codec mode from packet marker byte
- Voice RX timeout scales with expected parts: 15s (Range) / 21s (Balanced/Clarity)
- 4 encrypted group channels: General (blue), Command (green), Tactical (orange), Alerts (red)
- Group broadcast ACK: per-peer delivery tracking with 16-bit bitmask dedup, color-coded display (grey/yellow/green)
- Channel scan on boot: 8-channel CAD + RSSI sweep (~5 seconds), active channels highlighted
- Mesh relay with content-based deduplication (djb2 hash, survives re-encryption)
- 4-hop text relay + 2-hop voice relay with re-serialization and fresh GCM nonce per hop
- Relay-path quality mapping: per-peer link quality scoring from RSSI, SNR, and hop count
- Store-and-forward: 16-message queue with 30-minute TTL, dedup by msgId, delivers 4 messages per beacon cycle
- DM retry: 3 attempts at 5-second intervals with delivery tracking (~ pending, v delivered, X failed)
- Authenticated remote wipe: HMAC-SHA256 signed wipe commands with GPS timestamp replay protection (graceful no-GPS fallback)
- Duress PIN: 4-digit covert distress code stripped from sent messages, triggers silent alert with GPS to all peers
- GPS UTC timestamps that survive reboots (messages show correct age after power cycle)
- Mesh-distributed SA track sharing (ADS-B, Remote ID, WiFi Sentinel, FPV tracks)
- 900 MHz drone scanner with multi-discriminator classification (zone + SF + sub-band + delta), RF baseline, 4 scan profiles
- Acoustic gunshot detection with multi-sample confirmation and mesh broadcast
- Cursor-on-Target (CoT) bridge for TAK/ATAK integration via WebSocket, UDP multicast, and TCP
- Threat proximity alerts with configurable radius, altitude tracking, and auto-warnings
- Tactical waypoint sharing with mesh relay and LittleFS persistence
- Channel/PSK mismatch RF diagnostics on Status screen
- GPS baud rate persistence (cuts boot time from 7.5s to under 1.5s)
- SD card date-based log rotation with 30-day automatic cleanup
- Dead-drop sneakernet import/export via SD card
- Per-peer message threading with conversation view
- GPS position tracking and compass map display
- 8 canned tactical quick-reply messages
- Screen lock (hold-to-unlock) for field bag protection
- 4-level screen brightness with persistence
- Battery health analytics with voltage, discharge rate, and time remaining
- Radio activity indicator and signal quality monitoring
- Emergency broadcast shortcut (hold 'E' for 2s — auto-routes to Alerts channel, works from any screen including scan and lock)
- Task watchdog (30s, auto-reboot on hang) with boot crash logging

### Connected Operation (With GridDown on tablet)
- Three WiFi modes: AP (standalone), STA (join tablet hotspot), OFF (BLE+LoRa only)
- AP mode: creates GridDown-Radio network (192.168.4.1:8770), QR code scan-to-join
- STA mode: joins external network, mDNS as griddown-radio.local, QR code shows WebSocket address
- WiFi mode persisted to LittleFS, toggled via Settings F key with confirmation
- Zero-touch credential push: tablet sends WiFi config via WebSocket, operator confirms on-device
- WebSocket transport on port 8770 (JSON protocol) — works in all WiFi modes
- BLE NUS fallback transport (NimBLE) — independent of WiFi mode, always available
- CoT event forwarding to TAK clients via PWA bridge

---

## Board detail

| Board | MCU | LoRa | Display | Keyboard | GPS | Mic | PlatformIO env |
|-------|-----|------|---------|----------|-----|-----|--------|
| LILYGO T-Deck CYPHER-M8K | ESP32-S3 | SX1262 | 2.8in ST7789 320x240 | Physical + touch | u-blox M8K | ES7210 | `tdeck` |

**Buy the 915 MHz version for US operation** (902–928 MHz ISM band). A 433 or
868 MHz board will not work on the default channel plan.

---

## Build reference

```bash
pip3 install platformio --break-system-packages
cd tdeck-radio
pio run -e tdeck            # Compile
pio run -e tdeck -t upload  # Compile + flash
pio device monitor -b 115200  # Serial console
```

### Build-Time Options

| Define | Default | Purpose |
|--------|---------|---------|
| `SCAN_DEBUG` | Commented out | Enables verbose per-channel `[Scan] HIT` and `[Scan] Sweep` serial output |

### Bootloader Entry

| Method | How |
|--------|-----|
| Serial command | Type `!dfu` at 115200 baud |
| Settings screen | Press W key, confirm dialog |
| 1200bps touch | `stty -f /dev/cu.usbmodem101 1200` (macOS) |
| Hardware | Hold BOOT + press RESET |

### Serial Commands

| Command | Action |
|---------|--------|
| `!dfu` | Reboot into USB bootloader |
| `!boot` | Same as `!dfu` |
| `!reboot` | Soft reboot |
| `!info` | Print firmware version, uptime, heap, stats, battery |
| `!tak IP:PORT` | Set TAK server (e.g., `!tak 192.168.1.5:8087`) |
| `!tak off` | Disconnect and clear TAK server |
| `!tak` | Show current TAK server status |
| `!wipe local` | Immediately wipe THIS device (no confirmation) |
| `!wipe CALLSIGN` | Send authenticated remote wipe to target device |
| `!batcal X.XX` | Set battery ADC multiplier (default 2.27, persisted to LittleFS) |
| `!batcal` | Show current multiplier, raw ADC mV, and calibration instructions |
| `!help` | List available commands |

---

## Encryption

### Group PSK (Layer 1 — All Traffic)

AES-256-GCM with 12-byte random nonce per packet and 16-byte authentication tag. Passphrase derived via PBKDF2-HMAC-SHA256 (10,000 iterations, 32-byte salt). PSK key encrypted at rest on LittleFS with a device-specific XOR wrapping key. 0xAE marker byte prefix on all encrypted packets. Legacy v1 keys (SHA-256 derived) auto-migrate to v2 format on first boot. Configured via Settings K key.

### E2E Encryption (Layer 2 — Direct Messages)

Per-peer AES-256-GCM using ephemeral ECDH P-256 session keys. Keypair regenerated on every boot for forward secrecy. Public keys exchanged automatically via beacon broadcasts — no manual pairing required. E2E-encrypted messages carry the `"e2e":1` flag and base64-encoded ciphertext within the PSK-encrypted outer envelope.

**50-character limit:** LoRa payload constraint. Messages exceeding 50 characters silently fall back to PSK-only encryption. Cyan "E2E" tag appears only on messages that used E2E encryption. Serial logs: `[E2E] DM to PEER: N chars exceeds 50-char E2E limit, PSK-only`.

---

## Signed Delivery Confirmations

DM delivery ACKs are authenticated using HMAC-SHA256 over the per-peer ECDH session key. Tag computed on `"GridDown-ACK-v1|<acker>|<sender>|<msgId>"`, truncated to 8 bytes, transmitted as `"sig"` field. Signed+valid = delivered. Signed+invalid = rejected. Unsigned = accepted for backward compatibility.

---

## Remote Wipe

Authenticated device erasure via LoRa or serial. Wipe key derived via `HMAC-SHA256(pskKey, "GridDown-Wipe-v1")` (domain-separated). 16-byte HMAC tag over `"GridDown-Wipe-v1|<issuer>|<target>|<epoch>"`. GPS timestamp with 5-minute replay window. No-GPS fallback: HMAC verified, timestamp bypassed.

**Wire:** `{"type":"wipe","from":"ALPHA","to":"BRAVO","ts":1710000000,"sig":"<24-char-base64>"}`

**5-phase execution:** RAM zeroize (PSK, ECDH, sessions, messages, S&F, contacts, callsign) → LittleFS delete (14 files) → SD recursive delete → red "DEVICE WIPED" screen → ESP.restart()

**Send paths:** `!wipe local` / `!wipe CALLSIGN` serial commands; Settings UI (D key → trackball peer selection → double confirmation). Wipe commands are NOT mesh-relayed.

---

## Frequency Hopping (FHOP)

GPS-synced channel rotation across 8 channels in 30-second slots. PSK-seeded deterministic schedule. Requires GPS **position lock** (not just time) — the GPS module sends valid time from a single satellite before obtaining a position fix, so using time-only would cause one radio to hop while another stays on base channel. ~1% broadcast message loss at hop boundaries (DMs covered by retry).

---

## Duress System

4-digit PIN embedded in any outgoing message. PIN stripped before TX, hidden `"duress":true` flag added. Receiver sees normal text + DURESS alert with GPS. Setup: Settings U key.

---

## Mesh Networking

4-hop text relay + 2-hop voice relay, content-based djb2 dedup, store-and-forward (16 msg, 30min), DM retry (3x, 5s), 4 group channels, relay-path quality scoring, 8-slot relay queue cap.

---

## 900 MHz Drone Scanner

Real-time spectrum analyzer and drone detector for 902-928 MHz ISM band. 52 channels at 500 kHz steps. Detects ELRS, Crossfire, SiK, RFD900, Holybro, and unknown ISM emitters.

### Scan Profiles (P key)

| Profile | Method | Detects |
|---------|--------|---------|
| Quick LoRa | CAD SF6/BW500 | LoRa protocols only |
| All Drone (default) | CAD multi-SF + dual-BW RSSI | All drone protocols |
| Full Spectrum | RSSI only, 5-sample median | Any RF energy |
| ELRS Deep | CAD rotating SF5-8 | All ELRS rate modes |

### Multi-Discriminator Classification

Four independent discriminators distinguish drone telemetry from infrastructure:

**1. Frequency Zone Heuristic** — LoRaWAN US915 has no channels at 915.0-923.2 MHz. Any CAD in that gap = drone.

| Zone | Frequency | LoRaWAN | ELRS/Drone |
|------|-----------|---------|------------|
| Uplink | 902.3 - 914.9 MHz | 64+8 channels | Hops through |
| **Gap** | **915.0 - 923.2 MHz** | **None** | **Hops through** |
| Downlink | 923.3 - 927.5 MHz | 8 channels | Hops through |

**2. SF Discrimination** — Per-channel counters track low-SF (SF5-6, ELRS) vs high-SF (SF7+, LoRaWAN) CAD hits. >60% low-SF = drone even in uplink zone.

**3. Sub-Band Clustering** — LoRaWAN gateways listen on one 1.6 MHz sub-band. All CAD within 2 MHz span = single gateway, not drone FHSS.

**4. RF Baseline Delta** — Channels quiet during baseline but now active = new emitter. 60%+ new channels upgrades ambiguous to drone.

### Decision Tree

| Priority | Condition | Classification |
|----------|-----------|---------------|
| 1 | Any CAD in 915-923 gap | DRONE (absolute) |
| 2 | >60% low-SF + span >2MHz | DRONE (SF fingerprint) |
| 3 | ≤40% low-SF + span ≤2MHz | LoRaWAN (sub-band) |
| 4 | ≤40% low-SF + wide spread | LoRaWAN (multi-gateway) |
| 5a | 60%+ channels NEW vs baseline | DRONE (delta upgrade) |
| 5b | Otherwise | LoRaWAN (conservative) |

### Classification Types

| Type | Color | Alert | Track | Source |
|------|-------|-------|-------|--------|
| LoRa FHSS (ELRS/XFire) | Red | Yes | Yes | Drone control links |
| GFSK Telem (SiK) | Orange | Yes | Yes | Telemetry radios |
| Fixed LoRa | Yellow | Yes | No | Single-channel LoRa in gap |
| LoRaWAN Infra | Cyan | No | No | Smart meters, gateways |
| ISM Unknown | Gray | No | No | Unidentified RSSI |

### GFSK Detection (SiK / RFD900)

Two detection paths with broadband noise rejection:

**Broadband gate:** If >15% of channels are RSSI-active AND peak signal is weak (below NF+25dB), suppress all RSSI-only paths (thermal noise). If peak is strong (NF+25), gate is bypassed (real FHSS radio legitimately lights up many channels).

**Path A:** 3+ debounced channels, peak > NF+22dB, RSSI spread < 25dB.
**Path B:** 6+ transient channels in 10-sweep window, peak > NF+22dB, spread < 25dB.

**Sub-threshold awareness:** When 3+ RSSI channels are visible (NF+20) but peak is between NF+20 and NF+22, serial logs `[Scanner] Sub-threshold FHSS` every 10 seconds. Operator sees spectrum activity; system flags possible drone at range without committing to a classification.

### RF Baseline

Pre-recorded ambient RF environment for delta-based detection. Eliminates cold-start false positives and enables change-detection.

**Capture:** Press R in scan mode → 20-sweep dedicated scan (~8 seconds) → saves to LittleFS `/scan_bl.bin`.

**Per-channel data:** RSSI median (per-channel noise floor), CAD activity count, SF signature (low/high/mixed/none), infrastructure flag.

**On scan entry:** Auto-loads from LittleFS. Pre-flags infrastructure channels from sweep 1. NF divergence >10dB logged as warning.

**Clear:** Press X in scan mode. Reverts to standard behavior.

**Graceful fallback:** If no baseline exists, all detection paths work identically to non-baseline behavior. Purely additive.

**Header indicator:** "BL" in cyan when baseline is active.

### RSSI Measurement

All readings use 5-sample median (rejects SPI bus noise). 5ms AGC settle (T-Deck switching noise needs >3ms). Calibration sweep on scan entry with 3-sample median per channel, 12dB spur threshold.

### False Positive Prevention

| Mechanism | Prevents |
|-----------|----------|
| Median RSSI (not peak-hold) | SPI noise transients |
| 5ms AGC settle | Switching regulator noise |
| 20dB RSSI threshold | Thermal noise variance |
| RSSI decay every 3 sweeps | Noise hit accumulation |
| Broadband gate + strong bypass | Noise vs real FHSS |
| Zone heuristic | LoRaWAN misclassification |
| SF discrimination | ELRS vs LoRaWAN modulation |
| Sub-band clustering | Single-gateway pattern |
| Baseline delta | Known vs new emitters |
| Pre-clear fillScreen exception | SPI contention during scan |

### Scan Screen Controls

| Key | Action |
|-----|--------|
| B / Back | Exit scan, restore radio |
| C | Clear and restart |
| S | Share (log + alert + LoRa broadcast) |
| P | Cycle profile |
| G | Jump to strongest detection |
| I | Toggle infrastructure on cursor channel |
| R | Capture RF baseline (~8s) |
| X | Clear saved baseline |
| L/R | Move channel cursor |
| U/D | Toggle summary/detail view |

### On Scan Exit

SD log, FPV track at scanner GPS, Alerts channel notification, LoRa mesh broadcast, CoT events.

### Hop-Rate Analysis

Estimates FHSS speed from CAD hit ratios: 25Hz (long-range), 50Hz (mid-range), 150Hz (FPV proximity), 250Hz+ (race/close). Red for 150Hz+, yellow for lower.

---

## UI Screens

**Status:** Dashboard with callsign, peers, GPS, radio, WiFi/BLE, encryption, battery sparkline.

**Messages:** Chat bubbles, E2E tags, delivery indicators, channel filter (G key), thread view (F key).

**Compose:** Text input (199 char), Tab=recipient, L/R=channel, U/D=canned messages, /wp command.

**Conversation:** Per-peer message thread with E2E indicators.

**Voice:** Codec2 PTT. Record → Preview → Send/Redo. Loopback test (T key).

**Map:** Compass polar plot with north arrow, peers, tracks (with 8-position trails), waypoints, MGRS grid, bearing/distance readout. W=waypoint, X=delete.

**Peers:** Link quality bars, RSSI/SNR, E2E badges, distance/bearing, hop count.

**Debug:** TX/RX counts, mesh stats, battery voltage/discharge/remaining, uptime, heap.

**Settings:** Sub-screens rendered as post-draw overlays (Callsign, PSK, Duress PIN, Remote Wipe) to eliminate TFT bleed-through on ST7789/DMA hardware.

**Lock:** Hold V 2s to unlock. Emergency (E key) works while locked.

---

## Voice System

| Mode | Bitrate | Redundancy | TX Time | Best For |
|------|---------|------------|---------|----------|
| Range | 1600bps | 2x | ~15s | Max range |
| Balanced | 3200bps | 2x | ~25s | Best quality |
| Clarity | 3200bps | 1x | ~13s | Fast turnaround |

TX: I2S mic → DC removal → biquad → decimate → noise gate → AGC → pre-emphasis → VAD → Codec2 → packet.
RX: reassembly → Codec2 → de-emphasis → normalize → upsample → biquad → I2S speaker.

---

## Cursor-on-Target (CoT) Bridge

Bidirectional TAK integration. Settings T key: OFF → MC → TCP → All → OFF. Confirmation dialog on enable (OPSEC gate). Triple output: WebSocket, UDP multicast (239.2.3.1:6969), TCP to TAK server. Inbound: ground units → peers, aircraft → tracks, markers → waypoints. TAK config: `!tak IP:PORT` or `/tak IP:PORT`.

---

## Threat Proximity Alerts

Auto-warnings when tracks enter radius. Format: DRONE 480m NE, 45m descending [DJI-001]. 30s cooldown. Presets: 500m/1km/2km/5km/10km/OFF.

---

## Acoustic Gunshot Detection

ES7210 mic, pure DSP. Three sensitivity levels (J key: OFF/Hi/Med/Lo). Multi-sample confirmation. On detection: alert, audible warning, LoRa broadcast with GPS, SD log. 5s cooldown.

---

## TFT Display Notes

The ST7789 with DMA has a race condition where `fillScreen` inside draw functions can leave stale pixels. Handled with:
- Pre-clear `fillScreen(COLOR_BG)` in ui_tick before every draw dispatch (except scan screen)
- Settings sub-screens (Name, PSK, Duress, Wipe, QR) drawn as post-draw overlays that fully repaint
- When a sub-screen is active, the base `_drawSettingsScreen()` is skipped (eliminates flicker) but pre-clear still runs for DMA sequencing
- Scan screen manages its own incremental drawing to avoid SPI contention with SX1262
- SPI bus shared by Radio (SX1262), TFT (ST7789), and SD — thread-safe via single-threaded Arduino loop()

---

## Serial Log Prefixes

| Prefix | Gating | Notes |
|--------|--------|-------|
| `[Scanner]` | Always | Calibration, classification, broadcast |
| `[Baseline]` | Always | Capture, load, apply, clear, NF divergence |
| `[Scan]` | `#ifdef SCAN_DEBUG` | Per-channel diagnostics |
| `[EPH]` | Always | ECDH key exchange |
| `[E2E]` | Always | E2E encrypt/decrypt |
| `[FHOP]` | Always | Frequency hopping |
| `[ACK]` | Always | Delivery confirmations |
| `[WIPE]` | Always | Remote wipe |
| `[S&F]` | Always | Store-and-forward |
| `[PSK]` | Always | Group encryption |
| `[DM]` | Always | Direct messages |
| `[DURESS]` | Always | Covert distress |
| `[CoT]` | Always | TAK bridge |
| `[JAM]` | Always | Jamming detection + migration |
| `[GRP-ACK]` | Always | Group broadcast acknowledgments |
| `[Voice]` | Always | Voice encode/decode/TX/RX |
| `[Battery]` | Always | ADC readings |
| `[WiFi]` | Always | WiFi mode changes, STA connect |
| `[mDNS]` | Always | Service registration |

---

## LittleFS Files

| File | Purpose |
|------|---------|
| `/messages.json` | Persisted messages |
| `/callsign.cfg` | Device identity |
| `/psk_v2.bin` | Device-wrapped PSK key |
| `/channel.cfg` | Radio channel |
| `/brightness.cfg` | Screen brightness |
| `/mute.cfg` | Audio mute state |
| `/vmode.cfg` | Voice quality mode |
| `/gpsbaud.cfg` | GPS baud rate |
| `/kbbl.cfg` | Keyboard backlight |
| `/bootcnt.bin` | Boot counter |
| `/waypoints.json` | Tactical waypoints |
| `/duress.cfg` | Duress PIN |
| `/tak_server.cfg` | TAK server address |
| `/scan_bl.bin` | RF scanning baseline |
| `/wifi_mode.cfg` | WiFi operating mode (AP/STA/OFF) |
| `/wifi_sta.cfg` | STA mode SSID + password |
| `/batcal.cfg` | Battery ADC multiplier override |

---

## Radio Configuration

| Parameter | Default | Notes |
|-----------|---------|-------|
| Frequency | 915.0 MHz | CH1-8, 2.5MHz spacing |
| SF | SF10 | |
| Bandwidth | 125 kHz | |
| Coding Rate | 4/5 | |
| TX Power | 14 dBm | Max 22 dBm |
| Sync Word | 0x47 | Avoids Meshtastic 0x34 |

Scanner reconfigures to SF6/BW500. Full state restored on exit.

---

## Battery

Calibrated ADC via `analogReadMilliVolts()` (ESP32-S3 eFuse factory calibration) with explicit `ADC_11db` pin attenuation (matching Meshtastic approach). 16-sample averaging + EMA smoothing (alpha=0.15). 12-point LiPo voltage curve. USB charge rail clamped (>4.3V → 4.2V). GPIO 4 = ADC1_CH3 (works with WiFi active). Header: percentage + trend arrow. Debug: voltage, discharge rate, time remaining, sparkline.

---

## Keyboard Shortcuts

### Global
Hold E (2s) = Emergency broadcast (any screen including lock and scan)

### Status
M=Messages, C=Compose, V=Voice, P=Map, F=Scan, N=Peers, D=Debug, S=Settings, Z=Lock, Space=PTT

### Map
W=Waypoint, X=Delete, UP/DOWN=Select, F=Scan, Space=PTT, Back=Home

### Scan
B=Exit, C=Clear, S=Share, G=Peak, P=Profile, I=Infra, R=Baseline capture, X=Clear baseline, L/R=Cursor, U/D=View

### Settings
N=Name, K=PSK, R=Channel, A=Mute, B=Brightness, L=KB light, W=Flash, Q=Voice, P=Proximity, J=Gunshot, T=CoT, F=WiFi Mode, G=WiFi QR, U=Duress, D=Wipe, UP/DOWN=Scroll

---

## Flash Layout (16MB)

Custom partition table for the ESP32-S3FN16R8 (16MB integrated flash). Previous default was the PlatformIO 8MB table, which wasted half the hardware.

| Partition | Offset | Size | Purpose |
|-----------|--------|------|---------|
| Bootloader | 0x0 | ~16KB | ESP32-S3 second-stage bootloader |
| Partition table | 0x8000 | 4KB | This layout |
| NVS | 0x9000 | 20KB | WiFi credentials, BLE bonds, system config |
| OTA data | 0xE000 | 8KB | Boot partition selector (future OTA) |
| Application | 0x10000 | 8MB | Firmware (current ~2MB, 4x growth headroom) |
| LittleFS | 0x810000 | 7.9MB | Messages, configs, baseline, waypoints |

**Partition table change requires full erase:** `esptool.py --chip esp32s3 erase_flash` before flashing. All LittleFS data (messages, PSK, callsign, baseline) will be reset.

---

## FCC Compliance

SX1262 under FCC Part 15.247 (902-928 MHz ISM). Default 14 dBm (25 mW). Scanner is passive receive-only.

---

## Changelog

### v6.70.0
- **Remote ID drone detection (experimental, opt-in).** ASTM F3411 / Open Drone ID
  over 2.4 GHz. New detection **source** selector on the Scan screen — `R` cycles
  900 MHz / Remote ID / Both; 900 MHz remains the default. Reports UAS ID,
  operator ID, aircraft position and altitude, and the **operator/takeoff
  location**. Deduplicates the same drone across transports, correlates with the
  900 MHz scanner, and emits CoT as `TRACK_SRC_REMOTEID`.
- Fusion alert levels: a 900 MHz emitter with **no** Remote ID is ranked highest
  — an aircraft flying without a compliance beacon.
- Track announcements are PSK-encrypted, rate-limited (one per track per 60 s,
  re-sent only after 200 m of movement), sent at BULK priority, and **not**
  mesh-relayed.
- LoRa starvation watchdog: Remote ID capture auto-disables if LoRa reception
  stalls while peers are active.
- **Limitation:** BLE capture is compiled out in the default build (NimBLE
  observer role disabled), so detection is WiFi-only. Cooperative detection only.
  See SECURITY.md.
- New `src/remoteid.{h,cpp}` — platform-independent and covered by 133 host tests
  that compile the real source file rather than a re-implementation.

### v6.69.0
- **Security hardening.** Duress PIN now stored as a salted HMAC-SHA256 and
  supports 4–8 digits (8 recommended); the previous on-screen hint that revealed
  the first two digits is removed.
- **No shipped default Wi-Fi password.** Each radio generates a unique
  12-character AP password on first boot (Settings → `G` to read it). Existing
  tablets must re-pair.
- Frequency-hop sequence now derived with **HKDF-SHA256 (RFC 5869)** instead of an
  ad-hoc construction. All radios in a cluster must run v6.69.0+ to stay
  synchronised.
- Group passphrase minimum raised to **12 characters**; PBKDF2 no longer falls
  back to a bare SHA-256 on failure (fails closed instead of deriving a key
  nobody else shares).
- Settings now shows a non-reversible 4-character **Key Check Value** so two
  operators can confirm matching keys without revealing passphrase characters.
- Stored-PSK protection documented honestly in SECURITY.md as anti-cloning, not
  anti-forensic.

### v6.68.0
- On-device image send from the SD card. Stage pre-sized JPEGs (≤ 8 KB) in
  `/img_send/`, then `T` toggles the Images list between Received and Outbox and
  `S` sends. Received images can be re-shared the same way.
- `!sendimg <path>` serial command implemented (previously a stub).

### v6.67.0
- **WiFi operating modes:** Three modes (AP/STA/OFF) toggled via Settings F key with confirmation. AP creates GridDown-Radio network. STA joins external network (e.g., tablet hotspot) as client with exponential backoff reconnect (10s→30s→60s). OFF disables WiFi for maximum battery. Mode persisted to `/wifi_mode.cfg`.
- **mDNS registration:** STA mode registers as `griddown-radio.local` with `_ws._tcp` service on port 8770. TXT records: type, firmware version, callsign. Auto-starts on connect, stops on disconnect.
- **WebSocket credential push:** Tablet sends `wifi_config` JSON via WebSocket. T-Deck shows confirmation dialog with SSID. Operator accepts or rejects. Credentials saved to `/wifi_sta.cfg`, optional auto-switch to STA mode.
- **WiFi QR code:** Settings G key shows full-screen QR. AP mode: WiFi credentials (scan to join). STA mode: WebSocket discovery address. Renders as proper sub-screen (same pattern as Duress/Wipe).
- **Group broadcast ACK:** Broadcast messages track per-peer delivery with lightweight jittered ACK packets. 16-bit bitmask dedup (supports 16 peers, up from 8). Display: grey=none, yellow=partial, green=all confirmed. Persisted to messages.json.
- **Channel scan on boot:** Automatic 8-channel CAD + RSSI sweep (~5 seconds) on every startup. 10 CAD probes at SF10/BW125 + 5-sample median RSSI per channel. Active channels highlighted green.
- **Battery ADC calibration:** Replaced raw `analogRead()` math with `analogReadMilliVolts()` (eFuse factory calibration). Explicit `analogSetPinAttenuation(BAT_ADC, ADC_11db)` matching Meshtastic approach. USB charge rail clamped (>4.3V → 4.2V).
- **Voice RX timeout scaling:** `_voiceSlotTimeoutMs(total)` = max(total × 3000, 15000). Range (4 parts): 15s. Balanced/Clarity (7 parts): 21s. Fixed silent audio truncation in 3200 modes caused by hardcoded 10s timeout.
- **Voice jam detection suppression:** Single `jamLastVoiceActivity` timestamp set on every voice packet TX and RX. 8-second suppression window. Replaces fragile `voice_hasTxPacket()` + `voice_isRxPending()` guards that had timing gaps between assembly states.
- **Jam detection tuning:** Sustain increased from 3s to 10s (prevents false triggers from close-range radios). Fast EMA alpha reduced from 0.3 to 0.15. Cooldown increased from 30s to 60s. Eliminates false jam alerts during normal indoor testing.
- **FHOP requires GPS position lock:** Epoch sync now requires `gps.location.isValid()` in addition to time/date. Prevents one radio from hopping while another stays on base channel when only satellite time (not position) is available.
- **Settings sub-screen flicker fix:** Base `_drawSettingsScreen()` skipped when a sub-screen is active. Pre-clear still runs for DMA sequencing. Eliminates triple-wipe flicker on every keystroke in Name, PSK, Duress, Wipe, and QR entry.
- **QR code sub-screen pattern:** Converted from overlay (fought redraw cycle) to proper sub-screen in the same `if/else if` chain as Wipe/Duress/Name/PSK. Any key dismisses.
- **WCAG button contrast:** All button fills meet AA 4.5:1 minimum. `COLOR_BTN_ACCENT` (deep blue, 7.42:1). Yellow/disabled buttons use black text. Auto-dim removed.
- **Color accessibility:** All `0x3186`/`0x4208`/`0x4A49` dim colors replaced with `COLOR_DIM` (6.51:1).
- **System message truncation fix:** "No STA creds set. Use tablet push." fits notification banner width.
- **Production audit fixes:** `buf`/`decBuf` in handleReceive made static (saves 510 bytes stack). SPI bus sharing documented. All LittleFS opens confirmed guarded.

### v6.66.0
- **Signed ACKs:** HMAC-SHA256 delivery confirmations using per-peer ECDH session keys. 33/33 test suite.
- **Remote wipe:** Authenticated device erasure via LoRa or serial. HMAC-SHA256 + GPS replay protection. Settings UI with trackball peer selection + double confirmation. 32/32 test suite.
- **E2E send indicator:** Cyan "E2E" tag on encrypted messages.
- **Scanner: multi-discriminator classification:** Frequency zone heuristic, SF discrimination (per-channel low/high SF counters), sub-band clustering, delta detection from RF baseline. Five-priority decision tree.
- **Scanner: RF baseline:** Pre-recorded ambient environment. 20-sweep capture to LittleFS. Auto-load, pre-flag infrastructure from sweep 1. R=capture, X=clear, "BL" header indicator.
- **Scanner: LoRaWAN classification:** New SCAN_CLASS_LORAWAN type. Cyan display, no alert, excluded from D: count and track push.
- **Scanner: false positive elimination:** Median RSSI, 5ms AGC settle, 20dB threshold, broadband noise gate with strong-signal bypass, accelerated decay, tightened GFSK thresholds.
- **Scanner: GFSK detection tuning:** Three-tier threshold architecture — display at NF+20, GFSK classification at NF+22 (SCAN_GFSK_CLASSIFY_DB), broadband gate bypass at NF+25 (SCAN_STRONG_PEAK_DB). Closes the gap between visible spectrum activity and classification confidence for SiK/RFD900 telemetry radios at moderate range.
- **Scanner: sub-threshold FHSS log:** When multi-channel RSSI activity is visible on spectrum (NF+20) but below classification threshold (NF+22), serial logs `[Scanner] Sub-threshold FHSS: N ch active, peak=X dBm — possible drone at range`. Rate-limited to 10-second intervals.
- **Scanner: GFSK detection fix:** Broadband gate exempts strong signals (NF+25dB) so real SiK/RFD900 radios are detected.
- **Header pulse notifications:** Voice and scan screens use header color tint + sender callsign instead of overlay banner. Eliminates text overlap during voice RX. Green=DM, blue=broadcast, red=lost/error. 3-second fade. All other screens get both overlay banner + header pulse.
- **16MB flash partition table:** Custom partition table for ESP32-S3FN16R8. App partition 8MB (was 3.1MB), LittleFS 7.9MB (was 1.5MB). Requires full erase on first flash.
- **Settings overlay fix:** Sub-screens render as post-draw overlays to eliminate TFT bleed-through.
- **Pre-clear framebuffer:** Global fillScreen before every draw dispatch (except scan) prevents content persistence.
- **Display threshold correction:** Scan threshold line matches actual NF+20dB detection threshold.
- **SCAN_DEBUG gate:** Per-channel diagnostics gated for production builds.
- **FHOP boundary docs:** Hop boundary packet loss tradeoff documented.

### v6.65.0
- Initial public firmware with full feature set.

---

## License

GridDown Secure Messenger firmware is licensed under the **GNU General Public
License v3.0 or later** — see [LICENSE](LICENSE).

Third-party libraries remain under their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Run
`tools/verify_licenses.sh` after a build to verify those obligations against the
exact library versions vendored into your build tree.

**Trademarks are not licensed with the code.** "GridDown", "AtlasDeck", "AtlasRF",
and "BlackAtlas" are trademarks of BlackAtlas LLC — see
[TRADEMARK.md](TRADEMARK.md). You may fork freely; please rename your fork.

## Security

Please read **[SECURITY.md](SECURITY.md)** before deploying this firmware
operationally. It documents both what the firmware protects and — importantly —
what it does not, including limits that cannot be fixed on the current hardware:

- Packet **metadata is not encrypted**; traffic analysis is possible.
- Frequency hopping is **congestion avoidance, not jam resistance**, and it
  requires GPS time sync.
- The **stored group key is recoverable from a device you physically hold**. Treat
  a captured radio as a compromised cluster key and re-key.
- Received images are stored **unencrypted** on the microSD card.

**Report vulnerabilities privately to security@blackatlas.tech — not via public
issues.**

## Export control

This is open-source encryption software using only standard published algorithms.
See [EXPORT_CONTROL.md](EXPORT_CONTROL.md). You are responsible for complying with
the export and sanctions laws applicable to you.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions require a signed CLA; the
reasoning is explained there. Please open an issue before large changes — the
firmware has hard constraints (LoRa airtime, RAM, mesh interoperability) that
rule out some otherwise-sensible features.

## Verified builds

Binaries published at <https://flash.blackatlas.tech> and on the GitHub Releases
page are built by CI **from the tagged commit in this repository**, and each
release publishes its SHA-256. To confirm the binary you flashed matches the
published source:

```bash
sha256sum griddown-messenger-<version>.bin
# compare against the checksum in the corresponding GitHub Release
```
