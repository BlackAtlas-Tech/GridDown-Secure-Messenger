<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Privacy

This is firmware for a radio you own and operate. There is no vendor backend, no
telemetry, no account, and no analytics — BlackAtlas receives nothing from your
device, ever.

But the firmware does record and transmit data, and one feature passively monitors
2.4 GHz WiFi. This document states exactly what it does with all of it. Read the
first section if you read nothing else.

---

## The short version

| | |
|---|---|
| Data sent to BlackAtlas or any third party | **None.** No telemetry, no analytics, no crash reporting, no phone-home |
| Account or registration required | **None** |
| Internet connection required | **None** |
| Passive WiFi monitoring (Remote ID detection) | **Off by default.** Opt-in per session, receive-only, ASTM-filtered, RAM only |
| Position broadcast to peers | **Yes, when GPS has a fix** — this is the point of a mesh radio, but know that it happens |
| Data written to storage | Messages, GPS breadcrumbs, config, received images — all local, all on your device |

---

## What the firmware stores on the device

### On internal flash (LittleFS, 19 files)

| Data | File | Notes |
|---|---|---|
| Message history | `/messages.json` | Decrypted plaintext of your own conversations |
| Callsign | `/callsign.cfg` | Broadcast to peers by design |
| Group key | `/psk_v2.bin` | Obfuscated, **not** forensically protected — see [SECURITY.md](SECURITY.md) |
| Duress PIN | `/duress.cfg` | Salted HMAC-SHA256 hash only. The PIN itself is never stored, displayed, or logged |
| Wi-Fi AP password | `/appass.cfg` | Unique to this device, generated on first boot |
| Waypoints | `/waypoints.json` | Including any you received from peers |
| Radio/UI settings | various `.cfg` | Channel, brightness, mute, GPS baud, battery calibration, WiFi mode, TAK server |

### On the microSD card

- **Received images** — written as **plain, unencrypted JPEG** under `/img_recv/`,
  so you can read them on a computer. Capped at 50, oldest deleted first.
- **GPS logs** and dead-drop message archives, if you enable those features.

**Treat the SD card with the same care as the message log.**

### In RAM only (lost on power cycle, never written to storage)

- Remote ID detection tracks
- Peer list, signal statistics, breadcrumb trail
- Drone scanner detections
- Ephemeral ECDH keys — regenerated every boot, which is what gives direct
  messages forward secrecy

---

## What the firmware transmits

### Over LoRa, to anyone with your group key

- **Beacons** every 25–35 seconds: callsign, battery level, **and your GPS position
  when you have a fix**
- Messages, voice, images, waypoints — encrypted with AES-256-GCM
- Delivery confirmations and Remote ID detection alerts (if enabled)

**Position sharing is on by default when GPS has a fix.** That is the intended
behaviour of a team radio, but it is worth stating plainly: your teammates — and
anyone who holds the group key — know where you are.

### Metadata is NOT protected

LoRa packet headers are unencrypted. Contents are protected; **the fact, timing,
and routing of your transmissions are observable to anyone listening**, whether or
not they hold your key. Traffic analysis is possible. See
[SECURITY.md](SECURITY.md).

### Over Wi-Fi / Bluetooth

Only to a tablet you connect yourself, on your radio's own access point. No
outbound internet connections are made by the firmware. If you configure a TAK
server, data goes to the address **you** specify and nowhere else.

---

## Remote ID detection and passive monitoring

This is the feature most likely to raise a privacy question, so it is documented in
detail. It is **experimental and disabled by default** — press `D` on the Drone
Detection screen to enable it for the session.

**What it receives.** Broadcast **management frames only** — WiFi beacons and
Neighbor Awareness Networking frames carrying the ASTM F3411 Remote ID information
element, which drones are required by regulation to transmit openly.

**What it will not do.** Data frames are discarded inside the capture callback,
**before any parsing**. The firmware cannot decode the contents of anyone's WiFi
traffic. That boundary is structural, not a policy promise — the code path does not
exist. There is no deauthentication, no jamming, no spoofing, no association, and
no transmission of any kind while monitoring.

**What it retains.** Only drone Remote ID data: UAS ID, operator ID, and the
positions the drone itself broadcasts. Held in a 16-slot table in **RAM**, released
after 5 minutes without an update, **never written to flash or SD**. A captured
radio yields no detection history.

**What it deliberately does not build.** No inventory of nearby device
identifiers. The capture path matches the ASTM element and discards everything
else, so phones, laptops, and wearables around you are not logged, counted, or
stored. This was a design decision, not an omission — a BLE/WiFi scanner that
enumerates nearby devices is a surveillance tool regardless of intent, so the
filter is applied at the point of capture.

---

## Your responsibilities as an operator

The firmware cannot enforce these, and in most jurisdictions they are your legal
obligation, not ours:

- **Passive reception of broadcast frames** is generally lawful. **Decoding the
  contents of others' communications generally is not.** The firmware is built not
  to, and you should not modify it to.
- **Position data about other people** — teammates' locations arrive on your device
  and persist in waypoints and message history. Handle that as you would any
  personal data.
- **Received imagery** may contain identifiable people and is stored unencrypted on
  the SD card.
- **Recording and monitoring laws vary by jurisdiction.** Detection features may be
  regulated differently where you are. Check before deploying.

---

## Deleting your data

| To remove | How |
|---|---|
| Everything on the device | Settings → Wipe, or the serial wipe command. Five-phase erase: RAM, LittleFS, SD, display, reboot |
| Everything, remotely | Authenticated remote wipe from a peer, while in radio range |
| Message history only | Clear from the Messages screen |
| Received images | Delete individually with `X` on the Images screen, or remove the SD card |
| Remote ID tracks | Power cycle — they are RAM only |
| A complete factory reset | `pio run -e tdeck -t erase`, then reflash |

**A lost or captured radio should be treated as a compromised group key.** Re-key
the whole cluster. See [SECURITY.md](SECURITY.md).

---

## Changes to this document

This file is versioned with the firmware. Material changes will be noted in the
[README changelog](README.md#changelog). Questions:
**info@blackatlas.tech**. Security issues go to **info@blackatlas.tech** —
see [SECURITY.md](SECURITY.md).
