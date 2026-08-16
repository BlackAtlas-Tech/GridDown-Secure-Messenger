<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Security Policy

GridDown Secure Messenger is a tactical encrypted radio firmware. People may rely
on it in situations where a failure has real consequences. We would rather
document a weakness plainly than let an operator assume a protection they do not
have.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **info@blackatlas.tech** with:

- a description of the issue and why you believe it is exploitable
- affected firmware version (shown on the Status screen, or `!info` over serial)
- reproduction steps, or a proof of concept
- your assessment of impact

**What to expect:** acknowledgement within 5 business days; an initial assessment
within 15 business days; and coordinated disclosure once a fix is available or a
mitigation is documented. We will credit you unless you ask us not to. We do not
currently run a paid bounty programme.

**Supported versions:** only the latest released firmware receives security
fixes. There are no long-term support branches.

---

## What this firmware protects, and what it does not

Read this section before deploying. Several of these limits are deliberate
engineering trade-offs, not oversights, and some of them cannot be fixed on the
current hardware.

### Confidentiality of traffic — good

Message, voice, and image payloads are encrypted with **AES-256-GCM** using a
group pre-shared key derived from a passphrase via **PBKDF2-HMAC-SHA256**. Direct
messages add an ephemeral **ECDH P-256** exchange for end-to-end encryption with
per-boot forward secrecy. All primitives are standard published algorithms
implemented by mbedTLS. There is no proprietary cipher.

### Metadata — NOT protected

LoRa packet headers are **not** encrypted. An adversary within radio range can
observe that transmissions are occurring, their timing, length, and the
callsigns/routing fields needed for mesh relay. **Traffic analysis is possible
even though payload contents are not readable.** If the fact that you are
transmitting is itself sensitive, this firmware does not solve that — radio
silence does.

### Transmitting is inherently detectable

The radio emits. Direction-finding equipment can locate a transmitter. No
software feature changes this. Do not treat frequency hopping (below) as
concealment.

### Frequency hopping (FHOP) — congestion avoidance, NOT anti-jam

FHOP rotates across 8 channels on a **30-second** period, with the sequence
derived from the group PSK via **HKDF-SHA256 (RFC 5869)**.

**This is not meaningful jam resistance and should not be described as such.**
The 902–928 MHz band is only 26 MHz wide and can be blanket-jammed cheaply, and a
30-second dwell is trivial for a sweeping jammer to follow. Hopping fast enough
to defeat a jammer means hundreds or thousands of hops per second; this does not.
FHOP's real value is avoiding *unintentional* congestion and raising the
effort for casual interception.

FHOP also **requires GPS time sync**. It disengages when GPS time is lost, and
there is currently **no GPS spoofing or jamming detection** — a GPS-denied or
spoofed environment degrades or disables hopping. Radios with and without time
sync will not agree on a channel.

### Stored PSK at rest — anti-casual-copy only, NOT anti-forensic

**This is the most important limitation in this document.**

The group key is stored in LittleFS XOR-wrapped with a key derived from the
device's MAC address (`SHA-256("GridDown-DeviceWrap" ‖ MAC)`).

**The MAC address is not a secret.** It is broadcast in every Wi-Fi beacon, it is
often printed on the device, and the firmware prints it to the serial console at
boot. Combined with this published source, **anyone who obtains a flash dump can
recover the group PSK.** XOR with a deterministic key is obfuscation, not
encryption.

What this wrapping does achieve: a flash image copied from one device will not
load on another, which defeats casual cloning. What it does not achieve:
resistance to anyone who physically holds a device and can read its flash.

**Operational consequence — treat a lost or captured radio as a compromised group
key, and re-key the whole cluster.** Use the remote-wipe feature if the device is
still in radio range.

Why this is not simply fixed: the correct solution is ESP32 flash/NVS encryption
with an eFuse-backed per-device key. That requires per-device provisioning and
**would break the single-binary web flasher** at `flash.blackatlas.tech`, which is
how most operators install the firmware. We judged an honest, documented
limitation better than breaking the install path for everyone. Hardware-backed key
storage is planned for the AtlasDeck platform, where the provisioning flow is
under our control.

### Duress PIN — resists disclosure, not brute force

The duress PIN is stored as `HMAC-SHA256(random 16-byte salt, PIN)`. It is never
written in plaintext, never shown on the display, and never logged. Matching scans
the composed message for digit runs and compares in constant time. PIN removal
normalises surrounding whitespace so the edit leaves no visible tell.

**A 4-digit PIN has only 10,000 possible values.** Salted hashing prevents the PIN
being *read* off flash; it cannot prevent offline brute force by someone holding
the device. A deliberately slow KDF was rejected here because matching must hash
every candidate digit-run in a message, and it would not meaningfully change
resistance across so small a keyspace. **PINs of 4–8 digits are supported — use 8.**

### Received images are stored unencrypted

Images received over the air are written to the microSD card as plain JPEG under
`/img_recv/`, so they can be read on a computer. **Treat the SD card with the same
care as the message log.**

### Passphrase strength is the dominant factor

PBKDF2 runs at **10,000 iterations** with a **fixed application salt**. The fixed
salt is required for interoperability — every radio in a cluster must derive the
same key from the same passphrase — and it means precomputation against weak
passphrases is feasible. A minimum passphrase length of **12 characters** is
enforced. Use a long, high-entropy passphrase; that buys far more than any
iteration count would.

Raising the iteration count changes every derived key and would therefore require
a **coordinated, fleet-wide upgrade**, since a mixed fleet would silently fail to
communicate. It is deliberately unchanged for that reason.

### Key Check Value

The Settings screen shows a 4-hex-character **KCV** derived from the group key.
Two operators can compare KCVs to confirm their radios derived the same key
**without either revealing passphrase characters**. Earlier firmware displayed the
first four characters of the passphrase instead; that leak is removed.

### Wi-Fi AP password

Each device generates its own random 12-character AP password on first boot and
stores it in `/appass.cfg`. Read it from the T-Deck (Settings → WiFi). There is no
shipped default password. If the password cannot be persisted, the firmware warns
loudly on serial rather than silently regenerating each boot.

The AP protects the WebSocket control channel. **Anyone on that network can
control the radio** — treat AP access as equivalent to physical access.

### Remote ID detection — passive 2.4 GHz monitoring (experimental)

Firmware v6.70.0 can detect drones broadcasting FAA-mandated Remote ID
(ASTM F3411) using the ESP32-S3's 2.4 GHz radio. **It is opt-in and experimental.**
The default detection source is 900 MHz only; an operator who never selects a
Remote ID source never runs this code path.

**What is captured.** Broadcast **management frames only** — WiFi beacons and
Neighbor Awareness Networking action frames carrying the ASTM vendor-specific
information element. Data frames are discarded inside the capture callback,
before any parsing, so the firmware cannot decode the contents of third-party
WiFi traffic. That boundary is deliberate and structural, not a policy note.

**What is retained.** Remote ID identifiers (UAS ID, operator ID) and the
positions the drone itself broadcasts, held in a 16-slot table in **RAM only**.
Nothing is written to LittleFS or the SD card, and a track is released after five
minutes without an update. Incidental identifiers belonging to other devices are
**not** logged — the capture path matches the ASTM element and discards
everything else. A captured radio yields no detection history.

**Cooperative detection only.** This receives a beacon the drone is required to
broadcast. **An operator who disables Remote ID is invisible to it.** It provides
airspace awareness and detection of compliant or careless operators. It is **not**
counter-UAS coverage, and must not be relied on to find a drone flown by someone
who does not want to be found. The 900 MHz scanner remains the non-cooperative
detector.

**Bluetooth capture is unavailable in the default build.** `platformio.ini`
disables the NimBLE central and observer roles, saving roughly 60 KB of flash and
30 KB of RAM. Remote ID capture is therefore **WiFi-only**, and drones that
broadcast Remote ID *exclusively* over Bluetooth will not be detected. WiFi
capture itself runs at near-full rate because the access point already sits on
channel 6, where Remote ID WiFi traffic lives. Enabling BLE capture requires
removing that build flag and re-measuring flash and RAM headroom.

See [PRIVACY.md](PRIVACY.md) for the full statement of what is recorded, transmitted, and never stored.

**LoRa has absolute priority.** The capture callback filters and copies only,
into a bounded ring buffer that drops on overflow and counts the drops rather
than blocking. A watchdog disables Remote ID capture automatically if LoRa
reception stalls while peers are active. The radio's job is messaging and voice;
detection is sacrificed first, always.

**Detections are shared conservatively.** Track announcements go out encrypted
with the group PSK at the lowest queue priority, rate-limited to one per track
per 60 seconds and re-sent only after 200 m of movement, and are **not
mesh-relayed**. Remote ID broadcasts at roughly 1 Hz per drone; relaying that at
native rate would flood the channel.

**Not validated on hardware.** As of v6.70.0 this feature compiles and its
parsing and tracking logic is covered by 133 host tests, but detection range,
false-negative rate, and the effect of capture load on LoRa timing have **not**
been measured in the field. Treat it as experimental.

### Not evaluated

This firmware has **not** undergone third-party security audit, formal
verification, FIPS validation, or Common Criteria evaluation. It is not certified
for classified information. It is developed and maintained by a very small team;
please review the code yourself before relying on it.

---

## Threat model summary

| Adversary capability | Outcome |
|---|---|
| Passive RF interception, no PSK | Cannot read payloads. Can observe traffic patterns and callsigns. |
| Passive RF interception, has group PSK | Reads group traffic. Cannot read E2E direct messages between other parties. |
| Broadband jammer in range | Denies communication. FHOP does not prevent this. |
| Direction-finding equipment | Can locate a transmitting radio. |
| Physical possession of a radio | Can recover the group PSK from flash, and brute-force the duress PIN. Re-key the cluster. |
| Access to the Wi-Fi AP | Full control of the radio via WebSocket. |
| GPS jamming or spoofing | Disables FHOP; corrupts position and time. No spoof detection today. |
| Drone with Remote ID disabled | **Not detected** by Remote ID. May be detected by the 900 MHz scanner as an unidentified emitter. |
| Drone broadcasting Remote ID only over Bluetooth | **Not detected** in the default build (BLE capture compiled out). |
| Spoofed Remote ID broadcast | Not detected by a single radio — the position is self-reported and unauthenticated. |

---

## Hardening checklist for operators

1. Use a long, high-entropy group passphrase (12-character minimum enforced).
2. Compare the **KCV** across radios to confirm the cluster matches.
3. Use an **8-digit** duress PIN rather than 4.
4. Read the per-device AP password from the T-Deck; do not share it broadly.
5. Assume a lost or captured radio means a compromised cluster key — re-key.
6. Remember the SD card holds unencrypted received imagery.
7. Do not rely on FHOP for jam resistance or concealment.
8. If concealment matters, do not transmit.
9. Treat Remote ID detection as airspace awareness, not threat detection — absence
   of a Remote ID track is not evidence of absent aircraft.
