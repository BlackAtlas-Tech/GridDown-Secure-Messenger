<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Third-Party Notices

GridDown Secure Messenger firmware is licensed under **GPL-3.0-or-later**. It
links the third-party libraries below, each of which remains under its own
license and copyright. This file exists to satisfy those attribution
requirements.

> ### Verification status — VERIFIED, all items closed
>
> The table below was produced by running **`tools/verify_licenses.sh`** against
> `.pio/libdeps/tdeck` from a successful `pio run -e tdeck` build, i.e. against the
> exact library versions this firmware links. It is not from documentation or
> recollection.
>
> **All items are now resolved.** Every dependency is confirmed
> GPL-3.0-compatible, and both LGPL dependencies are confirmed **or-later** from
> their own source-header grants. The section below is retained as the evidence
> record rather than as outstanding work.

---

## Verification evidence (both items closed)

**1. TinyGPSPlus 1.1.0 — LGPL-2.1-or-later: CONFIRMED, closed.**
The PlatformIO package ships no `LICENSE`/`COPYING` file; the notice is in
`src/TinyGPSPlus.h`. Verified from the library's **own grant**:

```
.pio/libdeps/tdeck/TinyGPSPlus/src/TinyGPSPlus.h:12:
version 2.1 of the License, or (at your option) any later version.
```

LGPL-2.1-**or-later** may be taken to LGPL-3.0, which is GPL-3.0 compatible.
**This item is resolved.**

Because there is no licence file to bundle, the notice is transcribed here and
**must accompany binary releases**:

> TinyGPS++ — a small GPS library for Arduino providing universal NMEA parsing
> Based on work by and "distanceBetween" and "courseTo" courtesy of Maarten Lamers.
> Copyright (C) 2008–2013 Mikal Hart. All rights reserved.
>
> This library is free software; you can redistribute it and/or modify it under
> the terms of the GNU Lesser General Public License as published by the Free
> Software Foundation; either version 2.1 of the License, or (at your option) any
> later version.
>
> This library is distributed in the hope that it will be useful, but WITHOUT ANY
> WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
> PARTICULAR PURPOSE. See the GNU Lesser General Public License for details.
>
> You should have received a copy of the GNU Lesser General Public License along
> with this library; if not, write to the Free Software Foundation, Inc.,
> 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

*Verify this transcription against `src/TinyGPSPlus.h` in the exact version you
build before shipping — it is reproduced here from that header and a version bump
could change it.*

Record the exact licence and the file it came from in the table, and ship that
notice text alongside binary releases. A missing file is not a missing licence —
but it does mean the notice must be transcribed by hand. `verify_licenses.sh` now
falls back to scanning source headers and reports such cases as
*"in-source notice"* rather than *"NO LICENSE FILE FOUND"*.

**2. WebSockets 2.7.3 — LGPL-2.1-or-later: CONFIRMED, closed.**
Verified from the library's **own grant** in its source headers, which is the
authoritative statement (a bundled LGPL-2.1 licence file is not — see the caveat
below):

```
.pio/libdeps/tdeck/WebSockets/src/WebSockets.h:12:
 * version 2.1 of the License, or (at your option) any later version.
```

Present in `WebSockets.h`, `WebSockets4WebServer.h`, `WebSocketsClient.h`,
`WebSocketsServer.h` and `WebSocketsVersion.h`. LGPL-2.1-**or-later** may be taken
to LGPL-3.0, which is GPL-3.0 compatible. **This item is resolved.**

> **Caveat that applies to every LGPL/GPL dependency.** The bundled LGPL-2.1 and
> GPL-2.0 licence texts both contain the phrase *"any later version"* inside their
> own *"How to Apply These Terms"* appendix, regardless of what the library author
> actually chose. A licence-file scan therefore **cannot** distinguish
> "2.1-only" from "2.1-or-later". Always confirm from the library's own grant in
> its source headers or README. `tools/verify_licenses.sh` documents this
> limitation in-script and its PASS is not sufficient evidence on this point.

---

---

## Dependencies

Declared in `platformio.ini` under `lib_deps`.

| Library | Version | License (verified) | GPL-3.0 compatible? | Notes |
|---|---|---|---|---|
| [RadioLib](https://github.com/jgromes/RadioLib) — SX1262 LoRa driver | 6.6.0 | MIT | Yes | 1 copyright holder |
| [arduinoWebSockets](https://github.com/Links2004/arduinoWebSockets) — WebSocket server | 2.7.3 | **LGPL-2.1-or-later (confirmed from source headers)** | **Yes — resolved** | Retain notices |
| [ArduinoJson](https://github.com/bblanchon/ArduinoJson) — JSON serialisation | 7.4.3 | MIT | Yes | Uses the unicode © sign |
| [TFT_eSPI](https://github.com/Bodmer/TFT_eSPI) — ST7789 display driver | 2.5.43 | BSD-2-Clause | Yes | **2 copyright holders** (Bodmer; Adafruit, for GFX-derived functions) — ship `license.txt` verbatim |
| [TinyGPSPlus](https://github.com/mikalhart/TinyGPSPlus) — NMEA parsing | 1.1.0 | **LGPL-2.1-or-later (confirmed from source header)** | **Yes — resolved** | No licence file; notice transcribed in Open item 1 |
| [esp32_codec2](https://github.com/sh123/esp32_codec2) — Codec2 voice codec | 1.0.7 | **GPL-3.0** (verified against the build tree) | Yes — **and makes GPL-3.0-or-later mandatory for this firmware** | Retain notices |
| [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) — BLE stack | 1.4.3 | Apache-2.0 | Yes (GPL-3.0 only; **not** GPL-2.0) | 1 copyright holder |
| [TJpg_Decoder](https://github.com/Bodmer/TJpg_Decoder) — JPEG decode | 1.1.0 | BSD-2-Clause | Yes | **2 copyright holders** (Bodmer; ChaN for TJpgDec) — retain both |

> ### esp32_codec2 is GPL-3.0 — this makes GPL-3.0-or-later mandatory, not optional
>
> Verification showed the Codec2 wrapper is licensed **GPL-3.0**, not LGPL-2.1 as
> upstream Codec2 is. Because this firmware links it, the combined work **must** be
> distributed under GPL-3.0-or-later. Permissive licensing and proprietary
> distribution were never available options for a build that includes voice.
>
> **Consequence for previously distributed binaries.** Compiled firmware
> distributed before source publication was a GPL-3.0 combined work conveyed
> without an accompanying source offer. Publishing this repository resolves that
> prospectively (GPL-3.0 §6). **Raise the historical position with counsel**, and
> confirm the finding by reading the file directly:
>
> ```bash
> head -20 .pio/libdeps/tdeck/esp32_codec2/LICENSE
> ```
>
> If voice is ever removed from a build, this constraint changes — but nothing else
> in the dependency set permits proprietary distribution either
> (arduinoWebSockets is LGPL).

### Platform components### Platform components

| Component | Provenance | License |
|---|---|---|
| Arduino core for ESP32 (`framework-arduinoespressif32`) | Espressif | LGPL-2.1-or-later (core), Apache-2.0 (ESP-IDF components) |
| ESP-IDF (incl. **mbedTLS**, LittleFS port, NimBLE host) | Espressif / Arm | Apache-2.0 (ESP-IDF); mbedTLS is Apache-2.0 |

**mbedTLS** provides every cryptographic primitive used by this firmware
(AES-GCM, SHA-256, HMAC, PBKDF2, ECDH P-256). It is Apache-2.0 licensed and is
supplied by ESP-IDF rather than vendored here.

---

## Notes on compatibility

**Apache-2.0 and GPL:** Apache-2.0 is compatible with **GPL-3.0** but **not**
GPL-2.0. This is one of the reasons the project is GPL-3.0-or-later rather than
GPL-2.0.

**LGPL-2.1 dependencies:** LGPL-2.1 headers that read *"either version 2.1 of the
License, or (at your option) any later version"* permit relocation to LGPL-3.0,
which is GPL-3.0 compatible. A dependency pinned to LGPL-2.1-**only** needs
counsel's view. `tools/verify_licenses.sh` prints the actual header text so this
can be checked rather than assumed.

**BSD attribution:** TFT_eSPI's terms require that the copyright notice, the list
of conditions, and the disclaimer be retained in redistributions. Because that
library carries **multiple** copyright holders (Bodmer, and Adafruit Industries for
the GFX-derived functions), both must be preserved. Do not condense its
`license.txt` — ship it verbatim if binaries are distributed.

**Binary distribution:** compiled firmware at `flash.blackatlas.tech` is a
combined work. GPL-3.0 §6 requires that the corresponding source be offered to
recipients; publishing the source repository and linking it from the flasher page
satisfies this. Third-party notices must accompany binary releases as well as
source — `tools/verify_licenses.sh --bundle` assembles them.

---

## How to regenerate

```bash
pio run -e tdeck                 # populate .pio/libdeps/tdeck/
tools/verify_licenses.sh         # report actual licenses + flag mismatches
tools/verify_licenses.sh --bundle  # write dist/THIRD_PARTY_LICENSES.txt
```
