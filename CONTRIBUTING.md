<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Contributing to GridDown Secure Messenger

Thanks for your interest. This is a small project — maintained by a very small
team — so please read this before opening a large pull request.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Report security issues privately

**Never open a public issue for a vulnerability.** See [SECURITY.md](SECURITY.md).

## Contributor License Agreement (required)

Contributions require a signed **Contributor License Agreement**. The CLA asks you
to grant BlackAtlas LLC a license to your contribution broad enough to relicense
it, while you retain your own copyright.

**Why, stated plainly:** BlackAtlas may in future offer a separately licensed
build for customers who cannot accept GPL terms. Under GPL-3.0 alone, we could not
relicense code we do not hold rights to, so a single un-CLA'd contribution would
permanently foreclose that option. We would rather tell you this up front than
discover it later. If you object, we understand — open an issue and discuss the
change instead, and we will implement it independently where we agree.

The CLA bot will prompt you on your first pull request.

## Before you start

- **Open an issue first** for anything non-trivial. The firmware has hard
  constraints (LoRa airtime, ~320 KB RAM, no JPEG encoder, mesh interop) that make
  some otherwise-reasonable features unworkable. Better to find out before you
  write the code.
- **Interoperability is a compatibility contract.** Changes to the packet format,
  key derivation, or the frequency-hopping sequence break communication with
  radios already in the field. These need a version bump and a documented upgrade
  path — they are not ordinary patches.

## Development

```bash
pip install platformio
pio run -e tdeck                    # build
pio run -e tdeck -t upload          # flash
pio device monitor -b 115200        # serial console
```

**Full erase is required** when the partition table changes:
`pio run -e tdeck -t erase` then upload.

## Tests

Logic is covered by standalone host-compiled harnesses (they do not require
hardware):

```bash
g++ -std=c++17 -w -o t test_crypto_hardening.cpp -lmbedcrypto && ./t
```

Every harness must exit 0. If you change crypto, key derivation, the chunking
protocol, or the duress logic, **add or extend a harness** — these paths are hard
to test on-device and easy to break silently.

Note the known gap: the harnesses re-implement logic rather than compiling
`main.cpp`, so they verify behaviour but **not** that the firmware builds. Always
run `pio run -e tdeck` before opening a PR.

## Releasing

Maintainers: see [RELEASING.md](RELEASING.md). CI runs the build, licence
verification, pre-flight checks and host tests on every tag and refuses to publish
if any fail — so a broken build cannot reach the flasher.

## Style

Match the surrounding code: 4-space indent, `snake_case` for functions,
`camelCase` for locals, `_leadingUnderscore` for file-static helpers. Comment
*why*, not *what* — especially for hardware quirks and protocol constraints, where
the reason is rarely obvious later.

Add SPDX headers to new files:

```c
// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
```

## Pull requests

Keep them focused, explain the operational reasoning, state how you tested, and
call out any interop impact explicitly. Note that firmware licensed GPL-3.0 means
your contribution ships under those terms.

## What we are unlikely to merge

- Jamming, spoofing, or any transmit-side counter-UAS function. This project is
  detection-only, and that boundary is deliberate.
- Features that consume significant airtime without a strong operational case.
- Proprietary or non-standard cryptography. Standard published algorithms only —
  this also preserves the export-control position in
  [EXPORT_CONTROL.md](EXPORT_CONTROL.md).
- Marketing-driven capability claims not supported by measurement.
