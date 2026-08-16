<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->

## What this changes

<!-- What operational problem does it solve? Describe the field situation, not just the code. -->

## How it was tested

- [ ] `pio run -e tdeck` succeeds
- [ ] `tools/preflight.sh` passes
- [ ] Host test harnesses pass (`g++ -std=c++17 -w -o t test_*.cpp [src/module.cpp] && ./t`)
- [ ] Flashed and tested on hardware — **state how many radios and what you exercised:**

## Interoperability impact

Changes to the **packet format**, **key derivation**, or the **frequency-hop
sequence** break communication with radios already in the field. These need a
version bump and a documented upgrade path.

- [ ] No interoperability impact
- [ ] Breaks interop — described below, with the upgrade path

## Airtime

LoRa airtime is the scarce resource in this product.

- [ ] Transmits no additional data
- [ ] Transmits more — justified below, with the rate limiting applied

## Checklist

- [ ] SPDX headers on any new files
- [ ] No proprietary or non-standard cryptography (see [EXPORT_CONTROL.md](../EXPORT_CONTROL.md))
- [ ] No jamming, spoofing, or transmit-side counter-UAS function — this project is detection-only
- [ ] Capability claims are supported by measurement, not estimate
- [ ] `SECURITY.md` / `PRIVACY.md` updated if the change affects either
- [ ] CLA signed (the bot will prompt on your first PR)
