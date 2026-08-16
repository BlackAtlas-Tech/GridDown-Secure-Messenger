<!--
SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Export Control Notice

This repository contains open-source encryption software. This notice is provided
for transparency; it is **not legal advice**, and it does not relieve you of your
own obligations.

## Classification

| | |
|---|---|
| **Item** | GridDown Secure Messenger firmware (source and compiled binaries) |
| **Cryptography** | Standard published algorithms only — AES-256-GCM, SHA-256, HMAC-SHA256, PBKDF2-HMAC-SHA256, HKDF-SHA256 (RFC 5869), ECDH P-256, all via mbedTLS |
| **Non-standard cryptography** | None. No proprietary or unpublished cryptographic algorithm is implemented. |
| **Pre-publication binaries** | Self-classified **ECCN 5D992.c** (mass-market encryption software), Anti-Terrorism controls only |
| **Published source and corresponding object code** | **Not subject to the EAR** under 15 CFR §§ 734.3(b)(3) / 734.7, on the basis of public availability |
| **Jurisdiction** | EAR (not ITAR) |

## Notes

**Publicly available encryption source code.** Under 15 CFR § 742.15(b),
publicly available encryption source code classified under ECCN 5D002 is not
subject to the EAR. The notification requirement in § 742.15(b)(2) applies to
software providing or performing **"non-standard cryptography."** This firmware
uses only standard published algorithms, so that requirement is not triggered.
That exemption is **conditional on the cryptography remaining standard** — it is
not a blanket repeal.

**Frequency hopping.** The firmware derives a channel-rotation sequence from the
group pre-shared key using HKDF-SHA256. The relevant equipment control,
ECCN 5A001.b.3, does **not** apply: its Note excludes equipment operating at an
output power of **1 W or less**, and this firmware transmits at 14 dBm (25 mW) by
default, with a configurable maximum of 22 dBm (158 mW). The derivative software
control 5D001.a therefore does not attach either.

**Your obligations as a downloader.** Even for items not subject to the EAR,
separate U.S. sanctions and embargo rules may restrict your dealings. You are
responsible for complying with the export, re-export, and sanctions laws that
apply to you. Do not download or use this software if doing so would violate them.

**No warranty of classification.** BlackAtlas LLC's self-classification is made in
good faith and is not a determination by any government agency. If you require
certainty for your own compliance programme, obtain your own classification.
