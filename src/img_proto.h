// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
// GridDown Image Transfer Protocol — Phase 1
// Standalone chunking and reassembly logic for image transmission over LoRa.
//
// PHASE 0 ARCHITECTURE DECISIONS (encoded as constants below):
//
// 1. Image source: PWA on tablet (via WebSocket) or SD card (pre-loaded refs)
// 2. Format: JPEG, max 240×180, target 3-5KB, quality 30-40
// 3. Priority: BULK (lowest) — preempted by voice, DMs, beacons, broadcasts
// 4. Abort: sender cancel, receiver NACK timeout, 60s no-progress timeout
// 5. Encryption: PSK-only (group encryption) — no per-peer E2E for images
// 6. Mesh relay: NO — image chunks are direct-only to prevent network melt
// 7. Concurrent receives: MAX 2 simultaneous from different senders
// ═══════════════════════════════════════════════════════════════════════════

#ifndef IMG_PROTO_H
#define IMG_PROTO_H

#include <stdint.h>
#include <stddef.h>

// ── PROTOCOL CONSTANTS ──

// LoRa frame budget after PSK encryption overhead:
//   LORA_MAX_PAYLOAD = 255 bytes
//   PSK marker byte (0xAE) = 1 byte
//   AES-GCM nonce = 12 bytes
//   AES-GCM tag = 16 bytes
//   = 226 bytes available for plaintext protocol payload
//
// We leave room for JSON envelope wrapping (used by other GridDown protocols
// for consistency), so the binary chunk payload is conservatively 180 bytes.
#define IMG_CHUNK_PAYLOAD_SIZE   180

// Image transfer ID is a 16-bit identifier scoped per sender.
// Combined with sender callsign, gives a unique transfer key.
typedef uint16_t img_xfer_id_t;

// Maximum image size enforced at the protocol level (operational limit).
// 8KB ≈ 45 chunks ≈ 60 seconds of airtime at SF10/BW125 — already too long
// for tactical use, but provides a hard upper bound to prevent abuse.
#define IMG_MAX_SIZE_BYTES       8192
#define IMG_MAX_CHUNKS           ((IMG_MAX_SIZE_BYTES + IMG_CHUNK_PAYLOAD_SIZE - 1) / IMG_CHUNK_PAYLOAD_SIZE)

// Maximum filename length in img_hdr packet
#define IMG_FILENAME_MAX         24

// ── PACKET TYPES ──
// Wire format type strings (matches existing GridDown JSON protocol style)
#define IMG_TYPE_HDR    "img_hdr"     // Sender → receivers: announce transfer
#define IMG_TYPE_CHUNK  "img_chunk"   // Sender → receivers: payload data
#define IMG_TYPE_DONE   "img_done"    // Sender → receivers: all chunks sent
#define IMG_TYPE_NACK   "img_nack"    // Receiver → sender: missing chunks
#define IMG_TYPE_ABORT  "img_abort"   // Either side: cancel transfer

// ── ABORT REASONS ──
typedef enum {
    IMG_ABORT_USER       = 1,  // Operator cancelled
    IMG_ABORT_TIMEOUT    = 2,  // No progress for 60s
    IMG_ABORT_OOM        = 3,  // Receiver out of memory
    IMG_ABORT_TOO_LARGE  = 4,  // Image exceeds IMG_MAX_SIZE_BYTES
    IMG_ABORT_HASH_FAIL  = 5,  // Final hash verification failed after retries
    IMG_ABORT_TOO_MANY   = 6,  // Too many concurrent receives
} img_abort_reason_t;

// ── CHUNK BITMAP HELPERS ──
// Track which chunks have arrived using a bitmap (1 bit per chunk).
// 46 chunks max → 6 bytes bitmap.
#define IMG_BITMAP_BYTES         ((IMG_MAX_CHUNKS + 7) / 8)

static inline void img_bitmap_clear(uint8_t* bmp) {
    for (int i = 0; i < IMG_BITMAP_BYTES; i++) bmp[i] = 0;
}

static inline void img_bitmap_set(uint8_t* bmp, uint16_t chunk) {
    if (chunk >= IMG_MAX_CHUNKS) return;
    bmp[chunk >> 3] |= (1 << (chunk & 7));
}

static inline bool img_bitmap_get(const uint8_t* bmp, uint16_t chunk) {
    if (chunk >= IMG_MAX_CHUNKS) return false;
    return (bmp[chunk >> 3] & (1 << (chunk & 7))) != 0;
}

static inline uint16_t img_bitmap_count(const uint8_t* bmp, uint16_t total) {
    uint16_t n = 0;
    for (uint16_t i = 0; i < total; i++) {
        if (img_bitmap_get(bmp, i)) n++;
    }
    return n;
}

// Returns true if all chunks 0..total-1 are received.
static inline bool img_bitmap_complete(const uint8_t* bmp, uint16_t total) {
    return img_bitmap_count(bmp, total) == total;
}

// ── CRC-16 for chunk integrity ──
// CCITT-FALSE polynomial (x^16 + x^12 + x^5 + 1, init=0xFFFF)
// Catches single-bit errors and most burst errors. Final SHA-256 over
// the whole image catches anything CRC misses.
static inline uint16_t img_crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)data[i] << 8;
        for (int b = 0; b < 8; b++) {
            crc = (crc & 0x8000) ? (crc << 1) ^ 0x1021 : (crc << 1);
        }
    }
    return crc;
}

// ── CHUNKING ──
// Splits a buffer of `imgLen` bytes into chunks of IMG_CHUNK_PAYLOAD_SIZE.
// Returns total chunk count.
static inline uint16_t img_chunk_count(size_t imgLen) {
    return (uint16_t)((imgLen + IMG_CHUNK_PAYLOAD_SIZE - 1) / IMG_CHUNK_PAYLOAD_SIZE);
}

// Extract chunk N from the source image.
// Writes payload bytes to outBuf (max IMG_CHUNK_PAYLOAD_SIZE).
// Returns actual byte count written (last chunk may be partial).
// Returns 0 if chunk index is out of range.
static inline uint16_t img_chunk_extract(const uint8_t* src, size_t srcLen,
                                         uint16_t chunkIdx, uint8_t* outBuf) {
    size_t offset = (size_t)chunkIdx * IMG_CHUNK_PAYLOAD_SIZE;
    if (offset >= srcLen) return 0;
    size_t remaining = srcLen - offset;
    size_t copyLen = remaining < IMG_CHUNK_PAYLOAD_SIZE ? remaining : IMG_CHUNK_PAYLOAD_SIZE;
    for (size_t i = 0; i < copyLen; i++) outBuf[i] = src[offset + i];
    return (uint16_t)copyLen;
}

// ── REASSEMBLY ──
// Insert chunk N into the destination image buffer.
// Returns true if chunk was new (wasn't already received), false if duplicate.
static inline bool img_chunk_assemble(uint8_t* dst, size_t dstCapacity,
                                      uint16_t chunkIdx, const uint8_t* chunkData,
                                      uint16_t chunkLen, uint8_t* recvBitmap) {
    if (img_bitmap_get(recvBitmap, chunkIdx)) {
        return false;  // Duplicate — already have this chunk
    }
    size_t offset = (size_t)chunkIdx * IMG_CHUNK_PAYLOAD_SIZE;
    if (offset + chunkLen > dstCapacity) return false;  // Out of bounds
    for (uint16_t i = 0; i < chunkLen; i++) dst[offset + i] = chunkData[i];
    img_bitmap_set(recvBitmap, chunkIdx);
    return true;
}

// ── MISSING CHUNK ENUMERATION (for NACK construction) ──
// Fills outArr with up to maxOut chunk indices that are missing.
// Returns count of missing chunks written (capped at maxOut).
// Total missing count returned via outTotal (may exceed maxOut for huge gaps).
static inline uint16_t img_missing_chunks(const uint8_t* recvBitmap, uint16_t total,
                                          uint16_t* outArr, uint16_t maxOut,
                                          uint16_t* outTotalMissing) {
    uint16_t written = 0;
    uint16_t totalMissing = 0;
    for (uint16_t i = 0; i < total; i++) {
        if (!img_bitmap_get(recvBitmap, i)) {
            totalMissing++;
            if (written < maxOut) outArr[written++] = i;
        }
    }
    if (outTotalMissing) *outTotalMissing = totalMissing;
    return written;
}

#endif  // IMG_PROTO_H
