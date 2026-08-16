// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Remote ID drone detection (ASTM F3411 / Open Drone ID) over 2.4 GHz.
//
// DESIGN NOTE — deliberately free of Arduino/ESP-IDF dependencies.
// Everything in this header and remoteid.cpp is plain C++ operating on byte
// buffers and a caller-supplied millisecond clock. The ESP-IDF plumbing
// (promiscuous WiFi callback, NimBLE scan, duty-cycle task) lives in main.cpp
// and calls into this module.
//
// The reason matters: it lets the host test harness compile THIS ACTUAL FILE
// rather than a re-implementation of its logic. Earlier test harnesses in this
// project re-implemented the logic they tested, which is why a full suite could
// pass while the firmware did not build.

#ifndef REMOTEID_H
#define REMOTEID_H

#include <stdint.h>
#include <stddef.h>

// ── Limits ──
#define RID_MAX_TRACKS        16   // Concurrent tracked aircraft
#define RID_UASID_LEN         21   // 20 bytes + NUL
#define RID_OPID_LEN          21
#define RID_MSG_SIZE          25   // Every F3411 message is exactly 25 bytes
#define RID_MAX_PACK_MSGS     10   // Sanity cap on Message Pack count

// Track lifecycle (milliseconds)
#define RID_STALE_MS          60000UL    // No update -> shown as stale
#define RID_EXPIRE_MS         300000UL   // No update -> slot released

// ── F3411 message types (high nibble of byte 0) ──
#define RID_MSG_BASIC_ID      0x0
#define RID_MSG_LOCATION      0x1
#define RID_MSG_AUTH          0x2
#define RID_MSG_SELF_ID       0x3
#define RID_MSG_SYSTEM        0x4
#define RID_MSG_OPERATOR_ID   0x5
#define RID_MSG_PACK          0xF

// ── Transport the observation arrived on ──
#define RID_TRANSPORT_UNKNOWN     0
#define RID_TRANSPORT_WIFI_BEACON 1
#define RID_TRANSPORT_WIFI_NAN    2
#define RID_TRANSPORT_BLE_LEGACY  3
#define RID_TRANSPORT_BLE_LR      4

// ── Detection source selector (orthogonal to SCAN_PROFILE_*) ──
// Per spec: Remote ID is a separate detection SOURCE, not a fifth scan profile,
// because the existing profiles are all SX1262 parameter sets.
#define RID_SRC_900           0   // SX1262 sweep only (default — decision A)
#define RID_SRC_REMOTEID      1   // 2.4 GHz WiFi + BLE Remote ID only
#define RID_SRC_BOTH          2   // Interleaved
#define RID_SRC_COUNT         3

// ── Fusion / alert level (decision D) ──
#define RID_ALERT_NONE        0
#define RID_ALERT_RID_ONLY    1   // Compliant drone, identity known
#define RID_ALERT_CORRELATED  2   // Remote ID + 900 MHz control link agree
#define RID_ALERT_NO_RID      3   // 900 MHz emitter with NO Remote ID  <-- highest interest

// ── A tracked aircraft ──
struct RemoteIdTrack {
    char     uasId[RID_UASID_LEN];
    char     operatorId[RID_OPID_LEN];
    uint8_t  idType;
    uint8_t  uaType;

    // Aircraft state
    double   lat, lon;          // degrees; 0/0 == unknown
    bool     hasPosition;
    int16_t  altGeoM;           // geodetic altitude, metres
    int16_t  heightAglM;        // height above takeoff, metres
    uint16_t speedCms;          // cm/s
    uint16_t headingDeg;        // 0-359
    int16_t  vertSpeedCms;      // cm/s, signed (positive = climbing)

    // Operator / takeoff location — the highest-value field in the record
    double   opLat, opLon;
    bool     hasOperator;

    // Observation metadata
    int8_t   rssi;
    uint8_t  transportMask;     // Bitmask of RID_TRANSPORT_* seen (dedup evidence)
    uint32_t firstSeenMs, lastSeenMs;
    uint16_t msgCount;
    bool     correlated900;     // Also seen by the SX1262 scanner
    bool     valid;
};

// ── Bounded ring buffer for frames captured in interrupt/callback context ──
// The promiscuous callback must do minimal work: filter, copy, return. Parsing
// happens later at low priority. Drops on full and counts the drop — a visible
// drop count is strictly better than an invisible LoRa stall.
#define RID_RING_SLOTS        16
#define RID_RING_SLOT_BYTES   264   // Max useful F3411 payload we retain

struct RidRingSlot {
    uint8_t  data[RID_RING_SLOT_BYTES];
    uint16_t len;
    uint8_t  transport;
    int8_t   rssi;
};

struct RidRing {
    RidRingSlot slots[RID_RING_SLOTS];
    volatile uint8_t head;      // Write index (producer)
    volatile uint8_t tail;      // Read index (consumer)
    volatile uint32_t dropped;  // Frames discarded because the ring was full
    volatile uint32_t accepted;
};

// ════════════════════════════════════════════════════════════
// API
// ════════════════════════════════════════════════════════════

void rid_init(void);
void rid_reset(void);                       // Clear all tracks and counters

// ── Ring buffer (producer side is callback-safe) ──
void rid_ringInit(RidRing* r);
bool rid_ringPush(RidRing* r, const uint8_t* data, uint16_t len,
                  uint8_t transport, int8_t rssi);
bool rid_ringPop(RidRing* r, RidRingSlot* out);
uint32_t rid_ringDropped(const RidRing* r);
uint32_t rid_ringAccepted(const RidRing* r);

// ── Transport payload extraction ──
// Locate the F3411 payload inside a captured frame. Returns payload length and
// sets *offset, or 0 if this frame carries no Remote ID data.
// These bound-check aggressively: input is attacker-controlled RF.
uint16_t rid_extractFromBleAdv(const uint8_t* adv, uint16_t advLen, uint16_t* offset);
uint16_t rid_extractFromBeaconIe(const uint8_t* frame, uint16_t frameLen, uint16_t* offset);

// ── Message parsing ──
// Parse one 25-byte F3411 message into a track. Returns true if it was a
// recognised type and the track was updated.
bool rid_parseMessage(const uint8_t* msg, RemoteIdTrack* t);

// Parse a payload that may be a single message or a Message Pack.
// Returns the number of messages successfully applied.
int  rid_parsePayload(const uint8_t* payload, uint16_t len, RemoteIdTrack* t);

// ── Track table ──
// Ingest a parsed observation, merging into an existing track by UAS ID or
// allocating a slot (LRU eviction when full). Returns the track index, or -1.
int  rid_ingest(const RemoteIdTrack* obs, uint8_t transport, int8_t rssi, uint32_t nowMs);

// Full pipeline: raw captured payload -> track table.
int  rid_processPayload(const uint8_t* payload, uint16_t len,
                        uint8_t transport, int8_t rssi, uint32_t nowMs);

void rid_ageTracks(uint32_t nowMs);         // Mark stale, release expired
int  rid_trackCount(void);                  // Live (valid) tracks
int  rid_activeTrackCount(uint32_t nowMs);  // Non-stale tracks
const RemoteIdTrack* rid_getTrack(int idx);
const RemoteIdTrack* rid_findByUasId(const char* uasId);

// ── Fusion (decision D) ──
// Correlate against the 900 MHz scanner. `has900Detection` is true when the
// SX1262 scanner currently reports a drone-class detection.
void rid_correlate900(bool has900Detection, uint32_t nowMs);
uint8_t rid_alertLevel(bool has900Detection, uint32_t nowMs);

// ── Detection source ──
void    rid_setSource(uint8_t src);
uint8_t rid_getSource(void);
const char* rid_sourceName(uint8_t src);
bool    rid_sourceUsesRemoteId(uint8_t src);
bool    rid_sourceUses900(uint8_t src);

// ── Mesh alert rate limiting (decision C: direct-only, never relayed) ──
// Remote ID arrives at ~1 Hz per drone; relaying that would flood the channel.
// Returns true at most once per track per interval, and only on a new track or
// a significant position change.
#define RID_ALERT_MIN_INTERVAL_MS  60000UL
#define RID_ALERT_MOVE_THRESHOLD_M 200.0
bool rid_shouldSendAlert(int trackIdx, uint32_t nowMs);
void rid_markAlertSent(int trackIdx, uint32_t nowMs);

// ── Duty cycle accounting (decision B: honest indicator) ──
// The achieved BLE scan window may be shorter than requested when the tablet is
// connected. Silently shortening produces silent false negatives, so the
// achieved figure is measured and surfaced in the UI.
void    rid_dutyRecord(uint32_t scanMs, uint32_t windowMs);
uint8_t rid_dutyAchievedPct(void);
uint8_t rid_dutyRequestedPct(void);
void    rid_dutySetRequested(uint32_t scanMs, uint32_t periodMs);

// ── Helpers ──
double rid_haversineM(double lat1, double lon1, double lat2, double lon2);
const char* rid_uaTypeName(uint8_t uaType);
const char* rid_transportName(uint8_t transport);

#endif // REMOTEID_H
