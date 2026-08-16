// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Remote ID drone detection — ASTM F3411 / Open Drone ID parsing and tracking.
// See remoteid.h for the no-platform-dependency rationale.
//
// ── Threat model for this file ──
// Every byte reaching rid_extract*/rid_parse* comes off the air and is fully
// attacker-controlled. A malformed or hostile frame must never read out of
// bounds, never loop unboundedly, and never write past a fixed buffer. Every
// length is validated against the actual buffer length before use.

#include "remoteid.h"
#include <string.h>
#include <math.h>

// ── ASTM assigned identifiers ──
// BLE: Service Data (AD type 0x16) with 16-bit UUID 0xFFFA (ASTM International),
//      followed by 0x0D (ODID application code), then a message counter.
#define ASTM_UUID_LO      0xFA
#define ASTM_UUID_HI      0xFF
#define ODID_APP_CODE     0x0D
#define BLE_AD_SERVICE_DATA_16 0x16

// WiFi Beacon: Vendor Specific IE (0xDD), OUI FA-0B-BC (ASTM), vendor type 0x0D.
#define IE_VENDOR_SPECIFIC 0xDD
static const uint8_t ASTM_OUI[3] = { 0xFA, 0x0B, 0xBC };

// ════════════════════════════════════════════════════════════
// MODULE STATE
// ════════════════════════════════════════════════════════════
static RemoteIdTrack g_tracks[RID_MAX_TRACKS];
static uint8_t  g_source = RID_SRC_900;          // Decision A: 900 MHz default
static uint32_t g_lastAlertMs[RID_MAX_TRACKS];
static double   g_lastAlertLat[RID_MAX_TRACKS];
static double   g_lastAlertLon[RID_MAX_TRACKS];
static bool     g_alertSent[RID_MAX_TRACKS];

// Duty cycle accounting
static uint32_t g_dutyScanAccum = 0;
static uint32_t g_dutyWindowAccum = 0;
static uint8_t  g_dutyRequestedPct = 0;

void rid_init(void) { rid_reset(); }

void rid_reset(void) {
    memset(g_tracks, 0, sizeof(g_tracks));
    memset(g_lastAlertMs, 0, sizeof(g_lastAlertMs));
    memset(g_lastAlertLat, 0, sizeof(g_lastAlertLat));
    memset(g_lastAlertLon, 0, sizeof(g_lastAlertLon));
    memset(g_alertSent, 0, sizeof(g_alertSent));
    g_dutyScanAccum = 0;
    g_dutyWindowAccum = 0;
}

// ════════════════════════════════════════════════════════════
// RING BUFFER — producer side runs in callback context
// ════════════════════════════════════════════════════════════
void rid_ringInit(RidRing* r) {
    if (!r) return;
    memset(r, 0, sizeof(RidRing));
}

bool rid_ringPush(RidRing* r, const uint8_t* data, uint16_t len,
                  uint8_t transport, int8_t rssi) {
    if (!r || !data || len == 0) return false;
    if (len > RID_RING_SLOT_BYTES) len = RID_RING_SLOT_BYTES;

    uint8_t next = (uint8_t)((r->head + 1) % RID_RING_SLOTS);
    if (next == r->tail) {
        // Full. Drop rather than block or overwrite — LoRa must never wait on us.
        r->dropped++;
        return false;
    }
    RidRingSlot* s = &r->slots[r->head];
    memcpy(s->data, data, len);
    s->len = len;
    s->transport = transport;
    s->rssi = rssi;
    r->head = next;
    r->accepted++;
    return true;
}

bool rid_ringPop(RidRing* r, RidRingSlot* out) {
    if (!r || !out) return false;
    if (r->tail == r->head) return false;      // Empty
    memcpy(out, &r->slots[r->tail], sizeof(RidRingSlot));
    r->tail = (uint8_t)((r->tail + 1) % RID_RING_SLOTS);
    return true;
}

uint32_t rid_ringDropped(const RidRing* r)  { return r ? r->dropped  : 0; }
uint32_t rid_ringAccepted(const RidRing* r) { return r ? r->accepted : 0; }

// ════════════════════════════════════════════════════════════
// TRANSPORT EXTRACTION
// ════════════════════════════════════════════════════════════

// Walk BLE advertisement AD structures looking for ASTM service data.
// AD structure: [len][type][payload(len-1)]
uint16_t rid_extractFromBleAdv(const uint8_t* adv, uint16_t advLen, uint16_t* offset) {
    if (!adv || !offset || advLen < 6) return 0;
    uint16_t i = 0;
    while (i < advLen) {
        uint8_t adLen = adv[i];
        if (adLen == 0) break;                       // Padding / terminator
        if ((uint32_t)i + 1 + adLen > advLen) break; // Truncated — reject
        uint8_t adType = adv[i + 1];

        if (adType == BLE_AD_SERVICE_DATA_16 && adLen >= 4) {
            // payload: [uuid_lo][uuid_hi][app_code][counter][message...]
            const uint8_t* p = &adv[i + 2];
            uint8_t payLen = (uint8_t)(adLen - 1);
            if (payLen >= 4 &&
                p[0] == ASTM_UUID_LO && p[1] == ASTM_UUID_HI &&
                p[2] == ODID_APP_CODE) {
                *offset = (uint16_t)(i + 2 + 4);     // Skip uuid(2)+app(1)+counter(1)
                uint16_t remaining = (uint16_t)(payLen - 4);
                if ((uint32_t)*offset + remaining > advLen) return 0;
                return remaining;
            }
        }
        i = (uint16_t)(i + 1 + adLen);
    }
    return 0;
}

// Scan 802.11 beacon information elements for the ASTM vendor-specific IE.
// `frame` must point at the start of the IE list (after the fixed beacon fields).
// IE: [id][len][data(len)]; vendor IE data: [OUI(3)][vendorType(1)][counter(1)][msgs...]
uint16_t rid_extractFromBeaconIe(const uint8_t* frame, uint16_t frameLen, uint16_t* offset) {
    if (!frame || !offset || frameLen < 7) return 0;
    uint16_t i = 0;
    while ((uint32_t)i + 2 <= frameLen) {
        uint8_t ieId  = frame[i];
        uint8_t ieLen = frame[i + 1];
        if ((uint32_t)i + 2 + ieLen > frameLen) break;   // Truncated — reject

        if (ieId == IE_VENDOR_SPECIFIC && ieLen >= 5) {
            const uint8_t* d = &frame[i + 2];
            if (memcmp(d, ASTM_OUI, 3) == 0 && d[3] == ODID_APP_CODE) {
                *offset = (uint16_t)(i + 2 + 5);         // Skip OUI(3)+type(1)+counter(1)
                uint16_t remaining = (uint16_t)(ieLen - 5);
                if ((uint32_t)*offset + remaining > frameLen) return 0;
                return remaining;
            }
        }
        i = (uint16_t)(i + 2 + ieLen);
    }
    return 0;
}

// ════════════════════════════════════════════════════════════
// MESSAGE PARSING
// ════════════════════════════════════════════════════════════
static int32_t rd_i32le(const uint8_t* p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}
static uint16_t rd_u16le(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

// Copy a fixed-width, possibly unterminated ID field into a NUL-terminated
// buffer, stripping trailing spaces/NULs and rejecting non-printable bytes.
static void copyIdField(char* dst, size_t dstSize, const uint8_t* src, size_t srcLen) {
    size_t n = (srcLen < dstSize - 1) ? srcLen : dstSize - 1;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = src[i];
        if (c == 0) break;
        if (c < 0x20 || c > 0x7E) continue;   // Drop non-printable
        dst[o++] = (char)c;
    }
    while (o > 0 && dst[o - 1] == ' ') o--;   // Trim trailing spaces
    dst[o] = '\0';
}

bool rid_parseMessage(const uint8_t* msg, RemoteIdTrack* t) {
    if (!msg || !t) return false;
    uint8_t msgType = (uint8_t)(msg[0] >> 4);

    switch (msgType) {
        case RID_MSG_BASIC_ID: {
            t->idType = (uint8_t)(msg[1] >> 4);
            t->uaType = (uint8_t)(msg[1] & 0x0F);
            copyIdField(t->uasId, sizeof(t->uasId), &msg[2], 20);
            return true;
        }
        case RID_MSG_LOCATION: {
            uint8_t flags = msg[1];
            bool ewDirection = (flags & 0x02) != 0;
            bool speedMult   = (flags & 0x01) != 0;

            uint16_t dir = msg[2];
            if (ewDirection) dir = (uint16_t)(dir + 180);
            if (dir > 359) dir = (uint16_t)(dir % 360);
            t->headingDeg = dir;

            // Speed encoding: multiplier 0 -> 0.25 m/s units;
            // multiplier 1 -> 0.75 m/s units with a 255*0.25 offset.
            uint8_t rawSpeed = msg[3];
            if (!speedMult) {
                t->speedCms = (uint16_t)(rawSpeed * 25);
            } else {
                t->speedCms = (uint16_t)(rawSpeed * 75 + 255 * 25);
            }

            t->vertSpeedCms = (int16_t)((int8_t)msg[4] * 50);   // 0.5 m/s units

            int32_t rawLat = rd_i32le(&msg[5]);
            int32_t rawLon = rd_i32le(&msg[9]);
            double lat = rawLat * 1e-7;
            double lon = rawLon * 1e-7;
            // Reject implausible or "unknown" (0,0) coordinates
            if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0 &&
                !(rawLat == 0 && rawLon == 0)) {
                t->lat = lat;
                t->lon = lon;
                t->hasPosition = true;
            }

            // Altitudes: 0.5 m units, -1000 m offset. 0 encodes "unknown".
            uint16_t rawGeo = rd_u16le(&msg[15]);
            if (rawGeo != 0) t->altGeoM = (int16_t)((int32_t)rawGeo / 2 - 1000);
            uint16_t rawHgt = rd_u16le(&msg[17]);
            if (rawHgt != 0) t->heightAglM = (int16_t)((int32_t)rawHgt / 2 - 1000);
            return true;
        }
        case RID_MSG_SYSTEM: {
            int32_t rawLat = rd_i32le(&msg[2]);
            int32_t rawLon = rd_i32le(&msg[6]);
            double lat = rawLat * 1e-7;
            double lon = rawLon * 1e-7;
            if (lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0 &&
                !(rawLat == 0 && rawLon == 0)) {
                t->opLat = lat;
                t->opLon = lon;
                t->hasOperator = true;     // Highest-value field in the record
            }
            return true;
        }
        case RID_MSG_OPERATOR_ID: {
            copyIdField(t->operatorId, sizeof(t->operatorId), &msg[2], 20);
            return true;
        }
        case RID_MSG_AUTH:
        case RID_MSG_SELF_ID:
            return true;      // Recognised, nothing we retain
        default:
            return false;     // Unknown / reserved
    }
}

int rid_parsePayload(const uint8_t* payload, uint16_t len, RemoteIdTrack* t) {
    if (!payload || !t || len == 0) return 0;

    // Message Pack: [header][msgSize][msgCount][messages...]
    if ((payload[0] >> 4) == RID_MSG_PACK) {
        if (len < 3) return 0;
        uint8_t msgSize  = payload[1];
        uint8_t msgCount = payload[2];
        if (msgSize != RID_MSG_SIZE) return 0;
        if (msgCount == 0 || msgCount > RID_MAX_PACK_MSGS) return 0;
        if ((uint32_t)3 + (uint32_t)msgCount * msgSize > len) return 0;  // Truncated

        int applied = 0;
        for (uint8_t i = 0; i < msgCount; i++) {
            if (rid_parseMessage(&payload[3 + i * msgSize], t)) applied++;
        }
        return applied;
    }

    // Single message
    if (len < RID_MSG_SIZE) return 0;
    return rid_parseMessage(payload, t) ? 1 : 0;
}

// ════════════════════════════════════════════════════════════
// TRACK TABLE
// ════════════════════════════════════════════════════════════
static int findSlotByUasId(const char* uasId) {
    if (!uasId || uasId[0] == '\0') return -1;
    for (int i = 0; i < RID_MAX_TRACKS; i++) {
        if (g_tracks[i].valid && strncmp(g_tracks[i].uasId, uasId, RID_UASID_LEN) == 0)
            return i;
    }
    return -1;
}

static int allocSlot(uint32_t nowMs) {
    for (int i = 0; i < RID_MAX_TRACKS; i++) {
        if (!g_tracks[i].valid) return i;
    }
    // Full — evict least recently seen (LRU)
    int oldest = 0;
    uint32_t oldestSeen = g_tracks[0].lastSeenMs;
    for (int i = 1; i < RID_MAX_TRACKS; i++) {
        if (g_tracks[i].lastSeenMs < oldestSeen) {
            oldestSeen = g_tracks[i].lastSeenMs;
            oldest = i;
        }
    }
    (void)nowMs;
    memset(&g_tracks[oldest], 0, sizeof(RemoteIdTrack));
    g_alertSent[oldest] = false;
    g_lastAlertMs[oldest] = 0;
    return oldest;
}

int rid_ingest(const RemoteIdTrack* obs, uint8_t transport, int8_t rssi, uint32_t nowMs) {
    if (!obs) return -1;
    // A track without a UAS ID cannot be correlated or deduplicated across
    // transports, so it is not useful. Basic ID always accompanies a broadcast.
    if (obs->uasId[0] == '\0') return -1;

    int idx = findSlotByUasId(obs->uasId);
    bool isNew = false;
    if (idx < 0) {
        idx = allocSlot(nowMs);
        isNew = true;
        memset(&g_tracks[idx], 0, sizeof(RemoteIdTrack));
        g_tracks[idx].firstSeenMs = nowMs;
        memcpy(g_tracks[idx].uasId, obs->uasId, RID_UASID_LEN);
    }

    RemoteIdTrack* t = &g_tracks[idx];

    // Merge — only overwrite fields the observation actually carried, so a
    // Location-only message does not wipe a previously learned operator position.
    if (obs->idType || isNew) t->idType = obs->idType;
    if (obs->uaType || isNew) t->uaType = obs->uaType;
    if (obs->operatorId[0]) memcpy(t->operatorId, obs->operatorId, RID_OPID_LEN);
    if (obs->hasPosition) {
        t->lat = obs->lat; t->lon = obs->lon; t->hasPosition = true;
        t->altGeoM = obs->altGeoM;
        t->heightAglM = obs->heightAglM;
        t->speedCms = obs->speedCms;
        t->headingDeg = obs->headingDeg;
        t->vertSpeedCms = obs->vertSpeedCms;
    }
    if (obs->hasOperator) {
        t->opLat = obs->opLat; t->opLon = obs->opLon; t->hasOperator = true;
    }

    // Dedup across transports: the same drone commonly broadcasts on both WiFi
    // and BLE. Record which transports have been seen rather than creating a
    // second track.
    if (transport <= RID_TRANSPORT_BLE_LR) t->transportMask |= (uint8_t)(1u << transport);

    t->rssi = rssi;
    t->lastSeenMs = nowMs;
    t->msgCount++;
    t->valid = true;
    return idx;
}

int rid_processPayload(const uint8_t* payload, uint16_t len,
                       uint8_t transport, int8_t rssi, uint32_t nowMs) {
    RemoteIdTrack obs;
    memset(&obs, 0, sizeof(obs));
    int applied = rid_parsePayload(payload, len, &obs);
    if (applied <= 0) return -1;
    return rid_ingest(&obs, transport, rssi, nowMs);
}

void rid_ageTracks(uint32_t nowMs) {
    for (int i = 0; i < RID_MAX_TRACKS; i++) {
        if (!g_tracks[i].valid) continue;
        // Guard against clock rollback (millis() wrap is handled by unsigned math,
        // but a smaller nowMs than lastSeen would underflow the comparison).
        if (nowMs < g_tracks[i].lastSeenMs) continue;
        if (nowMs - g_tracks[i].lastSeenMs > RID_EXPIRE_MS) {
            memset(&g_tracks[i], 0, sizeof(RemoteIdTrack));
            g_alertSent[i] = false;
            g_lastAlertMs[i] = 0;
        }
    }
}

int rid_trackCount(void) {
    int n = 0;
    for (int i = 0; i < RID_MAX_TRACKS; i++) if (g_tracks[i].valid) n++;
    return n;
}

int rid_activeTrackCount(uint32_t nowMs) {
    int n = 0;
    for (int i = 0; i < RID_MAX_TRACKS; i++) {
        if (!g_tracks[i].valid) continue;
        if (nowMs >= g_tracks[i].lastSeenMs &&
            nowMs - g_tracks[i].lastSeenMs <= RID_STALE_MS) n++;
    }
    return n;
}

const RemoteIdTrack* rid_getTrack(int idx) {
    if (idx < 0 || idx >= RID_MAX_TRACKS) return NULL;
    if (!g_tracks[idx].valid) return NULL;
    return &g_tracks[idx];
}

const RemoteIdTrack* rid_findByUasId(const char* uasId) {
    int i = findSlotByUasId(uasId);
    return (i < 0) ? NULL : &g_tracks[i];
}

// ════════════════════════════════════════════════════════════
// FUSION (decision D)
// ════════════════════════════════════════════════════════════
void rid_correlate900(bool has900Detection, uint32_t nowMs) {
    for (int i = 0; i < RID_MAX_TRACKS; i++) {
        if (!g_tracks[i].valid) continue;
        bool fresh = (nowMs >= g_tracks[i].lastSeenMs) &&
                     (nowMs - g_tracks[i].lastSeenMs <= RID_STALE_MS);
        g_tracks[i].correlated900 = (has900Detection && fresh);
    }
}

// Decision D: a 900 MHz emitter with NO Remote ID is the most operationally
// significant signal the combined system can produce — an aircraft flying
// without a compliance beacon. It ranks above a correlated detection.
uint8_t rid_alertLevel(bool has900Detection, uint32_t nowMs) {
    int active = rid_activeTrackCount(nowMs);
    if (has900Detection && active == 0) return RID_ALERT_NO_RID;
    if (has900Detection && active > 0)  return RID_ALERT_CORRELATED;
    if (active > 0)                     return RID_ALERT_RID_ONLY;
    return RID_ALERT_NONE;
}

// ════════════════════════════════════════════════════════════
// SOURCE SELECTION
// ════════════════════════════════════════════════════════════
void rid_setSource(uint8_t src) { if (src < RID_SRC_COUNT) g_source = src; }
uint8_t rid_getSource(void) { return g_source; }

const char* rid_sourceName(uint8_t src) {
    switch (src) {
        case RID_SRC_900:      return "900MHz";
        case RID_SRC_REMOTEID: return "RemoteID";
        case RID_SRC_BOTH:     return "Both";
        default:               return "?";
    }
}
bool rid_sourceUsesRemoteId(uint8_t src) {
    return src == RID_SRC_REMOTEID || src == RID_SRC_BOTH;
}
bool rid_sourceUses900(uint8_t src) {
    return src == RID_SRC_900 || src == RID_SRC_BOTH;
}

// ════════════════════════════════════════════════════════════
// MESH ALERT RATE LIMITING (decision C)
// ════════════════════════════════════════════════════════════
bool rid_shouldSendAlert(int trackIdx, uint32_t nowMs) {
    if (trackIdx < 0 || trackIdx >= RID_MAX_TRACKS) return false;
    const RemoteIdTrack* t = &g_tracks[trackIdx];
    if (!t->valid) return false;

    if (!g_alertSent[trackIdx]) return true;      // New track — always announce

    // Rate limit
    if (nowMs >= g_lastAlertMs[trackIdx] &&
        nowMs - g_lastAlertMs[trackIdx] < RID_ALERT_MIN_INTERVAL_MS) return false;

    // Beyond the interval, only re-announce on significant movement
    if (t->hasPosition) {
        double moved = rid_haversineM(g_lastAlertLat[trackIdx], g_lastAlertLon[trackIdx],
                                      t->lat, t->lon);
        if (moved >= RID_ALERT_MOVE_THRESHOLD_M) return true;
    }
    return false;
}

void rid_markAlertSent(int trackIdx, uint32_t nowMs) {
    if (trackIdx < 0 || trackIdx >= RID_MAX_TRACKS) return;
    g_alertSent[trackIdx] = true;
    g_lastAlertMs[trackIdx] = nowMs;
    g_lastAlertLat[trackIdx] = g_tracks[trackIdx].lat;
    g_lastAlertLon[trackIdx] = g_tracks[trackIdx].lon;
}

// ════════════════════════════════════════════════════════════
// DUTY CYCLE ACCOUNTING (decision B)
// ════════════════════════════════════════════════════════════
void rid_dutySetRequested(uint32_t scanMs, uint32_t periodMs) {
    g_dutyRequestedPct = periodMs ? (uint8_t)((scanMs * 100UL) / periodMs) : 0;
    if (g_dutyRequestedPct > 100) g_dutyRequestedPct = 100;
}

void rid_dutyRecord(uint32_t scanMs, uint32_t windowMs) {
    // Sliding accumulation, halved when large to keep a recent-weighted average.
    g_dutyScanAccum += scanMs;
    g_dutyWindowAccum += windowMs;
    if (g_dutyWindowAccum > 600000UL) {       // ~10 minutes
        g_dutyScanAccum >>= 1;
        g_dutyWindowAccum >>= 1;
    }
}

uint8_t rid_dutyAchievedPct(void) {
    if (g_dutyWindowAccum == 0) return 0;
    uint32_t pct = (g_dutyScanAccum * 100UL) / g_dutyWindowAccum;
    return (uint8_t)(pct > 100 ? 100 : pct);
}
uint8_t rid_dutyRequestedPct(void) { return g_dutyRequestedPct; }

// ════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════
double rid_haversineM(double lat1, double lon1, double lat2, double lon2) {
    const double R = 6371000.0;
    double dLat = (lat2 - lat1) * M_PI / 180.0;
    double dLon = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dLat/2) * sin(dLat/2) +
               cos(lat1 * M_PI/180.0) * cos(lat2 * M_PI/180.0) *
               sin(dLon/2) * sin(dLon/2);
    return R * 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
}

const char* rid_uaTypeName(uint8_t uaType) {
    switch (uaType) {
        case 0:  return "Undeclared";
        case 1:  return "Aeroplane";
        case 2:  return "Rotorcraft";
        case 3:  return "Gyroplane";
        case 4:  return "Hybrid VTOL";
        case 5:  return "Ornithopter";
        case 6:  return "Glider";
        case 7:  return "Kite";
        case 8:  return "Free balloon";
        case 9:  return "Captive balloon";
        case 10: return "Airship";
        case 11: return "Parachute";
        case 12: return "Rocket";
        case 13: return "Tethered";
        case 14: return "Ground obstacle";
        default: return "Other";
    }
}

const char* rid_transportName(uint8_t transport) {
    switch (transport) {
        case RID_TRANSPORT_WIFI_BEACON: return "WiFi-B";
        case RID_TRANSPORT_WIFI_NAN:    return "WiFi-N";
        case RID_TRANSPORT_BLE_LEGACY:  return "BLE";
        case RID_TRANSPORT_BLE_LR:      return "BLE-LR";
        default:                        return "?";
    }
}
