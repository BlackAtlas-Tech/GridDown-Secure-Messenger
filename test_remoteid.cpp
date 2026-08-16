// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Build: g++ -std=c++17 -w -o t test_remoteid.cpp src/remoteid.cpp -lm
//
// NOTE: this harness compiles and links the ACTUAL src/remoteid.cpp — it does
// not re-implement the logic under test. Earlier harnesses in this project
// re-implemented their subject, which is how a fully passing suite coexisted
// with firmware that would not build. remoteid.cpp is deliberately free of
// Arduino/ESP-IDF dependencies so this is possible.

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <cmath>
#include "src/remoteid.h"

// ── Test infra ──
static int passed = 0, failed = 0;
static std::vector<std::string> failures;
#define ASSERT(c,d) do { if (c) { printf("  [PASS] %s\n", d); passed++; } \
  else { printf("  [FAIL] %s  (line %d)\n", d, __LINE__); failed++; failures.push_back(d); } } while(0)
#define ASSERT_EQ(a,b,d) do { long _x=(long)(a), _y=(long)(b); \
  if (_x==_y) { printf("  [PASS] %s\n", d); passed++; } \
  else { printf("  [FAIL] %s (got %ld, want %ld, line %d)\n", d, _x, _y, __LINE__); failed++; failures.push_back(d); } } while(0)
#define ASSERT_NEAR(a,b,tol,d) do { double _x=(a), _y=(b); \
  if (fabs(_x-_y) <= (tol)) { printf("  [PASS] %s\n", d); passed++; } \
  else { printf("  [FAIL] %s (got %.6f, want %.6f, line %d)\n", d, _x, _y, __LINE__); failed++; failures.push_back(d); } } while(0)
#define SECTION(n) printf("\n-- %s --\n", n)

// ════════════════════════════════════════════════════════════
// F3411 MESSAGE BUILDERS (test fixtures)
// ════════════════════════════════════════════════════════════
static void putI32(uint8_t* p, int32_t v) {
    p[0]=(uint8_t)(v&0xFF); p[1]=(uint8_t)((v>>8)&0xFF);
    p[2]=(uint8_t)((v>>16)&0xFF); p[3]=(uint8_t)((v>>24)&0xFF);
}
static void putU16(uint8_t* p, uint16_t v) { p[0]=(uint8_t)(v&0xFF); p[1]=(uint8_t)(v>>8); }

static std::vector<uint8_t> msgBasicId(const char* id, uint8_t idType=1, uint8_t uaType=2) {
    std::vector<uint8_t> m(25, 0);
    m[0] = (uint8_t)(RID_MSG_BASIC_ID << 4);
    m[1] = (uint8_t)((idType << 4) | (uaType & 0x0F));
    size_t n = strlen(id); if (n > 20) n = 20;
    memcpy(&m[2], id, n);
    return m;
}
static std::vector<uint8_t> msgLocation(double lat, double lon, int altM,
                                        uint8_t rawSpeed=40, uint8_t dir=90,
                                        bool ewDir=false, bool speedMult=false) {
    std::vector<uint8_t> m(25, 0);
    m[0] = (uint8_t)(RID_MSG_LOCATION << 4);
    m[1] = (uint8_t)((ewDir?0x02:0) | (speedMult?0x01:0));
    m[2] = dir;
    m[3] = rawSpeed;
    m[4] = 0;
    putI32(&m[5], (int32_t)llround(lat * 1e7));
    putI32(&m[9], (int32_t)llround(lon * 1e7));
    putU16(&m[13], 0);
    putU16(&m[15], (uint16_t)((altM + 1000) * 2));   // geodetic alt
    putU16(&m[17], (uint16_t)((altM + 1000) * 2));   // height AGL
    return m;
}
static std::vector<uint8_t> msgSystem(double opLat, double opLon) {
    std::vector<uint8_t> m(25, 0);
    m[0] = (uint8_t)(RID_MSG_SYSTEM << 4);
    putI32(&m[2], (int32_t)llround(opLat * 1e7));
    putI32(&m[6], (int32_t)llround(opLon * 1e7));
    return m;
}
static std::vector<uint8_t> msgOperatorId(const char* opid) {
    std::vector<uint8_t> m(25, 0);
    m[0] = (uint8_t)(RID_MSG_OPERATOR_ID << 4);
    size_t n = strlen(opid); if (n > 20) n = 20;
    memcpy(&m[2], opid, n);
    return m;
}
static std::vector<uint8_t> msgPack(const std::vector<std::vector<uint8_t>>& msgs) {
    std::vector<uint8_t> p;
    p.push_back((uint8_t)(RID_MSG_PACK << 4));
    p.push_back(25);
    p.push_back((uint8_t)msgs.size());
    for (auto& m : msgs) p.insert(p.end(), m.begin(), m.end());
    return p;
}

// ── Transport encapsulation fixtures ──
static std::vector<uint8_t> wrapBle(const std::vector<uint8_t>& payload) {
    // [len][0x16][uuidLo][uuidHi][appCode][counter][payload...]
    std::vector<uint8_t> adv;
    adv.push_back((uint8_t)(1 + 4 + payload.size()));  // len = type + 4 hdr + payload
    adv.push_back(0x16);
    adv.push_back(0xFA); adv.push_back(0xFF);
    adv.push_back(0x0D);
    adv.push_back(0x01);                                // message counter
    adv.insert(adv.end(), payload.begin(), payload.end());
    return adv;
}
static std::vector<uint8_t> wrapBeaconIe(const std::vector<uint8_t>& payload) {
    // [0xDD][len][OUI(3)][type][counter][payload...]
    std::vector<uint8_t> ie;
    ie.push_back(0xDD);
    ie.push_back((uint8_t)(5 + payload.size()));
    ie.push_back(0xFA); ie.push_back(0x0B); ie.push_back(0xBC);
    ie.push_back(0x0D);
    ie.push_back(0x01);
    ie.insert(ie.end(), payload.begin(), payload.end());
    return ie;
}

// ════════════════════════════════════════════════════════════
int main() {
    printf("============================================================\n");
    printf("  GridDown Remote ID Detection Tests (real remoteid.cpp)\n");
    printf("============================================================\n");

    // ───────────────────────────────────────────────────────
    SECTION("1. Basic ID parsing");
    {
    rid_reset();
    RemoteIdTrack t; memset(&t,0,sizeof(t));
    auto m = msgBasicId("1596F3AB12345678", 1, 2);
    ASSERT(rid_parseMessage(m.data(), &t), "Basic ID message accepted");
    ASSERT(strcmp(t.uasId,"1596F3AB12345678")==0, "UAS ID extracted");
    ASSERT_EQ(t.idType, 1, "ID type extracted");
    ASSERT_EQ(t.uaType, 2, "UA type extracted (rotorcraft)");
    ASSERT(strcmp(rid_uaTypeName(2),"Rotorcraft")==0, "UA type name maps");
    }

    SECTION("2. Location parsing — position, altitude, heading, speed");
    {
    RemoteIdTrack t; memset(&t,0,sizeof(t));
    auto m = msgLocation(37.7749, -122.4194, 120, 40, 90);
    ASSERT(rid_parseMessage(m.data(), &t), "Location message accepted");
    ASSERT(t.hasPosition, "hasPosition set");
    ASSERT_NEAR(t.lat, 37.7749, 1e-6, "Latitude decoded");
    ASSERT_NEAR(t.lon, -122.4194, 1e-6, "Longitude decoded (negative)");
    ASSERT_EQ(t.altGeoM, 120, "Geodetic altitude decoded (0.5m units, -1000 offset)");
    ASSERT_EQ(t.headingDeg, 90, "Heading decoded");
    ASSERT_EQ(t.speedCms, 40*25, "Speed decoded at 0.25 m/s multiplier");
    }

    SECTION("2b. Location edge cases");
    {
    // E/W direction bit adds 180 degrees
    RemoteIdTrack t; memset(&t,0,sizeof(t));
    auto m = msgLocation(1.0, 1.0, 0, 10, 100, /*ewDir*/true);
    rid_parseMessage(m.data(), &t);
    ASSERT_EQ(t.headingDeg, 280, "E/W direction bit adds 180 to heading");

    // Speed multiplier 1
    RemoteIdTrack t2; memset(&t2,0,sizeof(t2));
    auto m2 = msgLocation(1.0, 1.0, 0, 10, 0, false, /*speedMult*/true);
    rid_parseMessage(m2.data(), &t2);
    ASSERT_EQ(t2.speedCms, 10*75 + 255*25, "High-speed multiplier encoding");

    // (0,0) is 'unknown', not the Gulf of Guinea
    RemoteIdTrack t3; memset(&t3,0,sizeof(t3));
    auto m3 = msgLocation(0.0, 0.0, 50);
    rid_parseMessage(m3.data(), &t3);
    ASSERT(!t3.hasPosition, "Zero coordinates treated as unknown, not a position");

    // Heading wrap
    RemoteIdTrack t4; memset(&t4,0,sizeof(t4));
    auto m4 = msgLocation(1.0,1.0,0, 10, 179, true);
    rid_parseMessage(m4.data(), &t4);
    ASSERT(t4.headingDeg <= 359, "Heading stays within 0-359 after E/W offset");
    }

    SECTION("3. System message — operator location (highest-value field)");
    {
    RemoteIdTrack t; memset(&t,0,sizeof(t));
    auto m = msgSystem(37.7700, -122.4100);
    ASSERT(rid_parseMessage(m.data(), &t), "System message accepted");
    ASSERT(t.hasOperator, "hasOperator set");
    ASSERT_NEAR(t.opLat, 37.7700, 1e-6, "Operator latitude decoded");
    ASSERT_NEAR(t.opLon, -122.4100, 1e-6, "Operator longitude decoded");
    }

    SECTION("4. Operator ID + field sanitisation");
    {
    RemoteIdTrack t; memset(&t,0,sizeof(t));
    auto m = msgOperatorId("FAA123456789");
    rid_parseMessage(m.data(), &t);
    ASSERT(strcmp(t.operatorId,"FAA123456789")==0, "Operator ID extracted");

    // Trailing spaces trimmed, non-printables dropped
    RemoteIdTrack t2; memset(&t2,0,sizeof(t2));
    auto m2 = msgBasicId("ABC123");
    m2[2+6]=' '; m2[2+7]=' '; m2[2+8]=0x07;   // spaces then a bell char
    rid_parseMessage(m2.data(), &t2);
    ASSERT(strcmp(t2.uasId,"ABC123")==0, "Trailing spaces trimmed, control chars dropped");

    // A fully non-printable ID must not produce garbage
    RemoteIdTrack t3; memset(&t3,0,sizeof(t3));
    std::vector<uint8_t> m3(25,0);
    m3[0]=(uint8_t)(RID_MSG_BASIC_ID<<4); m3[1]=0x12;
    for (int i=0;i<20;i++) m3[2+i]=(uint8_t)(0x80+i);
    rid_parseMessage(m3.data(), &t3);
    ASSERT(t3.uasId[0]=='\0', "All-non-printable ID yields empty string, not garbage");
    }

    SECTION("5. Message Pack");
    {
    RemoteIdTrack t; memset(&t,0,sizeof(t));
    auto pack = msgPack({ msgBasicId("PACK001"), msgLocation(51.5,-0.12,80), msgSystem(51.49,-0.11) });
    int n = rid_parsePayload(pack.data(), (uint16_t)pack.size(), &t);
    ASSERT_EQ(n, 3, "All three packed messages applied");
    ASSERT(strcmp(t.uasId,"PACK001")==0, "ID from pack");
    ASSERT(t.hasPosition, "Position from pack");
    ASSERT(t.hasOperator, "Operator location from pack");
    }

    SECTION("5b. Malformed input must be rejected safely (attacker-controlled)");
    {
    RemoteIdTrack t; memset(&t,0,sizeof(t));
    // Truncated single message
    uint8_t shortMsg[10] = {0x00};
    ASSERT_EQ(rid_parsePayload(shortMsg, 10, &t), 0, "Message shorter than 25 bytes rejected");

    // Pack claiming more messages than the buffer holds
    auto pack = msgPack({ msgBasicId("X") });
    pack[2] = 9;   // claim 9 messages, only 1 present
    ASSERT_EQ(rid_parsePayload(pack.data(), (uint16_t)pack.size(), &t), 0,
              "Pack with count exceeding buffer rejected (no overread)");

    // Pack with absurd count
    auto pack2 = msgPack({ msgBasicId("Y") });
    pack2[2] = 255;
    ASSERT_EQ(rid_parsePayload(pack2.data(), (uint16_t)pack2.size(), &t), 0,
              "Pack with count above RID_MAX_PACK_MSGS rejected");

    // Pack with wrong message size
    auto pack3 = msgPack({ msgBasicId("Z") });
    pack3[1] = 30;
    ASSERT_EQ(rid_parsePayload(pack3.data(), (uint16_t)pack3.size(), &t), 0,
              "Pack with non-25 message size rejected");

    // Nulls and zero length
    ASSERT_EQ(rid_parsePayload(nullptr, 25, &t), 0, "Null payload rejected");
    ASSERT_EQ(rid_parsePayload(pack.data(), 0, &t), 0, "Zero-length payload rejected");
    ASSERT(!rid_parseMessage(nullptr, &t), "Null message rejected");

    // Unknown message type
    std::vector<uint8_t> unk(25,0); unk[0] = (uint8_t)(0x9 << 4);
    ASSERT(!rid_parseMessage(unk.data(), &t), "Unknown message type rejected");
    }

    // ───────────────────────────────────────────────────────
    SECTION("6. BLE advertisement extraction");
    {
    auto pack = msgPack({ msgBasicId("BLE001"), msgLocation(40.0,-74.0,100) });
    auto adv = wrapBle(pack);
    uint16_t off = 0;
    uint16_t len = rid_extractFromBleAdv(adv.data(), (uint16_t)adv.size(), &off);
    ASSERT(len > 0, "ASTM service data located in BLE advert");
    ASSERT_EQ(len, pack.size(), "Extracted length matches payload");
    ASSERT(memcmp(adv.data()+off, pack.data(), pack.size())==0, "Extracted bytes match payload");

    // Non-ASTM advert must not match
    uint8_t other[] = { 0x05, 0x16, 0xAA, 0xBB, 0x01, 0x02 };
    off = 0;
    ASSERT_EQ(rid_extractFromBleAdv(other, sizeof(other), &off), 0, "Non-ASTM UUID ignored");

    // Truncated AD structure must not overread
    auto trunc = adv; trunc[0] = 200;
    off = 0;
    ASSERT_EQ(rid_extractFromBleAdv(trunc.data(), (uint16_t)trunc.size(), &off), 0,
              "AD length beyond buffer rejected");

    // Zero-length AD terminator
    uint8_t zeroAd[] = { 0x00, 0x16, 0xFA, 0xFF };
    off = 0;
    ASSERT_EQ(rid_extractFromBleAdv(zeroAd, sizeof(zeroAd), &off), 0, "Zero AD length terminates safely");
    ASSERT_EQ(rid_extractFromBleAdv(nullptr, 10, &off), 0, "Null advert rejected");
    }

    SECTION("7. WiFi beacon vendor IE extraction");
    {
    auto pack = msgPack({ msgBasicId("WIFI001"), msgLocation(48.85,2.35,150) });
    auto ie = wrapBeaconIe(pack);
    uint16_t off = 0;
    uint16_t len = rid_extractFromBeaconIe(ie.data(), (uint16_t)ie.size(), &off);
    ASSERT(len > 0, "ASTM vendor IE located in beacon");
    ASSERT_EQ(len, pack.size(), "Extracted length matches payload");
    ASSERT(memcmp(ie.data()+off, pack.data(), pack.size())==0, "Extracted bytes match payload");

    // IE preceded by other IEs (realistic beacon)
    std::vector<uint8_t> multi = { 0x00, 0x04, 'T','e','s','t',   // SSID
                                   0x01, 0x02, 0x82, 0x84 };      // rates
    multi.insert(multi.end(), ie.begin(), ie.end());
    off = 0;
    ASSERT(rid_extractFromBeaconIe(multi.data(), (uint16_t)multi.size(), &off) > 0,
           "ASTM IE found after other IEs");

    // Wrong OUI
    auto badOui = ie; badOui[2] = 0x00;
    off = 0;
    ASSERT_EQ(rid_extractFromBeaconIe(badOui.data(), (uint16_t)badOui.size(), &off), 0,
              "Non-ASTM OUI ignored");

    // IE length beyond buffer
    auto trunc = ie; trunc[1] = 250;
    off = 0;
    ASSERT_EQ(rid_extractFromBeaconIe(trunc.data(), (uint16_t)trunc.size(), &off), 0,
              "IE length beyond buffer rejected");
    }

    // ───────────────────────────────────────────────────────
    SECTION("8. Ring buffer — bounded, drops on full, never blocks");
    {
    RidRing r; rid_ringInit(&r);
    uint8_t d[32]; memset(d, 0xAB, sizeof(d));

    int pushed = 0;
    for (int i = 0; i < RID_RING_SLOTS + 5; i++)
        if (rid_ringPush(&r, d, sizeof(d), RID_TRANSPORT_BLE_LEGACY, -60)) pushed++;
    ASSERT_EQ(pushed, RID_RING_SLOTS - 1, "Capacity is slots-1 (one slot reserved to distinguish full/empty)");
    ASSERT(rid_ringDropped(&r) > 0, "Overflow counted as dropped, not overwritten");

    RidRingSlot s;
    int popped = 0;
    while (rid_ringPop(&r, &s)) { popped++; ASSERT_EQ(s.len, sizeof(d), "Slot length preserved"); break; }
    ASSERT(popped == 1, "Pop returns a slot");
    while (rid_ringPop(&r, &s)) {}
    ASSERT(!rid_ringPop(&r, &s), "Pop on empty returns false");

    // Oversize payload is clamped, not overflowed
    rid_ringInit(&r);
    uint8_t big[RID_RING_SLOT_BYTES + 100]; memset(big, 0x5A, sizeof(big));
    ASSERT(rid_ringPush(&r, big, sizeof(big), RID_TRANSPORT_WIFI_BEACON, -70), "Oversize push accepted");
    rid_ringPop(&r, &s);
    ASSERT_EQ(s.len, RID_RING_SLOT_BYTES, "Oversize payload clamped to slot size");
    ASSERT(!rid_ringPush(nullptr, d, 4, 0, 0), "Null ring rejected");
    ASSERT(!rid_ringPush(&r, nullptr, 4, 0, 0), "Null data rejected");
    }

    // ───────────────────────────────────────────────────────
    SECTION("9. Track table — ingest, merge, dedup across transports");
    {
    rid_reset();
    uint32_t now = 100000;

    auto pack = msgPack({ msgBasicId("TRK001"), msgLocation(37.0,-122.0,100) });
    int idx = rid_processPayload(pack.data(), (uint16_t)pack.size(),
                                 RID_TRANSPORT_BLE_LEGACY, -65, now);
    ASSERT(idx >= 0, "Payload ingested to a track slot");
    ASSERT_EQ(rid_trackCount(), 1, "One track");

    const RemoteIdTrack* t = rid_getTrack(idx);
    ASSERT(t && strcmp(t->uasId,"TRK001")==0, "Track keyed by UAS ID");
    ASSERT_EQ(t->rssi, -65, "RSSI recorded");
    ASSERT(t->transportMask & (1u<<RID_TRANSPORT_BLE_LEGACY), "BLE transport recorded");

    // Same drone on WiFi — must merge, not duplicate
    int idx2 = rid_processPayload(pack.data(), (uint16_t)pack.size(),
                                  RID_TRANSPORT_WIFI_BEACON, -55, now+1000);
    ASSERT_EQ(idx2, idx, "Same UAS ID on a second transport merges into one track");
    ASSERT_EQ(rid_trackCount(), 1, "Still one track (deduplicated)");
    t = rid_getTrack(idx);
    ASSERT(t->transportMask & (1u<<RID_TRANSPORT_WIFI_BEACON), "WiFi transport also recorded");
    ASSERT_EQ(t->msgCount, 2, "Message count incremented");

    // A Location-only update must not erase a previously learned operator position
    auto sysOnly = msgPack({ msgBasicId("TRK001"), msgSystem(36.9,-121.9) });
    rid_processPayload(sysOnly.data(), (uint16_t)sysOnly.size(), RID_TRANSPORT_BLE_LEGACY, -60, now+2000);
    t = rid_getTrack(idx);
    ASSERT(t->hasOperator, "Operator position learned");
    auto locOnly = msgPack({ msgBasicId("TRK001"), msgLocation(37.1,-122.1,110) });
    rid_processPayload(locOnly.data(), (uint16_t)locOnly.size(), RID_TRANSPORT_BLE_LEGACY, -60, now+3000);
    t = rid_getTrack(idx);
    ASSERT(t->hasOperator, "Operator position RETAINED after a location-only update");
    ASSERT_NEAR(t->opLat, 36.9, 1e-6, "Operator latitude retained");
    ASSERT_NEAR(t->lat, 37.1, 1e-6, "Aircraft position updated");
    }

    SECTION("9b. Track without a UAS ID is not ingested");
    {
    rid_reset();
    auto locOnly = msgLocation(37.0,-122.0,100);
    int idx = rid_processPayload(locOnly.data(), (uint16_t)locOnly.size(),
                                 RID_TRANSPORT_BLE_LEGACY, -60, 1000);
    ASSERT(idx < 0, "Location-only payload with no ID is rejected (uncorrelatable)");
    ASSERT_EQ(rid_trackCount(), 0, "No track created");
    }

    SECTION("10. Track table — capacity and LRU eviction");
    {
    rid_reset();
    for (int i = 0; i < RID_MAX_TRACKS; i++) {
        char id[16]; snprintf(id,sizeof(id),"DRONE%03d", i);
        auto p = msgPack({ msgBasicId(id) });
        rid_processPayload(p.data(), (uint16_t)p.size(), RID_TRANSPORT_BLE_LEGACY, -60,
                           1000 + (uint32_t)i*100);
    }
    ASSERT_EQ(rid_trackCount(), RID_MAX_TRACKS, "Table fills to capacity");

    // One more must evict the least recently seen (DRONE000)
    auto extra = msgPack({ msgBasicId("NEWEST") });
    rid_processPayload(extra.data(), (uint16_t)extra.size(), RID_TRANSPORT_BLE_LEGACY, -60, 99999);
    ASSERT_EQ(rid_trackCount(), RID_MAX_TRACKS, "Capacity not exceeded");
    ASSERT(rid_findByUasId("NEWEST") != nullptr, "Newest track present");
    ASSERT(rid_findByUasId("DRONE000") == nullptr, "Least-recently-seen track evicted (LRU)");
    ASSERT(rid_findByUasId("DRONE015") != nullptr, "Recently seen track retained");
    }

    SECTION("11. Ageing — stale vs expired");
    {
    rid_reset();
    auto p = msgPack({ msgBasicId("AGE001") });
    uint32_t t0 = 1000000;
    rid_processPayload(p.data(), (uint16_t)p.size(), RID_TRANSPORT_BLE_LEGACY, -60, t0);
    ASSERT_EQ(rid_activeTrackCount(t0), 1, "Fresh track counts as active");
    ASSERT_EQ(rid_activeTrackCount(t0 + RID_STALE_MS + 1), 0, "Track goes stale after RID_STALE_MS");
    ASSERT_EQ(rid_trackCount(), 1, "Stale track still occupies its slot");

    rid_ageTracks(t0 + RID_EXPIRE_MS + 1);
    ASSERT_EQ(rid_trackCount(), 0, "Track released after RID_EXPIRE_MS");

    // Clock rollback must not underflow into mass expiry
    rid_reset();
    rid_processPayload(p.data(), (uint16_t)p.size(), RID_TRANSPORT_BLE_LEGACY, -60, 5000000);
    rid_ageTracks(1000);      // now < lastSeen
    ASSERT_EQ(rid_trackCount(), 1, "Clock rollback does not expire tracks");
    }

    // ───────────────────────────────────────────────────────
    SECTION("12. Fusion / alert levels (decision D)");
    {
    rid_reset();
    uint32_t now = 200000;
    ASSERT_EQ(rid_alertLevel(false, now), RID_ALERT_NONE, "No detections -> NONE");
    ASSERT_EQ(rid_alertLevel(true,  now), RID_ALERT_NO_RID,
              "900 MHz hit with NO Remote ID -> NO_RID (highest interest)");

    auto p = msgPack({ msgBasicId("FUSE001"), msgLocation(37.0,-122.0,100) });
    rid_processPayload(p.data(), (uint16_t)p.size(), RID_TRANSPORT_BLE_LEGACY, -60, now);
    ASSERT_EQ(rid_alertLevel(false, now), RID_ALERT_RID_ONLY, "Remote ID only -> RID_ONLY");
    ASSERT_EQ(rid_alertLevel(true,  now), RID_ALERT_CORRELATED, "Both sources -> CORRELATED");

    rid_correlate900(true, now);
    ASSERT(rid_getTrack(0)->correlated900, "Fresh track marked correlated");
    rid_correlate900(false, now);
    ASSERT(!rid_getTrack(0)->correlated900, "Correlation cleared when 900 MHz detection ends");

    // A stale track must not be treated as corroborating evidence
    rid_correlate900(true, now + RID_STALE_MS + 1);
    ASSERT(!rid_getTrack(0)->correlated900, "Stale track not marked correlated");
    ASSERT_EQ(rid_alertLevel(true, now + RID_STALE_MS + 1), RID_ALERT_NO_RID,
              "900 MHz hit with only a STALE Remote ID track -> NO_RID");
    }

    // ───────────────────────────────────────────────────────
    SECTION("13. Detection source selection (decision A: 900 MHz default)");
    {
    rid_reset();
    ASSERT_EQ(rid_getSource(), RID_SRC_900, "Default source is 900 MHz (opt-in Remote ID)");
    ASSERT(rid_sourceUses900(RID_SRC_900), "900 source uses SX1262");
    ASSERT(!rid_sourceUsesRemoteId(RID_SRC_900), "900 source does not use 2.4 GHz");

    rid_setSource(RID_SRC_REMOTEID);
    ASSERT_EQ(rid_getSource(), RID_SRC_REMOTEID, "Source set to Remote ID");
    ASSERT(rid_sourceUsesRemoteId(RID_SRC_REMOTEID), "Remote ID source uses 2.4 GHz");
    ASSERT(!rid_sourceUses900(RID_SRC_REMOTEID), "Remote ID source does not use SX1262");

    rid_setSource(RID_SRC_BOTH);
    ASSERT(rid_sourceUses900(RID_SRC_BOTH) && rid_sourceUsesRemoteId(RID_SRC_BOTH),
           "Both source uses each radio");

    rid_setSource(99);
    ASSERT_EQ(rid_getSource(), RID_SRC_BOTH, "Out-of-range source rejected, previous retained");
    ASSERT(strcmp(rid_sourceName(RID_SRC_BOTH),"Both")==0, "Source name maps");
    }

    // ───────────────────────────────────────────────────────
    SECTION("14. Mesh alert rate limiting (decision C)");
    {
    rid_reset();
    uint32_t now = 500000;
    auto p = msgPack({ msgBasicId("ALERT01"), msgLocation(37.0,-122.0,100) });
    int idx = rid_processPayload(p.data(), (uint16_t)p.size(), RID_TRANSPORT_BLE_LEGACY, -60, now);

    ASSERT(rid_shouldSendAlert(idx, now), "New track triggers an alert");
    rid_markAlertSent(idx, now);
    ASSERT(!rid_shouldSendAlert(idx, now + 1000), "Immediate re-alert suppressed");
    ASSERT(!rid_shouldSendAlert(idx, now + RID_ALERT_MIN_INTERVAL_MS - 1),
           "Suppressed for the whole minimum interval");

    // Past the interval but stationary -> still suppressed
    ASSERT(!rid_shouldSendAlert(idx, now + RID_ALERT_MIN_INTERVAL_MS + 1),
           "Past interval but stationary -> no alert (airtime discipline)");

    // Significant movement -> alert
    auto moved = msgPack({ msgBasicId("ALERT01"), msgLocation(37.01,-122.0,100) });  // ~1.1 km
    rid_processPayload(moved.data(), (uint16_t)moved.size(), RID_TRANSPORT_BLE_LEGACY, -60,
                       now + RID_ALERT_MIN_INTERVAL_MS + 2);
    ASSERT(rid_shouldSendAlert(idx, now + RID_ALERT_MIN_INTERVAL_MS + 2),
           "Significant movement past the interval triggers an alert");

    ASSERT(!rid_shouldSendAlert(-1, now), "Invalid index rejected");
    ASSERT(!rid_shouldSendAlert(RID_MAX_TRACKS, now), "Out-of-range index rejected");
    }

    // ───────────────────────────────────────────────────────
    SECTION("15. Duty cycle accounting (decision B: honest indicator)");
    {
    rid_reset();
    rid_dutySetRequested(5000, 20000);
    ASSERT_EQ(rid_dutyRequestedPct(), 25, "Requested duty cycle computed (5s in 20s)");
    ASSERT_EQ(rid_dutyAchievedPct(), 0, "No achieved figure before any measurement");

    // Simulate the tablet-connected case: only 2s of the requested 5s achieved
    for (int i = 0; i < 10; i++) rid_dutyRecord(2000, 20000);
    ASSERT_EQ(rid_dutyAchievedPct(), 10, "Achieved duty cycle reflects the shortfall (10%, not 25%)");
    ASSERT(rid_dutyAchievedPct() < rid_dutyRequestedPct(),
           "Achieved is visibly below requested — the shortfall is surfaced, not hidden");

    rid_dutySetRequested(5000, 0);
    ASSERT_EQ(rid_dutyRequestedPct(), 0, "Zero period handled without division by zero");
    }

    // ───────────────────────────────────────────────────────
    SECTION("16. Helpers");
    {
    // SF to Oakland ~ 13 km
    double d = rid_haversineM(37.7749,-122.4194, 37.8044,-122.2712);
    ASSERT(d > 12000 && d < 15000, "Haversine distance plausible for a known pair");
    ASSERT_NEAR(rid_haversineM(37.0,-122.0,37.0,-122.0), 0.0, 0.01, "Zero distance for identical points");
    ASSERT(strcmp(rid_transportName(RID_TRANSPORT_WIFI_BEACON),"WiFi-B")==0, "Transport name maps");
    ASSERT(rid_getTrack(-1)==nullptr && rid_getTrack(RID_MAX_TRACKS)==nullptr,
           "Out-of-range track index returns null");
    ASSERT(rid_findByUasId(nullptr)==nullptr, "Null UAS ID lookup safe");
    ASSERT(rid_findByUasId("")==nullptr, "Empty UAS ID lookup safe");
    }

    // ───────────────────────────────────────────────────────
    SECTION("17. End-to-end: BLE advert -> track with operator location");
    {
    rid_reset();
    uint32_t now = 900000;
    auto pack = msgPack({ msgBasicId("E2E-DRONE-01",1,2),
                          msgLocation(51.5074,-0.1278,150,60,45),
                          msgSystem(51.5060,-0.1250),
                          msgOperatorId("GBR-OP-9911") });
    auto adv = wrapBle(pack);

    uint16_t off = 0;
    uint16_t len = rid_extractFromBleAdv(adv.data(), (uint16_t)adv.size(), &off);
    ASSERT(len > 0, "Payload extracted from BLE advert");
    int idx = rid_processPayload(adv.data()+off, len, RID_TRANSPORT_BLE_LEGACY, -58, now);
    ASSERT(idx >= 0, "Track created from a realistic advert");

    const RemoteIdTrack* t = rid_getTrack(idx);
    ASSERT(strcmp(t->uasId,"E2E-DRONE-01")==0, "UAS ID correct end-to-end");
    ASSERT(strcmp(t->operatorId,"GBR-OP-9911")==0, "Operator ID correct end-to-end");
    ASSERT_NEAR(t->lat, 51.5074, 1e-6, "Aircraft latitude correct end-to-end");
    ASSERT(t->hasOperator, "Operator location present end-to-end");
    ASSERT_NEAR(t->opLat, 51.5060, 1e-6, "Operator latitude correct end-to-end");
    ASSERT_EQ(t->altGeoM, 150, "Altitude correct end-to-end");
    ASSERT_EQ(t->uaType, 2, "UA type correct end-to-end");

    // Distance from operator to aircraft is plausible
    double sep = rid_haversineM(t->lat,t->lon,t->opLat,t->opLon);
    ASSERT(sep > 100 && sep < 5000, "Operator-to-aircraft separation plausible");
    }

    SECTION("18. End-to-end: WiFi beacon -> track, merged with the BLE track");
    {
    // Continues from section 17 state — same drone, other transport
    uint32_t now = 901000;
    auto pack = msgPack({ msgBasicId("E2E-DRONE-01",1,2), msgLocation(51.5080,-0.1280,160) });
    auto ie = wrapBeaconIe(pack);
    uint16_t off = 0;
    uint16_t len = rid_extractFromBeaconIe(ie.data(), (uint16_t)ie.size(), &off);
    ASSERT(len > 0, "Payload extracted from beacon IE");
    int idx = rid_processPayload(ie.data()+off, len, RID_TRANSPORT_WIFI_BEACON, -49, now);
    ASSERT(idx >= 0, "Beacon observation ingested");
    ASSERT_EQ(rid_trackCount(), 1, "Still one track — WiFi and BLE deduplicated");

    const RemoteIdTrack* t = rid_getTrack(idx);
    ASSERT((t->transportMask & (1u<<RID_TRANSPORT_BLE_LEGACY)) &&
           (t->transportMask & (1u<<RID_TRANSPORT_WIFI_BEACON)),
           "Both transports recorded on the single track");
    ASSERT(t->hasOperator, "Operator location retained across transports");
    ASSERT_EQ(t->altGeoM, 160, "Latest altitude applied");
    }

    printf("\n============================================================\n");
    printf("  Results: %d/%d passed\n", passed, passed + failed);
    printf("============================================================\n");
    if (failed) { printf("\nFailures:\n"); for (auto& f : failures) printf("  - %s\n", f.c_str()); }
    return failed ? 1 : 0;
}
