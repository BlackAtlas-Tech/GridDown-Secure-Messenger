// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * GridDown T-Deck Standalone UI
 * 
 * Handles the 2.8" TFT display, physical keyboard, GPS module,
 * and local message storage for standalone operation without tablet.
 * 
 * When WiFi-connected to GridDown: acts as display/input device.
 * When standalone: shows received messages, allows composing,
 * queues outgoing messages for radio TX.
 */
#include "ui.h"
#include <TFT_eSPI.h>
#include <Wire.h>
#include <math.h>
#include <LittleFS.h>
#include <FS.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <codec2.h>
#include "soc/rtc_cntl_reg.h"  // For bootloader mode (RTC_CNTL_FORCE_DOWNLOAD_BOOT)
#include "esp_system.h"         // esp_reset_reason()
#include "mbedtls/ecdh.h"       // ECDH key exchange (P-256)
#include "mbedtls/ecp.h"        // Elliptic curve point operations
// Hoisted so code appearing earlier in this file than the PSK crypto block
// (duress PIN hashing, FHOP key derivation) can use these. Duplicate includes
// further down are no-ops (header guards).
#include "mbedtls/md.h"         // HMAC-SHA256 (duress hashing, HKDF)
#include "mbedtls/sha256.h"     // SHA-256
#include "esp_random.h"         // esp_fill_random (salts, AP password)
#include "remoteid.h"           // Remote ID detection: source selector + tracks

// Remote ID platform glue lives in main.cpp
extern bool     rid_isWatchdogTripped(void);
extern void     rid_clearWatchdog(void);
extern uint32_t rid_ringDroppedCount(void);
extern uint32_t rid_parsedCount(void);
using fs::File;

#ifndef NO_GPS
#include <TinyGPSPlus.h>
#endif

// Forward declarations
static void _saveMessages();
static void _flashNotification(const char* from, const char* text);
static void _drawButton(int x, int y, int w, int h, const char* label, uint16_t bg, uint16_t fg);
static void _drawSignalQuality(int x, int y);

// ═══════════════════════════════════════════════════════════
// HARDWARE
// ═══════════════════════════════════════════════════════════

static TFT_eSPI tft = TFT_eSPI();

// Screen dimensions (set at init from TFT, needed early for touch clamping)
static int scrW = 320;
static int scrH = 240;

#ifndef NO_GPS
static TinyGPSPlus gps;
static HardwareSerial gpsSerial(1);
#endif

// ═══════════════════════════════════════════════════════════
// TOUCH (GT911 — pure I2C polling, no INT pin dependency)
// Meshtastic found T-Deck GT911 INT is unreliable (pulses instead of latching).
// Solution: poll status register directly via I2C at 400kHz.
// ═══════════════════════════════════════════════════════════

#ifndef NO_KEYBOARD
static uint8_t touchAddr = 0;
static int16_t touchX = -1, touchY = -1;
static bool touchPressed = false;
static uint32_t lastTouchTime = 0;
static uint16_t gt911_xRes = 320;  // Read from GT911 config
static uint16_t gt911_yRes = 240;

// Read a 16-bit register from GT911 (big-endian register address)
static bool _gt911ReadReg(uint16_t reg, uint8_t* buf, uint8_t len) {
    Wire.beginTransmission(touchAddr);
    Wire.write(reg >> 8);
    Wire.write(reg & 0xFF);
    if (Wire.endTransmission(false) != 0) return false;
    Wire.requestFrom(touchAddr, len);
    for (uint8_t i = 0; i < len && Wire.available(); i++) {
        buf[i] = Wire.read();
    }
    return true;
}

static bool _touchInit() {
    const uint8_t addrs[] = { 0x5D, 0x14 };
    
    // Debug: scan I2C bus
    Serial.print("[Touch] I2C scan: ");
    for (uint8_t addr = 1; addr < 127; addr++) {
        Wire.beginTransmission(addr);
        if (Wire.endTransmission() == 0) Serial.printf("0x%02X ", addr);
    }
    Serial.println();
    
    // Find GT911
    for (int attempt = 0; attempt < 3; attempt++) {
        for (int i = 0; i < 2; i++) {
            Wire.beginTransmission(addrs[i]);
            if (Wire.endTransmission() == 0) {
                touchAddr = addrs[i];
                Serial.printf("[Touch] GT911 at 0x%02X (attempt %d)\n", touchAddr, attempt);
                
                // Read product ID (0x8140, 4 bytes)
                uint8_t pid[5] = {0};
                _gt911ReadReg(0x8140, pid, 4);
                Serial.printf("[Touch] Product ID: '%s'\n", pid);
                
                // Read configured resolution (0x8048-0x804B)
                uint8_t resCfg[4] = {0};
                _gt911ReadReg(0x8048, resCfg, 4);
                gt911_xRes = resCfg[0] | (resCfg[1] << 8);
                gt911_yRes = resCfg[2] | (resCfg[3] << 8);
                Serial.printf("[Touch] GT911 resolution: %dx%d\n", gt911_xRes, gt911_yRes);
                
                // If resolution is 0 or unreasonable, set defaults
                if (gt911_xRes == 0 || gt911_xRes > 4096) gt911_xRes = 320;
                if (gt911_yRes == 0 || gt911_yRes > 4096) gt911_yRes = 240;
                
                return true;
            }
        }
        delay(50);
    }
    
    Serial.println("[Touch] GT911 not found");
    return false;
}

static bool _touchRead() {
    if (touchAddr == 0) return false;
    
    // Read status register 0x814E
    uint8_t status = 0;
    _gt911ReadReg(0x814E, &status, 1);
    
    uint8_t touches = status & 0x0F;
    bool bufReady = (status & 0x80) != 0;
    
    // Always clear buffer status
    Wire.beginTransmission(touchAddr);
    Wire.write(0x81); Wire.write(0x4E); Wire.write(0x00);
    Wire.endTransmission();
    
    if (!bufReady || touches == 0 || touches > 5) {
        touchPressed = false;
        return false;
    }
    
    // Read first touch point at 0x8150
    uint8_t tp[7] = {0};
    _gt911ReadReg(0x8150, tp, 7);
    
    // CYPHER M8K GT911: no track ID prefix — data starts at tp[0]
    // Format: [xLow, xHigh, yLow, yHigh, ...]
    uint16_t gx = tp[0] | (tp[1] << 8);  // GT911 X (portrait)
    uint16_t gy = tp[2] | (tp[3] << 8);  // GT911 Y (portrait)
    
    // Portrait (240x320) → Landscape (320x240) rotation:
    //   screen_x = gt911_y
    //   screen_y = gt911_xRes - gt911_x
    touchX = (int32_t)gy * scrW / gt911_yRes;
    touchY = scrH - 1 - ((int32_t)gx * scrH / gt911_xRes);
    
    // Clamp
    if (touchX < 0) touchX = 0;
    if (touchX >= scrW) touchX = scrW - 1;
    if (touchY < 0) touchY = 0;
    if (touchY >= scrH) touchY = scrH - 1;
    
    touchPressed = true;
    lastTouchTime = millis();
    
    Serial.printf("[Touch] portrait(%d,%d) → screen(%d,%d)\n", gx, gy, touchX, touchY);
    return true;
}
#endif // NO_KEYBOARD

// ═══════════════════════════════════════════════════════════
// TRACKBALL
// ═══════════════════════════════════════════════════════════

// Internal key codes for trackball (non-printable to avoid compose conflicts)
#define TB_UP    0x01
#define TB_DOWN  0x02
#define TB_LEFT  0x03
#define TB_RIGHT 0x04
#define TB_BACK  0x05  // Back button (non-printable)

#ifdef TRACKBALL_UP
static uint32_t lastTrackball = 0;
static uint8_t  prevTrackState[5] = {HIGH, HIGH, HIGH, HIGH, HIGH};
#define TRACKBALL_DEBOUNCE 200

static char _readTrackball() {
    if (millis() - lastTrackball < TRACKBALL_DEBOUNCE) return 0;
    
    // Edge detection: only trigger on HIGH→LOW transition
    const uint8_t pins[5] = {TRACKBALL_UP, TRACKBALL_DOWN, TRACKBALL_LEFT, TRACKBALL_RIGHT, TRACKBALL_CLICK};
    const char    keys[5] = {TB_UP, TB_DOWN, TB_LEFT, TB_RIGHT, '\n'};  // Internal codes, NOT printable
    
    for (int i = 0; i < 5; i++) {
        uint8_t cur = digitalRead(pins[i]);
        if (cur == LOW && prevTrackState[i] == HIGH) {
            prevTrackState[i] = cur;
            lastTrackball = millis();
            return keys[i];
        }
        prevTrackState[i] = cur;
    }
    return 0;
}
#endif

// ═══════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════

// Display sleep
static uint32_t lastActivityMs = 0;
static uint32_t dimTimeoutMs = 0;       // Auto-dim DISABLED — user controls brightness via Settings
static uint32_t offTimeoutMs = 0;       // Auto-off DISABLED
static uint8_t  backlightState = 2;     // 0=off, 1=dim, 2=full
#define BACKLIGHT_LEDC_CHANNEL 0
#define BACKLIGHT_FULL    255
#define BACKLIGHT_DIM     40

// Audio (I2S — initialized in _audioInit)
static bool audioInitialized = false;
static bool audioMuted = false;  // Persisted to LittleFS

// Keyboard backlight state (declared early for settings screen access)
static uint8_t kbBrightness = 0;

// Screen lock state
static bool screenLocked = false;
static uint32_t lockHoldStart = 0;  // millis() when unlock key started being held

// Screen brightness levels: Low(30), Med(80), High(160), Max(255)
static uint8_t brightnessLevel = 3;  // 0-3 index
static const uint8_t brightnessPresets[] = { 30, 80, 160, 255 };
static const char* brightnessNames[] = { "Low", "Med", "High", "Max" };

// Canned messages for quick replies
#define CANNED_MSG_COUNT 8
static const char* cannedMessages[CANNED_MSG_COUNT] = {
    "Copy",
    "Negative",
    "En route",
    "All clear",
    "Need assist",
    "Rally point",
    "Hold position",
    "BREAK BREAK"
};
static int cannedMsgSelected = -1;  // -1 = not in canned mode

// Peer detail screen state
static int peerScrollIdx = 0;       // Which peer is selected/highlighted
static bool peerHealthView = false; // H key toggles health dashboard view

// Emergency broadcast state (hold 'E' for 2s from any screen, even locked)
static uint32_t emergencyHoldStart = 0;

// Microphone state (declared early for status screen access)
static bool micInitialized = false;

// Codec2 state (declared early for status screen access)
static bool codec2Ready = false;

// Voice quality mode (persisted to LittleFS)
static VoiceMode voiceMode = VMODE_RANGE;
static const char* voiceModeNames[] = { "Range", "Balanced", "Clarity" };
static const char* voiceModeBitrates[] = { "1600", "3200", "3200" };

// Returns the voice packet marker byte for the currently active codec mode
static inline uint8_t _voiceActiveMarker() {
    return (voiceMode == VMODE_RANGE) ? VOICE_MARKER_1600 : VOICE_MARKER_3200;
}

// Voice activity log (last 5 voice events for Voice screen)
#define VOICE_LOG_SIZE 5
struct VoiceLogEntry {
    char callsign[16];
    float rssi;
    float duration;    // seconds
    uint32_t timestamp; // millis()
    bool outgoing;
};
static VoiceLogEntry voiceLog[VOICE_LOG_SIZE];
static int voiceLogCount = 0;

static void _addVoiceLog(const char* callsign, float rssi, float duration, bool outgoing) {
    // Shift entries down
    if (voiceLogCount < VOICE_LOG_SIZE) voiceLogCount++;
    for (int i = voiceLogCount - 1; i > 0; i--) voiceLog[i] = voiceLog[i-1];
    // Add new at top
    strncpy(voiceLog[0].callsign, callsign, 15);
    voiceLog[0].callsign[15] = '\0';
    voiceLog[0].rssi = rssi;
    voiceLog[0].duration = duration;
    voiceLog[0].timestamp = millis();
    voiceLog[0].outgoing = outgoing;
}

// Voice target: who to send PTT to
// voiceTarget[0]=='\0' means broadcast to ALL
static char voiceTarget[16] = {0};
#define VOICE_RECORD_MS 10000 // Max recording ceiling (buffer is the real limit)

// Signal quality (updated from main.cpp)
static float sigRSSI = 0;
static float sigSNR = 0;
static uint32_t sigRxCount = 0;
static uint32_t sigTxCount = 0;
static uint32_t sigLastUpdate = 0;

// Battery history (30 readings = 5 min at 10s intervals)
#define BAT_HISTORY_SIZE 30
static uint8_t batHistory[BAT_HISTORY_SIZE] = {0};
static int batHistoryCount = 0;
static int batHistoryHead = 0;
static uint32_t lastBatRecord = 0;

// Confirmation modal state
static bool confirmPending = false;
static char confirmAction = 0;       // Key that triggered the confirmation
static char confirmText[64] = {0};   // Text shown in modal

// WiFi credential push prompt (from tablet via WebSocket)
static bool wifiCfgPending = false;
static char wifiCfgSSID[33] = {0};
static char wifiCfgPass[65] = {0};
static bool wifiCfgSwitch = false;
static uint8_t wifiCfgClient = 0;    // WebSocket client number for response

// Conversation (per-peer thread) state
static char convPeer[20] = {0};      // Which peer's thread is being viewed
static int convScrollOffset = 0;

// SD Card
#ifndef SD_CS
#define SD_CS 39
#endif
static bool sdMounted = false;

// Public accessor for image RX module and other consumers
bool sdCardMounted() { return sdMounted; }

// Phase 7: Image TX state accessors (defined in main.cpp).
// Used by Status screen and Images screen for progress display.
extern bool img_isTxActive();
extern uint8_t img_txProgress();
extern uint16_t img_txCurrentChunk();
extern uint16_t img_txTotalChunks();
extern uint8_t img_txRetryRound();
extern const char* img_txFilename();
extern size_t img_txTotalBytes();
extern uint16_t img_txEtaSeconds();
extern bool img_txCanCancel();
extern void img_cancelTx();
static int sdMsgCount = 0;
static int sdPktCount = 0;
static int sdTrackPts = 0;
static uint32_t lastGPSLog = 0;
static uint32_t gpsBaudRate = 0;  // Detected baud rate for display

// GPS-derived UTC epoch (seconds since 2000-01-01, updated when GPS time is valid)
// Used for message timestamps that survive reboots.
// 0 = no GPS time yet, use millis() fallback.
static uint32_t utcEpoch = 0;          // Last known UTC epoch seconds
static uint32_t utcEpochSyncMs = 0;    // millis() when utcEpoch was last synced

// Forward declarations — variables and functions defined later but referenced by draw functions
static void _sdTimestamp(char* buf, size_t len);
static SharedTrack tracks[TRACK_MAX];
static SharedWaypoint waypoints[WAYPOINT_MAX];
static int wpAutoCounter = 1;
static uint32_t proximityRadius = PROXIMITY_DEFAULT_M;
static bool     proximityEnabled = true;
static uint32_t proximityLastAlert[TRACK_MAX];
// gdEnabled and gdDetectionCount — moved here from Gunshot section
static bool     gdEnabled = true;          // Derived from gdSensitivity > 0
static uint32_t gdDetectionCount = 0;
static uint8_t  gdSensitivity = GD_SENS_HIGH;  // Default: High sensitivity
static const char* gdSensLabel[4] = { "OFF", "High", "Med", "Low" };
static const char* gdSensShort[4] = { "S:--", "S:Hi", "S:Md", "S:Lo" };
static bool     cotTakConfigured = false;  // Has a TAK server been set?
static uint8_t  cotMode = 0;              // 0=OFF, 1=Mcast, 2=TCP, 3=All
static bool     cotEnabled = false;       // Derived: cotMode > 0
static const char* cotModeLabel[4]  = { "OFF", "Multicast", "TAK Server", "All (MC+TCP)" };
static const char* cotModeShort[4]  = { "C:--", "MC", "TCP", "All" };
static int      settingsScroll = 0;
static int      mapCursorIdx = -1;  // Map screen target selection cursor

// ── Breadcrumb trail: circular buffer of own GPS positions ──
// Stores the last 64 positions for drawing a movement trail on the compass map.
// Updated every 5 seconds when GPS is valid. RAM-only — resets on reboot.
#define BREADCRUMB_MAX 64
struct Breadcrumb { double lat, lon; };
static Breadcrumb breadcrumbs[BREADCRUMB_MAX];
static int breadcrumbHead = 0;
static int breadcrumbCount = 0;
static uint32_t breadcrumbLastMs = 0;

// Get current UTC epoch (extrapolates from last GPS sync using millis delta)
static uint32_t _getUtcEpoch() {
    if (utcEpoch == 0) return 0;  // No GPS time yet
    return utcEpoch + (millis() - utcEpochSyncMs) / 1000;
}

uint32_t ui_getUtcEpoch() { return _getUtcEpoch(); }

// RF diagnostics for channel/PSK mismatch detection
static uint32_t rfLastRxAnyMs = 0;     // millis() of last raw LoRa packet (even undecryptable)
static uint32_t rfDecryptFails = 0;    // Count of packets that failed PSK decryption
static uint32_t rfLastDecryptFailMs = 0; // millis() of last decrypt failure
#define GPS_LOG_INTERVAL_MS 10000  // Log GPS every 10 seconds

// Boot diagnostics (crash recovery tracking)
static uint32_t bootCount = 0;         // Total boots since factory (persisted to LittleFS)
static char lastResetStr[16] = "N/A";  // Human-readable last reset reason

// Callsign (this device's identity for standalone mode)
static char myCallsign[16] = {0};  // Persisted to LittleFS

// PSK state (declared early so settings screen can reference)
static uint8_t pskKey[32] = {0};
static bool pskActive = false;
static char pskHint[8] = {0};

// Discovered peers (other T-Decks heard via beacons)
#define MAX_PEERS 16
struct Peer {
    char callsign[16];
    float lastRSSI;
    float lastSNR;          // SNR of last packet
    float rssiAvg;          // EMA of RSSI (smoothed)
    uint8_t lastHops;       // 0=direct, 1-2=relayed
    uint16_t rxCount;       // Packets received from this peer
    uint8_t linkQuality;    // 0-100% computed quality score
    uint32_t lastSeen;      // millis() when last heard
    bool active;
    double lat, lon;        // Last known GPS position (0,0 = unknown)
    bool hasPosition;
    uint8_t battery;        // Peer's last reported battery % (from beacon, 0 = unknown)
    // Ephemeral key agreement (ECDH P-256)
    uint8_t sessionKey[32]; // Derived per-pair AES-256 key
    bool hasSessionKey;     // true = ECDH completed, sessionKey valid
    uint8_t peerPubKey[65]; // Peer's P-256 uncompressed public key
    uint8_t peerPubKeyLen;  // 0 = no pubkey received yet
};
static Peer peers[MAX_PEERS];
static int peerCount = 0;

// ── Ephemeral ECDH state (P-256) ──
// Keypair generated fresh on every boot — provides forward secrecy
// (compromising a past session key doesn't help with future sessions)
static mbedtls_ecp_group ephGrp;
static mbedtls_mpi       ephPriv;
static mbedtls_ecp_point ephPub;
static bool              ephReady = false;
static uint8_t           ephPubBytes[65];  // Uncompressed: 0x04 || x(32) || y(32)
static size_t            ephPubLen = 0;

static void _voiceCycleTarget(int dir) {
    int curIdx = -1;
    for (int i = 0; i < peerCount; i++) {
        if (strcmp(peers[i].callsign, voiceTarget) == 0) { curIdx = i; break; }
    }
    curIdx += dir;
    if (curIdx < -1) curIdx = peerCount - 1;
    if (curIdx >= peerCount) curIdx = -1;
    
    if (curIdx < 0) {
        voiceTarget[0] = '\0';
    } else {
        strncpy(voiceTarget, peers[curIdx].callsign, 15);
        voiceTarget[15] = '\0';
    }
}

// Mesh relay — seen packet dedup ring buffer
#define MESH_SEEN_SIZE 64
struct SeenPacket {
    uint16_t pktId;
    char from[16];
    uint32_t timestamp;
};
static SeenPacket meshSeen[MESH_SEEN_SIZE];
static int meshSeenHead = 0;
static int meshRelayCount = 0;

// Store and forward — queued messages for offline peers
#define SNF_MAX_MESSAGES 16
#define SNF_EXPIRE_MS 1800000  // 30 minutes
#define SNF_MAX_PKT 255        // Max packet size
struct StoredMessage {
    uint8_t data[SNF_MAX_PKT];
    int len;
    char target[16];
    uint16_t msgId;             // For dedup — 0 = no ID (voice/broadcast)
    uint32_t storedAt;
    bool valid;
};
static StoredMessage snfQueue[SNF_MAX_MESSAGES];

static UIState uiState = {
    .currentScreen = SCREEN_STATUS,
    .scrollOffset = 0,
    .selectedIndex = 0,
    .composeBuffer = {0},
    .composeLen = 0,
    .selectedContact = -1,
    .dirty = true,
    .unreadCount = 0
};

// Channel selection (1-8, 2.5MHz apart: CH1=906.0 ... CH8=923.5)
static int currentChannel = 1;  // Persisted to LittleFS
#define CHANNEL_COUNT 8
static float _channelToFreq(int ch);  // Forward declaration

// Message ID counter for ACK tracking
static uint16_t nextMsgId = 1;

// Message storage (circular buffer in RAM, persisted to LittleFS)
#define MAX_MESSAGES 50
#define MAX_CONTACTS 16
static LocalMessage messages[MAX_MESSAGES];
static int msgCount = 0;
static int msgHead = 0;  // Write position

static Contact contacts[MAX_CONTACTS];
static int contactCount = 0;

// Composed message ready to send
static bool composeReady = false;
static bool clearPending = false;  // Message clear confirmation state
static bool threadView = false;    // Messages screen: false=flat, true=per-peer threads

// Group channels (logical channels within a PSK cluster)
static uint8_t activeGroupCh = GROUP_CH_GENERAL;  // Active channel for compose/filter
static bool    groupChFilter = false;              // true = filter messages screen to activeGroupCh
static const char* groupChNames[GROUP_CH_COUNT] = { "General", "Command", "Tactical", "Alerts" };
static const uint16_t groupChColors[GROUP_CH_COUNT] = {
    0x34DF,  // General: Blue (COLOR_ACCENT)
    0x07E0,  // Command: Green
    0xFD20,  // Tactical: Orange
    0xF800   // Alerts: Red
};

// Display colors
#define COLOR_BG       0x1082  // Dark navy (16,16,16)
#define COLOR_HEADER   0x2945  // Slightly lighter (41,40,41)
#define COLOR_TEXT     0xFFFF  // White
#define COLOR_DIM      0x9CF3  // Grey (156,156,156) — brightened for 5.35:1 on header
#define COLOR_ACCENT   0x34DF  // Blue (TEXT use — indicators, labels)
#define COLOR_BTN_ACCENT 0x1296 // Deep blue (BUTTON FILL — 7.42:1 with white text)
#define COLOR_SENT     0x2B6D  // Dark blue (outgoing msg)
#define COLOR_RECV     0x2124  // Dark grey (incoming msg)
#define COLOR_GREEN    0x07E0  // Lime green (TEXT use — indicators, status, peer quality)
#define COLOR_BTN_GREEN 0x03C0 // Deep green (BUTTON FILL — 5.70:1 with white text)
#define COLOR_RED      0xF800  // Red (TEXT use — alerts, errors, warnings)
#define COLOR_BTN_RED  0x9000  // Dark red (BUTTON FILL — 9.30:1 with white text)
#define COLOR_YELLOW   0xFFE0  // Yellow

// Keyboard state
static uint32_t lastKeyTime = 0;
#define KEY_DEBOUNCE_MS 80

// ═══════════════════════════════════════════════════════════
// KEYBOARD
// ═══════════════════════════════════════════════════════════

static char readKeyboard() {
#ifdef NO_KEYBOARD
    return 0;
#else
    Wire.requestFrom((uint8_t)KB_I2C_ADDR, (uint8_t)1);
    if (Wire.available()) {
        char c = Wire.read();
        if (c != 0 && (millis() - lastKeyTime) > KEY_DEBOUNCE_MS) {
            lastKeyTime = millis();
            return c;
        }
    }
    return 0;
#endif
}

// ═══════════════════════════════════════════════════════════
// GPS
// ═══════════════════════════════════════════════════════════

static void gps_init() {
#ifndef NO_GPS
    // ── NMEA validation helper ──
    // A real NMEA sentence starts with "$G" (e.g., $GNGGA, $GPGGA, $GNRMC, $GPRMC).
    // When reading 115200 baud data at 9600 baud, random bytes can produce a stray
    // 0x24 ('$') but the next byte will NOT be 'G' — it'll be garbage.
    // We require seeing "$G" followed by at least 3 more printable ASCII characters
    // to confirm real NMEA. This prevents false baud detection that permanently
    // breaks GPS by caching the wrong baud rate.
    //
    // Returns true if valid NMEA sentence start detected and drained into TinyGPS+.
    // The lambda captures gps and gpsSerial by reference from the enclosing scope.
    auto validateNMEA = [&](uint32_t timeoutMs) -> bool {
        uint32_t start = millis();
        int state = 0;     // 0=waiting for '$', 1=got '$' need 'G', 2=got '$G' need 3+ printable
        int printable = 0;
        while (millis() - start < timeoutMs) {
            if (!gpsSerial.available()) continue;
            char c = gpsSerial.read();
            gps.encode(c);
            switch (state) {
                case 0:
                    if (c == '$') state = 1;
                    break;
                case 1:
                    if (c == 'G') { state = 2; printable = 0; }
                    else state = 0;  // Reset — '$' not followed by 'G'
                    break;
                case 2:
                    if (c >= 'A' && c <= 'Z') printable++;
                    else state = 0;  // Non-alpha after $G — not NMEA
                    if (printable >= 3) {
                        // Confirmed NMEA sentence (e.g., "$GNGGA" or "$GPRMC")
                        // Drain remaining data into TinyGPS+ for 200ms
                        uint32_t drainStart = millis();
                        while (millis() - drainStart < 200) {
                            if (gpsSerial.available()) gps.encode(gpsSerial.read());
                        }
                        return true;
                    }
                    break;
            }
        }
        return false;
    };
    
    // Try persisted baud rate first (saves ~5s on normal reboot)
    File bf = LittleFS.open("/gpsbaud.cfg", "r");
    uint32_t savedBaud = 0;
    if (bf && bf.size() >= 4) {
        bf.read((uint8_t*)&savedBaud, 4);
        bf.close();
        if (savedBaud == 9600 || savedBaud == 38400 || savedBaud == 115200) {
            gpsSerial.begin(savedBaud, SERIAL_8N1, GPS_RX, GPS_TX);
            Serial.printf("[GPS] Trying saved %d baud... ", savedBaud);
            if (validateNMEA(1500)) {
                gpsBaudRate = savedBaud;
                Serial.println("OK (cached)");
                return;
            }
            Serial.println("stale, rescanning");
            gpsSerial.end();
            // Delete stale cache so we don't retry wrong baud forever
            LittleFS.remove("/gpsbaud.cfg");
        } else {
            bf.close();
        }
    } else {
        if (bf) bf.close();
    }
    
    // Auto-detect baud rate: T-Deck CYPHER M8K uses 115200.
    // Try 115200 first (most likely), then 9600 (common default), then 38400.
    const uint32_t rates[] = { 115200, 9600, 38400 };
    
    for (int r = 0; r < 3; r++) {
        gpsSerial.begin(rates[r], SERIAL_8N1, GPS_RX, GPS_TX);
        Serial.printf("[GPS] Trying %d baud... ", rates[r]);
        
        if (validateNMEA(2500)) {
            gpsBaudRate = rates[r];
            Serial.printf("OK (NMEA validated)\n");
            // Persist detected baud for next boot
            File wf = LittleFS.open("/gpsbaud.cfg", "w");
            if (wf) { wf.write((uint8_t*)&gpsBaudRate, 4); wf.close(); }
            return;
        }
        Serial.println("no valid NMEA");
        gpsSerial.end();
    }
    
    // Fallback to 115200 (T-Deck CYPHER default)
    gpsSerial.begin(115200, SERIAL_8N1, GPS_RX, GPS_TX);
    gpsBaudRate = 115200;
    Serial.println("[GPS] No NMEA detected, defaulting to 115200 baud");
#endif
}

static void gps_tick() {
#ifndef NO_GPS
    while (gpsSerial.available()) {
        gps.encode(gpsSerial.read());
    }
    // Sync UTC epoch from GPS time (once per second when fully locked)
    // IMPORTANT: Require location.isValid() — not just time/date.
    // GPS modules report valid time from a single satellite BEFORE position lock.
    // If we sync epoch on time-only, FHOP activates on one radio but not the other
    // (whichever is closer to a window), putting them on different channels.
    if (gps.time.isValid() && gps.date.isValid() && gps.date.year() > 2020 &&
        gps.location.isValid()) {
        static uint32_t lastEpochSync = 0;
        if (millis() - lastEpochSync >= 1000) {
            lastEpochSync = millis();
            // Convert GPS date/time to Unix epoch (seconds since 1970-01-01)
            // Simplified: days from 1970 to GPS year + month/day + time
            int y = gps.date.year();
            int m = gps.date.month();
            int d = gps.date.day();
            // Days from 1970-01-01 to year start
            uint32_t days = 0;
            for (int yr = 1970; yr < y; yr++) {
                days += (yr % 4 == 0 && (yr % 100 != 0 || yr % 400 == 0)) ? 366 : 365;
            }
            // Days for months in current year
            static const int mdays[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
            for (int mo = 1; mo < m && mo <= 12; mo++) {
                days += mdays[mo];
                if (mo == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) days++;
            }
            days += d - 1;
            utcEpoch = days * 86400UL + gps.time.hour() * 3600UL + 
                       gps.time.minute() * 60UL + gps.time.second();
            utcEpochSyncMs = millis();
        }
    }
    
    // Record breadcrumb trail (every 5 seconds when GPS is valid)
    if (gps.location.isValid() && millis() - breadcrumbLastMs >= 5000) {
        breadcrumbLastMs = millis();
        breadcrumbs[breadcrumbHead].lat = gps.location.lat();
        breadcrumbs[breadcrumbHead].lon = gps.location.lng();
        breadcrumbHead = (breadcrumbHead + 1) % BREADCRUMB_MAX;
        if (breadcrumbCount < BREADCRUMB_MAX) breadcrumbCount++;
    }
#endif
}

bool ui_getGPS(double* lat, double* lon, double* alt) {
#ifndef NO_GPS
    if (gps.location.isValid()) {
        *lat = gps.location.lat();
        *lon = gps.location.lng();
        *alt = gps.altitude.isValid() ? gps.altitude.meters() : 0;
        return true;
    }
#endif
    return false;
}

// ═══════════════════════════════════════════════════════════
// MESSAGE STORAGE
// ═══════════════════════════════════════════════════════════

void ui_addMessage(const char* from, const char* text, bool outgoing, bool encrypted, uint8_t channel) {
    LocalMessage& msg = messages[msgHead];
    strncpy(msg.from, from, sizeof(msg.from) - 1);
    msg.from[sizeof(msg.from) - 1] = '\0';
    strncpy(msg.text, text, sizeof(msg.text) - 1);
    msg.text[sizeof(msg.text) - 1] = '\0';
    msg.timestamp = _getUtcEpoch();  // UTC epoch when GPS available, 0 otherwise
    if (msg.timestamp == 0) msg.timestamp = millis() | 0x80000000;  // Bit 31 = millis flag
    msg.outgoing = outgoing;
    msg.encrypted = encrypted;
    msg.delivered = false;
    msg.failed = false;
    msg.msgId = 0;
    msg.channel = (channel == 0xFF) ? activeGroupCh : channel;  // 0xFF = use active channel
    msg.grpAckCount = 0;
    msg.grpAckTotal = 0;
    msg.grpAckPeers = 0;
    
    msgHead = (msgHead + 1) % MAX_MESSAGES;
    if (msgCount < MAX_MESSAGES) msgCount++;
    
    // Track unread if not on messages screen
    if (!outgoing && uiState.currentScreen != SCREEN_MESSAGES) {
        uiState.unreadCount++;
    }
    
    uiState.dirty = true;
    _saveMessages();
    
    // If not on messages screen, flash notification.
    // Voice/scan screens suppress the overlay banner in ui_tick but still get
    // the header pulse (tinted header + sender callsign) via _flashNotification.
    if (uiState.currentScreen != SCREEN_MESSAGES &&
        uiState.currentScreen != SCREEN_CONVERSATION &&
        uiState.currentScreen != SCREEN_MAP && !outgoing) {
        _flashNotification(from, text);
    }
    
    // Audio notification for incoming messages + wake display
    if (!outgoing) {
        ui_wake();
        ui_beepMessage();
    }
    
    // Log to SD card
    sd_logMessage(from, text, outgoing, encrypted, msg.channel);
}

void ui_addContact(const char* name, const char* fingerprint) {
    if (contactCount >= MAX_CONTACTS) return;
    // Check for duplicate
    for (int i = 0; i < contactCount; i++) {
        if (strcmp(contacts[i].fingerprint, fingerprint) == 0) {
            strncpy(contacts[i].name, name, sizeof(contacts[i].name) - 1);
            return;
        }
    }
    Contact& c = contacts[contactCount++];
    strncpy(c.name, name, sizeof(c.name) - 1);
    c.name[sizeof(c.name) - 1] = '\0';
    strncpy(c.fingerprint, fingerprint, sizeof(c.fingerprint) - 1);
    c.fingerprint[sizeof(c.fingerprint) - 1] = '\0';
    c.unread = 0;
    uiState.dirty = true;
}

static void _saveMessages() {
    // Save last 20 messages to LittleFS for persistence across reboots
    File f = LittleFS.open("/messages.json", "w");
    if (!f) return;
    JsonDocument doc;
    JsonArray arr = doc.to<JsonArray>();
    int start = (msgCount < 20) ? 0 : msgCount - 20;
    for (int i = start; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        JsonObject obj = arr.add<JsonObject>();
        obj["f"] = messages[idx].from;
        obj["t"] = messages[idx].text;
        obj["ts"] = messages[idx].timestamp;
        obj["o"] = messages[idx].outgoing;
        obj["e"] = messages[idx].encrypted;
        obj["d"] = messages[idx].delivered;
        obj["fl"] = messages[idx].failed;
        obj["id"] = messages[idx].msgId;
        obj["ch"] = messages[idx].channel;
        if (messages[idx].grpAckCount > 0 || messages[idx].grpAckTotal > 0) {
            obj["gac"] = messages[idx].grpAckCount;
            obj["gat"] = messages[idx].grpAckTotal;
        }
    }
    serializeJson(doc, f);
    f.close();
}

static void _loadMessages() {
    File f = LittleFS.open("/messages.json", "r");
    if (!f) return;
    JsonDocument doc;
    if (deserializeJson(doc, f)) { f.close(); return; }
    f.close();
    JsonArray arr = doc.as<JsonArray>();
    for (JsonObject obj : arr) {
        const char* from = obj["f"] | "?";
        const char* text = obj["t"] | "";
        uint32_t ts = obj["ts"] | 0;
        bool out = obj["o"] | false;
        bool enc = obj["e"] | false;
        LocalMessage& msg = messages[msgHead];
        strncpy(msg.from, from, sizeof(msg.from) - 1);
        msg.from[sizeof(msg.from) - 1] = '\0';
        strncpy(msg.text, text, sizeof(msg.text) - 1);
        msg.text[sizeof(msg.text) - 1] = '\0';
        msg.timestamp = ts;
        msg.outgoing = out;
        msg.encrypted = enc;
        msg.delivered = obj["d"] | false;
        msg.failed = obj["fl"] | false;
        msg.msgId = obj["id"] | 0;
        msg.channel = obj["ch"] | 0;  // Default to General for legacy messages
        msg.grpAckCount = obj["gac"] | 0;
        msg.grpAckTotal = obj["gat"] | 0;
        msg.grpAckPeers = 0;  // Bitmask not persisted (peer indices change across reboots)
        msgHead = (msgHead + 1) % MAX_MESSAGES;
        if (msgCount < MAX_MESSAGES) msgCount++;
    }
    Serial.printf("[UI] Loaded %d messages from flash\n", msgCount);
}

// ═══════════════════════════════════════════════════════════
// DISPLAY RENDERING
// ═══════════════════════════════════════════════════════════

// Touch button regions (stored after each draw for hit detection)
struct TouchBtn { int x, y, w, h; char action; };
#define MAX_BUTTONS 20
static TouchBtn buttons[MAX_BUTTONS];
static int buttonCount = 0;

static void _clearButtons() { buttonCount = 0; }

static void _addButton(int x, int y, int w, int h, char action) {
    if (buttonCount < MAX_BUTTONS) {
        buttons[buttonCount++] = { x, y, w, h, action };
    }
}

static void _drawButton(int x, int y, int w, int h, const char* label, uint16_t bg, uint16_t fg) {
    tft.fillRoundRect(x, y, w, h, 4, bg);
    tft.setTextColor(fg);
    tft.setTextSize(1);
    // Center text in button
    int tw = strlen(label) * 6;
    tft.setCursor(x + (w - tw) / 2, y + (h - 8) / 2);
    tft.print(label);
}

static char _checkTouch(int tx, int ty) {
    for (int i = 0; i < buttonCount; i++) {
        if (tx >= buttons[i].x && tx < buttons[i].x + buttons[i].w &&
            ty >= buttons[i].y && ty < buttons[i].y + buttons[i].h) {
            return buttons[i].action;
        }
    }
    return 0;
}

// Header pulse notification state — must be declared before _drawHeader uses them
static uint32_t headerPulseUntil = 0;
static uint16_t headerPulseColor = 0;
static char headerPulseFrom[20] = {0};

static void _drawHeader(const char* title, bool showBack) {
    // Header pulse: tint background when notification is active
    bool pulseActive = (headerPulseUntil > 0 && millis() < headerPulseUntil);
    uint16_t headerBg = pulseActive ? headerPulseColor : COLOR_HEADER;
    
    tft.fillRect(0, 0, scrW, 24, headerBg);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    
    int textX = 8;
    
    // Back button on left side (if requested)
    if (showBack) {
        tft.fillRoundRect(2, 2, 36, 20, 3, COLOR_BTN_RED);
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(6, 6);
        tft.print("<Back");
        _addButton(2, 2, 36, 20, TB_BACK);
        textX = 42;
    }
    
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(textX, 6);
    tft.print(title);
    
    // Header pulse: append sender callsign after title
    if (pulseActive && headerPulseFrom[0] != '\0') {
        tft.setTextColor(0xFFFF);  // Bright white for contrast
        tft.printf(" <- %s", headerPulseFrom);  // ← sender callsign
    }
    
    // Right side status: [activity dot] [signal] [bat% trend] [GPS]
    int rx = scrW;
    
    // GPS (rightmost)
#ifndef NO_GPS
    rx -= 28;
    tft.setCursor(rx, 6);
    tft.setTextColor(gps.location.isValid() ? COLOR_GREEN : COLOR_DIM);
    tft.print("GPS");
#endif
    
    // Battery percentage + trend arrow + USB indicator
    extern uint8_t getBatteryPercent();
    extern bool isUsbCharging();
    uint8_t bat = getBatteryPercent();
    bool usbPower = isUsbCharging();
    
    // Compute trend from history (compare newest vs 2-min-ago reading)
    char trendChar = ' ';
    if (usbPower) {
        trendChar = '+';  // Charging indicator
    } else if (batHistoryCount >= 12) {  // Need ~2 min of data (12 × 10s)
        int newestIdx = (batHistoryHead - 1 + BAT_HISTORY_SIZE) % BAT_HISTORY_SIZE;
        int olderIdx = (batHistoryHead - 12 + BAT_HISTORY_SIZE) % BAT_HISTORY_SIZE;
        int diff = (int)batHistory[newestIdx] - (int)batHistory[olderIdx];
        if (diff > 2) trendChar = '^';       // Charging
        else if (diff < -3) trendChar = 'v';  // Draining fast
        else trendChar = '>';                  // Stable / slow drain
    }
    
    rx -= 40;
    tft.setCursor(rx, 6);
    if (usbPower) {
        tft.setTextColor(0x07FF);  // Cyan for USB power
    } else {
        tft.setTextColor(bat > 20 ? COLOR_GREEN : (bat > 10 ? COLOR_YELLOW : COLOR_RED));
    }
    tft.printf("%d%%%c", bat, trendChar);
    
    // Show voltage when low (critical info for field decision-making)
    if (bat <= 20) {
        rx -= 28;
        tft.setCursor(rx, 6);
        tft.setTextColor(COLOR_RED);
        tft.printf("%.1fV", batVoltage);
    }
    
    // Mini signal bars
    if (sigLastUpdate > 0) {
        rx -= 22;
        int bars = 0;
        if (sigRSSI > -70) bars = 3;
        else if (sigRSSI > -90) bars = 2;
        else if (sigRSSI > -110) bars = 1;
        uint16_t sc = bars >= 2 ? COLOR_GREEN : bars == 1 ? COLOR_YELLOW : COLOR_RED;
        for (int i = 0; i < 3; i++) {
            int bh = 4 + i * 4;
            tft.fillRect(rx + i * 5, 18 - bh, 3, bh, i < bars ? sc : 0x2104);
        }
    }
    
    // Radio activity dot (green=recent TX/RX within 3s, dim=idle)
    rx -= 10;
    bool recentActivity = (lastRadioActivity > 0 && (millis() - lastRadioActivity) < 3000);
    tft.fillCircle(rx + 3, 12, 3, recentActivity ? COLOR_GREEN : 0x2104);
}

// ── Voice RX overlay banner ──
// Draws from y=0 covering the header + content area, so it looks intentional
// on ANY screen rather than partially corrupting content at y=26.
// After playback, uiState.dirty triggers a full redraw that restores the screen.
static void _drawRxBanner2(uint16_t color, const char* line1, const char* line2) {
    tft.fillRect(0, 0, scrW, 48, color);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(10, 6);
    tft.print(line1);
    if (line2 && line2[0]) {
        tft.setCursor(10, 26);
        tft.print(line2);
    }
}
static void _drawRxBanner1(uint16_t color, const char* line1) {
    tft.fillRect(0, 0, scrW, 28, color);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(10, 8);
    tft.print(line1);
}

static void _drawStatusScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("GridDown Radio", false);
    
    int y = 34;
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    
    // Identity
    tft.setCursor(8, y);
    if (ui_callsignSet()) {
        tft.setTextColor(COLOR_GREEN);
        tft.printf("Callsign: %s", myCallsign);
    } else {
        tft.setTextColor(COLOR_RED);
        tft.print("Callsign: NOT SET (Settings)");
    }
    y += 14;
    
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y);
    int activePeers = 0;
    for (int i = 0; i < peerCount; i++) if (peers[i].active) activePeers++;
    tft.printf("Msgs: %d  Peers: %d/%d", msgCount, activePeers, peerCount);
    
    // Remote ID detection indicator. Amber when the achieved BLE duty cycle is
    // materially below what was requested, so degradation is visible.
    if (rid_sourceUsesRemoteId(rid_getSource())) {
        int ridN = rid_activeTrackCount(millis());
        char ridInd[20];
        snprintf(ridInd, sizeof(ridInd), "RID %d", ridN);
        int rw = strlen(ridInd) * 6;
        tft.setCursor(scrW - rw - 8, y - 18);
        if (rid_isWatchdogTripped())                  tft.setTextColor(COLOR_RED);
        else if (rid_dutyAchievedPct() + 5 < rid_dutyRequestedPct()) tft.setTextColor(0xFD20);
        else if (ridN > 0)                            tft.setTextColor(0x07E0);
        else                                          tft.setTextColor(COLOR_DIM);
        tft.print(ridInd);
        tft.setTextColor(COLOR_DIM);
    }

    // Phase 7: Image TX progress indicator on Status screen.
    // Right-aligned blue text shown only when a transfer is active.
    if (img_isTxActive()) {
        char imgInd[24];
        snprintf(imgInd, sizeof(imgInd), "IMG %u%% ~%us",
                 img_txProgress(), img_txEtaSeconds());
        int indW = strlen(imgInd) * 6;
        tft.setCursor(scrW - indW - 8, y);
        tft.setTextColor(COLOR_ACCENT);
        tft.print(imgInd);
    }
    y += 18;
    
    // GPS
#ifndef NO_GPS
    tft.setCursor(8, y);
    if (gps.location.isValid()) {
        tft.setTextColor(COLOR_GREEN);
        tft.printf("GPS: %.6f, %.6f", gps.location.lat(), gps.location.lng());
        y += 12;
        tft.setCursor(8, y);
        tft.setTextColor(COLOR_DIM);
        tft.printf("Alt: %.0fm  Sats: %d  %dbaud", 
            gps.altitude.meters(), gps.satellites.value(), gpsBaudRate);
    } else {
        tft.setTextColor(COLOR_YELLOW);
        tft.printf("GPS: Searching... (%d sats) %dbaud", 
            gps.satellites.value(), gpsBaudRate);
    }
    y += 18;
#endif

    // Radio status
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y);
    if (fhop_isActive()) {
        tft.printf("Radio: CH%d (%.1fMHz) FHOP", fhop_getCurrentChannel(), fhop_getCurrentFreq());
        tft.setTextColor(COLOR_GREEN);
        tft.print(" ON");
    } else {
        tft.printf("Radio: CH%d (%.1fMHz) SF10 14dBm", currentChannel, _channelToFreq(currentChannel));
    }
    y += 14;
    
    // WiFi status + BLE address
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y);
    uint8_t wMode = wifi_getMode();
    if (wMode == WIFI_MODE_GD_AP) {
        tft.printf("WiFi: %s:8770", WiFi.softAPIP().toString().c_str());
    } else if (wMode == WIFI_MODE_GD_STA) {
        if (wifi_staIsConnected()) {
            tft.setTextColor(COLOR_GREEN);
            tft.printf("WiFi: griddown-radio.local");
        } else {
            tft.setTextColor(COLOR_YELLOW);
            tft.printf("WiFi: STA connecting...");
        }
    } else {
        tft.setTextColor(COLOR_RED);
        tft.print("WiFi: OFF");
    }
    // BLE status on same line
    tft.setCursor(scrW - 60, y);
    tft.setTextColor(bleClientConnected ? COLOR_GREEN : (bleInitialized ? COLOR_DIM : COLOR_RED));
    tft.print(bleClientConnected ? "BLE:ON" : (bleInitialized ? "BLE" : "---"));
    y += 14;
    
    // Standalone encryption + audio status
    tft.setCursor(8, y);
    if (psk_isEnabled()) {
        tft.setTextColor(COLOR_GREEN);
        tft.printf("Encrypt: AES-256 (%s****)", psk_getPassphraseHint());
    } else {
        tft.setTextColor(COLOR_RED);
        tft.print("Encrypt: OFF (set in Settings)");
    }
    // Audio indicator at right side
    tft.setCursor(scrW - 90, y);
    tft.setTextColor(audioMuted ? COLOR_RED : COLOR_GREEN);
    tft.print(audioMuted ? "MUTE" : "SND");
    tft.setCursor(scrW - 48, y);
    tft.setTextColor(micInitialized ? (codec2Ready ? COLOR_GREEN : COLOR_YELLOW) : COLOR_DIM);
    tft.print(micInitialized ? (codec2Ready ? "C2" : "MIC") : "---");
    y += 16;
    
    // Signal quality bars + RSSI/SNR + RX/TX (full width, no sparkline overlap)
    _drawSignalQuality(8, y);
    y += 24;
    
    // Battery sparkline (compact, own row, right-aligned)
    if (batHistoryCount > 1) {
        int sparkX = scrW - 90, sparkY = y, sparkW = 80, sparkH = 14;
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(sparkX - 24, sparkY + 3);
        tft.print("Bat");
        tft.drawRect(sparkX, sparkY, sparkW, sparkH, 0x2104);
        for (int i = 1; i < batHistoryCount && i < sparkW; i++) {
            int idx0 = (batHistoryHead - batHistoryCount + i - 1 + BAT_HISTORY_SIZE) % BAT_HISTORY_SIZE;
            int idx1 = (batHistoryHead - batHistoryCount + i + BAT_HISTORY_SIZE) % BAT_HISTORY_SIZE;
            int y0 = sparkY + sparkH - 2 - (batHistory[idx0] * (sparkH - 4) / 100);
            int y1 = sparkY + sparkH - 2 - (batHistory[idx1] * (sparkH - 4) / 100);
            int x0 = sparkX + 1 + (i - 1) * (sparkW - 2) / (batHistoryCount - 1);
            int x1 = sparkX + 1 + i * (sparkW - 2) / (batHistoryCount - 1);
            uint16_t lc = batHistory[idx1] > 20 ? COLOR_GREEN : COLOR_RED;
            tft.drawLine(x0, y0, x1, y1, lc);
        }
    }
    y += 16;
    
    // RF diagnostics — channel/PSK mismatch detection
    // Shows time since last raw packet + decrypt failures
    {
        uint32_t rxAge = ui_rfLastRxAge();
        uint32_t decFails = ui_rfDecryptFailCount();
        tft.setCursor(8, y);
        
        if (rxAge == UINT32_MAX) {
            // Never received any packet
            tft.setTextColor(COLOR_YELLOW);
            tft.print("RF: No packets heard");
        } else if (rxAge > 300 && peerCount == 0) {
            // 5+ minutes with no packets and no peers — likely wrong channel or no one nearby
            tft.setTextColor(COLOR_RED);
            tft.printf("RF: Silent %lum — check CH/antenna", rxAge / 60);
        } else if (decFails > 0 && peerCount == 0 && rxAge < 60) {
            // Receiving packets but can't decrypt — PSK mismatch
            tft.setTextColor(COLOR_RED);
            tft.printf("RF: %lu decrypt fails — check PSK", decFails);
        } else if (rxAge < 10) {
            tft.setTextColor(COLOR_GREEN);
            tft.printf("RF: Active (last %lus)", rxAge);
        } else {
            tft.setTextColor(COLOR_DIM);
            tft.printf("RF: Last RX %lus ago", rxAge);
        }
        y += 14;
    }
    
    // Nav buttons — two rows of 4
    int btnW = 58, btnH = 24, gap = 3;
    int row1Y = scrH - btnH * 2 - gap - 6;
    int row2Y = scrH - btnH - 4;
    int startX = (scrW - (5 * btnW + 4 * gap)) / 2;
    
    // Row 1: Msgs, Compose, Voice, Map, Scan
    char msgLabel[24];
    if (uiState.unreadCount > 0) {
        snprintf(msgLabel, sizeof(msgLabel), "Msg(%d)", uiState.unreadCount);
        _drawButton(startX, row1Y, btnW, btnH, msgLabel, COLOR_BTN_RED, COLOR_TEXT);
    } else {
        _drawButton(startX, row1Y, btnW, btnH, "Msgs", COLOR_BTN_ACCENT, COLOR_TEXT);
    }
    _addButton(startX, row1Y, btnW, btnH, 'M');
    
    _drawButton(startX + 1*(btnW + gap), row1Y, btnW, btnH, "Compose", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(startX + 1*(btnW + gap), row1Y, btnW, btnH, 'C');
    
    uint16_t voiceColor = codec2Ready ? COLOR_RED : COLOR_DIM;
    _drawButton(startX + 2*(btnW + gap), row1Y, btnW, btnH, "Voice", voiceColor, COLOR_TEXT);
    _addButton(startX + 2*(btnW + gap), row1Y, btnW, btnH, 'V');
    
    _drawButton(startX + 3*(btnW + gap), row1Y, btnW, btnH, "Map", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(startX + 3*(btnW + gap), row1Y, btnW, btnH, 'P');
    
    _drawButton(startX + 4*(btnW + gap), row1Y, btnW, btnH, "Scan", 0x4800, COLOR_TEXT);
    _addButton(startX + 4*(btnW + gap), row1Y, btnW, btnH, 'F');
    
    // Row 2: Peers, Debug, Setup, Lock, E:SOS
    char peerLabel[16];
    snprintf(peerLabel, sizeof(peerLabel), "Peers(%d)", activePeers);
    _drawButton(startX, row2Y, btnW, btnH, peerLabel, COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(startX, row2Y, btnW, btnH, 'N');
    
    _drawButton(startX + 1*(btnW + gap), row2Y, btnW, btnH, "Debug", COLOR_HEADER, COLOR_DIM);
    _addButton(startX + 1*(btnW + gap), row2Y, btnW, btnH, 'D');
    
    _drawButton(startX + 2*(btnW + gap), row2Y, btnW, btnH, "Setup", COLOR_HEADER, COLOR_DIM);
    _addButton(startX + 2*(btnW + gap), row2Y, btnW, btnH, 'S');
    
    _drawButton(startX + 3*(btnW + gap), row2Y, btnW, btnH, 
                screenLocked ? "Unlock" : "Lock", 
                screenLocked ? COLOR_RED : COLOR_HEADER, COLOR_TEXT);
    _addButton(startX + 3*(btnW + gap), row2Y, btnW, btnH, 'Z');
    
    _drawButton(startX + 4*(btnW + gap), row2Y, btnW, btnH, "E:SOS", COLOR_BTN_RED, COLOR_TEXT);
}

// Format relative time from timestamp
// Bit 31 set = millis-based timestamp (clear bit to get raw millis)
// Bit 31 clear, value > 1.5B = UTC epoch (seconds since 1970-01-01)
// Bit 31 clear, value < 1.5B = legacy millis (pre-GPS firmware)
static void _fmtAge(uint32_t ts, char* buf, size_t len) {
    uint32_t ageSec;
    if (ts & 0x80000000) {
        // Millis-based (current boot only)
        uint32_t rawMs = ts & 0x7FFFFFFF;
        ageSec = (millis() - rawMs) / 1000;
    } else if (ts > 1500000000UL && utcEpoch > 0) {
        // UTC epoch — compute age from current GPS time
        uint32_t now = _getUtcEpoch();
        ageSec = (now > ts) ? (now - ts) : 0;
    } else {
        // Legacy millis or no GPS — best-effort relative
        ageSec = (millis() > ts) ? (millis() - ts) / 1000 : 0;
    }
    if (ageSec < 60)       snprintf(buf, len, "%ds", ageSec);
    else if (ageSec < 3600) snprintf(buf, len, "%dm", ageSec / 60);
    else if (ageSec < 86400) snprintf(buf, len, "%dh", ageSec / 3600);
    else                    snprintf(buf, len, "%dd", ageSec / 86400);
}

static void _drawMessagesScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    
    // Header with channel filter indicator
    if (groupChFilter) {
        char hdr[32];
        snprintf(hdr, sizeof(hdr), "Messages [%s]", groupChNames[activeGroupCh]);
        _drawHeader(threadView ? "Threads" : hdr, true);
        // Color bar under header to show active filter
        tft.fillRect(0, 24, scrW, 2, groupChColors[activeGroupCh]);
    } else {
        _drawHeader(threadView ? "Threads" : "Messages", true);
    }
    
    // Count visible messages (after filter)
    int visibleCount = 0;
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        if (!groupChFilter || messages[idx].channel == activeGroupCh) visibleCount++;
    }
    
    if (visibleCount == 0) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(scrW / 2 - 40, scrH / 2 - 8);
        tft.print(groupChFilter ? "No messages on ch" : "No messages");
        int btnY = scrH - 34;
        _drawButton(8, btnY, 90, 28, "Compose", COLOR_BTN_ACCENT, COLOR_TEXT);
        _addButton(8, btnY, 90, 28, 'C');
        // Channel filter button
        char gLabel[12];
        snprintf(gLabel, sizeof(gLabel), groupChFilter ? "%s" : "All", groupChNames[activeGroupCh]);
        _drawButton(scrW - 64, btnY, 58, 28, gLabel, 
                    groupChFilter ? groupChColors[activeGroupCh] : COLOR_HEADER, COLOR_TEXT);
        _addButton(scrW - 64, btnY, 58, 28, 'G');
        return;
    }
    
    // ── THREAD VIEW: Show unique peers with last message ──
    if (threadView) {
        // Collect unique peers
        struct ThreadEntry { char name[20]; int lastIdx; int unread; uint32_t lastTs; };
        ThreadEntry threads[16];
        int threadCount = 0;
        
        for (int i = 0; i < msgCount; i++) {
            int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
            LocalMessage& m = messages[idx];
            const char* peer = m.outgoing ? "You" : m.from;
            if (m.outgoing) continue;  // Only index by sender for threading
            
            // Find or create thread entry
            int t = -1;
            for (int j = 0; j < threadCount; j++) {
                if (strcmp(threads[j].name, peer) == 0) { t = j; break; }
            }
            if (t < 0 && threadCount < 16) {
                t = threadCount++;
                strncpy(threads[t].name, peer, 19); threads[t].name[19] = '\0';
                threads[t].unread = 0;
                threads[t].lastIdx = idx;
                threads[t].lastTs = m.timestamp;
            }
            if (t >= 0) {
                threads[t].lastIdx = idx;  // Always update to latest
                threads[t].lastTs = m.timestamp;
            }
        }
        
        int y = 28;
        int lineH = 30;
        for (int i = 0; i < threadCount && y + lineH <= scrH - 38; i++) {
            LocalMessage& lastMsg = messages[threads[i].lastIdx];
            
            tft.fillRoundRect(4, y, scrW - 8, lineH - 2, 4, COLOR_RECV);
            tft.setTextColor(COLOR_YELLOW);
            tft.setTextSize(1);
            tft.setCursor(10, y + 2);
            tft.print(threads[i].name);
            
            char age[8];
            _fmtAge(threads[i].lastTs, age, sizeof(age));
            tft.setTextColor(COLOR_DIM);
            tft.setCursor(scrW - 6 * strlen(age) - 10, y + 2);
            tft.print(age);
            
            // Last message preview
            tft.setTextColor(COLOR_TEXT);
            tft.setCursor(10, y + 15);
            char trunc[44];
            strncpy(trunc, lastMsg.text, 43); trunc[43] = '\0';
            tft.print(trunc);
            
            // Tap target: open conversation for this peer
            _addButton(4, y, scrW - 8, lineH - 2, '1' + i);  // keys '1'-'9' select thread
            y += lineH;
        }
        
        int btnY = scrH - 34;
        _drawButton(4, btnY, 60, 28, "Flat", COLOR_BTN_ACCENT, COLOR_TEXT);
        _addButton(4, btnY, 60, 28, 'F');
        
        _drawButton(70, btnY, 72, 28, "Compose", COLOR_BTN_ACCENT, COLOR_TEXT);
        _addButton(70, btnY, 72, 28, 'C');
        
        _drawButton(scrW - 68, btnY, 62, 28, "Home", COLOR_HEADER, COLOR_DIM);
        _addButton(scrW - 68, btnY, 62, 28, TB_BACK);
        return;
    }
    
    // Layout: header=26px (24 + 2px filter bar), messages area, bottom bar=34px
    int msgAreaTop = groupChFilter ? 28 : 26;
    int msgAreaBot = scrH - 36;
    int lineH = 28;
    int maxVisible = (msgAreaBot - msgAreaTop) / lineH;
    
    // Build filtered index list
    int filteredIdx[MAX_MESSAGES];
    int filteredCount = 0;
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        if (!groupChFilter || messages[idx].channel == activeGroupCh) {
            filteredIdx[filteredCount++] = idx;
        }
    }
    
    // Clamp scroll offset to filtered count
    int maxScroll = filteredCount > maxVisible ? filteredCount - maxVisible : 0;
    if (uiState.scrollOffset > maxScroll) uiState.scrollOffset = maxScroll;
    if (uiState.scrollOffset < 0) uiState.scrollOffset = 0;
    
    // Calculate which filtered messages to show (newest at bottom)
    int start = filteredCount - maxVisible - uiState.scrollOffset;
    if (start < 0) start = 0;
    int end = start + maxVisible;
    if (end > filteredCount) end = filteredCount;
    
    int y = msgAreaTop;
    for (int fi = start; fi < end; fi++) {
        int idx = filteredIdx[fi];
        LocalMessage& msg = messages[idx];
        
        uint16_t bgColor = msg.outgoing ? COLOR_SENT : COLOR_RECV;
        int bubbleX = msg.outgoing ? 60 : 4;
        int bubbleW = scrW - 64;
        
        tft.fillRoundRect(bubbleX, y, bubbleW, lineH - 4, 4, bgColor);
        
        // Channel color dot (4px circle, left edge of bubble)
        tft.fillCircle(bubbleX + 6, y + lineH / 2 - 2, 3, groupChColors[msg.channel]);
        
        // Sender (shifted right to make room for dot)
        tft.setTextColor(msg.outgoing ? COLOR_ACCENT : COLOR_YELLOW);
        tft.setCursor(bubbleX + 14, y + 2);
        tft.setTextSize(1);
        tft.print(msg.from);
        
        // Timestamp (right side of sender line)
        char age[8];
        _fmtAge(msg.timestamp, age, sizeof(age));
        int ageW = strlen(age) * 6;
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(bubbleX + bubbleW - ageW - 4, y + 2);
        tft.print(age);
        
        // Delivery status indicator for outgoing messages
        if (msg.outgoing && msg.msgId > 0) {
            int indX = bubbleX + bubbleW - ageW - 16;
            if (msg.grpAckTotal > 0) {
                // Group broadcast — show peer ACK count
                uint16_t ackColor = (msg.grpAckCount >= msg.grpAckTotal) ? COLOR_GREEN :
                                    (msg.grpAckCount > 0) ? COLOR_YELLOW : COLOR_DIM;
                tft.setTextColor(ackColor);
                tft.setCursor(indX - 8, y + 2);
                tft.printf("%d/%d", msg.grpAckCount, msg.grpAckTotal);
            } else if (msg.failed) {
                tft.setTextColor(COLOR_RED);
                tft.setCursor(indX, y + 2);
                tft.print("X");  // Failed
            } else if (msg.delivered) {
                tft.setTextColor(COLOR_GREEN);
                tft.setCursor(indX, y + 2);
                tft.print("v");  // Delivered
            } else {
                tft.setTextColor(COLOR_YELLOW);
                tft.setCursor(indX, y + 2);
                tft.print("~");  // Pending
            }
        }
        
        // Text (truncated)
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(bubbleX + 4, y + 13);
        char trunc[40];
        strncpy(trunc, msg.text, 39);
        trunc[39] = '\0';
        tft.print(trunc);
        
        // E2E encryption indicator (cyan, matches peer screen badge)
        if (msg.encrypted) {
            tft.setTextColor(0x07FF);  // Cyan — consistent with peers screen E2E badge
            tft.setCursor(bubbleX + bubbleW - 22, y + 13);
            tft.print("E2E");
        }
        
        y += lineH;
    }
    
    // Scroll position indicator (right edge)
    if (maxScroll > 0) {
        int trackH = msgAreaBot - msgAreaTop - 4;
        int thumbH = max(trackH * maxVisible / filteredCount, 8);
        int thumbY = msgAreaTop + 2 + (trackH - thumbH) * (maxScroll - uiState.scrollOffset) / maxScroll;
        tft.fillRect(scrW - 3, msgAreaTop, 2, trackH + 4, 0x2104);  // Track
        tft.fillRect(scrW - 3, thumbY, 2, thumbH, COLOR_DIM);       // Thumb
    }
    
    // Bottom bar
    int btnY = scrH - 34;
    
    _drawButton(4, btnY, 38, 28, "New", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(4, btnY, 38, 28, 'C');
    
    _drawButton(46, btnY, 38, 28, "Thrd", COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(46, btnY, 38, 28, 'F');
    
    // Channel filter button (G key) — shows "All" or active channel name
    {
        char gLabel[10];
        snprintf(gLabel, sizeof(gLabel), groupChFilter ? "%.7s" : "All", groupChNames[activeGroupCh]);
        _drawButton(88, btnY, 52, 28, gLabel,
                    groupChFilter ? groupChColors[activeGroupCh] : COLOR_HEADER, COLOR_TEXT);
        _addButton(88, btnY, 52, 28, 'G');
    }
    
    if (maxScroll > 0) {
        _drawButton(146, btnY, 28, 28, "Up", 
                    uiState.scrollOffset < maxScroll ? COLOR_HEADER : 0x2104, COLOR_TEXT);
        _addButton(146, btnY, 28, 28, TB_UP);
        
        _drawButton(178, btnY, 28, 28, "Dn", 
                    uiState.scrollOffset > 0 ? COLOR_HEADER : 0x2104, COLOR_TEXT);
        _addButton(178, btnY, 28, 28, TB_DOWN);
    }
    
    if (msgCount > 0) {
        _drawButton(212, btnY, 36, 28, "Clr", COLOR_BTN_RED, COLOR_TEXT);
        _addButton(192, btnY, 40, 28, 'X');
    }
    
    _drawButton(scrW - 56, btnY, 52, 28, "Home", COLOR_HEADER, COLOR_DIM);
    _addButton(scrW - 56, btnY, 52, 28, TB_BACK);
    // Touch scrolling handled by drag-to-scroll in ui_tick (not button zones)
}

static void _drawComposeScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Compose", true);
    
    // Contact/recipient selector
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, 30);
    tft.print("To: ");
    if (uiState.selectedContact >= 0 && uiState.selectedContact < contactCount) {
        tft.setTextColor(COLOR_GREEN);
        tft.print(contacts[uiState.selectedContact].name);
        tft.setTextColor(COLOR_DIM);
        tft.print(" (direct)");
    } else {
        tft.setTextColor(COLOR_YELLOW);
        tft.print("ALL (broadcast)");
    }
    
    // Group channel indicator + hint
    tft.setCursor(8, 40);
    tft.setTextColor(groupChColors[activeGroupCh]);
    tft.fillCircle(12, 44, 3, groupChColors[activeGroupCh]);
    tft.setCursor(20, 40);
    tft.printf("Ch: %s", groupChNames[activeGroupCh]);
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(140, 40);
    tft.print("<>=ch  TB=reply");
    
    // Compose area
    tft.drawRect(4, 48, scrW - 8, scrH - 100, COLOR_DIM);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(8, 52);
    tft.setTextSize(1);
    
    // Word-wrap the compose buffer
    int cx = 8, cy = 52;
    for (int i = 0; i < uiState.composeLen; i++) {
        if (cx > scrW - 16 || uiState.composeBuffer[i] == '\n') {
            cx = 8;
            cy += 12;
        }
        tft.setCursor(cx, cy);
        tft.print(uiState.composeBuffer[i]);
        cx += 6;
    }
    
    // Cursor (static — blink handled in ui_tick without full redraw)
    tft.fillRect(cx, cy, 6, 10, COLOR_ACCENT);
    
    // Bottom buttons
    int btnY = scrH - 34;
    _drawButton(8, btnY, 80, 28, "Send", COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(8, btnY, 80, 28, '\n');
    
    _drawButton(96, btnY, 70, 28, "Contact", COLOR_HEADER, COLOR_TEXT);
    _addButton(96, btnY, 70, 28, '\t');
    
    _drawButton(scrW - 90, btnY, 82, 28, "Cancel", COLOR_BTN_RED, COLOR_TEXT);
    _addButton(scrW - 90, btnY, 82, 28, TB_BACK);  // Cancel
    
    // Character count (inside compose box, bottom-right corner)
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(scrW - 52, scrH - 54);
    tft.printf("%d/199", uiState.composeLen);
}

// ═══════════════════════════════════════════════════════════
// MAP SCREEN — Shows peer positions relative to our location
// ═══════════════════════════════════════════════════════════

// Haversine distance in meters
static double _haversine(double lat1, double lon1, double lat2, double lon2) {
    double dLat = (lat2 - lat1) * DEG_TO_RAD;
    double dLon = (lon2 - lon1) * DEG_TO_RAD;
    double a = sin(dLat / 2) * sin(dLat / 2) +
               cos(lat1 * DEG_TO_RAD) * cos(lat2 * DEG_TO_RAD) *
               sin(dLon / 2) * sin(dLon / 2);
    return 6371000.0 * 2.0 * atan2(sqrt(a), sqrt(1 - a));
}

// Bearing from point 1 to point 2 in degrees (0=N, 90=E)
static double _bearing(double lat1, double lon1, double lat2, double lon2) {
    double dLon = (lon2 - lon1) * DEG_TO_RAD;
    double y = sin(dLon) * cos(lat2 * DEG_TO_RAD);
    double x = cos(lat1 * DEG_TO_RAD) * sin(lat2 * DEG_TO_RAD) -
               sin(lat1 * DEG_TO_RAD) * cos(lat2 * DEG_TO_RAD) * cos(dLon);
    double brg = atan2(y, x) * RAD_TO_DEG;
    return fmod(brg + 360.0, 360.0);
}

// Cardinal direction from bearing angle
static const char* _cardinal(double brg) {
    if (brg < 22.5 || brg >= 337.5) return "N";
    if (brg < 67.5)  return "NE";
    if (brg < 112.5) return "E";
    if (brg < 157.5) return "SE";
    if (brg < 202.5) return "S";
    if (brg < 247.5) return "SW";
    if (brg < 292.5) return "W";
    return "NW";
}

// Simplified MGRS grid reference from lat/lon
// Produces format "18S UJ 23456 56789" (zone + band + 100km square + 5-digit easting/northing)
static void _latLonToMGRS(double lat, double lon, char* buf, int bufLen) {
    // UTM zone
    int zone = (int)((lon + 180.0) / 6.0) + 1;
    if (zone > 60) zone = 60;
    
    // UTM latitude band letter (C-X, excluding I and O)
    const char bands[] = "CDEFGHJKLMNPQRSTUVWX";
    int bandIdx = (int)((lat + 80.0) / 8.0);
    if (bandIdx < 0) bandIdx = 0;
    if (bandIdx > 19) bandIdx = 19;
    char band = bands[bandIdx];
    
    // UTM projection (simplified, WGS84)
    double latRad = lat * DEG_TO_RAD;
    double lonRad = lon * DEG_TO_RAD;
    double lon0 = ((zone - 1) * 6.0 - 180.0 + 3.0) * DEG_TO_RAD;  // Central meridian
    
    double a = 6378137.0;  // WGS84 semi-major
    double f = 1.0 / 298.257223563;
    double e2 = 2 * f - f * f;
    double ep2 = e2 / (1 - e2);
    double k0 = 0.9996;
    
    double N = a / sqrt(1 - e2 * sin(latRad) * sin(latRad));
    double T = tan(latRad) * tan(latRad);
    double C = ep2 * cos(latRad) * cos(latRad);
    double A = (lonRad - lon0) * cos(latRad);
    
    // Meridional arc (simplified series)
    double M = a * ((1 - e2/4 - 3*e2*e2/64) * latRad
                    - (3*e2/8 + 3*e2*e2/32) * sin(2*latRad)
                    + (15*e2*e2/256) * sin(4*latRad));
    
    double easting = k0 * N * (A + (1-T+C)*A*A*A/6) + 500000.0;
    double northing = k0 * (M + N * tan(latRad) * (A*A/2 + (5-T+9*C+4*C*C)*A*A*A*A/24));
    if (lat < 0) northing += 10000000.0;
    
    // 100km grid square letters (set depends on zone)
    int setNum = ((zone - 1) % 6);
    const char* colLetters[] = {"ABCDEFGH", "JKLMNPQR", "STUVWXYZ", "ABCDEFGH", "JKLMNPQR", "STUVWXYZ"};
    const char* rowLetters[] = {"ABCDEFGHJKLMNPQRSTUV", "FGHJKLMNPQRSTUVABCDE"};
    
    int col100k = ((int)(easting / 100000.0)) - 1;
    if (col100k < 0) col100k = 0;
    if (col100k > 7) col100k = 7;
    int row100k = ((int)(northing / 100000.0)) % 20;
    
    char sq1 = colLetters[setNum][col100k];
    char sq2 = rowLetters[setNum % 2][row100k];
    
    int e5 = (int)fmod(easting, 100000.0);
    int n5 = (int)fmod(northing, 100000.0);
    
    snprintf(buf, bufLen, "%d%c %c%c %05d %05d", zone, band, sq1, sq2, e5, n5);
}

static void _drawMapScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Map", true);
    
    double myLat, myLon, myAlt;
    bool haveGPS = ui_getGPS(&myLat, &myLon, &myAlt);
    
    // Layout: map circle centered in available space, info bar below, buttons at bottom
    int mapCX = scrW / 2;
    int mapCY = 26 + (scrH - 80) / 2;
    int mapR = min(scrW, scrH - 80) / 2 - 10;
    int infoY = mapCY + mapR + 12;  // Info bar Y
    int btnY = scrH - 34;
    
    // Draw compass ring
    tft.drawCircle(mapCX, mapCY, mapR, COLOR_DIM);
    tft.drawCircle(mapCX, mapCY, mapR / 2, 0x2104);
    
    // Cardinal directions
    tft.setTextColor(COLOR_DIM); tft.setTextSize(1);
    tft.setCursor(mapCX - 2, mapCY - mapR - 10); tft.print("N");
    tft.setCursor(mapCX - 2, mapCY + mapR + 3);  tft.print("S");
    tft.setCursor(mapCX - mapR - 8, mapCY - 4);  tft.print("W");
    tft.setCursor(mapCX + mapR + 3, mapCY - 4);  tft.print("E");
    
    // ── NORTH ARROW (red triangle pointing up from center) ──
    int naLen = mapR / 3;  // Arrow length
    int naTipX = mapCX, naTipY = mapCY - naLen;
    tft.drawLine(mapCX, mapCY, naTipX, naTipY, COLOR_RED);
    tft.fillTriangle(naTipX, naTipY, naTipX - 4, naTipY + 8, naTipX + 4, naTipY + 8, COLOR_RED);
    
    // Our position at center
    tft.fillCircle(mapCX, mapCY, 4, COLOR_GREEN);
    if (ui_callsignSet()) {
        tft.setTextColor(COLOR_GREEN);
        tft.setCursor(mapCX + 6, mapCY - 4);
        tft.print(ui_getCallsign());
    }
    
    if (!haveGPS) {
        tft.setTextColor(COLOR_YELLOW);
        tft.setCursor(mapCX - 50, mapCY + 20);
        tft.print("Waiting for GPS...");
    } else {
        // Auto-scale (peers + tracks + waypoints)
        double maxDist = 100;
        for (int i = 0; i < peerCount; i++) {
            if (!peers[i].hasPosition || !peers[i].active) continue;
            double d = _haversine(myLat, myLon, peers[i].lat, peers[i].lon);
            if (d > maxDist) maxDist = d;
        }
        for (int i = 0; i < TRACK_MAX; i++) {
            if (!tracks[i].valid) continue;
            double d = _haversine(myLat, myLon, tracks[i].lat, tracks[i].lon);
            if (d > maxDist) maxDist = d;
        }
        for (int i = 0; i < WAYPOINT_MAX; i++) {
            if (!waypoints[i].valid) continue;
            double d = _haversine(myLat, myLon, waypoints[i].lat, waypoints[i].lon);
            if (d > maxDist) maxDist = d;
        }
        maxDist *= 1.3;
        
        // Scale label
        tft.setTextColor(COLOR_DIM); tft.setCursor(mapCX + mapR - 24, mapCY + mapR + 3);
        if (maxDist < 1000) tft.printf("%.0fm", maxDist);
        else tft.printf("%.1fkm", maxDist / 1000.0);
        
        // Count selectable items for cursor bounds (peers + tracks + waypoints)
        int selectableCount = 0;
        for (int i = 0; i < peerCount; i++) if (peers[i].hasPosition) selectableCount++;
        for (int i = 0; i < TRACK_MAX; i++) if (tracks[i].valid) selectableCount++;
        for (int i = 0; i < WAYPOINT_MAX; i++) if (waypoints[i].valid) selectableCount++;
        if (mapCursorIdx >= selectableCount) mapCursorIdx = selectableCount - 1;
        
        // ── Breadcrumb trail (own movement history) ──
        // Drawn as fading dots from oldest (dimmest) to newest (brightest).
        // Oldest crumbs are nearly invisible, newest are light green.
        if (breadcrumbCount > 1) {
            for (int b = 0; b < breadcrumbCount; b++) {
                // Walk from oldest to newest
                int idx = (breadcrumbHead - breadcrumbCount + b + BREADCRUMB_MAX) % BREADCRUMB_MAX;
                double bDist = _haversine(myLat, myLon, breadcrumbs[idx].lat, breadcrumbs[idx].lon);
                if (bDist < 1.0) continue;  // Skip if on top of current position
                double bBrg = _bearing(myLat, myLon, breadcrumbs[idx].lat, breadcrumbs[idx].lon);
                double bRad = bBrg * DEG_TO_RAD;
                double bScale = (bDist / maxDist) * mapR;
                if (bScale > mapR) continue;  // Off-screen
                int bx = mapCX + (int)(sin(bRad) * bScale);
                int by = mapCY - (int)(cos(bRad) * bScale);
                bx = constrain(bx, 8, scrW - 8);
                by = constrain(by, 30, scrH - 60);
                // Fade: oldest = very dim, newest = brighter
                // Use green channel intensity: 8 (oldest) to 31 (newest)
                int intensity = 8 + (b * 23) / breadcrumbCount;
                uint16_t dotColor = (intensity << 5);  // Green channel in RGB565
                tft.fillCircle(bx, by, 1, dotColor);
            }
        }
        
        // ── Plot peers ──
        int selectIdx = 0;
        for (int i = 0; i < peerCount; i++) {
            if (!peers[i].hasPosition) continue;
            
            double dist = _haversine(myLat, myLon, peers[i].lat, peers[i].lon);
            double brg = _bearing(myLat, myLon, peers[i].lat, peers[i].lon);
            double brgRad = brg * DEG_TO_RAD;
            double scale = (dist / maxDist) * mapR;
            int px = mapCX + (int)(sin(brgRad) * scale);
            int py = mapCY - (int)(cos(brgRad) * scale);
            px = constrain(px, 8, scrW - 8);
            py = constrain(py, 30, scrH - 60);
            
            bool selected = (mapCursorIdx == selectIdx);
            uint16_t dotColor = peers[i].active ? COLOR_ACCENT : COLOR_DIM;
            tft.fillCircle(px, py, selected ? 5 : 3, selected ? COLOR_TEXT : dotColor);
            if (selected) tft.drawCircle(px, py, 7, COLOR_TEXT);
            tft.setTextColor(dotColor); tft.setCursor(px + 7, py - 4);
            tft.print(peers[i].callsign);
            
            selectIdx++;
        }
        
        // ── Plot tracks with trails ──
        for (int i = 0; i < TRACK_MAX; i++) {
            if (!tracks[i].valid) continue;
            
            double dist = _haversine(myLat, myLon, tracks[i].lat, tracks[i].lon);
            double brg = _bearing(myLat, myLon, tracks[i].lat, tracks[i].lon);
            double brgRad = brg * DEG_TO_RAD;
            double scale = (dist / maxDist) * mapR;
            int tx = mapCX + (int)(sin(brgRad) * scale);
            int ty = mapCY - (int)(cos(brgRad) * scale);
            tx = constrain(tx, 8, scrW - 8);
            ty = constrain(ty, 30, scrH - 60);
            
            uint16_t tColor;
            switch (tracks[i].src) {
                case TRACK_SRC_ADSB:     tColor = COLOR_YELLOW; break;
                case TRACK_SRC_REMOTEID: tColor = 0xFD20; break;
                case TRACK_SRC_SENTINEL: tColor = COLOR_RED; break;
                case TRACK_SRC_FPV:      tColor = COLOR_RED; break;
                default:                 tColor = 0x7BEF; break;
            }
            
            // ── Track trail: fading polyline from oldest to current ──
            if (tracks[i].trailCount >= 2) {
                for (int t = 0; t < tracks[i].trailCount - 1; t++) {
                    // Read oldest to newest
                    int idx0 = (tracks[i].trailHead - tracks[i].trailCount + t + 8) % 8;
                    int idx1 = (idx0 + 1) % 8;
                    
                    double d0 = _haversine(myLat, myLon, tracks[i].trailLat[idx0], tracks[i].trailLon[idx0]);
                    double b0 = _bearing(myLat, myLon, tracks[i].trailLat[idx0], tracks[i].trailLon[idx0]) * DEG_TO_RAD;
                    double s0 = (d0 / maxDist) * mapR;
                    int x0 = mapCX + (int)(sin(b0) * s0);
                    int y0 = mapCY - (int)(cos(b0) * s0);
                    
                    double d1 = _haversine(myLat, myLon, tracks[i].trailLat[idx1], tracks[i].trailLon[idx1]);
                    double b1 = _bearing(myLat, myLon, tracks[i].trailLat[idx1], tracks[i].trailLon[idx1]) * DEG_TO_RAD;
                    double s1 = (d1 / maxDist) * mapR;
                    int x1 = mapCX + (int)(sin(b1) * s1);
                    int y1 = mapCY - (int)(cos(b1) * s1);
                    
                    // Fade: oldest segments dimmer
                    uint16_t fadeColor = (t < 2) ? 0x2104 : (t < 5) ? 0x4A49 : tColor;
                    tft.drawLine(x0, y0, x1, y1, fadeColor);
                }
            }
            
            // Track icon
            bool selected = (mapCursorIdx == selectIdx);
            int sz = (tracks[i].src == TRACK_SRC_ADSB) ? 4 : 3;
            if (selected) { tft.drawCircle(tx, ty, sz + 4, COLOR_TEXT); sz += 1; }
            float hRad = tracks[i].hdg * DEG_TO_RAD;
            int ax = tx + (int)(sin(hRad) * 6);
            int ay = ty - (int)(cos(hRad) * 6);
            tft.drawLine(tx, ty, ax, ay, tColor);
            tft.fillTriangle(tx - sz, ty + sz, tx + sz, ty + sz, tx, ty - sz, tColor);
            
            // Label
            tft.setTextColor(tColor); tft.setCursor(tx + 7, ty - 4);
            tft.print(tracks[i].id);
            
            selectIdx++;
        }
        
        // ── Plot waypoints (now cursor-selectable) ──
        for (int i = 0; i < WAYPOINT_MAX; i++) {
            if (!waypoints[i].valid) continue;
            double dist = _haversine(myLat, myLon, waypoints[i].lat, waypoints[i].lon);
            double brg = _bearing(myLat, myLon, waypoints[i].lat, waypoints[i].lon);
            double brgRad = brg * DEG_TO_RAD;
            double scale = (dist / maxDist) * mapR;
            int wx = mapCX + (int)(sin(brgRad) * scale);
            int wy = mapCY - (int)(cos(brgRad) * scale);
            wx = constrain(wx, 8, scrW - 8);
            wy = constrain(wy, 30, scrH - 60);
            uint16_t wColor;
            switch (waypoints[i].icon) {
                case WP_ICON_RALLY:   wColor = 0x07FF; break;
                case WP_ICON_HAZARD:  wColor = COLOR_RED; break;
                case WP_ICON_LKP:     wColor = 0xFD20; break;
                case WP_ICON_CAMP:    wColor = COLOR_GREEN; break;
                case WP_ICON_WATER:   wColor = COLOR_ACCENT; break;
                default:              wColor = 0x07FF; break;
            }
            bool selected = (mapCursorIdx == selectIdx);
            if (selected) tft.drawCircle(wx, wy, 8, COLOR_TEXT);
            tft.drawLine(wx, wy-4, wx+4, wy, wColor);
            tft.drawLine(wx+4, wy, wx, wy+4, wColor);
            tft.drawLine(wx, wy+4, wx-4, wy, wColor);
            tft.drawLine(wx-4, wy, wx, wy-4, wColor);
            tft.fillCircle(wx, wy, 1, wColor);
            tft.setTextColor(wColor); tft.setCursor(wx+6, wy-4);
            tft.print(waypoints[i].name);
            selectIdx++;
        }
        
        // ── INFO BAR: MGRS (left) + Bearing readout (right) ──
        // MGRS grid reference
        char mgrs[32];
        _latLonToMGRS(myLat, myLon, mgrs, sizeof(mgrs));
        tft.setTextColor(COLOR_DIM); tft.setCursor(4, infoY);
        tft.print(mgrs);
        
        // Bearing/distance readout for selected target (peers + tracks + waypoints)
        if (mapCursorIdx >= 0) {
            double selLat = 0, selLon = 0;
            const char* selName = "";
            int idx = 0;
            // Find selected peer
            for (int i = 0; i < peerCount && idx <= mapCursorIdx; i++) {
                if (!peers[i].hasPosition) continue;
                if (idx == mapCursorIdx) { selLat = peers[i].lat; selLon = peers[i].lon; selName = peers[i].callsign; }
                idx++;
            }
            // Find selected track
            for (int i = 0; i < TRACK_MAX && idx <= mapCursorIdx; i++) {
                if (!tracks[i].valid) continue;
                if (idx == mapCursorIdx) { selLat = tracks[i].lat; selLon = tracks[i].lon; selName = tracks[i].id; }
                idx++;
            }
            // Find selected waypoint
            for (int i = 0; i < WAYPOINT_MAX && idx <= mapCursorIdx; i++) {
                if (!waypoints[i].valid) continue;
                if (idx == mapCursorIdx) { selLat = waypoints[i].lat; selLon = waypoints[i].lon; selName = waypoints[i].name; }
                idx++;
            }
            if (selLat != 0 || selLon != 0) {
                double sDist = _haversine(myLat, myLon, selLat, selLon);
                double sBrg = _bearing(myLat, myLon, selLat, selLon);
                tft.setTextColor(COLOR_TEXT); tft.setCursor(4, infoY + 11);
                char distBuf[16];
                if (sDist < 1000) snprintf(distBuf, sizeof(distBuf), "%.0fm", sDist);
                else snprintf(distBuf, sizeof(distBuf), "%.1fkm", sDist / 1000.0);
                tft.printf("%s: %s %.0f%s %s", selName, distBuf, sBrg, "\xF8", _cardinal(sBrg));
            }
        } else {
            // No selection — show coordinates
            tft.setTextColor(COLOR_DIM); tft.setCursor(4, infoY + 11);
            tft.printf("%.5f, %.5f  [U/D:select]", myLat, myLon);
        }
    }
    
    // Status line
    tft.setTextColor(COLOR_DIM); tft.setCursor(4, btnY - 12);
    int trackTotal = track_getCount();
    int wpTotal = wp_getCount();
    tft.printf("Trk:%d WP:%d Mesh:%d", trackTotal, wpTotal, meshRelayCount);
    
    // Buttons
    _drawButton(4, btnY, 50, 28, "Drop", 0x07FF, 0x0000);
    _addButton(4, btnY, 50, 28, 'W');
    if (wp_getCount() > 0) {
        _drawButton(58, btnY, 42, 28, "Del", COLOR_BTN_RED, COLOR_TEXT);
        _addButton(58, btnY, 42, 28, 'X');
    }
    _drawButton(scrW - 56, btnY, 52, 28, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(scrW - 56, btnY, 52, 28, TB_BACK);
}

// ═══════════════════════════════════════════════════════════
// PTT — Shared push-to-talk function (callable from any screen)
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// VOICE MESSAGE STATE MACHINE
// Record → Preview → Send/Redo
// ═══════════════════════════════════════════════════════════

// Forward declarations for mic variables (defined in mic section below)
#ifndef MIC_SAMPLE_RATE
#define MIC_SAMPLE_RATE   16000
#endif
static int micBufPos = 0;  // Mic buffer write position (used by state machine and mic_record)

enum VoiceMsgState { VM_IDLE, VM_RECORDING, VM_PREVIEW };
static VoiceMsgState vmState = VM_IDLE;
static float vmRecordedDuration = 0;

static void _vmStartRecord() {
    if (!micInitialized || !codec2Ready) {
        Serial.println("[Voice] Mic/Codec2 not ready");
        return;
    }
    vmState = VM_RECORDING;
    uiState.dirty = true;
    
    // PTT activation beep
    ui_beep(1200, 50);
    
    // Clear content area before showing recording overlay
    tft.fillRect(0, 24, scrW, scrH - 24, COLOR_BG);
    tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_RED);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 60, scrH / 2 - 12);
    if (voiceTarget[0]) tft.printf("REC → %s", voiceTarget);
    else tft.print("REC — Broadcasting");
    tft.setCursor(scrW / 2 - 50, scrH / 2 + 2);
    tft.print("0.0s — V to Stop");
    
    // Record (interruptible — user presses V/Space/Enter to stop)
    int samples = mic_record(VOICE_RECORD_MS);
    
    if (samples < 4000) {  // Less than ~0.25s — too short
        Serial.printf("[Voice] Too short (%d samples), discarding\n", samples);
        vmState = VM_IDLE;
        tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_RED);
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(scrW / 2 - 40, scrH / 2 - 6);
        tft.print("Too short");
        delay(500);
        uiState.dirty = true;
        return;
    }
    
    vmRecordedDuration = samples / (float)MIC_SAMPLE_RATE;
    
    // Transition to PREVIEW — play raw audio
    vmState = VM_PREVIEW;
    
    // Clear content area for preview overlay
    tft.fillRect(0, 24, scrW, scrH - 24, COLOR_BG);
    tft.fillRect(0, scrH / 2 - 24, scrW, 52, COLOR_ACCENT);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 55, scrH / 2 - 18);
    tft.printf("Preview (%.1fs)", vmRecordedDuration);
    tft.setCursor(scrW / 2 - 45, scrH / 2 - 4);
    tft.print("Playing...");
    
    // Play raw mic buffer (full quality, no Codec2)
    mic_playback();
    
    // Show Send/Redo buttons
    tft.fillRect(0, scrH / 2 - 24, scrW, 52, COLOR_HEADER);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 35, scrH / 2 - 18);
    tft.printf("%.1fs recorded", vmRecordedDuration);
    
    // Draw Send button (green)
    int bw = 70, bh = 24, gap = 16;
    int sendX = scrW / 2 - bw - gap / 2;
    int redoX = scrW / 2 + gap / 2;
    int btnY = scrH / 2;
    
    tft.fillRoundRect(sendX, btnY, bw, bh, 4, COLOR_BTN_GREEN);
    tft.setTextColor(0x0000);  // Black text on green
    tft.setCursor(sendX + bw / 2 - 15, btnY + 7);
    tft.print("Send");
    _addButton(sendX, btnY, bw, bh, 'S');
    
    // Draw Redo button (red)
    tft.fillRoundRect(redoX, btnY, bw, bh, 4, COLOR_BTN_RED);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(redoX + bw / 2 - 15, btnY + 7);
    tft.print("Redo");
    _addButton(redoX, btnY, bw, bh, 'R');
    
    Serial.printf("[Voice] Preview: %.1fs, awaiting Send/Redo\n", vmRecordedDuration);
}

// Forward declaration — builds TX parts from already-encoded Codec2 data
static int _voicePackageEncoded();

static void _vmSend() {
    if (vmState != VM_PREVIEW || micBufPos == 0) return;
    
    // Show encoding banner (clear content area first)
    tft.fillRect(0, 24, scrW, scrH - 24, COLOR_BG);
    tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_YELLOW);
    tft.setTextColor(0x0000);
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 40, scrH / 2 - 6);
    tft.print("Encoding...");
    
    // Encode existing micBuffer with full DSP pipeline
    int encBytes = codec2_encodeMicBuffer();
    if (encBytes == 0) {
        tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_RED);
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(scrW / 2 - 35, scrH / 2 - 6);
        tft.print("Encode failed");
        vmState = VM_IDLE;
        uiState.dirty = true;
        return;
    }
    
    // Package encoded frames into TX parts
    int parts = _voicePackageEncoded();
    
    if (parts > 0) {
        float duration = codec2_getEncodedFrames() * 0.04f;
        tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_BTN_GREEN);
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(scrW / 2 - 55, scrH / 2 - 6);
        tft.printf("Sending %.1fs (%d parts)", duration, parts);
        
        const char* target = voiceTarget[0] ? voiceTarget : "*";
        _addVoiceLog(target, 0, duration, true);
        char label[32];
        snprintf(label, sizeof(label), "[Voice %.1fs]", duration);
        ui_addMessage("You", label, true, false);
        Serial.printf("[Voice] TX: %d parts (%.1fs)\n", parts, duration);
    } else {
        tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_RED);
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(scrW / 2 - 35, scrH / 2 - 6);
        tft.print("Package failed");
    }
    
    vmState = VM_IDLE;
    uiState.dirty = true;
}

static void _vmRedo() {
    Serial.println("[Voice] Redo — clearing recording");
    micBufPos = 0;
    vmState = VM_IDLE;
    uiState.dirty = true;
}

// Main PTT handler — routes based on state
static void _doPTT() {
    switch (vmState) {
        case VM_IDLE:
            _vmStartRecord();
            break;
        case VM_RECORDING:
            // mic_record handles stop internally via keyboard polling
            break;
        case VM_PREVIEW:
            // V in preview = Send
            _vmSend();
            break;
    }
}

// Voice loopback test: record → encode → decode → play locally (no radio TX)
static void _doVoiceTest() {
    if (!micInitialized || !codec2Ready) {
        Serial.println("[Test] Mic/Codec2 not ready");
        return;
    }
    
    // Clear content area before test overlay
    tft.fillRect(0, 24, scrW, scrH - 24, COLOR_BG);
    tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_RED);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 60, scrH / 2 - 12);
    tft.print("TEST — Recording");
    tft.setCursor(scrW / 2 - 50, scrH / 2 + 2);
    tft.print("0.0s — V to Stop");
    
    int samples = mic_record(VOICE_RECORD_MS);
    if (samples == 0) { uiState.dirty = true; return; }
    
    tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_YELLOW);
    tft.setTextColor(0x0000);
    tft.setCursor(scrW / 2 - 40, scrH / 2 - 6);
    tft.print("Encoding...");
    
    int encBytes = codec2_encodeMicBuffer();
    
    tft.setCursor(scrW / 2 - 40, scrH / 2 + 4);
    tft.print("Decoding...");
    
    codec2_decodeToBuffer(codec2_getEncodedBuf(), codec2_getEncodedFrames());
    
    tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_BTN_GREEN);
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(scrW / 2 - 60, scrH / 2 - 6);
    tft.printf("Playing %d frames (%d bytes)", codec2_getEncodedFrames(), encBytes);
    
    codec2_playDecoded();
    ui_beep(800, 50);
    uiState.dirty = true;
}

// ═══════════════════════════════════════════════════════════
// VOICE SCREEN — PTT button, activity log, channel info
// ═══════════════════════════════════════════════════════════

static void _drawVoiceScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Voice", true);
    
    int y = 28;
    
    // Channel + encryption status
    tft.setTextColor(COLOR_DIM);
    tft.setTextSize(1);
    tft.setCursor(8, y);
    tft.printf("CH%d (%.1fMHz)  %s", currentChannel, _channelToFreq(currentChannel),
               pskActive ? "Encrypted" : "PLAINTEXT");
    y += 14;
    
    // Codec2 status + voice mode
    tft.setCursor(8, y);
    if (codec2Ready) {
        tft.setTextColor(COLOR_GREEN);
        tft.printf("Codec2 %sbps  ", voiceModeBitrates[voiceMode]);
        uint16_t modeColor = (voiceMode == VMODE_RANGE) ? COLOR_ACCENT : 
                             (voiceMode == VMODE_BALANCED) ? COLOR_GREEN : COLOR_YELLOW;
        tft.setTextColor(modeColor);
        tft.printf("[%s]", voiceModeNames[voiceMode]);
    } else {
        tft.setTextColor(COLOR_RED);
        tft.print("Codec2 not available");
    }
    y += 16;
    
    // === Target selector ===
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(8, y);
    tft.print("To: ");
    
    // Left arrow button
    _drawButton(46, y - 2, 20, 14, "<", COLOR_HEADER, COLOR_DIM);
    _addButton(46, y - 2, 20, 14, TB_LEFT);
    
    // Target name
    int targetX = 72;
    if (voiceTarget[0] == '\0') {
        tft.setTextColor(COLOR_YELLOW);
        tft.setCursor(targetX, y);
        tft.print("ALL (broadcast)");
    } else {
        tft.setTextColor(COLOR_GREEN);
        tft.setCursor(targetX, y);
        tft.printf("%s (direct)", voiceTarget);
    }
    
    // Right arrow button
    _drawButton(scrW - 28, y - 2, 20, 14, ">", COLOR_HEADER, COLOR_DIM);
    _addButton(scrW - 28, y - 2, 20, 14, TB_RIGHT);
    
    y += 18;
    
    // === Large PTT button (center of screen) ===
    int pttW = 160, pttH = 48;
    int pttX = (scrW - pttW) / 2;
    int pttY = y;
    
    if (vmState == VM_PREVIEW) {
        // Preview mode — show Send/Redo buttons instead of PTT
        tft.setTextColor(COLOR_TEXT);
        tft.setTextSize(1);
        tft.setCursor(pttX + 10, pttY);
        tft.printf("%.1fs recorded", vmRecordedDuration);
        
        int bw = 70, bh = 32, gap = 16;
        int sendX = scrW / 2 - bw - gap / 2;
        int redoX = scrW / 2 + gap / 2;
        int btnY = pttY + 14;
        
        tft.fillRoundRect(sendX, btnY, bw, bh, 6, COLOR_BTN_GREEN);
        tft.setTextColor(0x0000);
        tft.setTextSize(2);
        tft.setCursor(sendX + bw / 2 - 24, btnY + 8);
        tft.print("Send");
        _addButton(sendX, btnY, bw, bh, 'S');
        
        tft.fillRoundRect(redoX, btnY, bw, bh, 6, COLOR_BTN_RED);
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(redoX + bw / 2 - 24, btnY + 8);
        tft.print("Redo");
        tft.setTextSize(1);
        _addButton(redoX, btnY, bw, bh, 'R');
    } else {
        // Normal PTT button
        uint16_t pttColor = (micInitialized && codec2Ready) ? COLOR_RED : COLOR_DIM;
        tft.fillRoundRect(pttX, pttY, pttW, pttH, 8, pttColor);
        tft.drawRoundRect(pttX, pttY, pttW, pttH, 8, COLOR_TEXT);
        tft.setTextColor(COLOR_TEXT);
        tft.setTextSize(2);
        tft.setCursor(pttX + pttW / 2 - 54, pttY + 8);
        tft.print("RECORD");
        tft.setTextSize(1);
        tft.setCursor(pttX + pttW / 2 - 55, pttY + 30);
        tft.print("V to record, preview, send");
        _addButton(pttX, pttY, pttW, pttH, 'V');
    }
    
    y = pttY + pttH + 10;
    
    // === Voice activity log ===
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y);
    tft.print("Recent voice activity:");
    y += 12;
    
    int logMaxY = scrH - 40;  // Stop before bottom nav buttons
    
    if (voiceLogCount == 0) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(16, y);
        tft.print("No voice activity yet");
    } else {
        for (int i = 0; i < voiceLogCount && i < VOICE_LOG_SIZE && y + 12 <= logMaxY; i++) {
            VoiceLogEntry& v = voiceLog[i];
            
            // Age
            char age[8];
            _fmtAge(v.timestamp, age, sizeof(age));
            
            // Color: outgoing=blue, incoming=yellow
            tft.setTextColor(v.outgoing ? COLOR_ACCENT : COLOR_YELLOW);
            tft.setCursor(8, y);
            
            if (v.outgoing) {
                if (v.callsign[0] == '*') {
                    tft.printf("TX ALL  %.1fs  %s", v.duration, age);
                } else {
                    tft.printf("TX→%s  %.1fs  %s", v.callsign, v.duration, age);
                }
            } else {
                tft.printf("RX %s  %.1fs  %.0fdBm  %s", 
                           v.callsign, v.duration, v.rssi, age);
            }
            y += 12;
        }
    }
    
    // Bottom nav — Clear, Test (local loopback), Home
    int btnY2 = scrH - 34;
    int navW = 56, navGap = 6;
    int navStartX = (scrW - (3 * navW + 2 * navGap)) / 2;
    
    uint16_t clrColor = voiceLogCount > 0 ? COLOR_RED : COLOR_DIM;
    _drawButton(navStartX, btnY2, navW, 28, "Clear", clrColor, COLOR_TEXT);
    _addButton(navStartX, btnY2, navW, 28, 'X');
    
    _drawButton(navStartX + navW + navGap, btnY2, navW, 28, "Test", COLOR_YELLOW, 0x0000);
    _addButton(navStartX + navW + navGap, btnY2, navW, 28, 'T');
    
    _drawButton(navStartX + 2 * (navW + navGap), btnY2, navW, 28, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(navStartX + 2 * (navW + navGap), btnY2, navW, 28, TB_BACK);
}

static bool pskEntryMode = false;
static bool callsignEntryMode = false;
static bool duressEntryMode = false;
static bool wipeSelectMode = false;       // Peer selection for remote wipe
static int  wipeSelectIdx = 0;            // Selected peer index
static bool wipeConfirmStage2 = false;    // Second confirmation ("Cannot undo")
static char pskBuffer[32] = {0};
static int pskBufLen = 0;

// ═══════════════════════════════════════════════════════════
// EMERGENCY BROADCAST — Hold 'E' for 2s from any screen
// Immediately broadcasts "BREAK BREAK BREAK" on current channel.
// Works even when screen is locked. Overrides all other input.
// ═══════════════════════════════════════════════════════════

static void _triggerEmergencyBroadcast() {
    Serial.println("[EMERGENCY] Broadcasting BREAK BREAK BREAK");
    
    // If scanning, stop scan and restore radio first
    if (scan_isActive()) {
        scan_stop();
        Serial.println("[EMERGENCY] Scan stopped for emergency broadcast");
    }
    
    // Force broadcast mode
    uiState.selectedContact = -1;
    
    // Build message with GPS if available
    double lat, lon, alt;
    if (ui_getGPS(&lat, &lon, &alt)) {
        snprintf(uiState.composeBuffer, sizeof(uiState.composeBuffer),
                 "BREAK BREAK BREAK [%.5f,%.5f]", lat, lon);
    } else {
        strncpy(uiState.composeBuffer, "BREAK BREAK BREAK", sizeof(uiState.composeBuffer));
    }
    uiState.composeLen = strlen(uiState.composeBuffer);
    composeReady = true;
    
    // Force Alerts channel for emergency — user stays on Alerts to see responses
    activeGroupCh = GROUP_CH_ALERTS;
    
    // Add to local message log (explicitly on Alerts channel)
    ui_addMessage("You", uiState.composeBuffer, true, false, GROUP_CH_ALERTS);
    
    // Full-screen red alert banner
    tft.fillScreen(COLOR_RED);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(2);
    tft.setCursor(scrW / 2 - 60, scrH / 2 - 30);
    tft.print("EMERGENCY");
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 72, scrH / 2);
    tft.print("BREAK BREAK BREAK sent");
    tft.setCursor(scrW / 2 - 60, scrH / 2 + 16);
    tft.print("Broadcast to ALL");
    
    // Alert tone — three ascending beeps
    ui_beep(800, 150);
    delay(80);
    ui_beep(1200, 150);
    delay(80);
    ui_beep(1600, 300);
    
    // Hold banner for 2 seconds then return to status
    delay(1500);
    
    // Unlock if locked (emergency overrides lock)
    if (screenLocked) {
        screenLocked = false;
        lockHoldStart = 0;
    }
    
    uiState.currentScreen = SCREEN_MESSAGES;
    uiState.scrollOffset = 0;
    uiState.dirty = true;
    emergencyHoldStart = 0;
}

// ═══════════════════════════════════════════════════════════
// BOOTLOADER MODE — Reboot into USB download mode for flashing
// Sets RTC register flag that survives soft reset, then restarts.
// ESP32-S3 ROM checks this flag on boot and enters USB serial
// bootloader instead of running firmware. Device stays in
// download mode until reflashed or hard power-cycled.
// ═══════════════════════════════════════════════════════════

static void _enterBootloader() {
    Serial.println("[System] Entering USB bootloader mode...");
    Serial.flush();
    
    // Show banner before reboot
    tft.fillScreen(0x0000);
    tft.setTextColor(COLOR_YELLOW);
    tft.setTextSize(2);
    tft.setCursor(scrW / 2 - 84, scrH / 2 - 24);
    tft.print("FLASH MODE");
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(scrW / 2 - 90, scrH / 2 + 4);
    tft.print("USB bootloader active.");
    tft.setCursor(scrW / 2 - 96, scrH / 2 + 20);
    tft.print("Run: pio run -e tdeck -t upload");
    tft.setCursor(scrW / 2 - 72, scrH / 2 + 38);
    tft.print("Power cycle to cancel.");
    delay(500);
    
    // Set RTC flag: force ROM bootloader on next reset
    SET_PERI_REG_MASK(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
    esp_restart();
    // Never reaches here
}

// ── Settings sub-screens: fully independent draw functions ──
// Each is routed via its own SCREEN_ enum in the ui_tick draw dispatch.
// This guarantees zero shared rendering with the main settings screen.

static void _drawWipeScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    
    if (!wipeConfirmStage2) {
        _drawHeader("Remote Wipe", true);
        int y = 30;
        tft.setTextColor(COLOR_RED);
        tft.setTextSize(1);
        tft.setCursor(8, y); tft.print("Select target device:"); y += 18;
        
        int visiblePeers = 0;
        for (int i = 0; i < peerCount; i++) {
            if (!peers[i].active) continue;
            if (y + 14 > scrH - 58) break;
            
            bool selected = (visiblePeers == wipeSelectIdx);
            if (selected) {
                tft.fillRect(4, y - 1, scrW - 8, 14, COLOR_RED);
                tft.setTextColor(0xFFFF);
            } else {
                tft.setTextColor(COLOR_DIM);
            }
            tft.setCursor(10, y);
            tft.printf("%s (%.0fdBm)", peers[i].callsign, peers[i].lastRSSI);
            
            y += 15;
            visiblePeers++;
        }
        
        {
            bool selected = (visiblePeers == wipeSelectIdx);
            if (selected) {
                tft.fillRect(4, y - 1, scrW - 8, 14, COLOR_RED);
                tft.setTextColor(0xFFFF);
            } else {
                tft.setTextColor(COLOR_YELLOW);
            }
            tft.setCursor(10, y);
            tft.print("[THIS DEVICE — local wipe]");
            visiblePeers++;
        }
        
        int maxIdx = visiblePeers > 0 ? visiblePeers - 1 : 0;
        if (wipeSelectIdx > maxIdx) wipeSelectIdx = maxIdx;
        
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(8, scrH - 56);
        tft.print("Up/Down = select");
        tft.setCursor(8, scrH - 44);
        tft.print("Enter  = confirm");
        
        int btnY = scrH - 28;
        _drawButton(scrW - 82, btnY, 74, 24, "Cancel", COLOR_HEADER, COLOR_TEXT);
        _addButton(scrW - 82, btnY, 74, 24, TB_BACK);
    } else {
        char wipeName[20] = {0};
        int visIdx = 0;
        for (int i = 0; i < peerCount; i++) {
            if (!peers[i].active) continue;
            if (visIdx == wipeSelectIdx) {
                strncpy(wipeName, peers[i].callsign, sizeof(wipeName) - 1);
                break;
            }
            visIdx++;
        }
        if (wipeName[0] == '\0') strncpy(wipeName, "THIS DEVICE", sizeof(wipeName) - 1);
        
        tft.fillRect(0, 0, scrW, 28, COLOR_RED);
        tft.setTextColor(0xFFFF);
        tft.setTextSize(2);
        tft.setCursor(24, 6);
        tft.print("CONFIRM WIPE");
        tft.setTextSize(1);
        
        int cy = scrH / 2 - 20;
        tft.setTextColor(0xFFFF);
        tft.setCursor(30, cy);
        tft.printf("Target: %s", wipeName); cy += 20;
        tft.setTextColor(COLOR_YELLOW);
        tft.setCursor(30, cy);
        tft.print("ALL data will be destroyed."); cy += 14;
        tft.setCursor(30, cy);
        tft.print("This CANNOT be undone.");
        
        int btnY = scrH - 28;
        _drawButton(8, btnY, 100, 24, "WIPE NOW", COLOR_BTN_RED, 0xFFFF);
        _addButton(8, btnY, 100, 24, '\n');
        _drawButton(scrW - 82, btnY, 74, 24, "Cancel", COLOR_HEADER, COLOR_TEXT);
        _addButton(scrW - 82, btnY, 74, 24, TB_BACK);
    }
}

static void _drawCallsignScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Set Callsign", true);
    int y = 34;
    tft.setTextColor(COLOR_ACCENT);
    tft.setTextSize(1);
    tft.setCursor(8, y); tft.print("Your callsign:"); y += 20;
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y); tft.print("(1-15 chars, shown to other T-Decks)"); y += 20;
    
    tft.drawRect(8, y, scrW - 16, 24, COLOR_DIM);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(12, y + 6);
    tft.print(pskBuffer);
    int cx = 12 + pskBufLen * 6;
    if ((millis() / 500) % 2) tft.fillRect(cx, y + 4, 6, 14, COLOR_ACCENT);
    
    int btnY = scrH - 34;
    if (pskBufLen >= 1) {
        _drawButton(8, btnY, 80, 28, "Save", COLOR_BTN_GREEN, COLOR_TEXT);
        _addButton(8, btnY, 80, 28, '\n');
    }
    _drawButton(scrW - 90, btnY, 82, 28, "Cancel", COLOR_BTN_RED, COLOR_TEXT);
    _addButton(scrW - 90, btnY, 82, 28, TB_BACK);
}

static void _drawPskScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Group PSK", true);
    int y = 34;
    tft.setTextColor(COLOR_ACCENT);
    tft.setTextSize(1);
    tft.setCursor(8, y); tft.print("Enter Group Passphrase:"); y += 20;
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y); tft.print("(min 4 chars, shared by all T-Decks)"); y += 20;
    
    tft.drawRect(8, y, scrW - 16, 24, COLOR_DIM);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(12, y + 6);
    tft.print(pskBuffer);
    int cx = 12 + pskBufLen * 6;
    if ((millis() / 500) % 2) tft.fillRect(cx, y + 4, 6, 14, COLOR_ACCENT);
    y += 40;
    
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y);
    tft.printf("Length: %d chars", pskBufLen);
    y += 16;
    
    tft.setTextColor(COLOR_YELLOW);
    tft.setCursor(8, y);
    tft.print("All devices must run v6.65+");
    y += 12;
    tft.setCursor(8, y);
    tft.print("for new passphrases to work");
    
    int btnY = scrH - 34;
    if (pskBufLen >= 4) {
        _drawButton(8, btnY, 80, 28, "Save", COLOR_BTN_GREEN, COLOR_TEXT);
        _addButton(8, btnY, 80, 28, '\n');
    }
    _drawButton(scrW - 90, btnY, 82, 28, "Cancel", COLOR_BTN_RED, COLOR_TEXT);
    _addButton(scrW - 90, btnY, 82, 28, TB_BACK);
    if (pskActive) {
        _drawButton(100, btnY, 80, 28, "Clear", COLOR_YELLOW, COLOR_BG);
        _addButton(100, btnY, 80, 28, 'X');
    }
}

static void _drawDuressScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Duress PIN", true);
    int y = 34;
    tft.setTextColor(COLOR_RED);
    tft.setTextSize(1);
    tft.setCursor(8, y); tft.print("Set Duress PIN (4 digits):"); y += 20;
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y); tft.print("Type PIN in any message to send"); y += 12;
    tft.setCursor(8, y); tft.print("silent distress alert to all peers"); y += 20;
    
    tft.drawRect(8, y, scrW - 16, 24, COLOR_DIM);
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(12, y + 6);
    for (int i = 0; i < pskBufLen; i++) tft.print("*");
    int cx = 12 + pskBufLen * 6;
    if ((millis() / 500) % 2) tft.fillRect(cx, y + 4, 6, 14, COLOR_ACCENT);
    y += 34;
    
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y); tft.printf("%d/4 digits", pskBufLen);
    y += 16;
    
    tft.setTextColor(COLOR_YELLOW);
    tft.setCursor(8, y); tft.print("PIN is stripped from sent message");
    y += 12;
    tft.setCursor(8, y); tft.print("Receiver sees normal text + alert");
    
    int btnY = scrH - 34;
    if (pskBufLen == 4) {
        _drawButton(8, btnY, 80, 28, "Save", COLOR_BTN_GREEN, COLOR_TEXT);
        _addButton(8, btnY, 80, 28, '\n');
    }
    _drawButton(scrW - 90, btnY, 82, 28, "Cancel", COLOR_BTN_RED, COLOR_TEXT);
    _addButton(scrW - 90, btnY, 82, 28, TB_BACK);
    if (duress_isSet()) {
        _drawButton(100, btnY, 80, 28, "Clear", COLOR_YELLOW, COLOR_BG);
        _addButton(100, btnY, 80, 28, 'X');
    }
}

static void _drawSettingsScreen() {
    // ── Normal settings screen — no entry mode checks ──
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Settings", true);
    
    int y = 34;
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    
    // Bottom buttons occupy fixed area — compute clipping boundary
    int btnH2 = 24, gap2 = 3;
    int row1Y2 = scrH - btnH2 * 2 - gap2 - 4;
    int row2Y2 = scrH - btnH2 - 2;
    int infoClip = row1Y2 - 2;  // Don't draw past this Y
    
    // Scrollable info area (settingsScroll is file-scope static)
    y -= settingsScroll;
    
    // Callsign
    if (y >= 26 && y < infoClip) {
        tft.setCursor(8, y);
        if (ui_callsignSet()) { tft.setTextColor(COLOR_GREEN); tft.printf("Callsign: %s", myCallsign); }
        else { tft.setTextColor(COLOR_RED); tft.print("Callsign: NOT SET"); }
    }
    y += 13;
    
    // Radio + WiFi (combined)
    if (y >= 26 && y < infoClip) {
        tft.setTextColor(COLOR_DIM); tft.setCursor(8, y);
        uint8_t wm = wifi_getMode();
        if (wm == WIFI_MODE_GD_AP) {
            tft.printf("CH%d (%.1fMHz)  WiFi:AP", currentChannel, _channelToFreq(currentChannel));
        } else if (wm == WIFI_MODE_GD_STA) {
            tft.printf("CH%d  WiFi:STA", currentChannel);
            if (wifi_staIsConnected()) {
                tft.setTextColor(COLOR_GREEN);
                tft.printf(" %s", wifi_getSTASSID());
            } else {
                tft.setTextColor(COLOR_YELLOW);
                tft.print(" ...");
            }
        } else {
            tft.printf("CH%d (%.1fMHz)  WiFi:OFF", currentChannel, _channelToFreq(currentChannel));
        }
    }
    y += 13;
    
    // Messages + Contacts
    if (y >= 26 && y < infoClip) {
        tft.setTextColor(COLOR_DIM); tft.setCursor(8, y);
        tft.printf("Msgs:%d  Contacts:%d", msgCount, contactCount);
    }
    y += 15;
    
    // PSK Encryption
    if (y >= 26 && y < infoClip) {
        tft.setCursor(8, y);
        if (pskActive) { tft.setTextColor(COLOR_GREEN); tft.printf("PSK: AES-256-GCM (KCV %s)", pskHint); }
        else { tft.setTextColor(COLOR_RED); tft.print("PSK: OFF (plaintext)"); }
    }
    y += 13;
    
    // SD Card
    if (y >= 26 && y < infoClip) {
        tft.setCursor(8, y);
        if (sdMounted) {
            uint64_t total = SD.totalBytes();
            uint64_t used = SD.usedBytes();
            uint64_t freeMB = (total - used) / (1024*1024);
            tft.setTextColor(COLOR_GREEN); tft.printf("SD:%lluMB ", freeMB);
            tft.setTextColor(COLOR_DIM); tft.printf("Log:%dM %dP %dG", sdMsgCount, sdPktCount, sdTrackPts);
        } else {
            tft.setTextColor(COLOR_RED); tft.print("SD: Not inserted");
        }
    }
    y += 15;
    
    // Proximity + Gunshot (same line)
    if (y >= 26 && y < infoClip) {
        tft.setCursor(8, y);
        if (proximityEnabled) {
            tft.setTextColor(COLOR_GREEN);
            if (proximityRadius < 1000) tft.printf("Prox:%lum", proximityRadius);
            else tft.printf("Prox:%.1fkm", proximityRadius / 1000.0);
        } else { tft.setTextColor(COLOR_RED); tft.print("Prox:OFF"); }
        tft.setCursor(scrW / 2, y);
        if (gdSensitivity > 0 && micInitialized) {
            tft.setTextColor(gdSensitivity == GD_SENS_HIGH ? COLOR_GREEN : COLOR_YELLOW);
            tft.printf("Shot:%s(%lu)", gdSensLabel[gdSensitivity], gdDetectionCount);
        } else if (!micInitialized) {
            tft.setTextColor(COLOR_DIM);
            tft.print("Shot:no mic");
        } else {
            tft.setTextColor(COLOR_RED);
            tft.print("Shot:OFF");
        }
    }
    y += 13;
    
    // CoT bridge
    if (y >= 26 && y < infoClip) {
        tft.setCursor(8, y);
        if (cotMode > 0) {
            tft.setTextColor(COLOR_GREEN); tft.printf("CoT:%s", cotModeShort[cotMode]);
            if (cotMode == COT_MODE_TCP || cotMode == COT_MODE_ALL) {
                tft.setTextColor(cot_takConnected() ? COLOR_GREEN : COLOR_RED);
                tft.printf(" %s", cot_takConnected() ? "conn" : "disc");
            }
        }
        else { tft.setTextColor(COLOR_DIM); tft.print("CoT: OFF"); }
        // Duress on same line (right side)
        tft.setCursor(scrW / 2 + 20, y);
        if (duress_isSet()) { tft.setTextColor(COLOR_GREEN); tft.printf("Duress:%s", duress_getHint()); }
        else { tft.setTextColor(COLOR_DIM); tft.print("Duress:--"); }
    }
    y += 13;
    
    // Shortcut hints
    if (y >= 26 && y < infoClip) {
        tft.setTextColor(COLOR_DIM);  // Shortcut hints
        tft.setCursor(8, y);
        tft.print("U=Duress PIN   D=Remote Wipe");
    }
    y += 13;
    if (y >= 26 && y < infoClip) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(8, y);
        tft.print("G=WiFi QR Code");
    }
    y += 13;
    if (y >= 26 && y < infoClip) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(8, y);
        tft.printf("F=WiFi Mode (%s)", wifi_modeLabel(wifi_getMode()));
    }
    y += 13;
    
    // Scroll indicator (if content extends beyond visible area)
    int totalInfoH = y + settingsScroll - 34;  // Total content height
    if (totalInfoH > infoClip - 34) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(scrW - 20, infoClip - 10);
        if (settingsScroll > 0) tft.print("^");  // Can scroll up
        if (y < infoClip) {} else tft.print("v");  // Can scroll down
    }
    
    // Bottom buttons — two rows (btnH2, gap2, row1Y2, row2Y2 declared above)
    
    // Row 1: Name, PSK, CH, Sound, Brightness
    _drawButton(2, row1Y2, 46, btnH2, "Name", ui_callsignSet() ? COLOR_BTN_GREEN : COLOR_BTN_RED, COLOR_TEXT);
    _addButton(2, row1Y2, 46, btnH2, 'N');
    
    _drawButton(52, row1Y2, 38, btnH2, "PSK", pskActive ? COLOR_BTN_GREEN : COLOR_BTN_RED, COLOR_TEXT);
    _addButton(52, row1Y2, 38, btnH2, 'K');
    
    char chLabel[8];
    snprintf(chLabel, sizeof(chLabel), "CH%d", currentChannel);
    _drawButton(94, row1Y2, 38, btnH2, chLabel, COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(94, row1Y2, 38, btnH2, 'R');
    
    _drawButton(136, row1Y2, 36, btnH2, audioMuted ? "Mte" : "Snd", 
                audioMuted ? COLOR_BTN_RED : COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(136, row1Y2, 36, btnH2, 'A');
    
    char brtLabel[8];
    snprintf(brtLabel, sizeof(brtLabel), "B:%s", brightnessNames[brightnessLevel]);
    _drawButton(176, row1Y2, 46, btnH2, brtLabel, COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(176, row1Y2, 46, btnH2, 'B');
    
    _drawButton(226, row1Y2, 36, btnH2, kbBrightness > 0 ? "Lit" : "Drk",
                kbBrightness > 0 ? COLOR_BTN_GREEN : COLOR_DIM,
                kbBrightness > 0 ? COLOR_TEXT : 0x0000);
    _addButton(226, row1Y2, 36, btnH2, 'L');
    
    _drawButton(scrW - 52, row1Y2, 48, btnH2, "Home", COLOR_HEADER, COLOR_TEXT);
    _addButton(scrW - 52, row1Y2, 48, btnH2, TB_BACK);
    
    // Row 2: Flash (bootloader), Voice mode
    _drawButton(2, row2Y2, 60, btnH2, "Flash", COLOR_YELLOW, 0x0000);
    _addButton(2, row2Y2, 60, btnH2, 'W');
    
    // Voice mode button (Range / Balanced / Clarity)
    char voxLabel[12];
    snprintf(voxLabel, sizeof(voxLabel), "V:%s", voiceModeNames[voiceMode]);
    uint16_t voxColor = (voiceMode == VMODE_RANGE) ? COLOR_BTN_ACCENT : 
                        (voiceMode == VMODE_BALANCED) ? COLOR_BTN_GREEN : COLOR_YELLOW;
    uint16_t voxText = (voiceMode == VMODE_CLARITY) ? 0x0000 : COLOR_TEXT;  // Black on yellow, white on others
    _drawButton(66, row2Y2, 68, btnH2, voxLabel, voxColor, voxText);
    _addButton(66, row2Y2, 68, btnH2, 'Q');
    
    // Proximity toggle/radius button
    char proxLabel[12];
    if (proximityEnabled) {
        if (proximityRadius < 1000)
            snprintf(proxLabel, sizeof(proxLabel), "P:%lum", proximityRadius);
        else
            snprintf(proxLabel, sizeof(proxLabel), "P:%.0fk", proximityRadius / 1000.0);
    } else {
        snprintf(proxLabel, sizeof(proxLabel), "P:Off");
    }
    _drawButton(138, row2Y2, 58, btnH2, proxLabel,
                proximityEnabled ? COLOR_BTN_GREEN : COLOR_DIM,
                proximityEnabled ? COLOR_TEXT : 0x0000);
    _addButton(138, row2Y2, 58, btnH2, 'P');
    
    // Gunshot detection sensitivity cycle
    bool gdActive = (gdSensitivity > 0 && micInitialized);
    uint16_t gdBtnColor = gdActive ? (gdSensitivity == GD_SENS_HIGH ? COLOR_BTN_GREEN : COLOR_YELLOW) : COLOR_DIM;
    uint16_t gdBtnText = (gdBtnColor == COLOR_YELLOW || gdBtnColor == COLOR_DIM) ? 0x0000 : COLOR_TEXT;
    _drawButton(200, row2Y2, 42, btnH2, gdSensShort[gdSensitivity], gdBtnColor, gdBtnText);
    _addButton(200, row2Y2, 42, btnH2, 'J');
    
    // CoT mode cycle button
    uint16_t cotBtnColor = COLOR_DIM;
    if (cotMode == COT_MODE_MCAST) cotBtnColor = COLOR_BTN_GREEN;
    else if (cotMode == COT_MODE_TCP) cotBtnColor = (cot_takConnected() ? COLOR_BTN_GREEN : COLOR_YELLOW);
    else if (cotMode == COT_MODE_ALL) cotBtnColor = COLOR_BTN_ACCENT;
    uint16_t cotBtnText = (cotBtnColor == COLOR_YELLOW || cotBtnColor == COLOR_DIM) ? 0x0000 : COLOR_TEXT;
    _drawButton(246, row2Y2, 38, btnH2, cotModeShort[cotMode], cotBtnColor, cotBtnText);
    _addButton(246, row2Y2, 38, btnH2, 'T');
    
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(288, row2Y2 + 8);
    tft.print(GRIDDOWN_FW_VERSION);
}

// ═══════════════════════════════════════════════════════════
// PEERS SCREEN — Node list with signal, distance, last heard
// ═══════════════════════════════════════════════════════════

// ── Peer Health Dashboard — compact overview of team status ──
// Activated by pressing 'H' on the Peers screen.
// Shows: callsign, battery bar, signal quality bar, RSSI, last-heard age.
// Fits all peers on one screen (up to 16) without scrolling for quick team glance.
static void _drawPeerHealthDashboard() {
    _clearButtons();
    _drawHeader("Team Health", true);
    
    int y = 26;
    
    if (peerCount == 0) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(scrW / 2 - 50, scrH / 2 - 8);
        tft.print("No peers heard");
        int btnY2 = scrH - 20;
        _drawButton(4, btnY2, 50, 16, "Peers", COLOR_BTN_ACCENT, COLOR_TEXT);
        _addButton(4, btnY2, 50, 16, 'H');
        _drawButton(scrW - 54, btnY2, 50, 16, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
        _addButton(scrW - 54, btnY2, 50, 16, TB_BACK);
        return;
    }
    
    // Column header
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(4, y);    tft.print("CALL");
    tft.setCursor(68, y);   tft.print("BAT");
    tft.setCursor(128, y);  tft.print("SIG");
    tft.setCursor(188, y);  tft.print("RSSI");
    tft.setCursor(232, y);  tft.print("HOP");
    tft.setCursor(262, y);  tft.print("AGO");
    y += 12;
    
    // Separator line
    tft.drawFastHLine(4, y, scrW - 8, COLOR_DIM);
    y += 3;
    
    // Compact row per peer — fits ~12 rows before bottom buttons
    int lineH = 14;
    for (int i = 0; i < peerCount && y + lineH <= scrH - 24; i++) {
        Peer& p = peers[i];
        
        // Determine staleness (>120s since last heard = stale)
        uint32_t age = millis() - p.lastSeen;
        bool stale = (age > 120000);
        
        // Callsign (truncated to 8 chars for compact display)
        tft.setTextColor(stale ? COLOR_DIM : COLOR_TEXT);
        tft.setCursor(4, y);
        char shortName[9];
        strncpy(shortName, p.callsign, 8);
        shortName[8] = '\0';
        tft.print(shortName);
        
        // Battery bar (20px wide)
        int batX = 68, batW = 24, batH = 8;
        if (p.battery > 0) {
            int batFill = (int)((float)p.battery / 100.0f * batW);
            uint16_t batColor = p.battery > 50 ? COLOR_GREEN : (p.battery > 20 ? COLOR_YELLOW : COLOR_RED);
            tft.fillRect(batX, y + 1, batW, batH, 0x2104);          // Background
            tft.fillRect(batX, y + 1, batFill, batH, batColor);     // Fill
            tft.drawRect(batX, y + 1, batW, batH, COLOR_DIM);       // Border
            // Battery nub
            tft.fillRect(batX + batW, y + 3, 2, 4, COLOR_DIM);
            // Percentage text
            tft.setTextColor(batColor);
            tft.setCursor(batX + batW + 4, y);
            tft.printf("%d", p.battery);
        } else {
            tft.setTextColor(COLOR_DIM);
            tft.setCursor(batX, y);
            tft.print("--");
        }
        
        // Signal quality bar (20px wide)
        int sigX = 128, sigW = 24, sigH = 8;
        int sigFill = (int)((float)p.linkQuality / 100.0f * sigW);
        uint16_t sigColor = p.linkQuality > 60 ? COLOR_GREEN : (p.linkQuality > 30 ? COLOR_YELLOW : COLOR_RED);
        if (stale) sigColor = COLOR_DIM;
        tft.fillRect(sigX, y + 1, sigW, sigH, 0x2104);
        tft.fillRect(sigX, y + 1, sigFill, sigH, sigColor);
        tft.drawRect(sigX, y + 1, sigW, sigH, COLOR_DIM);
        tft.setTextColor(sigColor);
        tft.setCursor(sigX + sigW + 3, y);
        tft.printf("%d", p.linkQuality);
        
        // RSSI value
        tft.setCursor(188, y);
        uint16_t rssiColor = p.lastRSSI > -90 ? COLOR_GREEN : (p.lastRSSI > -110 ? COLOR_YELLOW : COLOR_RED);
        if (stale) rssiColor = COLOR_DIM;
        tft.setTextColor(rssiColor);
        tft.printf("%.0f", p.lastRSSI);
        
        // Hop count
        tft.setCursor(236, y);
        if (p.lastHops == 0) { tft.setTextColor(COLOR_GREEN); tft.print("D"); }
        else { tft.setTextColor(COLOR_YELLOW); tft.printf("%d", p.lastHops); }
        
        // Last heard age
        char ageStr[8];
        _fmtAge(p.lastSeen, ageStr, sizeof(ageStr));
        tft.setCursor(262, y);
        tft.setTextColor(stale ? COLOR_RED : COLOR_DIM);
        tft.print(ageStr);
        
        y += lineH;
    }
    
    // Bottom bar: own battery + buttons
    int btnY = scrH - 20;
    extern uint8_t getBatteryPercent();
    extern bool isUsbCharging();
    uint8_t myBat = getBatteryPercent();
    bool myUsb = isUsbCharging();
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(4, btnY + 2);
    tft.printf("Me:%d%%", myBat);
    if (myUsb) { tft.setTextColor(0x07FF); tft.print("+"); }
    
    _drawButton(scrW / 2 - 40, btnY, 36, 16, "List", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(scrW / 2 - 40, btnY, 36, 16, 'H');
    _drawButton(scrW / 2 + 4, btnY, 40, 16, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(scrW / 2 + 4, btnY, 40, 16, TB_BACK);
}

static void _drawPeersScreen() {
    // Health dashboard toggle (H key)
    if (peerHealthView) {
        _drawPeerHealthDashboard();
        return;
    }
    
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Peers", true);
    
    int y = 28;
    
    if (peerCount == 0) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(scrW / 2 - 50, scrH / 2 - 8);
        tft.print("No peers heard");
        int btnY2 = scrH - 34;
        _drawButton(scrW / 2 - 40, btnY2, 80, 28, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
        _addButton(scrW / 2 - 40, btnY2, 80, 28, TB_BACK);
        return;
    }
    
    // Clamp scroll
    if (peerScrollIdx >= peerCount) peerScrollIdx = peerCount - 1;
    if (peerScrollIdx < 0) peerScrollIdx = 0;
    
    int lineH = 36;
    int maxVis = (scrH - 68) / lineH;  // Header + bottom bar
    int startIdx = 0;
    if (peerScrollIdx >= maxVis) startIdx = peerScrollIdx - maxVis + 1;
    
    for (int i = startIdx; i < peerCount && y + lineH <= scrH - 38; i++) {
        Peer& p = peers[i];
        bool selected = (i == peerScrollIdx);
        
        if (selected) tft.fillRect(0, y, scrW, lineH - 2, COLOR_HEADER);
        
        // Callsign + hop indicator
        uint16_t nameColor = p.active ? COLOR_GREEN : COLOR_DIM;
        tft.setTextColor(nameColor);
        tft.setTextSize(1);
        tft.setCursor(8, y + 2);
        tft.print(p.callsign);
        // Hop badge: D=direct, 1H/2H=relayed
        tft.setCursor(8 + strlen(p.callsign) * 6 + 4, y + 2);
        if (p.lastHops == 0) { tft.setTextColor(COLOR_GREEN); tft.print("D"); }
        else { tft.setTextColor(COLOR_YELLOW); tft.printf("%dH", p.lastHops); }
        // E2E badge: shows when ephemeral session key is established
        if (p.hasSessionKey) {
            tft.setTextColor(0x07FF);  // Cyan
            tft.print(" E2E");
        }
        
        // Link quality bar (0-100%, colored)
        int qBarX = 110, qBarW = 40, qBarH = 6;
        int qFill = (int)(p.linkQuality / 100.0f * qBarW);
        uint16_t qColor = p.linkQuality > 60 ? COLOR_GREEN : (p.linkQuality > 30 ? COLOR_YELLOW : COLOR_RED);
        tft.fillRect(qBarX, y + 4, qBarW, qBarH, 0x2104);
        tft.fillRect(qBarX, y + 4, qFill, qBarH, qColor);
        tft.setTextColor(COLOR_DIM); tft.setCursor(qBarX + qBarW + 3, y + 2);
        tft.printf("%d%%", p.linkQuality);
        
        // RSSI + SNR
        tft.setCursor(190, y + 2);
        tft.setTextColor(p.lastRSSI > -90 ? COLOR_GREEN : (p.lastRSSI > -110 ? COLOR_YELLOW : COLOR_RED));
        tft.printf("%.0f", p.lastRSSI);
        tft.setTextColor(COLOR_DIM);
        tft.printf("/%.0f", p.lastSNR);
        
        // Last heard age (right edge)
        char age[8];
        _fmtAge(p.lastSeen, age, sizeof(age));
        tft.setCursor(scrW - 36, y + 2);
        tft.setTextColor(p.active ? COLOR_DIM : COLOR_RED);
        tft.print(age);
        
        // Second line: position + rx count
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(16, y + 16);
        if (p.hasPosition) {
            double myLat, myLon, myAlt;
            if (ui_getGPS(&myLat, &myLon, &myAlt)) {
                double d = _haversine(myLat, myLon, p.lat, p.lon);
                double brg = _bearing(myLat, myLon, p.lat, p.lon);
                if (d < 1000) tft.printf("%.0fm %.0f°", d, brg);
                else tft.printf("%.1fkm %.0f°", d / 1000, brg);
            } else {
                tft.printf("%.5f, %.5f", p.lat, p.lon);
            }
        } else {
            tft.print("No position");
        }
        tft.setCursor(scrW - 60, y + 16);
        tft.setTextColor(COLOR_DIM);
        tft.printf("rx:%d", p.rxCount);
        
        y += lineH;
    }
    
    // Scroll indicator
    if (peerCount > maxVis) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(scrW - 60, scrH - 50);
        tft.printf("%d/%d", peerScrollIdx + 1, peerCount);
    }
    
    // Bottom nav
    int btnY2 = scrH - 34;
    _drawButton(4, btnY2, 60, 28, "Health", COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(4, btnY2, 60, 28, 'H');
    _drawButton(scrW - 64, btnY2, 60, 28, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(scrW - 64, btnY2, 60, 28, TB_BACK);
}

// ═══════════════════════════════════════════════════════════
// IMAGES SCREEN — On-device JPEG decode + display (Phase 5)
// ═══════════════════════════════════════════════════════════
// Lists received images from /img_recv/ on SD card with sender, age,
// and file size. Selected image is decoded with TJpgDec and displayed
// full-screen on the 320×240 ST7789. Storage cap: 50 images, oldest auto-deleted.

#include <TJpg_Decoder.h>

#define IMG_VIEW_DIR        "/img_recv"
#define IMG_SEND_DIR        "/img_send"   // Operator outbox (pre-staged JPEGs to transmit)

// Image list source: received inbox vs operator-staged outbox.
enum ImgListSource { IMG_SRC_RECV = 0, IMG_SRC_SEND = 1 };

// On-device SD send (defined in main.cpp). Int-returning wrappers so this
// translation unit does not need the ImgSendResult enum. 0 == success.
extern int img_loadAndSendFromSD_c(const char* path);
extern const char* img_sendResultStr_c(int r);
#define IMG_VIEW_MAX_FILES  50    // Storage cap (oldest auto-pruned)
#define IMG_VIEW_LIST_MAX   30    // UI list capacity (subset of files)

struct ImgFile {
    char     path[80];
    char     sender[16];
    char     filename[32];   // Display name
    uint32_t size;
    uint32_t mtime;          // Sort key (file modification time, or seconds-from-name)
};

static ImgFile imgList[IMG_VIEW_LIST_MAX];
static int     imgListCount = 0;
static int     imgListSel = 0;            // Cursor (selected entry in list view)
static int     imgListScroll = 0;         // Top of visible window
static bool    imgFullView = false;       // false=list, true=full-screen image
static uint32_t imgListLastScan = 0;      // Re-scan SD periodically
static ImgListSource imgListSrc = IMG_SRC_RECV;  // Which directory the list shows

// TJpgDec callback — draws decoded JPEG block to TFT
static bool _img_jpgRender(int16_t x, int16_t y, uint16_t w, uint16_t h, uint16_t* bitmap) {
    if (y >= scrH) return false;  // Stop decoding (clipped)
    tft.pushImage(x, y, w, h, bitmap);
    return true;  // Continue
}

// Parse a filename like "ALPHA_1234567_ABCD.jpg" → sender="ALPHA", mtime=1234567
static void _img_parseFilename(const char* fname, ImgFile* out) {
    out->sender[0] = '\0';
    out->mtime = 0;
    strncpy(out->filename, fname, sizeof(out->filename) - 1);
    out->filename[sizeof(out->filename) - 1] = '\0';
    
    // Extract sender (chars before first '_')
    const char* underscore = strchr(fname, '_');
    if (!underscore) return;
    int senderLen = (int)(underscore - fname);
    if (senderLen >= (int)sizeof(out->sender)) senderLen = sizeof(out->sender) - 1;
    memcpy(out->sender, fname, senderLen);
    out->sender[senderLen] = '\0';
    
    // Extract timestamp (chars between first and second '_')
    const char* p = underscore + 1;
    uint32_t ts = 0;
    while (*p >= '0' && *p <= '9') { ts = ts * 10 + (*p - '0'); p++; }
    out->mtime = ts;
}

// Scan SD card directory, populate imgList[], sort newest-first
static void _img_scanList() {
    imgListCount = 0;
    if (!sdMounted) return;
    
    // Two-pass: count + collect-into-temp, sort, then take newest IMG_VIEW_LIST_MAX.
    // Single-pass loading (load first N, then sort) is wrong because directory
    // enumeration order isn't mtime-sorted — older files at the start would
    // crowd out newer files past IMG_VIEW_LIST_MAX.
    const char* scanDir = (imgListSrc == IMG_SRC_SEND) ? IMG_SEND_DIR : IMG_VIEW_DIR;
    File dir = SD.open(scanDir);
    if (!dir || !dir.isDirectory()) return;
    
    // Use a static temp buffer sized to IMG_VIEW_MAX_FILES so we can hold all
    // candidates before sorting. ~80 bytes/entry × 50 = 4KB on stack ok.
    static ImgFile temp[IMG_VIEW_MAX_FILES];
    int tempCount = 0;
    
    File f = dir.openNextFile();
    while (f && tempCount < IMG_VIEW_MAX_FILES) {
        if (!f.isDirectory()) {
            const char* fname = f.name();
            const char* basename = strrchr(fname, '/');
            basename = basename ? basename + 1 : fname;
            int flen = strlen(basename);
            if (flen > 4 && (strcasecmp(basename + flen - 4, ".jpg") == 0)) {
                ImgFile* slot = &temp[tempCount];
                _img_parseFilename(basename, slot);
                slot->size = f.size();
                snprintf(slot->path, sizeof(slot->path), "%s/%s", scanDir, basename);
                tempCount++;
            }
        }
        f.close();
        f = dir.openNextFile();
    }
    dir.close();
    
    // Sort newest-first (descending mtime)
    for (int i = 0; i < tempCount - 1; i++) {
        for (int j = i + 1; j < tempCount; j++) {
            if (temp[j].mtime > temp[i].mtime) {
                ImgFile tmp = temp[i]; temp[i] = temp[j]; temp[j] = tmp;
            }
        }
    }
    
    // Take top IMG_VIEW_LIST_MAX into the visible list
    int copyCount = tempCount > IMG_VIEW_LIST_MAX ? IMG_VIEW_LIST_MAX : tempCount;
    for (int i = 0; i < copyCount; i++) imgList[i] = temp[i];
    imgListCount = copyCount;
    
    // Clamp cursor and scroll to valid range
    if (imgListSel >= imgListCount) imgListSel = imgListCount - 1;
    if (imgListSel < 0) imgListSel = 0;
}

// Storage cap enforcement — delete oldest files when count exceeds IMG_VIEW_MAX_FILES.
// Called on entry to the Images screen and after manual deletes.
void img_pruneOldest() {
    if (!sdMounted) return;
    
    // Collect ALL files (not bounded by IMG_VIEW_LIST_MAX) and find oldest
    // We do this in passes to avoid a second large array on the stack.
    File dir = SD.open(IMG_VIEW_DIR);
    if (!dir || !dir.isDirectory()) return;
    
    int totalCount = 0;
    File f = dir.openNextFile();
    while (f) {
        if (!f.isDirectory()) {
            const char* nm = f.name();
            int nlen = strlen(nm);
            if (nlen > 4 && strcasecmp(nm + nlen - 4, ".jpg") == 0) totalCount++;
        }
        f.close();
        f = dir.openNextFile();
    }
    dir.close();
    
    while (totalCount > IMG_VIEW_MAX_FILES) {
        // Find single oldest file in this pass
        char oldestPath[80] = {0};
        uint32_t oldestTs = UINT32_MAX;
        
        File d2 = SD.open(IMG_VIEW_DIR);
        if (!d2 || !d2.isDirectory()) return;
        
        File ff = d2.openNextFile();
        while (ff) {
            if (!ff.isDirectory()) {
                const char* nm = ff.name();
                const char* base = strrchr(nm, '/'); base = base ? base + 1 : nm;
                int blen = strlen(base);
                if (blen > 4 && strcasecmp(base + blen - 4, ".jpg") == 0) {
                    ImgFile probe;
                    _img_parseFilename(base, &probe);
                    if (probe.mtime < oldestTs) {
                        oldestTs = probe.mtime;
                        snprintf(oldestPath, sizeof(oldestPath), "%s/%s", IMG_VIEW_DIR, base);
                    }
                }
            }
            ff.close();
            ff = d2.openNextFile();
        }
        d2.close();
        
        if (oldestPath[0]) {
            SD.remove(oldestPath);
            Serial.printf("[Images] Pruned oldest: %s\n", oldestPath);
            totalCount--;
        } else break;
    }
}

// Format an age string from mtime (seconds since boot ago)
static void _img_ageStr(uint32_t mtimeSec, char* out, size_t outSize) {
    uint32_t nowSec = millis() / 1000;
    if (mtimeSec == 0 || mtimeSec > nowSec) {
        snprintf(out, outSize, "?");
        return;
    }
    uint32_t age = nowSec - mtimeSec;
    if (age < 60)         snprintf(out, outSize, "%us", age);
    else if (age < 3600)  snprintf(out, outSize, "%um", age / 60);
    else if (age < 86400) snprintf(out, outSize, "%uh", age / 3600);
    else                  snprintf(out, outSize, "%ud", age / 86400);
}

// Draw a compact size string (e.g. "4.2K", "812B")
static void _img_sizeStr(uint32_t bytes, char* out, size_t outSize) {
    if (bytes < 1024) snprintf(out, outSize, "%uB", bytes);
    else snprintf(out, outSize, "%.1fK", bytes / 1024.0f);
}

// Render the list view — sender, filename, age, size per row
// Helper: render TX progress banner at given Y. Returns Y after banner.
// Caller is responsible for ensuring img_isTxActive() returned true.
static int _drawImageTxBanner(int y) {
    int bannerH = 38;
    // Background gradient (blue tint for active TX)
    tft.fillRect(0, y, scrW, bannerH, 0x10A6);  // Dark blue
    tft.drawFastHLine(0, y + bannerH - 1, scrW, COLOR_ACCENT);
    
    // Filename + size
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(6, y + 4);
    const char* fname = img_txFilename();
    char hdrLine[42];
    size_t bytes = img_txTotalBytes();
    char sizeBuf[12];
    if (bytes < 1024) snprintf(sizeBuf, sizeof(sizeBuf), "%uB", (unsigned)bytes);
    else snprintf(sizeBuf, sizeof(sizeBuf), "%.1fK", bytes / 1024.0f);
    snprintf(hdrLine, sizeof(hdrLine), "TX: %.18s %s", fname[0] ? fname : "image", sizeBuf);
    tft.print(hdrLine);
    
    // Progress bar
    int barY = y + 16;
    int barX = 6;
    int barW = scrW - 12;
    int barH = 8;
    tft.drawRect(barX, barY, barW, barH, COLOR_DIM);
    int fillW = (img_txProgress() * (barW - 2)) / 100;
    if (fillW > 0) tft.fillRect(barX + 1, barY + 1, fillW, barH - 2, COLOR_ACCENT);
    
    // Status line: chunk N/M, retry, ETA
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(6, y + 27);
    uint16_t cur = img_txCurrentChunk();
    uint16_t tot = img_txTotalChunks();
    uint8_t retry = img_txRetryRound();
    uint16_t eta = img_txEtaSeconds();
    char statusLine[48];
    if (retry > 0) {
        snprintf(statusLine, sizeof(statusLine),
                 "Chunk %u/%u  retry %u/3  ~%us  [X=cancel]",
                 cur, tot, retry, eta);
    } else {
        snprintf(statusLine, sizeof(statusLine),
                 "Chunk %u/%u  ~%us remaining  [X=cancel]",
                 cur, tot, eta);
    }
    tft.print(statusLine);
    
    return y + bannerH + 2;  // Return Y for next element
}

static void _drawImagesListView() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Images", true);
    
    int contentY = 28;  // Below header
    
    // Phase 7: TX progress banner at top when an image is being transmitted
    bool txActive = img_isTxActive();
    if (txActive) {
        contentY = _drawImageTxBanner(contentY);
    }
    
    if (!sdMounted) {
        tft.setTextColor(COLOR_RED);
        tft.setCursor(10, contentY + 18);
        tft.print("No SD card mounted");
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(10, contentY + 38);
        tft.print("Image RX requires SD storage");
        return;
    }
    
    if (imgListCount == 0) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(10, contentY + 18);
        if (imgListSrc == IMG_SRC_SEND) {
            tft.print("Outbox empty");
            tft.setCursor(10, contentY + 38);
            tft.print("Put <=8KB JPEGs in /img_send/ on SD");
            tft.setCursor(10, contentY + 54);
            tft.print("Press T to view Received");
        } else {
            tft.print("No images received yet");
            tft.setCursor(10, contentY + 38);
            tft.print("Images arrive over LoRa from peers");
            tft.setCursor(10, contentY + 54);
            tft.print("Press T for Outbox (send from SD)");
        }
        return;
    }
    
    // Header row
    tft.setTextColor(COLOR_DIM);
    tft.setTextSize(1);
    tft.setCursor(8, contentY);
    if (imgListSrc == IMG_SRC_SEND) {
        tft.printf("OUTBOX: %d image%s  (S=send, T=received)",
                   imgListCount, imgListCount == 1 ? "" : "s");
    } else {
        tft.printf("RECEIVED: %d  (S=re-send, T=outbox)", imgListCount);
    }
    
    // List entries — variable rows depending on TX banner presence
    const int rowHeight = 26;
    const int listTop = txActive ? 90 : 48;  // 90 leaves room for 38px TX banner + spacing
    const int btnY = scrH - 28;
    const int maxRows = (btnY - listTop - 4) / rowHeight;
    
    if (imgListSel < imgListScroll) imgListScroll = imgListSel;
    if (imgListSel >= imgListScroll + maxRows) imgListScroll = imgListSel - maxRows + 1;
    if (imgListScroll < 0) imgListScroll = 0;
    
    for (int row = 0; row < maxRows; row++) {
        int idx = imgListScroll + row;
        if (idx >= imgListCount) break;
        
        ImgFile& f = imgList[idx];
        int y = listTop + row * rowHeight;
        bool selected = (idx == imgListSel);
        
        if (selected) {
            tft.fillRect(2, y - 2, scrW - 4, rowHeight - 2, 0x10A2);  // Highlight bar
        }
        
        // Sender (left)
        tft.setTextColor(selected ? COLOR_TEXT : COLOR_GREEN);
        tft.setCursor(8, y);
        tft.print(f.sender[0] ? f.sender : "?");
        
        // Age + size (right-aligned)
        char ageBuf[12], sizeBuf[12];
        _img_ageStr(f.mtime, ageBuf, sizeof(ageBuf));
        _img_sizeStr(f.size, sizeBuf, sizeof(sizeBuf));
        char rightStr[24];
        snprintf(rightStr, sizeof(rightStr), "%s %s", sizeBuf, ageBuf);
        int rightW = strlen(rightStr) * 6;
        tft.setTextColor(selected ? COLOR_TEXT : COLOR_DIM);
        tft.setCursor(scrW - 8 - rightW, y);
        tft.print(rightStr);
        
        // Filename (second line, dimmer)
        tft.setTextColor(selected ? COLOR_TEXT : COLOR_DIM);
        tft.setCursor(8, y + 11);
        char shortName[28];
        strncpy(shortName, f.filename, sizeof(shortName) - 1);
        shortName[sizeof(shortName) - 1] = '\0';
        tft.print(shortName);
    }
    
    // Scroll indicator if list overflows
    if (imgListCount > maxRows) {
        int barH = (maxRows * (btnY - listTop - 4)) / imgListCount;
        int barY = listTop + (imgListScroll * (btnY - listTop - 4)) / imgListCount;
        tft.fillRect(scrW - 3, barY, 2, barH, COLOR_ACCENT);
    }
    
    // Buttons: View | Delete | Home
    _drawButton(2, btnY, 42, 24, "View", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(2, btnY, 42, 24, '\n');
    _drawButton(46, btnY, 44, 24, "Send", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(46, btnY, 44, 24, 'S');
    _drawButton(92, btnY, 38, 24, "Src", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(92, btnY, 38, 24, 'T');
    _drawButton(132, btnY, 38, 24, "Del", COLOR_BTN_RED, COLOR_TEXT);
    _addButton(132, btnY, 38, 24, 'X');
    _drawButton(scrW - 56, btnY, 52, 24, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(scrW - 56, btnY, 52, 24, TB_BACK);
}

// Render full-screen JPEG decode of selected image
static void _drawImagesFullView() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    
    if (imgListSel < 0 || imgListSel >= imgListCount) {
        imgFullView = false;
        return;
    }
    
    ImgFile& f = imgList[imgListSel];
    
    // Decode JPEG from SD card directly to display
    TJpgDec.setJpgScale(1);          // 1:1 (no downscaling)
    TJpgDec.setSwapBytes(true);
    TJpgDec.setCallback(_img_jpgRender);
    
    // Center the image. JPEG dimensions retrieved before decoding.
    uint16_t w = 0, h = 0;
    if (TJpgDec.getSdJpgSize(&w, &h, f.path) == 0) {
        // Successfully read dimensions
    }
    int xOff = (scrW > (int)w) ? (scrW - (int)w) / 2 : 0;
    int yOff = (scrH > (int)h) ? (scrH - (int)h) / 2 : 0;
    if (yOff > 30) yOff = 30;  // Leave room for header banner
    
    // Decode and render
    if (TJpgDec.drawSdJpg(xOff, yOff, f.path) != 0) {
        // Decode failed — show error message
        tft.fillScreen(COLOR_BG);
        tft.setTextColor(COLOR_RED);
        tft.setTextSize(1);
        tft.setCursor(10, 50);
        tft.print("Decode failed:");
        tft.setCursor(10, 70);
        tft.print(f.path);
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(10, 90);
        tft.print("File may be corrupt or not a JPEG");
    }
    
    // Translucent footer bar with metadata
    int barY = scrH - 18;
    tft.fillRect(0, barY, scrW, 18, 0x10A2);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(4, barY + 5);
    char sizeBuf[12], ageBuf[12];
    _img_sizeStr(f.size, sizeBuf, sizeof(sizeBuf));
    _img_ageStr(f.mtime, ageBuf, sizeof(ageBuf));
    tft.printf("%s  %s  %s  [%d/%d]",
               f.sender[0] ? f.sender : "?",
               sizeBuf, ageBuf,
               imgListSel + 1, imgListCount);
}

// Public draw entry point — called from screen dispatch
static void _drawImagesScreen() {
    if (imgFullView) _drawImagesFullView();
    else _drawImagesListView();
}

// Send the currently-selected image over LoRa (on-device, no tablet).
// Works for both the Outbox (/img_send) and Received (/img_recv, re-share) lists.
static void _img_sendSelected() {
    if (imgListSel < 0 || imgListSel >= imgListCount) return;
    if (img_txCanCancel()) {
        ui_addMessage("SYSTEM", "Image TX busy - cancel current first", true, false, GROUP_CH_ALERTS);
        return;
    }
    const char* path = imgList[imgListSel].path;
    int r = img_loadAndSendFromSD_c(path);
    char msg[64];
    if (r == 0) snprintf(msg, sizeof(msg), "Sending %.24s", imgList[imgListSel].filename);
    else        snprintf(msg, sizeof(msg), "Send failed: %s", img_sendResultStr_c(r));
    ui_addMessage("SYSTEM", msg, true, false, GROUP_CH_ALERTS);
    uiState.dirty = true;
}

// Handle keys for both list and full-screen view
static void _imagesKey(int key) {
    if (imgFullView) {
        // Full-screen view: TB_LEFT/UP = previous, TB_RIGHT/DOWN = next, B/Esc = back to list
        if (key == 'b' || key == 27 || key == TB_BACK) {
            imgFullView = false;
            uiState.dirty = true;
        }
        else if (key == TB_LEFT || key == TB_UP) {
            if (imgListSel > 0) { imgListSel--; uiState.dirty = true; }
        }
        else if (key == TB_RIGHT || key == TB_DOWN) {
            if (imgListSel < imgListCount - 1) { imgListSel++; uiState.dirty = true; }
        }
        else if (key == 's' || key == 'S') {
            _img_sendSelected();   // Send the image currently being viewed
        }
        else if (key == 'x' || key == 'X') {
            // Delete current image, return to list
            if (imgListSel >= 0 && imgListSel < imgListCount) {
                SD.remove(imgList[imgListSel].path);
                Serial.printf("[Images] Deleted: %s\n", imgList[imgListSel].path);
                _img_scanList();
                if (imgListCount == 0) imgFullView = false;
                else if (imgListSel >= imgListCount) imgListSel = imgListCount - 1;
                uiState.dirty = true;
            }
        }
        return;
    }
    
    // List view
    if (key == 'b' || key == 27 || key == TB_BACK || key == TB_LEFT) {
        uiState.currentScreen = SCREEN_STATUS;
        uiState.dirty = true;
    }
    else if (key == TB_UP) {
        if (imgListSel > 0) { imgListSel--; uiState.dirty = true; }
    }
    else if (key == TB_DOWN) {
        if (imgListSel < imgListCount - 1) { imgListSel++; uiState.dirty = true; }
    }
    else if (key == '\n' || key == TB_RIGHT) {
        if (imgListCount > 0) {
            imgFullView = true;
            uiState.dirty = true;
        }
    }
    else if (key == 't' || key == 'T') {
        // Toggle source: Received <-> Outbox
        imgListSrc = (imgListSrc == IMG_SRC_RECV) ? IMG_SRC_SEND : IMG_SRC_RECV;
        if (imgListSrc == IMG_SRC_SEND) SD.mkdir(IMG_SEND_DIR);  // ensure outbox exists
        imgListSel = 0;
        imgListScroll = 0;
        _img_scanList();
        uiState.dirty = true;
    }
    else if (key == 's' || key == 'S') {
        _img_sendSelected();   // Send (Outbox) or re-share (Received)
    }
    else if (key == 'x' || key == 'X') {
        // Prefer cancelling active TX over deleting an image
        if (img_txCanCancel()) {
            img_cancelTx();
            Serial.println("[ImgTx] Cancelled by operator (Images screen)");
            uiState.dirty = true;
        } else if (imgListSel >= 0 && imgListSel < imgListCount) {
            SD.remove(imgList[imgListSel].path);
            Serial.printf("[Images] Deleted: %s\n", imgList[imgListSel].path);
            _img_scanList();
            uiState.dirty = true;
        }
    }
}

// Called when entering the Images screen — refresh list and apply storage cap
void images_onEnter() {
    imgListSrc = IMG_SRC_RECV;   // Default to the received-images view on entry
    img_pruneOldest();           // Storage cap applies only to /img_recv
    _img_scanList();
    imgListLastScan = millis();
    imgFullView = false;
    imgListSel = 0;
    imgListScroll = 0;
}

// ═══════════════════════════════════════════════════════════
// DEBUG SCREEN — Radio stats, system health
// ═══════════════════════════════════════════════════════════

static void _drawDebugScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    _drawHeader("Radio Debug", true);
    
    int y = 28;
    tft.setTextSize(1);
    
    // Radio stats
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(8, y);
    tft.printf("TX:%lu  RX:%lu  CH%d %.1fMHz", sigTxCount, sigRxCount,
               currentChannel, _channelToFreq(currentChannel));
    y += 11;
    
    tft.setCursor(8, y);
    tft.setTextColor(sigLastUpdate > 0 ? COLOR_GREEN : COLOR_RED);
    if (sigLastUpdate > 0) {
        uint32_t ago = (millis() - sigLastUpdate) / 1000;
        tft.printf("RSSI:%.0f SNR:%.1f (%lus ago)", sigRSSI, sigSNR, ago);
    } else {
        tft.print("No packets received");
    }
    y += 13;
    
    // Mesh stats
    int activePeers = 0;
    for (int i = 0; i < peerCount; i++) if (peers[i].active) activePeers++;
    int snfTotal = 0;
    for (int i = 0; i < SNF_MAX_MESSAGES; i++) if (snfQueue[i].valid) snfTotal++;
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y);
    tft.printf("Peers:%d/%d  Relay:%d  S&F:%d", activePeers, peerCount, meshRelayCount, snfTotal);
    y += 14;
    
    // Battery health section
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(8, y); tft.print("--- Battery ---"); y += 12;
    
    extern uint8_t getBatteryPercent();
    uint8_t bat = getBatteryPercent();
    tft.setTextColor(bat > 20 ? COLOR_GREEN : COLOR_RED);
    tft.setCursor(8, y);
    tft.printf("%.2fV  %d%%", batVoltage, bat);
    
    // Discharge rate from history
    if (batHistoryCount >= 6) {
        int newestIdx = (batHistoryHead - 1 + BAT_HISTORY_SIZE) % BAT_HISTORY_SIZE;
        int samples = min(batHistoryCount, BAT_HISTORY_SIZE);
        int olderIdx = (batHistoryHead - samples + BAT_HISTORY_SIZE) % BAT_HISTORY_SIZE;
        int delta = (int)batHistory[newestIdx] - (int)batHistory[olderIdx];
        float minutes = samples * 10.0f / 60.0f;
        float pctPerHour = (delta / minutes) * 60.0f;
        tft.setTextColor(COLOR_DIM);
        tft.printf("  %.1f%%/hr", pctPerHour);
        
        // Estimate time remaining
        if (pctPerHour < -0.5f && bat > 0) {
            float hoursLeft = bat / (-pctPerHour);
            tft.setCursor(200, y);
            tft.setTextColor(hoursLeft > 2 ? COLOR_GREEN : (hoursLeft > 0.5f ? COLOR_YELLOW : COLOR_RED));
            tft.printf("~%.1fh left", hoursLeft);
        }
    }
    y += 14;
    
    // System stats
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(8, y); tft.print("--- System ---"); y += 12;
    
    uint32_t uptimeSec = millis() / 1000;
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(8, y);
    tft.printf("Up:%luh%lum%lus  Heap:%luK", 
               uptimeSec / 3600, (uptimeSec % 3600) / 60, uptimeSec % 60,
               (uint32_t)ESP.getFreeHeap() / 1024);
    y += 11;
    
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(8, y);
    tft.printf("FW:%s  SD:%s  Msgs:%d", GRIDDOWN_FW_VERSION, sdMounted ? "OK" : "No", msgCount);
    y += 11;
    
    tft.setCursor(8, y);
    tft.printf("Mic:%s C2:%s BLE:%s Brt:%s",
               micInitialized ? "OK" : "--",
               codec2Ready ? "OK" : "--",
               bleInitialized ? (bleClientConnected ? "On" : "Rdy") : "--",
               brightnessNames[brightnessLevel]);
    y += 11;
    
    // Boot diagnostics
    tft.setCursor(8, y);
    uint16_t rstColor = COLOR_DIM;
    esp_reset_reason_t rstReason = esp_reset_reason();
    if (rstReason == ESP_RST_PANIC || rstReason == ESP_RST_TASK_WDT || 
        rstReason == ESP_RST_INT_WDT || rstReason == ESP_RST_WDT) {
        rstColor = COLOR_RED;
    } else if (rstReason == ESP_RST_BROWNOUT) {
        rstColor = COLOR_YELLOW;
    }
    tft.setTextColor(rstColor);
    tft.printf("Boots:%lu  Last:%s", bootCount, lastResetStr);
    
    // Home button
    _drawButton(scrW / 2 - 40, scrH - 28, 80, 24, "Home", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(scrW / 2 - 40, scrH - 28, 80, 24, TB_BACK);
}

// ═══════════════════════════════════════════════════════════
// LOCK SCREEN OVERLAY
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// CONFIRMATION MODAL — Generic OK/Cancel dialog
// ═══════════════════════════════════════════════════════════

static void _drawConfirmModal() {
    if (!confirmPending) return;
    int mW = 240, mH = 60;
    int mX = (scrW - mW) / 2, mY = (scrH - mH) / 2;
    tft.fillRoundRect(mX, mY, mW, mH, 6, COLOR_HEADER);
    tft.drawRoundRect(mX, mY, mW, mH, 6, COLOR_ACCENT);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(mX + 10, mY + 8);
    tft.print(confirmText);
    tft.setCursor(mX + 10, mY + 24);
    tft.setTextColor(COLOR_DIM);
    tft.print("Enter=Confirm  Esc=Cancel");
    
    _drawButton(mX + 10, mY + 38, 70, 18, "Confirm", COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(mX + 10, mY + 38, 70, 18, '\n');
    _drawButton(mX + mW - 80, mY + 38, 70, 18, "Cancel", COLOR_BTN_RED, COLOR_TEXT);
    _addButton(mX + mW - 80, mY + 38, 70, 18, 27);  // ESC
}

static void _drawWifiConfigModal() {
    if (!wifiCfgPending) return;
    int mW = 280, mH = 74;
    int mX = (scrW - mW) / 2, mY = (scrH - mH) / 2;
    tft.fillRoundRect(mX, mY, mW, mH, 6, COLOR_HEADER);
    tft.drawRoundRect(mX, mY, mW, mH, 6, COLOR_ACCENT);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(mX + 10, mY + 6);
    tft.print("Tablet wants to share WiFi:");
    tft.setCursor(mX + 10, mY + 20);
    tft.setTextColor(COLOR_GREEN);
    tft.printf("SSID: %s", wifiCfgSSID);
    if (wifiCfgSwitch) {
        tft.setCursor(mX + 10, mY + 34);
        tft.setTextColor(COLOR_YELLOW);
        tft.print("Will switch to STA mode");
    } else {
        tft.setCursor(mX + 10, mY + 34);
        tft.setTextColor(COLOR_DIM);
        tft.print("Save credentials (no mode change)");
    }
    
    _drawButton(mX + 10, mY + 52, 70, 18, "Accept", COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(mX + 10, mY + 52, 70, 18, '\n');
    _drawButton(mX + mW - 80, mY + 52, 70, 18, "Reject", COLOR_BTN_RED, COLOR_TEXT);
    _addButton(mX + mW - 80, mY + 52, 70, 18, 27);  // ESC
}

// ═══════════════════════════════════════════════════════════
// CONVERSATION SCREEN — Per-peer message thread
// ═══════════════════════════════════════════════════════════

static int _countPeerMessages(const char* peer) {
    int count = 0;
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        LocalMessage& m = messages[idx];
        if (m.outgoing) {
            // Outgoing: match if "You" sent to this peer (from field = "You" always)
            // We can't distinguish per-recipient in broadcast, so show all outgoing
            count++;
        } else if (strcmp(m.from, peer) == 0) {
            count++;
        }
    }
    return count;
}

static void _drawConversationScreen() {
    tft.fillScreen(COLOR_BG);
    _clearButtons();
    char title[32];
    snprintf(title, sizeof(title), "Chat: %s", convPeer);
    _drawHeader(title, true);
    
    // Collect messages involving this peer
    int msgAreaTop = 26;
    int msgAreaBot = scrH - 36;
    int lineH = 28;
    int maxVisible = (msgAreaBot - msgAreaTop) / lineH;
    
    // Count messages for this peer
    int peerMsgCount = 0;
    int peerMsgIdxs[MAX_MESSAGES];
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        LocalMessage& m = messages[idx];
        bool match = (!m.outgoing && strcmp(m.from, convPeer) == 0) ||
                     (m.outgoing);  // Show all outgoing in any thread
        if (match) {
            peerMsgIdxs[peerMsgCount++] = idx;
        }
    }
    
    if (peerMsgCount == 0) {
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(scrW / 2 - 40, scrH / 2);
        tft.print("No messages");
    } else {
        // Clamp scroll
        int maxScroll = peerMsgCount > maxVisible ? peerMsgCount - maxVisible : 0;
        if (convScrollOffset > maxScroll) convScrollOffset = maxScroll;
        if (convScrollOffset < 0) convScrollOffset = 0;
        
        int start = peerMsgCount - maxVisible - convScrollOffset;
        if (start < 0) start = 0;
        int end = start + maxVisible;
        if (end > peerMsgCount) end = peerMsgCount;
        
        int y = msgAreaTop;
        for (int i = start; i < end; i++) {
            LocalMessage& msg = messages[peerMsgIdxs[i]];
            uint16_t bgColor = msg.outgoing ? COLOR_SENT : COLOR_RECV;
            int bubbleX = msg.outgoing ? 60 : 4;
            int bubbleW = scrW - 64;
            
            tft.fillRoundRect(bubbleX, y, bubbleW, lineH - 4, 4, bgColor);
            
            // Sender
            tft.setTextColor(msg.outgoing ? COLOR_ACCENT : COLOR_YELLOW);
            tft.setCursor(bubbleX + 4, y + 2);
            tft.setTextSize(1);
            tft.print(msg.from);
            
            // Age
            char age[8];
            _fmtAge(msg.timestamp, age, sizeof(age));
            int ageW = strlen(age) * 6;
            tft.setTextColor(COLOR_DIM);
            tft.setCursor(bubbleX + bubbleW - ageW - 4, y + 2);
            tft.print(age);
            
            // Delivery indicator
            if (msg.outgoing && msg.msgId > 0) {
                int indX = bubbleX + bubbleW - ageW - 16;
                if (msg.grpAckTotal > 0) {
                    uint16_t ackColor = (msg.grpAckCount >= msg.grpAckTotal) ? COLOR_GREEN :
                                        (msg.grpAckCount > 0) ? COLOR_YELLOW : COLOR_DIM;
                    tft.setTextColor(ackColor);
                    tft.setCursor(indX - 8, y + 2);
                    tft.printf("%d/%d", msg.grpAckCount, msg.grpAckTotal);
                } else if (msg.failed) {
                    tft.setTextColor(COLOR_RED);
                    tft.setCursor(indX, y + 2); tft.print("X");
                } else if (msg.delivered) {
                    tft.setTextColor(COLOR_GREEN);
                    tft.setCursor(indX, y + 2); tft.print("v");
                } else {
                    tft.setTextColor(COLOR_YELLOW);
                    tft.setCursor(indX, y + 2); tft.print("~");
                }
            }
            
            // Text
            tft.setTextColor(COLOR_TEXT);
            tft.setCursor(bubbleX + 4, y + 13);
            char trunc[40];
            strncpy(trunc, msg.text, 39); trunc[39] = '\0';
            tft.print(trunc);
            
            // E2E encryption indicator
            if (msg.encrypted) {
                tft.setTextColor(0x07FF);  // Cyan
                tft.setCursor(bubbleX + bubbleW - 22, y + 13);
                tft.print("E2E");
            }
            
            y += lineH;
        }
    }
    
    // Bottom nav
    int btnY2 = scrH - 34;
    _drawButton(8, btnY2, 72, 28, "Reply", COLOR_BTN_GREEN, COLOR_TEXT);
    _addButton(8, btnY2, 72, 28, 'C');
    
    _drawButton(scrW / 2 - 30, btnY2, 60, 28, "Back", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(scrW / 2 - 30, btnY2, 60, 28, TB_BACK);
    
    _drawButton(scrW - 80, btnY2, 72, 28, "Home", COLOR_HEADER, COLOR_DIM);
    _addButton(scrW - 80, btnY2, 72, 28, 'H');
}

// Scan screen UI state
static int scanCursorIdx = -1;  // -1 = no cursor, 0-51 = highlighted channel

// ═══════════════════════════════════════════════════════════
// SCAN HELPERS — classification label + SD logging
// ═══════════════════════════════════════════════════════════

const char* scan_classLabel(uint8_t cls) {
    switch (cls) {
        case SCAN_CLASS_LORA_FHSS:  return "LoRa_FHSS";
        case SCAN_CLASS_GFSK_FHSS:  return "GFSK_Telem";
        case SCAN_CLASS_FIXED_LORA: return "Fixed_LoRa";
        case SCAN_CLASS_ISM_UNK:    return "ISM_Unknown";
        case SCAN_CLASS_LORAWAN:   return "LoRaWAN";
        default:                    return "None";
    }
}

// Human-readable display labels (longer, with parentheticals)
static const char* _scanClassDisplayLabel(uint8_t cls) {
    switch (cls) {
        case SCAN_CLASS_LORA_FHSS:  return "LoRa FHSS (ELRS/XFire)";
        case SCAN_CLASS_GFSK_FHSS:  return "GFSK Telem (SiK)";
        case SCAN_CLASS_FIXED_LORA: return "Fixed LoRa";
        case SCAN_CLASS_ISM_UNK:    return "ISM Unknown";
        case SCAN_CLASS_LORAWAN:   return "LoRaWAN Infra";
        default:                    return "???";
    }
}

static uint16_t _scanClassColor(uint8_t cls) {
    switch (cls) {
        case SCAN_CLASS_LORA_FHSS:  return COLOR_RED;
        case SCAN_CLASS_GFSK_FHSS:  return 0xFD20;  // Orange
        case SCAN_CLASS_FIXED_LORA: return COLOR_YELLOW;
        case SCAN_CLASS_ISM_UNK:    return COLOR_DIM;
        case SCAN_CLASS_LORAWAN:   return 0x07FF;  // Cyan — infrastructure, not a threat
        default:                    return COLOR_DIM;
    }
}

// Hop rate category label (LoRa FHSS only)
static const char* _scanRateLabel(uint8_t cat) {
    switch (cat) {
        case 1: return "25Hz LR";     // Long-range fixed-wing
        case 2: return "50Hz";         // Mid-range
        case 3: return "150Hz FPV";    // FPV proximity
        case 4: return "250Hz+ Race";  // FPV race / close proximity
        default: return "";
    }
}

// Compact rate label for tight display areas
static const char* _scanRateShort(uint8_t cat) {
    switch (cat) {
        case 1: return "25Hz";
        case 2: return "50Hz";
        case 3: return "150Hz";
        case 4: return "250+Hz";
        default: return "";
    }
}

void sd_logScanSession() {
    if (!sdMounted) return;
    
    const ScanDetection* dets = scan_getDetections();
    bool anyValid = false;
    for (int d = 0; d < 4; d++) if (dets[d].valid) anyValid = true;
    if (!anyValid) return;
    
    char ts[32];
    _sdTimestamp(ts, sizeof(ts));
    
    // Date-based log file
    char logPath[48];
#ifndef NO_GPS
    if (gps.date.isValid() && gps.date.year() > 2020) {
        snprintf(logPath, sizeof(logPath), "/griddown/logs/scan_%04d%02d%02d.csv",
                 gps.date.year(), gps.date.month(), gps.date.day());
    } else
#endif
    {
        snprintf(logPath, sizeof(logPath), "/griddown/logs/scan_unknown.csv");
    }
    
    File f = SD.open(logPath, FILE_APPEND);
    if (!f) return;
    
    double lat = 0, lon = 0, alt = 0;
    ui_getGPS(&lat, &lon, &alt);
    
    for (int d = 0; d < 4; d++) {
        if (!dets[d].valid) continue;
        uint32_t durSec = (dets[d].lastSeen - dets[d].firstSeen) / 1000;
        f.printf("%s,%s,%.1f,%.0f,%d,%lu,%.5f,%.5f,%lu,%s,%.2f\n",
                 ts, scan_classLabel(dets[d].classification),
                 dets[d].peakFreq, dets[d].peakRSSI,
                 dets[d].channelCount, durSec, lat, lon,
                 scan_getSweepCount(),
                 _scanRateLabel(dets[d].rateCategory),
                 dets[d].hitRatio);
    }
    f.close();
}

// Free-space path loss range estimation
// FSPL: RSSI = TXdBm - 20*log10(d_m) - 20*log10(f_MHz) + 27.55
// Solving: d_m = 10^((TXdBm - RSSI - 20*log10(f_MHz) + 27.55) / 20)
float scan_estimateRange(float rssi, float txPowerDbm) {
    float freqTerm = 20.0f * log10f(915.0f);  // ~59.23 for 915MHz
    float exponent = (txPowerDbm - rssi - freqTerm + 27.55f) / 20.0f;
    float range = powf(10.0f, exponent);
    if (range < 1.0f) range = 1.0f;
    if (range > 100000.0f) range = 100000.0f;  // Cap at 100km
    return range;
}

// Format range for display
static void _fmtRange(float meters, char* buf, size_t len) {
    if (meters < 1000.0f) {
        snprintf(buf, len, "~%.0fm", meters);
    } else {
        snprintf(buf, len, "~%.1fkm", meters / 1000.0f);
    }
}

// Trend arrow character and color
static void _trendIndicator(float slope, const char** arrow, uint16_t* color) {
    if (slope > SCAN_TREND_APPROACH) {
        *arrow = "\x18";  // Up arrow (approaching)
        *color = COLOR_RED;
    } else if (slope < SCAN_TREND_RECEDE) {
        *arrow = "\x19";  // Down arrow (receding)
        *color = COLOR_GREEN;
    } else {
        *arrow = "-";     // Stable
        *color = COLOR_YELLOW;
    }
}

// Scan screen view mode: 0 = spectrum + summary, 1 = sparkline detail
static int scanViewMode = 0;
static bool scanHelpOverlay = false;   // H toggles the key-reference overlay
static void _drawScanHelpOverlay();    // Defined below; called from _drawScanScreen
// Assumed TX power for range estimation (250mW = 24dBm default)
static float scanTxPowerDbm = 24.0f;

static void _drawScanScreen() {
    _clearButtons();
    digitalWrite(LORA_CS, HIGH);
    
    const ScanResult* results = scan_getResults();
    int channelCount = scan_getChannelCount();
    if (!results || channelCount <= 0) {
        tft.fillRect(0, 0, scrW, scrH, 0x0000);
        tft.setTextColor(COLOR_DIM); tft.setTextSize(2);
        tft.setCursor(40, scrH / 2 - 8); tft.print("Scanner not ready");
        return;
    }
    float noiseFloor = scan_getNoiseFloor();
    float threshold = noiseFloor + 20.0f;  // Must match SCAN_RSSI_THRESHOLD_DB in main.cpp
    uint32_t elapsed = scan_getElapsedMs() / 1000;
    int activeCount = scan_getActiveDetections();
    uint32_t sweeps = scan_getSweepCount();
    
    // Layout: header covers 0-24 (matches _drawHeader), chart fills middle, freq 10px, info 33px, buttons 25px
    int btnH = 24, btnY = scrH - btnH - 1;
    int chartTop = 25, chartBottom = btnY - 44;
    if (chartBottom < chartTop + 40) chartBottom = chartTop + 40;
    int chartLeft = 4, chartRight = scrW - 4;
    int chartH = chartBottom - chartTop;
    int chartW = chartRight - chartLeft;
    
    // Clear margins that the chart fill doesn't cover (avoids ghost pixels).
    // NOTE: the header band is deliberately NOT cleared to black here. It used to
    // be, and was then immediately refilled dark red two lines later — so every
    // repaint painted the top 25 px black and then red, which reads as a flash.
    // The red fill below is opaque and covers the band on its own.
    tft.fillRect(0, chartTop, chartLeft, chartH, 0x0000);   // Left margin
    tft.fillRect(chartRight, chartTop, scrW - chartRight, chartH, 0x0000); // Right margin

    // === HEADER (dark red, full 24px to match _drawHeader and cover old screen) ===
    tft.fillRect(0, 0, scrW, chartTop, 0x4800);
    tft.setTextColor(COLOR_TEXT); tft.setTextSize(1); tft.setCursor(3, 3);
    // Detection source (900 / RID / BOTH) precedes the 900 MHz profile name,
    // because it determines whether that profile is even in use.
    uint8_t ridSrc = rid_getSource();
    tft.printf("%s", rid_sourceName(ridSrc));
    if (rid_sourceUses900(ridSrc)) tft.printf("/%s", scan_profileName(scan_getProfile()));
    tft.printf("  D:%d  %lu:%02lu", activeCount, elapsed/60, elapsed%60);

    // Remote ID track count, and the ACHIEVED BLE duty cycle (decision B).
    // A silently shortened scan window produces silent false negatives, so the
    // shortfall against the requested figure is shown rather than hidden.
    if (rid_sourceUsesRemoteId(ridSrc)) {
        int ridN = rid_activeTrackCount(millis());
        uint8_t achieved = rid_dutyAchievedPct();
        uint8_t want = rid_dutyRequestedPct();
        tft.setTextColor(ridN > 0 ? 0x07E0 : 0x07FF);   // Green if tracks, else cyan
        tft.printf("  RID:%d", ridN);
        if (want > 0 && achieved + 5 < want) {
            tft.setTextColor(0xFD20);                    // Amber — degraded
            tft.printf(" %u/%u%%", achieved, want);
        }
        if (rid_isWatchdogTripped()) {
            tft.setTextColor(COLOR_RED);
            tft.print(" OFF!");
        }
        tft.setTextColor(COLOR_TEXT);
    }
    // Strongest-detection trend in the header. Previously the trend arrow appeared
    // only in the detection list, which is hidden whenever a channel cursor is
    // active — so the single most actionable piece of information on the screen
    // could be invisible depending on where the cursor happened to be.
    {
        const ScanDetection* hdets = scan_getDetections();
        int hbest = -1; float hbestR = -999;
        for (int d = 0; d < 4; d++) {
            if (hdets[d].valid && hdets[d].historyCount >= 6 && hdets[d].peakRSSI > hbestR) {
                hbestR = hdets[d].peakRSSI; hbest = d;
            }
        }
        if (hbest >= 0) {
            const char* harrow; uint16_t hcol;
            _trendIndicator(hdets[hbest].trendSlope, &harrow, &hcol);
            tft.setTextColor(hcol);
            tft.setCursor(scrW - 118, 3);
            tft.printf("%s%+.1f", harrow, hdets[hbest].trendSlope);
            tft.setTextColor(COLOR_TEXT);
        }
    }

    // Baseline indicator
    if (scan_baselineAvailable()) {
        tft.setTextColor(0x07FF);  // Cyan
        tft.print(" BL");
    }
    // Battery + GPS on right (compact)
    extern uint8_t getBatteryPercent();
    uint8_t bat = getBatteryPercent();
    tft.setTextColor(bat > 20 ? COLOR_GREEN : COLOR_YELLOW);
    tft.setCursor(scrW - 60, 3); tft.printf("%d%%", bat);
#ifndef NO_GPS
    tft.setCursor(scrW - 28, 3);
    tft.setTextColor(gps.location.isValid() ? COLOR_GREEN : COLOR_DIM);
    tft.print("GPS");
#endif
    // Line 2: missed-peers indicator (beacons overdue since scan started)
    if (peerCount > 0 && elapsed >= 45) {
        int overdue = 0;
        uint32_t now = millis();
        for (int i = 0; i < peerCount; i++) {
            if (peers[i].active && (now - peers[i].lastSeen) > 60000) overdue++;
        }
        if (overdue > 0) {
            tft.setCursor(3, 14);
            tft.setTextColor(COLOR_YELLOW);
            tft.printf("%d peer%s overdue — exit to check", overdue, overdue > 1 ? "s" : "");
        }
    }
    
    // === CHART AREA (single fill + bars on top = minimal flicker) ===
    // Fill entire chart rect in one call, then draw bars over it
    tft.fillRect(chartLeft, chartTop, chartW, chartH, 0x0841);
    tft.drawRect(chartLeft - 1, chartTop - 1, chartW + 2, chartH + 2, 0x2945);
    
    // Auto-scale Y
    float rssiMin = 0, rssiMax = -200;
    for (int i = 0; i < channelCount; i++) {
        if (rssiMin == 0 || results[i].rssi < rssiMin) rssiMin = results[i].rssi;
        if (results[i].rssi > rssiMax) rssiMax = results[i].rssi;
        if (results[i].rssiPeak > rssiMax) rssiMax = results[i].rssiPeak;
    }
    if (threshold > rssiMax) rssiMax = threshold;
    rssiMin -= 3.0f; rssiMax += 8.0f;
    if (rssiMax - rssiMin < 20.0f) { float m = (rssiMax+rssiMin)/2; rssiMin = m-10; rssiMax = m+10; }
    float rssiRange = rssiMax - rssiMin;
    
    // Noise floor + threshold lines (solid, thin)
    float nfFrac = (noiseFloor - rssiMin) / rssiRange;
    int nfY = chartBottom - (int)(nfFrac * chartH);
    if (nfY > chartTop+2 && nfY < chartBottom-2)
        tft.drawFastHLine(chartLeft+1, nfY, chartW-2, COLOR_GREEN);
    float thFrac = (threshold - rssiMin) / rssiRange;
    int thY = chartBottom - (int)(thFrac * chartH);
    if (thY > chartTop+2 && thY < chartBottom-2)
        tft.drawFastHLine(chartLeft+1, thY, chartW-2, COLOR_YELLOW);
    
    // dBm scale: just 2-3 small labels at right edge inside chart (no reference lines)
    int stepDb = (rssiRange > 40) ? 20 : 10;
    int startDb = ((int)rssiMin / stepDb) * stepDb;
    tft.setTextSize(1);
    for (int db = startDb; db <= (int)rssiMax; db += stepDb) {
        float f = ((float)db - rssiMin) / rssiRange;
        int y = chartBottom - (int)(f * chartH);
        if (y > chartTop+8 && y < chartBottom-8) {
            tft.setTextColor(COLOR_DIM);
            tft.setCursor(chartRight - 22, y - 3);
            tft.printf("%d", db);
        }
    }
    
    // Spectrum bars
    float barW = (float)chartW / channelCount;
    if (barW < 2) barW = 2;
    for (int i = 0; i < channelCount; i++) {
        float frac = (results[i].rssi - rssiMin) / rssiRange;
        if (frac < 0.02f) frac = 0.02f;
        if (frac > 1.0f) frac = 1.0f;
        int bH = (int)(frac * chartH);
        if (bH < 2) bH = 2;
        int bx = chartLeft + (int)(i * barW);
        int bw = (int)barW - 1;
        if (bw < 1) bw = 1;
        
        uint16_t col;
        if (results[i].infrastructure) col = 0x630C;
        else if (results[i].active && results[i].cadHits >= 3) col = COLOR_RED;
        else if (results[i].active) col = 0xFD20;
        else if (results[i].rssi > threshold) col = COLOR_YELLOW;
        else col = COLOR_DIM;
        
        tft.fillRect(bx, chartBottom - bH, bw, bH, col);
        
        if (i == scanCursorIdx) {
            tft.drawRect(bx-1, chartTop, bw+2, chartH, COLOR_TEXT);
            tft.fillRect(bx, chartBottom - bH, bw, bH, results[i].active ? COLOR_TEXT : COLOR_ACCENT);
        }
        
        // Transient hop marker — shows FHSS hopping trail on QUIET channels
        // Only marks channels where energy WAS recently detected but ISN'T now.
        // Active bars already show current energy; markers show where it's been.
        // Creates a visual breadcrumb trail of frequency hopping.
        if (!results[i].infrastructure && !results[i].active && 
            results[i].rssi <= threshold && results[i].lastTransientSweep > 0) {
            // Recency: last 20 sweeps for visual trail (tighter than detection window)
            uint32_t trailWindow = (sweeps > 20) ? sweeps - 20 : 0;
            if (results[i].lastTransientSweep >= trailWindow) {
                // Age-based brightness: recent = bright cyan, old = dim
                uint32_t age = sweeps - results[i].lastTransientSweep;
                uint16_t dotColor;
                if (age < 5) dotColor = 0x07FF;       // Bright cyan (last ~1.5s)
                else if (age < 12) dotColor = 0x0410;  // Dim cyan
                else dotColor = 0x2104;                 // Very dim (fading out)
                
                // Small diamond marker at fixed height above baseline
                int dotY = chartBottom - 6;
                int cx = bx + bw / 2;
                tft.drawPixel(cx, dotY - 1, dotColor);
                tft.drawPixel(cx - 1, dotY, dotColor);
                tft.drawPixel(cx, dotY, dotColor);
                tft.drawPixel(cx + 1, dotY, dotColor);
                tft.drawPixel(cx, dotY + 1, dotColor);
            }
        }
    }
    
    // === FREQ LABELS ===
    int freqY = chartBottom + 1;
    tft.fillRect(0, chartBottom, scrW, 10, 0x0000);
    tft.setTextColor(COLOR_DIM); tft.setTextSize(1);
    tft.setCursor(chartLeft, freqY);                   tft.print("902");
    tft.setCursor(chartLeft + chartW/4 - 6, freqY);   tft.print("908");
    tft.setCursor(chartLeft + chartW/2 - 6, freqY);   tft.print("915");
    tft.setCursor(chartLeft + 3*chartW/4 - 6, freqY); tft.print("921");
    tft.setCursor(chartRight - 18, freqY);             tft.print("928");
    
    // === INFO PANEL (3 lines, black bg) ===
    int infoY = chartBottom + 11;
    tft.fillRect(0, infoY-1, scrW, btnY - infoY + 1, 0x0000);
    tft.setTextSize(1);
    
    if (scanCursorIdx >= 0 && scanCursorIdx < channelCount) {
        const ScanResult& ch = results[scanCursorIdx];
        tft.setTextColor(COLOR_TEXT); tft.setCursor(4, infoY);
        tft.printf("%.1fMHz ", ch.freq);
        tft.setTextColor(ch.active ? COLOR_RED : COLOR_DIM);
        tft.printf("%.0fdBm Pk:%.0f", ch.rssi, ch.rssiPeak);
        if (ch.infrastructure) { tft.setTextColor(0x630C); tft.print(" INFRA"); }
        infoY += 11;
        tft.setCursor(4, infoY); tft.setTextColor(COLOR_DIM);
        tft.printf("CAD:%d RSSI:%d ", ch.cadHits, ch.rssiHits);
        if (ch.active && ch.cadHits>=3) { tft.setTextColor(COLOR_RED); tft.print("LoRa"); }
        else if (ch.active) { tft.setTextColor(0xFD20); tft.print(ch.isWideband?"Wide":"Narrow"); }
        else { tft.setTextColor(COLOR_DIM); tft.print("quiet"); }
        infoY += 11;
        tft.setCursor(4, infoY); tft.setTextColor(COLOR_DIM);
        tft.print("L/R:nav I:infra R:baseline  H:help");
    } else if (scanViewMode == 1) {
        const ScanDetection* dets = scan_getDetections();
        int best = -1; float bestR = -200;
        for (int d=0;d<4;d++) if (dets[d].valid && dets[d].peakRSSI>bestR) { bestR=dets[d].peakRSSI; best=d; }
        if (best >= 0) {
            const ScanDetection& det = dets[best];
            tft.setTextColor(_scanClassColor(det.classification)); tft.setCursor(4, infoY);
            tft.printf("%s %.0fdBm", _scanClassDisplayLabel(det.classification), det.peakRSSI);
            // Hop rate badge (LoRa FHSS only)
            if (det.rateCategory > 0) {
                tft.setTextColor(det.rateCategory >= 3 ? COLOR_RED : COLOR_YELLOW);
                tft.printf(" %s", _scanRateShort(det.rateCategory));
            }
            const char* arrow; uint16_t ac; _trendIndicator(det.trendSlope, &arrow, &ac);
            char rb[16]; _fmtRange(scan_estimateRange(det.peakRSSI, scanTxPowerDbm), rb, sizeof(rb));
            tft.setTextColor(ac); tft.setCursor(scrW-70, infoY); tft.printf("%s %s", arrow, rb);
            infoY += 11;
            uint32_t ds = (det.lastSeen - det.firstSeen)/1000;
            tft.setCursor(4, infoY); tft.setTextColor(COLOR_DIM);
            tft.printf("%dch %lus slope:%.1f r:%.0f%% [U/D]", det.channelCount, ds, det.trendSlope, det.hitRatio * 100);
        } else { tft.setTextColor(COLOR_DIM); tft.setCursor(4, infoY); tft.print("No detections [U/D:summary]"); }
    } else {
        const ScanDetection* dets = scan_getDetections();
        bool any = false;
        for (int d=0;d<4;d++) {
            if (!dets[d].valid) continue; any = true;
            tft.setTextColor(_scanClassColor(dets[d].classification)); tft.setCursor(4, infoY);
            tft.printf("%s %.0fdBm %dch", _scanClassDisplayLabel(dets[d].classification),
                       dets[d].peakRSSI, dets[d].channelCount);
            // Hop rate badge (LoRa FHSS only, after enough sweeps)
            if (dets[d].rateCategory > 0) {
                tft.setTextColor(dets[d].rateCategory >= 3 ? COLOR_RED : COLOR_YELLOW);
                tft.printf(" %s", _scanRateShort(dets[d].rateCategory));
            }
            if (dets[d].historyCount >= 6) {
                const char* arrow; uint16_t ac; _trendIndicator(dets[d].trendSlope, &arrow, &ac);
                char rb[16]; _fmtRange(scan_estimateRange(dets[d].peakRSSI, scanTxPowerDbm), rb, sizeof(rb));
                tft.setCursor(scrW-60, infoY); tft.setTextColor(ac); tft.printf("%s%s", arrow, rb);
            }
            infoY += 11; if (infoY >= btnY-2) break;
        }
        if (!any) {
            tft.setTextColor(COLOR_DIM); tft.setCursor(4, infoY);
            tft.print(sweeps==0 ? "Initializing..." : "Scanning... no signals detected");
            infoY += 11;
        }
        // Legend
        tft.setCursor(4, infoY);
        tft.setTextColor(COLOR_RED); tft.print("*"); tft.setTextColor(COLOR_DIM); tft.print("LoRa ");
        tft.setTextColor(0xFD20); tft.print("*"); tft.setTextColor(COLOR_DIM); tft.print("GFSK ");
        tft.setTextColor(COLOR_GREEN); tft.print("-"); tft.setTextColor(COLOR_DIM); tft.print("flr ");
        tft.setTextColor(COLOR_YELLOW); tft.print("-"); tft.setTextColor(COLOR_DIM); tft.print("thr");
        tft.setCursor(scrW-72, infoY); tft.print("[L/R U/D]");
    }
    
    // === BUTTONS (5 buttons: Exit, Profile, Share, Clear, Peak) ===
    tft.fillRect(0, btnY, scrW, scrH-btnY, 0x0000);
    // Six buttons now (Run/Prof/Share/Clear/Peak/Src). Previously sized for five:
    // 5*50+4*4=266 centred at x27, so a 6th button landed at x297 and ran to 347
    // on a 320 px screen. Narrower buttons and a tighter gap fit six on-screen.
    int bW=48, bG=3, tW=6*bW+5*bG, bX=(scrW-tW)/2;
    
    _drawButton(bX, btnY, bW, btnH, "Exit", COLOR_HEADER, COLOR_TEXT);
    _addButton(bX, btnY, bW, btnH, 'b');
    
    // Profile button — shows current profile short name
    static const char* profShort[] = {"QL", "AD", "FS", "ED"};
    char profLabel[8];
    snprintf(profLabel, sizeof(profLabel), "P:%s", profShort[scan_getProfile()]);
    _drawButton(bX+(bW+bG), btnY, bW, btnH, profLabel, COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(bX+(bW+bG), btnY, bW, btnH, 'P');
    
    _drawButton(bX+2*(bW+bG), btnY, bW, btnH, "Share", activeCount>0?COLOR_BTN_GREEN:COLOR_DIM, activeCount>0?COLOR_TEXT:0x0000);
    _addButton(bX+2*(bW+bG), btnY, bW, btnH, 'S');
    
    _drawButton(bX+3*(bW+bG), btnY, bW, btnH, "Clear", COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(bX+3*(bW+bG), btnY, bW, btnH, 'C');
    
    _drawButton(bX+4*(bW+bG), btnY, bW, btnH, "Peak", COLOR_YELLOW, 0x0000);
    _addButton(bX+4*(bW+bG), btnY, bW, btnH, 'G');

    // Remote ID track panel — drawn above the button row when the source
    // includes Remote ID. Uses the chart area, which the 900 MHz sweep does not
    // populate when it is disabled.
    if (rid_sourceUsesRemoteId(rid_getSource()) && scanViewMode == 1) {
        ui_drawRemoteIdPanel(chartTop + 4, 3);
    }

    // Detection source selector — R cycles 900MHz / RemoteID / Both.
    // Placed last so the existing button positions are unchanged.
    char srcLabel[12];
    snprintf(srcLabel, sizeof(srcLabel), "D:%s",
             rid_getSource() == RID_SRC_900 ? "900" :
             rid_getSource() == RID_SRC_REMOTEID ? "RID" : "Both");
    _drawButton(bX+5*(bW+bG), btnY, bW, btnH, srcLabel, COLOR_BTN_ACCENT, COLOR_TEXT);
    _addButton(bX+5*(bW+bG), btnY, bW, btnH, 'D');

    // Drawn last so it overlays the chart, panel and buttons.
    if (scanHelpOverlay) _drawScanHelpOverlay();
}

// Live progress bar during a baseline capture. Called from scan_baselineCapture()
// (main.cpp) once per sweep. The capture blocks for 6-8 seconds; without this the
// screen is untouched throughout, which is indistinguishable from a hang.
void ui_baselineProgressTick(uint8_t pct) {
    int barW = scrW - 60, barX = 30, barY = scrH / 2 + 10, barH = 12;
    tft.drawRect(barX, barY, barW, barH, COLOR_DIM);
    int fill = (int)((barW - 2) * pct / 100);
    if (fill > 0) tft.fillRect(barX + 1, barY + 1, fill, barH - 2, COLOR_ACCENT);
    tft.setTextSize(1);
    tft.setTextColor(COLOR_TEXT, COLOR_BG);
    tft.setCursor(barX, barY + barH + 6);
    tft.printf("%3u%%  scanning 52 channels", pct);
}

// Key reference overlay for the Drone Detection screen.
// Rationale: this screen now carries two independent detection sources and eight
// key bindings. Expecting an operator to remember them, or to read a datasheet in
// the field, is unrealistic — so the screen documents itself.
static void _drawScanHelpOverlay() {
    int w = scrW - 16, h = scrH - 26;   // Taller: content needs ~198px
    int x = 8, y = 13;

    tft.fillRoundRect(x, y, w, h, 6, COLOR_BG);
    tft.drawRoundRect(x, y, w, h, 6, COLOR_ACCENT);

    tft.setTextSize(1);
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(x + 8, y + 6);
    tft.print("DRONE DETECTION - KEY REFERENCE");

    int ty = y + 22;
    struct { const char* k; const char* d; } rows[] = {
        { "D", "Detection source: 900MHz / RemoteID / Both" },
        { "R", "Capture RF baseline (900MHz, ~8s sweep)" },
        { "P", "Scan profile (900MHz sweep parameters)" },
        { "S", "Share detections with the team over LoRa" },
        { "C", "Clear detections and counters" },
        { "G", "Toggle peak-hold display" },
        { "I", "Mark selected channel as infrastructure" },
        { "X", "Clear the saved RF baseline" },
        { "Up/Dn", "Toggle chart / detection list (Remote ID tracks)" },
        { "L/R", "Navigate channels; dismiss cursor with Up/Dn" },
        { "H", "Close this help" },
        { "B", "Back to Status" },
    };
    for (unsigned i = 0; i < sizeof(rows)/sizeof(rows[0]); i++) {
        tft.setTextColor(COLOR_YELLOW);
        tft.setCursor(x + 10, ty);
        tft.print(rows[i].k);
        tft.setTextColor(COLOR_TEXT);
        tft.setCursor(x + 40, ty);
        tft.print(rows[i].d);
        ty += 10;
    }

    // Trend legend. The arrows and colours were already being drawn, but their
    // meaning was never stated anywhere — and the colour mapping is worth being
    // explicit about, since red-for-approaching is a threat convention rather
    // than an obvious one.
    ty += 4;
    tft.setTextColor(COLOR_ACCENT);
    tft.setCursor(x + 10, ty);
    tft.print("SIGNAL TREND (dB/s, nearer/further only)");
    ty += 10;
    tft.setTextColor(COLOR_RED);
    tft.setCursor(x + 10, ty);
    tft.print("\x18");
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(x + 40, ty);
    tft.print("rising - emitter APPROACHING");
    ty += 10;
    tft.setTextColor(COLOR_GREEN);
    tft.setCursor(x + 10, ty);
    tft.print("\x19");
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(x + 40, ty);
    tft.print("falling - emitter RECEDING");
    ty += 10;
    tft.setTextColor(COLOR_YELLOW);
    tft.setCursor(x + 10, ty);
    tft.print("-");
    tft.setTextColor(COLOR_TEXT);
    tft.setCursor(x + 40, ty);
    tft.print("steady, or fewer than 6 samples yet");

    // Be explicit about the limitations here too: the operator reading this screen
    // is the person most likely to over-trust the display.
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(x + 8, y + h - 22);
    tft.print("RemoteID = compliant drones only (WiFi).");
    tft.setCursor(x + 8, y + h - 12);
    tft.print("No track is NOT proof of no aircraft.");
}

// ═══════════════════════════════════════════════════════════
// REMOTE ID TRACK PANEL
// ═══════════════════════════════════════════════════════════
// Rendered on the Scan screen when the detection source includes Remote ID.
// Shows identity, aircraft position relative to us, and — the highest-value
// field — the operator/takeoff location.
void ui_drawRemoteIdPanel(int y, int maxRows) {
    uint32_t now = millis();
    int shown = 0;

    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(4, y);
    int total = rid_activeTrackCount(now);
    if (total == 0) {
        tft.print("Remote ID: no compliant drones detected");
        // State the limitation on screen: absence is not proof of absence.
        tft.setCursor(4, y + 11);
        tft.print("(cooperative only - non-broadcasting drones unseen)");
        return;
    }
    tft.printf("Remote ID tracks: %d", total);
    y += 12;

    for (int i = 0; i < RID_MAX_TRACKS && shown < maxRows; i++) {
        const RemoteIdTrack* t = rid_getTrack(i);
        if (!t) continue;
        if (now < t->lastSeenMs || now - t->lastSeenMs > RID_STALE_MS) continue;

        // Row 1: ID, UA type, RSSI, transports, correlation
        tft.setTextColor(t->correlated900 ? 0xFD20 : COLOR_TEXT);   // Amber if corroborated
        tft.setCursor(4, y);
        tft.printf("%-14.14s %ddBm", t->uasId, t->rssi);
        if (t->transportMask & (1u << RID_TRANSPORT_WIFI_BEACON)) tft.print(" W");
        if (t->transportMask & (1u << RID_TRANSPORT_BLE_LEGACY))  tft.print(" B");
        if (t->correlated900) tft.print(" +900");
        y += 10;

        // Row 2: aircraft position/altitude and bearing+distance from us
        tft.setTextColor(COLOR_DIM);
        tft.setCursor(10, y);
        if (t->hasPosition) {
#ifndef NO_GPS
            if (gps.location.isValid()) {
                double d = _haversine(gps.location.lat(), gps.location.lng(),
                                      t->lat, t->lon);
                tft.printf("alt %dm  %.1fkm  %ukm/h", t->altGeoM, d / 1000.0,
                           (unsigned)(t->speedCms * 36 / 1000));
            } else
#endif
            {
                tft.printf("alt %dm  %.4f,%.4f", t->altGeoM, t->lat, t->lon);
            }
        } else {
            tft.print("position unknown");
        }
        y += 10;

        // Row 3: operator location — often more actionable than the aircraft
        if (t->hasOperator) {
            tft.setTextColor(0x07E0);                 // Green: this is the prize
            tft.setCursor(10, y);
#ifndef NO_GPS
            if (gps.location.isValid()) {
                double od = _haversine(gps.location.lat(), gps.location.lng(),
                                       t->opLat, t->opLon);
                tft.printf("OPERATOR %.2fkm  %.4f,%.4f", od / 1000.0, t->opLat, t->opLon);
            } else
#endif
            {
                tft.printf("OPERATOR %.4f,%.4f", t->opLat, t->opLon);
            }
            y += 10;
        }
        y += 2;
        shown++;
    }
}

// ═══════════════════════════════════════════════════════════
// WiFi QR CODE DISPLAY (Mode-Aware)
// AP mode:  readable credentials panel (per-device password — no static QR)
// STA mode: ws://griddown-radio.local:8770               (Version 3, 29x29)
// Packed as bits: 1 = black module, 0 = white. MSB first per byte.
// ═══════════════════════════════════════════════════════════

// AP mode QR removed: the AP password is now per-device, so a pre-baked QR
// encoding a fixed password would hand tablets a failing credential.
// AP mode shows readable credentials instead (see _drawQRScreen).

// STA mode QR — WebSocket discovery address
#define QR_STA_SIZE 29
#define QR_STA_BPR  4
static const uint8_t qrStaData[116] = {
    0xFE, 0x79, 0xE3, 0xF8,  // row 0
    0x82, 0xCE, 0xEA, 0x08,  // row 1
    0xBA, 0x85, 0x1A, 0xE8,  // row 2
    0xBA, 0xE0, 0xDA, 0xE8,  // row 3
    0xBA, 0x31, 0xBA, 0xE8,  // row 4
    0x82, 0x41, 0x22, 0x08,  // row 5
    0xFE, 0xAA, 0xAB, 0xF8,  // row 6
    0x00, 0x83, 0x88, 0x00,  // row 7
    0x82, 0x98, 0xD6, 0x70,  // row 8
    0xE8, 0xF4, 0xF1, 0xC0,  // row 9
    0x63, 0x27, 0x83, 0x70,  // row 10
    0x78, 0x54, 0x3B, 0x88,  // row 11
    0x9F, 0x2D, 0xAE, 0x50,  // row 12
    0x60, 0x20, 0xD3, 0xF8,  // row 13
    0xEA, 0xB0, 0x6B, 0x70,  // row 14
    0xF9, 0x69, 0x37, 0x70,  // row 15
    0x93, 0x18, 0xF0, 0x30,  // row 16
    0xF8, 0xFE, 0x5F, 0xD8,  // row 17
    0xDA, 0x29, 0x77, 0x88,  // row 18
    0x85, 0x54, 0x23, 0xD8,  // row 19
    0xB7, 0x1B, 0x7F, 0xE0,  // row 20
    0x00, 0xBA, 0x08, 0xB0,  // row 21
    0xFE, 0x28, 0x5A, 0xA0,  // row 22
    0x82, 0x53, 0x98, 0xC8,  // row 23
    0xBA, 0x4E, 0xBF, 0xC0,  // row 24
    0xBA, 0x7A, 0x04, 0x30,  // row 25
    0xBA, 0x35, 0x57, 0xD0,  // row 26
    0x82, 0x72, 0x82, 0xE8,  // row 27
    0xFE, 0xB7, 0xF1, 0xA0   // row 28
};

// SSID for display purposes. main.cpp owns WIFI_AP_SSID as a #define, which is
// not visible in this translation unit; keep these two in sync.
#define WIFI_AP_SSID_UI "GridDown-Radio"

static bool qrDisplayActive = false;

static void _drawQRScreen() {
    // Full sub-screen — completely overwrites the Settings draw
    tft.fillScreen(0xFFFF);  // White background for QR scanners

    bool useSta = (wifi_getMode() == WIFI_MODE_GD_STA && wifi_staIsConnected());

    // ── AP mode: show credentials as text, not a QR code ──
    // The AP password is now generated per device, so the pre-baked AP QR
    // bitmap (which encoded a fixed password) would hand the tablet a
    // credential that fails. Rendering a correct QR would need a runtime QR
    // encoder, which isn't in the firmware, so the operator reads the
    // credentials instead. The password alphabet deliberately excludes
    // ambiguous glyphs (0/O/1/l/I) to make this easy.
    if (!useSta) {
        extern const char* wifi_getApPassword();
        const char* pass = wifi_getApPassword();

        tft.setTextColor(0x0000);
        tft.setTextSize(2);
        tft.setCursor(10, 22);
        tft.print("Join This Radio");

        tft.setTextSize(1);
        tft.setTextColor(0x4208);
        tft.setCursor(10, 52);
        tft.print("Connect your tablet to this WiFi:");

        // Network name
        tft.setTextColor(0x0000);
        tft.setTextSize(1);
        tft.setCursor(10, 76);
        tft.print("Network");
        tft.setTextSize(2);
        tft.setCursor(10, 88);
        tft.print(WIFI_AP_SSID_UI);

        // Password — largest element on screen, it's what gets typed
        tft.setTextSize(1);
        tft.setCursor(10, 116);
        tft.print("Password");
        tft.setTextSize(3);
        tft.setCursor(10, 130);
        tft.print(pass);

        // Address
        tft.setTextSize(1);
        tft.setTextColor(0x4208);
        tft.setCursor(10, 166);
        tft.print("Then open:  http://192.168.4.1:8770");

        tft.setCursor(10, 186);
        tft.print("Unique to this device. Settings > WiFi.");

        tft.setCursor((scrW - 60) / 2, scrH - 16);
        tft.print("[AP mode]");
        return;
    }

    // ── STA mode: QR still valid (encodes only a URL, no credentials) ──
    const uint8_t* qrData = qrStaData;
    int qrSize = QR_STA_SIZE;
    int bpr = QR_STA_BPR;

    int pixPerMod = 6;
    int qrPixels = qrSize * pixPerMod;
    int qrX = (scrW - qrPixels) / 2;   // Center horizontally
    int qrY = 4;

    for (int row = 0; row < qrSize; row++) {
        for (int col = 0; col < qrSize; col++) {
            int byteIdx = row * bpr + (col / 8);
            int bitIdx = 7 - (col % 8);
            bool black = (qrData[byteIdx] >> bitIdx) & 1;
            if (black) {
                tft.fillRect(qrX + col * pixPerMod, qrY + row * pixPerMod,
                             pixPerMod, pixPerMod, 0x0000);
            }
        }
    }

    int textY = qrY + qrPixels + 4;
    tft.setTextColor(0x0000);
    tft.setTextSize(1);
    tft.setCursor((scrW - 192) / 2, textY);
    tft.print("Scan to connect to radio");
    tft.setCursor((scrW - 210) / 2, textY + 12);
    tft.setTextColor(0x4208);
    tft.print("ws://griddown-radio.local:8770");

    tft.setCursor((scrW - 60) / 2, textY + 26);
    tft.setTextColor(0x4208);
    tft.printf("[%s mode]", "STA");
}


static void _drawLockScreen() {
    _clearButtons();
    tft.fillScreen(0x0000);
    tft.setTextColor(COLOR_DIM);
    tft.setTextSize(2);
    tft.setCursor(scrW / 2 - 60, scrH / 2 - 36);
    tft.print("LOCKED");
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(scrW / 2 - 72, scrH / 2 - 4);
    tft.print("Hold V for 2s to unlock");
    tft.setTextColor(COLOR_RED);
    tft.setCursor(scrW / 2 - 80, scrH / 2 + 14);
    tft.print("Hold E for 2s = EMERGENCY");
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(scrW / 2 - 50, scrH / 2 + 32);
    tft.printf("GridDown %s", GRIDDOWN_FW_VERSION);
}

// Notification state (timed banner, doesn't overlap buttons)
static uint32_t notifyUntil = 0;
static char notifyFrom[20] = {0};
static char notifyText[40] = {0};

static void _flashNotification(const char* from, const char* text) {
    strncpy(notifyFrom, from, sizeof(notifyFrom) - 1);
    notifyFrom[sizeof(notifyFrom) - 1] = '\0';
    strncpy(notifyText, text, sizeof(notifyText) - 1);
    notifyText[sizeof(notifyText) - 1] = '\0';
    notifyUntil = millis() + 4000;  // Show for 4 seconds
    
    // Header pulse: tint header for 3 seconds with sender info.
    // Provides notification on voice/scan screens where overlay is suppressed,
    // and a subtle secondary cue on all other screens.
    headerPulseUntil = millis() + 3000;
    headerPulseColor = COLOR_ACCENT;  // Blue-ish tint for text messages
    strncpy(headerPulseFrom, from, sizeof(headerPulseFrom) - 1);
    headerPulseFrom[sizeof(headerPulseFrom) - 1] = '\0';
    
    uiState.dirty = true;  // Force redraw to show banner + pulse
}

// ── Public API: image received notification ──
// Called from main.cpp _img_rx_finalize() when an image is fully received.
// Shows a brief banner ("IMG from CMD: 4.2KB") and plays a beep.
// Does not block — operator continues whatever they were doing.
void ui_imageReceived(const char* from, size_t bytes, bool savedToSD) {
    char banner[40];
    if (savedToSD) {
        if (bytes < 1024) {
            snprintf(banner, sizeof(banner), "IMG: %dB %s", (int)bytes, "(SD)");
        } else {
            snprintf(banner, sizeof(banner), "IMG: %.1fKB %s", bytes / 1024.0f, "(SD)");
        }
    } else {
        if (bytes < 1024) {
            snprintf(banner, sizeof(banner), "IMG: %dB (no SD)", (int)bytes);
        } else {
            snprintf(banner, sizeof(banner), "IMG: %.1fKB (no SD)", bytes / 1024.0f);
        }
    }
    _flashNotification(from, banner);
    // Distinct rising chirp — not a regular message beep
    ui_beep(800, 60);
    delay(40);
    ui_beep(1200, 60);
    delay(40);
    ui_beep(1600, 80);
    Serial.printf("[UI] Image notification: from=%s bytes=%d sd=%d\n", from, (int)bytes, savedToSD);
    
    // After saving, enforce the 50-file storage cap and refresh
    // the image list if the operator is currently viewing it.
    if (savedToSD) {
        img_pruneOldest();
        if (uiState.currentScreen == SCREEN_IMAGES && !imgFullView) {
            _img_scanList();
            uiState.dirty = true;
        }
    }
}

// Draw notification banner (called from tick, overlays below header)
static void _drawNotifyBanner() {
    if (millis() >= notifyUntil) return;
    // Full overlay from y=0 — covers header cleanly on any screen
    tft.fillRoundRect(0, 0, scrW, 48, 0, COLOR_ACCENT);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(10, 6);
    tft.printf("New from %s:", notifyFrom);
    tft.setCursor(10, 26);
    tft.setTextColor(0xFFFF);
    char trunc[44];
    strncpy(trunc, notifyText, 43);
    trunc[43] = '\0';
    tft.print(trunc);
}

// Set header pulse from voice RX (called from voice handler, non-blocking)
static void _voiceHeaderPulse(const char* from, bool isDM) {
    headerPulseUntil = millis() + 2500;
    headerPulseColor = isDM ? COLOR_GREEN : COLOR_ACCENT;
    strncpy(headerPulseFrom, from, sizeof(headerPulseFrom) - 1);
    headerPulseFrom[sizeof(headerPulseFrom) - 1] = '\0';
    uiState.dirty = true;
}

// ═══════════════════════════════════════════════════════════
// INPUT HANDLING
// ═══════════════════════════════════════════════════════════

// Forward declarations (defined after _handleInput, called from within it)
static void _wifiCfgAccept();
static void _wifiCfgReject();

static void _handleInput(char key) {
    if (key == 0) return;
    ui_wake();  // Any input resets sleep timer
    
    // ── EMERGENCY BROADCAST: Hold 'E' for 2 seconds from ANY screen ──
    // This is checked BEFORE the lock guard — emergency overrides everything
    if (key == 'e' || key == 'E') {
        if (emergencyHoldStart == 0) {
            emergencyHoldStart = millis();
        } else if (millis() - emergencyHoldStart >= 2000) {
            _triggerEmergencyBroadcast();
            return;
        }
        // Don't return here — let 'e' also pass through to compose if <2s
    } else {
        emergencyHoldStart = 0;  // Any other key resets the hold timer
    }
    
    // ── Lock guard: only V held 2s can unlock ──
    if (screenLocked) {
        if (key == 'v' || key == 'V') {
            if (lockHoldStart == 0) {
                lockHoldStart = millis();
            } else if (millis() - lockHoldStart >= 2000) {
                ui_setLocked(false);
                ui_beep(1500, 80);
                Serial.println("[UI] Screen unlocked");
            }
        } else {
            lockHoldStart = 0;  // Reset if any other key
        }
        return;  // Consume all input while locked
    }
    
    // ── WiFi config prompt guard ──
    if (wifiCfgPending) {
        if (key == '\r' || key == '\n') {
            _wifiCfgAccept();
        } else if (key == 27 || key == TB_BACK) {
            _wifiCfgReject();
        }
        // All other keys consumed while prompt is showing
        return;
    }
    
    // ── Confirmation modal guard ──
    if (confirmPending) {
        if (key == '\r' || key == '\n') {
            // Execute confirmed action
            if (confirmAction == 'R') {
                // Channel change confirmed
                int ch = ui_getChannel() + 1;
                if (ch > 8) ch = 1;
                ui_setChannel(ch);
                ui_beep(1000 + ch * 200, 60);
            }
            else if (confirmAction == 'W') {
                // Bootloader mode confirmed — this does not return
                _enterBootloader();
            }
            else if (confirmAction == 'F') {
                // Start 900MHz scan confirmed
                scanCursorIdx = -1;
                scanViewMode = 0;
                scan_start();
                uiState.currentScreen = SCREEN_SCAN;
            }
            else if (confirmAction == 0x01) {
                // WiFi mode toggle confirmed — cycle to next mode
                uint8_t cur = wifi_getMode();
                uint8_t next;
                if (cur == WIFI_MODE_GD_AP) next = WIFI_MODE_GD_STA;
                else if (cur == WIFI_MODE_GD_STA) next = WIFI_MODE_GD_OFF;
                else next = WIFI_MODE_GD_AP;
                
                // Block STA switch if no credentials configured
                if (next == WIFI_MODE_GD_STA && wifi_getSTASSID()[0] == '\0') {
                    ui_addMessage("SYSTEM", "No STA creds set. Use tablet push.", false, false);
                    if (!audioMuted) ui_beep(600, 150);
                    Serial.println("[WiFi] STA blocked — no credentials configured");
                } else {
                    wifi_setMode(next);
                    char msg[48];
                    snprintf(msg, sizeof(msg), "WiFi mode: %s", wifi_modeLabel(next));
                    ui_addMessage("SYSTEM", msg, false, false);
                    Serial.printf("[WiFi] Mode changed to %s via Settings\n", wifi_modeLabel(next));
                    if (!audioMuted) ui_beep(1200, 80);
                }
            }
            else if (confirmAction == 'T') {
                // CoT enable confirmed — start in Multicast mode
                cot_setMode(COT_MODE_MCAST);
                Serial.println("[CoT] Enabled via confirmation (MC mode)");
            }
            confirmPending = false;
            uiState.dirty = true;
        } else if (key == 27 || key == TB_BACK) {
            confirmPending = false;
            uiState.dirty = true;
        }
        return;
    }
    
    switch (uiState.currentScreen) {
        case SCREEN_STATUS:
            if (key == 'm' || key == 'M') { uiState.currentScreen = SCREEN_MESSAGES; uiState.unreadCount = 0; uiState.dirty = true; }
            else if (key == 'c' || key == 'C') { uiState.currentScreen = SCREEN_COMPOSE; uiState.dirty = true; }
            else if (key == 'p' || key == 'P') { uiState.currentScreen = SCREEN_MAP; uiState.dirty = true; }
            else if (key == 'v' || key == 'V') { uiState.currentScreen = SCREEN_VOICE; uiState.dirty = true; }
            else if (key == 's' || key == 'S') { settingsScroll = 0; uiState.currentScreen = SCREEN_SETTINGS; uiState.dirty = true; }
            else if (key == 'n' || key == 'N') { peerScrollIdx = 0; uiState.currentScreen = SCREEN_PEERS; uiState.dirty = true; }
            else if (key == 'i' || key == 'I') { images_onEnter(); uiState.currentScreen = SCREEN_IMAGES; uiState.dirty = true; }
            else if (key == 'd' || key == 'D') { uiState.currentScreen = SCREEN_DEBUG; uiState.dirty = true; }
            else if (key == 'z' || key == 'Z') { ui_setLocked(!screenLocked); }
            else if (key == 'f' || key == 'F') {
                snprintf(confirmText, sizeof(confirmText), "Stop radio. Start 900MHz scan?");
                confirmAction = 'F';
                confirmPending = true;
                uiState.dirty = true;
            }
            else if (key == ' ') { uiState.currentScreen = SCREEN_VOICE; _doPTT(); }  // Spacebar → Voice screen + record
            else if (key == TB_DOWN || key == '\n') { uiState.currentScreen = SCREEN_MESSAGES; uiState.unreadCount = 0; uiState.dirty = true; }
            break;
            
        case SCREEN_MAP:
            if (key == 'b' || key == 27 || key == TB_BACK || key == TB_LEFT) { mapCursorIdx = -1; uiState.currentScreen = SCREEN_STATUS; uiState.dirty = true; }
            else if (key == ' ') { uiState.currentScreen = SCREEN_VOICE; _doPTT(); }
            else if (key == TB_UP || key == TB_DOWN) {
                // Cycle through selectable peers + tracks + waypoints
                int total = 0;
                for (int i = 0; i < peerCount; i++) if (peers[i].hasPosition) total++;
                for (int i = 0; i < TRACK_MAX; i++) if (tracks[i].valid) total++;
                for (int i = 0; i < WAYPOINT_MAX; i++) if (waypoints[i].valid) total++;
                if (total > 0) {
                    if (key == TB_DOWN) {
                        mapCursorIdx++;
                        if (mapCursorIdx >= total) mapCursorIdx = -1;  // Wrap to deselect
                    } else {
                        mapCursorIdx--;
                        if (mapCursorIdx < -1) mapCursorIdx = total - 1;  // Wrap to last
                    }
                    uiState.dirty = true;
                }
            }
            else if (key == 'w' || key == 'W') {
                // Drop waypoint at current GPS position
                double wLat, wLon, wAlt;
                if (ui_getGPS(&wLat, &wLon, &wAlt)) {
                    char wpName[20];
                    snprintf(wpName, sizeof(wpName), "WP-%d", wpAutoCounter++);
                    wp_add(wpName, wLat, wLon, WP_ICON_GENERIC,
                           ui_callsignSet() ? ui_getCallsign() : "local");
                    // Set compose buffer so main.cpp TX broadcasts the waypoint
                    char wpMsg[80];
                    snprintf(wpMsg, sizeof(wpMsg), "/wp %s %.5f %.5f", wpName, wLat, wLon);
                    strncpy(uiState.composeBuffer, wpMsg, sizeof(uiState.composeBuffer) - 1);
                    uiState.composeLen = strlen(uiState.composeBuffer);
                    uiState.selectedContact = -1;  // Broadcast
                    activeGroupCh = GROUP_CH_TACTICAL;
                    composeReady = true;
                    ui_beep(1500, 80);
                    uiState.dirty = true;
                } else {
                    // No GPS — flash warning
                    tft.fillRoundRect(40, scrH / 2 - 14, scrW - 80, 28, 6, COLOR_RED);
                    tft.setTextColor(COLOR_TEXT);
                    tft.setCursor(60, scrH / 2 - 6);
                    tft.print("No GPS fix");
                }
            }
            else if (key == 'x' || key == 'X') {
                // Delete most recently created waypoint
                int newest = -1;
                uint32_t newestTime = 0;
                for (int i = 0; i < WAYPOINT_MAX; i++) {
                    if (waypoints[i].valid && waypoints[i].createdAt >= newestTime) {
                        newestTime = waypoints[i].createdAt;
                        newest = i;
                    }
                }
                if (newest >= 0) {
                    wp_remove(newest);
                    ui_beep(800, 100);
                    uiState.dirty = true;
                }
            }
            else if (key == 'f' || key == 'F') {
                snprintf(confirmText, sizeof(confirmText), "Stop radio. Start 900MHz scan?");
                confirmAction = 'F';
                confirmPending = true;
                uiState.dirty = true;
            }
            break;
            
        case SCREEN_VOICE:
            if (vmState == VM_PREVIEW) {
                // In preview: S/V/Enter = Send, R/Backspace = Redo, Esc = Redo
                if (key == 's' || key == 'S' || key == 'v' || key == 'V' || key == '\n') { _vmSend(); }
                else if (key == 'r' || key == 'R' || key == 8 || key == 127 || key == 27 || key == TB_BACK) { _vmRedo(); }
            } else {
                // Normal voice screen
                if (key == 'b' || key == 27 || key == TB_BACK) { vmState = VM_IDLE; uiState.currentScreen = SCREEN_STATUS; uiState.dirty = true; }
                else if (key == 'v' || key == 'V' || key == ' ' || key == '\n') { _doPTT(); }
                else if (key == 't' || key == 'T') { _doVoiceTest(); }
                else if (key == TB_LEFT || key == ',') { _voiceCycleTarget(-1); uiState.dirty = true; }
                else if (key == TB_RIGHT || key == '.') { _voiceCycleTarget(1); uiState.dirty = true; }
                else if (key == 'x' || key == 'X') {
                    if (voiceLogCount > 0) {
                        voiceLogCount = 0;
                        ui_beep(800, 100);
                        Serial.println("[UI] Voice log cleared");
                        uiState.dirty = true;
                    }
                }
            }
            break;
            
        case SCREEN_MESSAGES:
            if (key == 'b' || key == 27 || key == TB_BACK) { clearPending = false; threadView = false; uiState.currentScreen = SCREEN_STATUS; uiState.scrollOffset = 0; uiState.dirty = true; }
            else if (key == 'c' || key == 'C') { clearPending = false; uiState.currentScreen = SCREEN_COMPOSE; uiState.dirty = true; }
            else if (key == 'f' || key == 'F') { threadView = !threadView; uiState.dirty = true; }
            else if (key == 'g' || key == 'G') {
                // Cycle group channel filter: All → General → Command → Tactical → Alerts → All
                if (!groupChFilter) {
                    groupChFilter = true;
                    activeGroupCh = GROUP_CH_GENERAL;
                } else if (activeGroupCh < GROUP_CH_COUNT - 1) {
                    activeGroupCh++;
                } else {
                    groupChFilter = false;
                    activeGroupCh = GROUP_CH_GENERAL;
                }
                uiState.scrollOffset = 0;  // Reset scroll on filter change
                uiState.dirty = true;
            }
            else if (threadView && key >= '1' && key <= '9') {
                // Open conversation for selected thread
                int tIdx = key - '1';
                // Rebuild thread list to find peer name for this index
                int tc = 0;
                char foundPeer[20] = {0};
                for (int i = 0; i < msgCount && tc <= tIdx; i++) {
                    int idx2 = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
                    if (messages[idx2].outgoing) continue;
                    bool seen = false;
                    for (int j = 0; j < i; j++) {
                        int jdx = (msgHead - msgCount + j + MAX_MESSAGES) % MAX_MESSAGES;
                        if (!messages[jdx].outgoing && strcmp(messages[jdx].from, messages[idx2].from) == 0) { seen = true; break; }
                    }
                    if (!seen) {
                        if (tc == tIdx) { strncpy(foundPeer, messages[idx2].from, 19); foundPeer[19] = '\0'; }
                        tc++;
                    }
                }
                if (foundPeer[0]) {
                    strncpy(convPeer, foundPeer, 19); convPeer[19] = '\0';
                    convScrollOffset = 0;
                    uiState.currentScreen = SCREEN_CONVERSATION;
                    uiState.dirty = true;
                }
            }
            else if (key == 'X' || key == 'x') {
                // Clear all messages — first press sets flag, second press confirms
                if (clearPending) {
                    // Confirmed — clear everything
                    msgCount = 0;
                    msgHead = 0;
                    uiState.scrollOffset = 0;
                    LittleFS.remove("/messages.json");
                    clearPending = false;
                    ui_beep(800, 200);
                    Serial.println("[UI] Messages cleared");
                    uiState.dirty = true;
                } else {
                    // First press — show confirmation
                    clearPending = true;
                    tft.fillRoundRect(30, scrH / 2 - 20, scrW - 60, 40, 6, COLOR_RED);
                    tft.setTextColor(COLOR_TEXT);
                    tft.setTextSize(1);
                    tft.setCursor(50, scrH / 2 - 10);
                    tft.print("Clear all messages?");
                    tft.setCursor(50, scrH / 2 + 4);
                    tft.print("Tap Clear again to confirm");
                }
            }
            // Scroll: UP = older messages (increase offset), DOWN = newer (decrease)
            else if (key == 'u' || key == 'U' || key == TB_UP) {
                int maxVis = (scrH - 60) / 28;
                int maxScr = msgCount > maxVis ? msgCount - maxVis : 0;
                uiState.scrollOffset = min(uiState.scrollOffset + 1, maxScr);
                uiState.dirty = true;
            }
            else if (key == 'd' || key == 'D' || key == TB_DOWN) {
                uiState.scrollOffset = max(uiState.scrollOffset - 1, 0);
                uiState.dirty = true;
            }
            else if (key == ' ') { uiState.currentScreen = SCREEN_VOICE; _doPTT(); }
            break;
            
        case SCREEN_COMPOSE:
            if (key == 27 || key == TB_BACK) { // ESC or Back/Cancel button
                uiState.composeLen = 0;
                uiState.composeBuffer[0] = '\0';
                uiState.currentScreen = SCREEN_MESSAGES;
                uiState.dirty = true;
            }
            else if (key == '\r' || key == '\n') { // Enter or trackball click — send
                if (uiState.composeLen > 0) {
                    uiState.composeBuffer[uiState.composeLen] = '\0';
                    composeReady = true;
                    // Switch to Messages immediately — don't redraw Compose
                    uiState.currentScreen = SCREEN_MESSAGES;
                    uiState.scrollOffset = 0;
                    uiState.dirty = true;
                }
            }
            else if (key == '\t') { // Tab — cycle recipients: broadcast → contacts
                if (contactCount > 0) {
                    uiState.selectedContact++;
                    if (uiState.selectedContact >= contactCount) {
                        uiState.selectedContact = -1;  // Back to broadcast
                    }
                }
                uiState.dirty = true;
            }
            else if (key == 8 || key == 127) { // Backspace
                if (uiState.composeLen > 0) {
                    uiState.composeLen--;
                    uiState.composeBuffer[uiState.composeLen] = '\0';
                    uiState.dirty = true;
                }
            }
            // Trackball in compose: cycle canned messages
            else if (key == TB_UP) {
                cannedMsgSelected++;
                if (cannedMsgSelected >= CANNED_MSG_COUNT) cannedMsgSelected = 0;
                uiState.composeLen = strlen(cannedMessages[cannedMsgSelected]);
                strncpy(uiState.composeBuffer, cannedMessages[cannedMsgSelected], 199);
                uiState.composeBuffer[uiState.composeLen] = '\0';
                uiState.dirty = true;
            }
            else if (key == TB_DOWN) {
                cannedMsgSelected--;
                if (cannedMsgSelected < 0) cannedMsgSelected = CANNED_MSG_COUNT - 1;
                uiState.composeLen = strlen(cannedMessages[cannedMsgSelected]);
                strncpy(uiState.composeBuffer, cannedMessages[cannedMsgSelected], 199);
                uiState.composeBuffer[uiState.composeLen] = '\0';
                uiState.dirty = true;
            }
            else if (key == TB_LEFT || key == TB_RIGHT) {
                // Cycle group channel (left = previous, right = next)
                if (key == TB_RIGHT) {
                    activeGroupCh = (activeGroupCh + 1) % GROUP_CH_COUNT;
                } else {
                    activeGroupCh = (activeGroupCh + GROUP_CH_COUNT - 1) % GROUP_CH_COUNT;
                }
                uiState.dirty = true;
            }
            else if (key >= 32 && key < 127 && uiState.composeLen < 199) { // Printable char
                uiState.composeBuffer[uiState.composeLen++] = key;
                uiState.composeBuffer[uiState.composeLen] = '\0';
                uiState.dirty = true;
            }
            break;
            
        case SCREEN_SETTINGS:
            // QR code display: any key dismisses
            if (qrDisplayActive) {
                qrDisplayActive = false;
                uiState.dirty = true;
                break;
            }
            if (callsignEntryMode) {
                if (key == 27 || key == TB_BACK) {
                    callsignEntryMode = false;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                }
                else if ((key == '\r' || key == '\n') && pskBufLen >= 1) {
                    ui_setCallsign(pskBuffer);
                    callsignEntryMode = false;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                    ui_beep(1500, 100);
                }
                else if (key == 8 || key == 127) {
                    if (pskBufLen > 0) { pskBufLen--; pskBuffer[pskBufLen] = '\0'; uiState.dirty = true; }
                }
                else if (key == TB_UP || key == TB_DOWN || key == TB_LEFT || key == TB_RIGHT) {}
                else if (key >= 32 && key < 127 && pskBufLen < 15) {
                    pskBuffer[pskBufLen++] = key;
                    pskBuffer[pskBufLen] = '\0';
                    uiState.dirty = true;
                }
            }
            else if (pskEntryMode) {
                if (key == 27 || key == TB_BACK) {
                    pskEntryMode = false;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                }
                else if ((key == '\r' || key == '\n') && pskBufLen >= 4) {
                    psk_setPassphrase(pskBuffer);
                    pskEntryMode = false;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                    ui_beep(1500, 100);
                }
                else if (key == 'X') {
                    psk_setPassphrase(NULL);
                    pskEntryMode = false;
                    uiState.dirty = true;
                    ui_beep(800, 200);
                }
                else if (key == 8 || key == 127) {
                    if (pskBufLen > 0) { pskBufLen--; pskBuffer[pskBufLen] = '\0'; uiState.dirty = true; }
                }
                else if (key == TB_UP || key == TB_DOWN || key == TB_LEFT || key == TB_RIGHT) {}
                else if (key >= 32 && key < 127 && pskBufLen < 30) {
                    pskBuffer[pskBufLen++] = key;
                    pskBuffer[pskBufLen] = '\0';
                    uiState.dirty = true;
                }
            }
            else if (duressEntryMode) {
                if (key == 27 || key == TB_BACK) {
                    duressEntryMode = false;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                }
                else if ((key == '\r' || key == '\n') && pskBufLen == 4) {
                    duress_setPin(pskBuffer);
                    duressEntryMode = false;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                    ui_beep(1500, 100);
                }
                else if (key == 'X') {
                    duress_clearPin();
                    duressEntryMode = false;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                    ui_beep(800, 200);
                }
                else if (key == 8 || key == 127) {
                    if (pskBufLen > 0) { pskBufLen--; pskBuffer[pskBufLen] = '\0'; uiState.dirty = true; }
                }
                else if (key >= '0' && key <= '9' && pskBufLen < 4) {
                    pskBuffer[pskBufLen++] = key;
                    pskBuffer[pskBufLen] = '\0';
                    uiState.dirty = true;
                }
            }
            else if (wipeSelectMode) {
                if (key == 27 || key == TB_BACK) {
                    if (wipeConfirmStage2) {
                        wipeConfirmStage2 = false;
                    } else {
                        wipeSelectMode = false;
                    }
                    uiState.dirty = true;
                }
                else if (key == TB_UP || key == TB_DOWN) {
                    if (!wipeConfirmStage2) {
                        int total = 0;
                        for (int i = 0; i < peerCount; i++) {
                            if (peers[i].active) total++;
                        }
                        total++;
                        if (key == TB_DOWN) { wipeSelectIdx++; if (wipeSelectIdx >= total) wipeSelectIdx = 0; }
                        else { wipeSelectIdx--; if (wipeSelectIdx < 0) wipeSelectIdx = total - 1; }
                        uiState.dirty = true;
                    }
                }
                else if (key == '\r' || key == '\n') {
                    if (!wipeConfirmStage2) {
                        wipeConfirmStage2 = true;
                        uiState.dirty = true;
                    } else {
                        char wipeName[20] = {0};
                        int visIdx = 0;
                        bool isLocal = false;
                        for (int i = 0; i < peerCount; i++) {
                            if (!peers[i].active) continue;
                            if (visIdx == wipeSelectIdx) {
                                strncpy(wipeName, peers[i].callsign, sizeof(wipeName) - 1);
                                break;
                            }
                            visIdx++;
                        }
                        if (wipeName[0] == '\0') isLocal = true;
                        
                        wipeSelectMode = false;
                        wipeConfirmStage2 = false;
                        
                        if (isLocal) {
                            wipe_execute("Local wipe (Settings)");
                        } else {
                            uint32_t epoch = _getUtcEpoch();
                            if (epoch == 0) {
                                ui_addMessage("SYSTEM", "Wipe failed — no GPS time", true, false, GROUP_CH_ALERTS);
                                ui_beep(400, 300);
                            } else if (!psk_isEnabled()) {
                                ui_addMessage("SYSTEM", "Wipe failed — no PSK", true, false, GROUP_CH_ALERTS);
                                ui_beep(400, 300);
                            } else {
                                char sigB64[28];
                                if (wipe_sign(ui_getCallsign(), wipeName, epoch, sigB64, sizeof(sigB64))) {
                                    JsonDocument wipeDoc;
                                    wipeDoc["type"] = "wipe";
                                    wipeDoc["from"] = ui_getCallsign();
                                    wipeDoc["to"] = wipeName;
                                    wipeDoc["ts"] = epoch;
                                    wipeDoc["sig"] = sigB64;
                                    String wipeJson;
                                    serializeJson(wipeDoc, wipeJson);
                                    
                                    extern bool enqueuePacket(const uint8_t* data, size_t len, bool highPri);
                                    uint8_t pkt[255];
                                    int pktLen = 0;
                                    if (psk_isEnabled()) {
                                        uint8_t enc[255];
                                        int eLen = psk_encrypt((const uint8_t*)wipeJson.c_str(),
                                                               wipeJson.length(), enc, sizeof(enc));
                                        if (eLen > 0) {
                                            pkt[0] = 0xAE;
                                            memcpy(pkt + 1, enc, eLen);
                                            pktLen = eLen + 1;
                                        }
                                    }
                                    if (pktLen > 0) {
                                        enqueuePacket(pkt, pktLen, true);
                                        char alertMsg[48];
                                        snprintf(alertMsg, sizeof(alertMsg), "WIPE sent to %s", wipeName);
                                        ui_addMessage("SYSTEM", alertMsg, true, false, GROUP_CH_ALERTS);
                                        ui_beep(800, 200);
                                        Serial.printf("[WIPE] Sent to %s from Settings UI\n", wipeName);
                                    }
                                } else {
                                    ui_addMessage("SYSTEM", "Wipe sign failed", true, false, GROUP_CH_ALERTS);
                                    ui_beep(400, 300);
                                }
                            }
                        }
                        uiState.dirty = true;
                    }
                }
            } else {
                Serial.printf("[Settings] Key: '%c' (0x%02X)\n", key >= 32 ? key : '?', (uint8_t)key);
                if (key == 'b' || key == 27 || key == TB_BACK || key == TB_LEFT) {
                    uiState.currentScreen = SCREEN_STATUS; uiState.dirty = true;
                }
                else if (key == 'K' || key == 'k') {
                    pskEntryMode = true;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                }
                else if (key == 'N' || key == 'n') {
                    callsignEntryMode = true;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                }
                else if (key == 'A' || key == 'a') {
                    ui_setMute(!audioMuted);
                    uiState.dirty = true;
                    if (!audioMuted) ui_beep(1500, 80);
                }
                else if (key == 'R' || key == 'r') {
                    confirmAction = 'R';
                    int nextCh = ui_getChannel() + 1;
                    if (nextCh > 8) nextCh = 1;
                    snprintf(confirmText, sizeof(confirmText), "Switch to CH%d (%.1fMHz)?", nextCh, _channelToFreq(nextCh));
                    confirmPending = true;
                    uiState.dirty = true;
                }
                else if (key == 'L' || key == 'l') {
                    ui_toggleKeyboardBacklight();
                    uiState.dirty = true;
                }
                else if (key == 'B' || key == 'b') {
                    ui_cycleBrightness();
                    uiState.dirty = true;
                }
                else if (key == 'W' || key == 'w') {
                    confirmAction = 'W';
                    snprintf(confirmText, sizeof(confirmText), "Reboot to USB bootloader?");
                    confirmPending = true;
                    uiState.dirty = true;
                }
                else if (key == 'Q' || key == 'q') {
                    ui_cycleVoiceMode();
                    uiState.dirty = true;
                    if (!audioMuted) ui_beep(1500, 80);
                }
                else if (key == 'P' || key == 'p') {
                    if (!proximityEnabled) {
                        proximityEnabled = true;
                        proximityRadius = 500;
                    } else if (proximityRadius <= 500) {
                        proximityRadius = 1000;
                    } else if (proximityRadius <= 1000) {
                        proximityRadius = 2000;
                    } else if (proximityRadius <= 2000) {
                        proximityRadius = 5000;
                    } else if (proximityRadius <= 5000) {
                        proximityRadius = 10000;
                    } else {
                        proximityEnabled = false;
                        proximityRadius = PROXIMITY_DEFAULT_M;
                    }
                    uiState.dirty = true;
                    if (!audioMuted) ui_beep(1200, 60);
                }
                else if (key == 'J' || key == 'j') {
                    gunshot_cycleSensitivity();
                    if (!audioMuted) ui_beep(gdSensitivity > 0 ? 1500 : 800, 80);
                }
                else if (key == 'T' || key == 't') {
                    if (cotMode == COT_MODE_OFF) {
                        confirmAction = 'T';
                        snprintf(confirmText, sizeof(confirmText), "Enable CoT? Position will broadcast");
                        confirmPending = true;
                        uiState.dirty = true;
                    } else {
                        cot_cycleMode();
                    }
                }
                else if (key == TB_UP || key == TB_DOWN) {
                    if (key == TB_DOWN) { settingsScroll += 14; if (settingsScroll > 60) settingsScroll = 60; }
                    else { settingsScroll -= 14; if (settingsScroll < 0) settingsScroll = 0; }
                    uiState.dirty = true;
                }
                else if (key == 'U' || key == 'u') {
                    duressEntryMode = true;
                    pskBufLen = 0; pskBuffer[0] = '\0';
                    uiState.dirty = true;
                }
                else if (key == 'D' || key == 'd') {
                    wipeSelectMode = true;
                    wipeSelectIdx = 0;
                    wipeConfirmStage2 = false;
                    uiState.dirty = true;
                }
                else if (key == 'G' || key == 'g') {
                    // Show WiFi QR code as sub-screen (same pattern as Duress/Wipe)
                    qrDisplayActive = true;
                    uiState.dirty = true;
                }
                else if (key == 'F' || key == 'f') {
                    // Cycle WiFi mode: AP → STA → OFF → AP (with confirmation)
                    uint8_t curMode = wifi_getMode();
                    const char* warning;
                    if (curMode == WIFI_MODE_GD_AP) {
                        if (wifi_getSTASSID()[0] != '\0') {
                            snprintf(confirmText, sizeof(confirmText), "Switch to STA: %s?", wifi_getSTASSID());
                        } else {
                            snprintf(confirmText, sizeof(confirmText), "Switch to STA? (no creds set)");
                        }
                    } else if (curMode == WIFI_MODE_GD_STA) {
                        snprintf(confirmText, sizeof(confirmText), "Disable WiFi? BLE/LoRa only.");
                    } else {
                        snprintf(confirmText, sizeof(confirmText), "Enable WiFi AP mode?");
                    }
                    confirmAction = 0x01;
                    confirmPending = true;
                    uiState.dirty = true;
                }
            }
            break;
            
        case SCREEN_CONVERSATION:
            if (key == 'b' || key == 27 || key == TB_BACK) {
                uiState.currentScreen = SCREEN_MESSAGES; threadView = true; uiState.dirty = true;
            }
            else if (key == 'c' || key == 'C') {
                uiState.currentScreen = SCREEN_COMPOSE; uiState.dirty = true;
            }
            else if (key == 'h' || key == 'H') {
                uiState.currentScreen = SCREEN_STATUS; uiState.dirty = true;
            }
            else if (key == TB_UP || key == 'u' || key == 'U') {
                convScrollOffset++; uiState.dirty = true;
            }
            else if (key == TB_DOWN || key == 'd' || key == 'D') {
                if (convScrollOffset > 0) { convScrollOffset--; uiState.dirty = true; }
            }
            break;
            
        case SCREEN_PEERS:
            if (key == 'b' || key == 27 || key == TB_BACK || key == TB_LEFT) {
                peerHealthView = false;
                uiState.currentScreen = SCREEN_STATUS; uiState.dirty = true;
            }
            else if (key == 'h' || key == 'H') {
                peerHealthView = !peerHealthView;
                uiState.dirty = true;
            }
            else if (key == TB_UP || key == 'u' || key == 'U') {
                if (peerScrollIdx > 0) { peerScrollIdx--; uiState.dirty = true; }
            }
            else if (key == TB_DOWN || key == 'd' || key == 'D') {
                if (peerScrollIdx < peerCount - 1) { peerScrollIdx++; uiState.dirty = true; }
            }
            else if (key == ' ') { uiState.currentScreen = SCREEN_VOICE; _doPTT(); }
            break;
            
        case SCREEN_IMAGES:
            _imagesKey(key);
            break;
            
        case SCREEN_DEBUG:
            if (key == 'b' || key == 27 || key == TB_BACK || key == TB_LEFT) {
                uiState.currentScreen = SCREEN_STATUS; uiState.dirty = true;
            }
            else if (key == ' ') { uiState.currentScreen = SCREEN_VOICE; _doPTT(); }
            break;
            
        case SCREEN_SCAN:
            if (key == 'b' || key == 27 || key == TB_BACK) {
                // Deassert all SPI chip selects before scan_stop touches the radio
                digitalWrite(LORA_CS, HIGH);
                digitalWrite(TFT_CS, HIGH);
                scan_stop();
                // Radio SPI is now done — safe to use TFT SPI
                // Clear screen AFTER radio restore to prevent SPI contention artifacts
                delay(5);  // Let SPI bus settle after radio commands
                tft.fillScreen(0x0000);
                scanCursorIdx = -1;
                scanViewMode = 0;
                uiState.currentScreen = SCREEN_STATUS;
                uiState.dirty = true;
            }
            else if (key == 'c' || key == 'C') {
                scan_stop();
                scanCursorIdx = -1;
                scanViewMode = 0;
                scan_start();
                uiState.dirty = true;
            }
            else if (key == 's' || key == 'S') {
                // Share: stop (triggers SD log + alerts + LoRa broadcast), then restart
                int detCount = scan_getActiveDetections();
                digitalWrite(LORA_CS, HIGH);
                scan_stop();
                scan_start();
                // SPI settle after radio commands before TFT draw
                delay(5);
                // Brief visual confirmation
                tft.fillRoundRect(scrW/2 - 60, scrH/2 - 12, 120, 24, 6, COLOR_BTN_GREEN);
                tft.setTextColor(0x0000); tft.setTextSize(1);
                tft.setCursor(scrW/2 - 48, scrH/2 - 4);
                tft.printf("Shared %d detect", detCount);
                if (!audioMuted) ui_beep(1500, 60);
                uiState.dirty = true;
            }
            else if (key == TB_LEFT || key == ',') {
                // Move cursor left
                if (scanCursorIdx < 0) {
                    scanCursorIdx = scan_getChannelCount() - 1;  // Start from right
                } else if (scanCursorIdx > 0) {
                    scanCursorIdx--;
                }
                uiState.dirty = true;
            }
            else if (key == TB_RIGHT || key == '.') {
                // Move cursor right
                if (scanCursorIdx < 0) {
                    scanCursorIdx = 0;  // Start from left
                } else if (scanCursorIdx < scan_getChannelCount() - 1) {
                    scanCursorIdx++;
                }
                uiState.dirty = true;
            }
            else if (key == 'g' || key == 'G') {
                // Jump cursor to strongest active detection
                const ScanResult* res = scan_getResults();
                int count = scan_getChannelCount();
                int bestIdx = -1;
                float bestRSSI = -200;
                for (int i = 0; i < count; i++) {
                    if (res[i].active && res[i].rssiPeak > bestRSSI) {
                        bestRSSI = res[i].rssiPeak;
                        bestIdx = i;
                    }
                }
                scanCursorIdx = bestIdx;  // -1 if no active detections
                uiState.dirty = true;
            }
            else if (key == TB_UP || key == TB_DOWN) {
                if (scanCursorIdx >= 0) {
                    // Cursor active: dismiss cursor
                    scanCursorIdx = -1;
                } else {
                    // No cursor: toggle between summary and sparkline view
                    scanViewMode = (scanViewMode == 0) ? 1 : 0;
                }
                uiState.dirty = true;
            }
            else if (key == 'h' || key == 'H') {
                scanHelpOverlay = !scanHelpOverlay;
                uiState.dirty = true;
            }
            else if (scanHelpOverlay) {
                // Any other key dismisses the overlay rather than acting through
                // it — an operator should never be able to trigger a baseline
                // capture or source change by pressing a key at a help screen.
                scanHelpOverlay = false;
                uiState.dirty = true;
            }
            else if (key == 'd' || key == 'D') {
                // Cycle Detection source: 900MHz -> RemoteID -> Both.
                // NOTE: deliberately 'D', not 'R' — 'R' is RF baseline capture,
                // bound later in this same else-if chain. Using 'R' here silently
                // shadowed it and made baseline capture unreachable.
                uint8_t next = (uint8_t)((rid_getSource() + 1) % RID_SRC_COUNT);
                rid_setSource(next);
                rid_clearWatchdog();          // Operator intent overrides a prior trip

                // The 900 MHz sweep must stop when the source no longer uses it,
                // otherwise the SX1262 keeps sweeping and cannot receive messages.
                if (rid_sourceUses900(next)) {
                    scan_start();
                } else {
                    scan_stop();
                }
                char msg[64];
                snprintf(msg, sizeof(msg), "Detection source: %s", rid_sourceName(next));
                ui_addMessage("SYSTEM", msg, true, false, GROUP_CH_ALERTS);
                uiState.dirty = true;
                if (!audioMuted) ui_beep(900 + next * 250, 60);
            }
            else if (key == 'p' || key == 'P') {
                // Cycle scan profile — requires restart
                uint8_t next = (scan_getProfile() + 1) % SCAN_PROFILE_COUNT;
                scan_stop();
                scan_setProfile(next);
                scanCursorIdx = -1;
                scanViewMode = 0;
                scan_start();
                uiState.dirty = true;
                if (!audioMuted) ui_beep(1000 + next * 200, 60);
            }
            else if (key == 'i' || key == 'I') {
                // Toggle infrastructure flag on cursor channel
                if (scanCursorIdx >= 0 && scanCursorIdx < scan_getChannelCount()) {
                    scan_toggleInfra(scanCursorIdx);
                    uiState.dirty = true;
                    if (!audioMuted) ui_beep(800, 40);
                }
            }
            else if (key == 'r' || key == 'R') {
                // Capture RF baseline — stop scan, run dedicated baseline sweep, restart
                scan_stop();
                delay(5);
                // Visual feedback: show "Capturing baseline..." on screen
                tft.fillScreen(COLOR_BG);
                tft.setTextColor(COLOR_ACCENT); tft.setTextSize(2);
                tft.setCursor(30, scrH / 2 - 30);
                tft.print("RF Baseline");
                tft.setTextSize(1); tft.setTextColor(COLOR_DIM);
                tft.setCursor(30, scrH / 2);
                tft.print("Capturing... ensure NO drones nearby");
                tft.setCursor(30, scrH / 2 + 16);
                tft.print("~8 seconds, do not move device");
                
                scan_baselineCapture();  // Blocks for ~8 seconds
                
                // Show result
                tft.fillScreen(COLOR_BG);
                tft.setTextColor(COLOR_GREEN); tft.setTextSize(2);
                tft.setCursor(40, scrH / 2 - 20);
                tft.print("Baseline Saved");
                tft.setTextSize(1); tft.setTextColor(COLOR_DIM);
                tft.setCursor(40, scrH / 2 + 8);
                tft.printf("NF: %.0f dBm", scan_getNoiseFloor());
                if (!audioMuted) ui_beep(1500, 100);
                delay(1500);
                
                // Restart scan with baseline active
                scan_start();
                uiState.dirty = true;
            }
            else if (key == 'x' || key == 'X') {
                // Clear baseline
                if (scan_baselineAvailable()) {
                    scan_baselineClear();
                    if (!audioMuted) ui_beep(800, 200);
                    // Restart scan without baseline
                    scan_stop();
                    scan_start();
                    uiState.dirty = true;
                }
            }
            break;
    }
}

// ═══════════════════════════════════════════════════════════
// COMPOSE OUTPUT
// ═══════════════════════════════════════════════════════════

const char* ui_getComposeText() {
    return uiState.composeBuffer;
}

bool ui_hasComposedMessage() {
    return composeReady;
}

void ui_clearCompose() {
    composeReady = false;
    uiState.composeLen = 0;
    uiState.composeBuffer[0] = '\0';
    uiState.currentScreen = SCREEN_MESSAGES;
    uiState.scrollOffset = 0;  // Show newest messages (including the one just sent)
    uiState.dirty = true;
}

Screen ui_getCurrentScreen() { return uiState.currentScreen; }
int ui_getMessageCount() { return msgCount; }
int ui_getContactCount() { return contactCount; }

// ═══════════════════════════════════════════════════════════
// CHANNEL SELECTION
// 8 channels in US ISM 902-928 MHz band, 2.5 MHz apart
// ═══════════════════════════════════════════════════════════

static float _channelToFreq(int ch) {
    // Ch1=906.0, Ch2=908.5, Ch3=911.0, Ch4=913.5, Ch5=916.0, Ch6=918.5, Ch7=921.0, Ch8=923.5
    if (ch < 1) ch = 1;
    if (ch > 8) ch = 8;
    return 906.0f + (ch - 1) * 2.5f;
}

void ui_setChannel(int channel) {
    if (channel < 1) channel = 1;
    if (channel > 8) channel = 8;
    currentChannel = channel;
    File f = LittleFS.open("/channel.cfg", "w");
    if (f) { f.write((uint8_t)channel); f.close(); }
    Serial.printf("[Radio] Channel set to %d (%.1f MHz)\n", channel, _channelToFreq(channel));
}

int   ui_getChannel() { return currentChannel; }
float ui_getChannelFreq() { return _channelToFreq(currentChannel); }

static void _loadChannel() {
    File f = LittleFS.open("/channel.cfg", "r");
    if (f) {
        int ch = f.read();
        if (ch >= 1 && ch <= 8) currentChannel = ch;
        f.close();
    }
}

// ═══════════════════════════════════════════════════════════
// GROUP CHANNELS (logical channels within a PSK cluster)
// ═══════════════════════════════════════════════════════════

uint8_t ui_getActiveGroupChannel() { return activeGroupCh; }

const char* ui_getGroupChannelName(uint8_t ch) {
    if (ch >= GROUP_CH_COUNT) return "?";
    return groupChNames[ch];
}

void ui_setActiveGroupChannel(uint8_t ch) {
    if (ch >= GROUP_CH_COUNT) ch = GROUP_CH_GENERAL;
    activeGroupCh = ch;
}

void ui_cycleGroupChannel() {
    activeGroupCh = (activeGroupCh + 1) % GROUP_CH_COUNT;
    Serial.printf("[Group] Active channel: %s (%d)\n", groupChNames[activeGroupCh], activeGroupCh);
}

// ═══════════════════════════════════════════════════════════
// UNREAD MESSAGE COUNTER
// ═══════════════════════════════════════════════════════════

int  ui_getUnreadCount() { return uiState.unreadCount; }
void ui_clearUnread() { uiState.unreadCount = 0; }

// ═══════════════════════════════════════════════════════════
// MESSAGE ACK SYSTEM (direct messages only)
// ═══════════════════════════════════════════════════════════

void ui_markDelivered(uint16_t msgId) {
    if (msgId == 0) return;
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        if (messages[idx].msgId == msgId && messages[idx].outgoing) {
            messages[idx].delivered = true;
            uiState.dirty = true;
            Serial.printf("[ACK] Message %d delivered\n", msgId);
            return;
        }
    }
}

void ui_markFailed(uint16_t msgId) {
    if (msgId == 0) return;
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        if (messages[idx].msgId == msgId && messages[idx].outgoing && !messages[idx].delivered) {
            messages[idx].failed = true;
            uiState.dirty = true;
            Serial.printf("[ACK] Message %d FAILED (retries exhausted)\n", msgId);
            return;
        }
    }
}

void ui_setGroupAckTotal(uint16_t msgId, uint8_t total) {
    if (msgId == 0) return;
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        if (messages[idx].msgId == msgId && messages[idx].outgoing) {
            messages[idx].grpAckTotal = total;
            return;
        }
    }
}

void ui_markGroupAck(uint16_t msgId, const char* from) {
    if (msgId == 0 || !from) return;
    for (int i = 0; i < msgCount; i++) {
        int idx = (msgHead - msgCount + i + MAX_MESSAGES) % MAX_MESSAGES;
        if (messages[idx].msgId == msgId && messages[idx].outgoing) {
            // Map peer to bit position (by peer index)
            int peerIdx = -1;
            for (int p = 0; p < peerCount && p < 16; p++) {
                if (strcasecmp(peers[p].callsign, from) == 0) {
                    peerIdx = p;
                    break;
                }
            }
            // Only count if not already ACKed by this peer
            if (peerIdx >= 0 && !(messages[idx].grpAckPeers & (1 << peerIdx))) {
                messages[idx].grpAckPeers |= (1 << peerIdx);
                messages[idx].grpAckCount++;
                uiState.dirty = true;
                Serial.printf("[GRP-ACK] Message %d: %d/%d peers confirmed (%s)\n",
                              msgId, messages[idx].grpAckCount, messages[idx].grpAckTotal, from);
            }
            return;
        }
    }
}

int ui_getActivePeerCount() {
    int active = 0;
    uint32_t now = millis();
    for (int i = 0; i < peerCount; i++) {
        if (peers[i].active && (now - peers[i].lastSeen) < 120000) active++;
    }
    return active;
}

// ═══════════════════════════════════════════════════════════
// WIFI CONFIG PROMPT — Triggered by WebSocket wifi_config push
// ═══════════════════════════════════════════════════════════

void ui_showWifiConfigPrompt(const char* ssid, const char* pass, bool switchNow, uint8_t wsClient) {
    strncpy(wifiCfgSSID, ssid, 32); wifiCfgSSID[32] = '\0';
    strncpy(wifiCfgPass, pass, 64); wifiCfgPass[64] = '\0';
    wifiCfgSwitch = switchNow;
    wifiCfgClient = wsClient;
    wifiCfgPending = true;
    uiState.dirty = true;
    if (!audioMuted) ui_beep(1800, 60);  // Alert tone
    Serial.printf("[WiFi] Config prompt: SSID='%s' switch=%s\n", ssid, switchNow ? "yes" : "no");
}

static void _wifiCfgAccept() {
    wifi_setSTACredentials(wifiCfgSSID, wifiCfgPass);
    
    // Send acceptance response BEFORE mode switch (ws.close() kills connections)
    extern void sendToClient(uint8_t clientNum, const String& msg);
    JsonDocument resp;
    resp["type"] = "wifi_status";
    resp["accepted"] = true;
    resp["sta_configured"] = true;
    resp["sta_ssid"] = wifiCfgSSID;
    resp["switching"] = wifiCfgSwitch;
    resp["mode"] = wifi_modeLabel(wifi_getMode());
    String json;
    serializeJson(resp, json);
    sendToClient(wifiCfgClient, json);
    
    // NOW switch mode (this closes WebSocket and changes WiFi interface)
    if (wifiCfgSwitch && wifi_getMode() != WIFI_MODE_GD_STA) {
        wifi_setMode(WIFI_MODE_GD_STA);
    }
    
    Serial.printf("[WiFi] Config accepted: SSID='%s'\n", wifiCfgSSID);
    if (!audioMuted) ui_beep(1500, 80);
    
    wifiCfgPending = false;
    uiState.dirty = true;
}

static void _wifiCfgReject() {
    // Send rejection response via WebSocket
    extern void sendToClient(uint8_t clientNum, const String& msg);
    JsonDocument resp;
    resp["type"] = "wifi_status";
    resp["accepted"] = false;
    resp["reason"] = "Operator rejected";
    String json;
    serializeJson(resp, json);
    sendToClient(wifiCfgClient, json);
    
    Serial.println("[WiFi] Config rejected by operator");
    if (!audioMuted) ui_beep(600, 150);
    
    wifiCfgPending = false;
    uiState.dirty = true;
}

// ═══════════════════════════════════════════════════════════
// VOICE MODE — Range / Balanced / Clarity
// Simple accessors defined here; codec2-dependent functions
// (_voiceModeApply, ui_cycleVoiceMode) defined after Codec2 section.
// ═══════════════════════════════════════════════════════════

VoiceMode ui_getVoiceMode() { return voiceMode; }

bool voice_useRedundancy() {
    // Range and Balanced both use 2× redundancy pass
    return (voiceMode == VMODE_RANGE || voiceMode == VMODE_BALANCED);
}

int voice_getCodecBitrate() {
    return (voiceMode == VMODE_RANGE) ? 1600 : 3200;
}

// Forward declarations (defined after Codec2 variables exist)
static void _voiceModeApply();
void ui_cycleVoiceMode();

static void _loadVoiceMode() {
    File f = LittleFS.open("/vmode.cfg", "r");
    if (f) {
        int mode = f.read();
        if (mode >= 0 && mode <= 2) voiceMode = (VoiceMode)mode;
        f.close();
    }
    // _voiceModeApply() is called after codec2_init when both instances exist
}

// ═══════════════════════════════════════════════════════════
// BATTERY HISTORY
// ═══════════════════════════════════════════════════════════

void ui_recordBattery(uint8_t pct) {
    // Rate limit: one reading per 10s
    if (millis() - lastBatRecord < 10000 && lastBatRecord != 0) return;
    lastBatRecord = millis();
    
    batHistory[batHistoryHead] = pct;
    batHistoryHead = (batHistoryHead + 1) % BAT_HISTORY_SIZE;
    if (batHistoryCount < BAT_HISTORY_SIZE) batHistoryCount++;
}

uint16_t ui_getLastMsgId() { return nextMsgId - 1; }

uint16_t ui_nextMsgId() {
    uint16_t id = nextMsgId++;
    if (nextMsgId == 0) nextMsgId = 1;
    return id;
}

void ui_setLastMsgId(uint16_t id) {
    // Set msgId on the most recently added message (at msgHead-1)
    int idx = (msgHead - 1 + MAX_MESSAGES) % MAX_MESSAGES;
    messages[idx].msgId = id;
}


// ═══════════════════════════════════════════════════════════
// DISPLAY SLEEP / WAKE
// ═══════════════════════════════════════════════════════════

static void _setBacklight(uint8_t level) {
    // level: 0=off, 1=dim, 2=full (uses brightnessLevel preset)
    if (level == backlightState) return;
    backlightState = level;
#ifdef TFT_BL
    uint8_t duty = (level == 2) ? brightnessPresets[brightnessLevel] 
                 : (level == 1) ? BACKLIGHT_DIM : 0;
    ledcWrite(BACKLIGHT_LEDC_CHANNEL, duty);
#endif
}

void ui_wake() {
    lastActivityMs = millis();
    if (backlightState < 2) {
        _setBacklight(2);
        uiState.dirty = true;  // Redraw after wake
    }
}

void ui_setSleepTimeout(uint32_t dimMs, uint32_t offMs) {
    dimTimeoutMs = dimMs;
    offTimeoutMs = offMs;
}

static void _handleDisplaySleep() {
    if (dimTimeoutMs == 0) return;  // Disabled
    uint32_t elapsed = millis() - lastActivityMs;
    if (elapsed >= offTimeoutMs && backlightState != 0) {
        _setBacklight(0);
    } else if (elapsed >= dimTimeoutMs && backlightState == 2) {
        _setBacklight(1);
    }
}

// ── Screen brightness control ──
void ui_cycleBrightness() {
    brightnessLevel = (brightnessLevel + 1) % 4;
#ifdef TFT_BL
    if (backlightState == 2) {
        ledcWrite(BACKLIGHT_LEDC_CHANNEL, brightnessPresets[brightnessLevel]);
    }
#endif
    // Persist
    File f = LittleFS.open("/brightness.cfg", "w");
    if (f) { f.write(brightnessLevel); f.close(); }
}
uint8_t ui_getBrightnessLevel() { return brightnessLevel; }

static void _loadBrightness() {
    File f = LittleFS.open("/brightness.cfg", "r");
    if (f) {
        uint8_t v = f.read();
        if (v < 4) brightnessLevel = v;
        f.close();
    }
}

// ── Screen lock ──
bool ui_isLocked() { return screenLocked; }
void ui_setLocked(bool lock) { 
    screenLocked = lock; 
    lockHoldStart = 0;
    uiState.dirty = true;
}

// ═══════════════════════════════════════════════════════════
// AUDIO — I2S tone generation
// T-Deck speaker is connected via I2S bus, not direct PWM:
//   WS (LRCLK) = GPIO5, BCK (BCLK) = GPIO7, DOUT = GPIO6
// ═══════════════════════════════════════════════════════════

#include <driver/i2s.h>

#define I2S_WS_PIN   5
#define I2S_BCK_PIN  7
#define I2S_DOUT_PIN 6
#define I2S_PORT     I2S_NUM_0
#define I2S_SAMPLE_RATE 16000

static void _audioInit() {
    if (audioInitialized) return;
    
    i2s_config_t i2s_config = {
        .mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_TX),
        .sample_rate = I2S_SAMPLE_RATE,
        .bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT,
        .channel_format = I2S_CHANNEL_FMT_ONLY_LEFT,
        .communication_format = I2S_COMM_FORMAT_STAND_I2S,
        .intr_alloc_flags = ESP_INTR_FLAG_LEVEL1,
        .dma_buf_count = 4,
        .dma_buf_len = 256,
        .use_apll = false,
        .tx_desc_auto_clear = true,
        .fixed_mclk = 0
    };
    
    i2s_pin_config_t pin_config = {
        .mck_io_num = I2S_PIN_NO_CHANGE,  // Speaker amp doesn't need MCLK
        .bck_io_num = I2S_BCK_PIN,
        .ws_io_num = I2S_WS_PIN,
        .data_out_num = I2S_DOUT_PIN,
        .data_in_num = I2S_PIN_NO_CHANGE
    };
    
    esp_err_t err = i2s_driver_install(I2S_PORT, &i2s_config, 0, NULL);
    if (err != ESP_OK) {
        Serial.printf("[Audio] I2S install failed: %d\n", err);
        return;
    }
    
    err = i2s_set_pin(I2S_PORT, &pin_config);
    if (err != ESP_OK) {
        Serial.printf("[Audio] I2S pin config failed: %d\n", err);
        return;
    }
    
    i2s_zero_dma_buffer(I2S_PORT);
    audioInitialized = true;
    Serial.printf("[Audio] I2S initialized (WS=%d BCK=%d DOUT=%d)\n", 
                  I2S_WS_PIN, I2S_BCK_PIN, I2S_DOUT_PIN);
}

void ui_setMute(bool mute) {
    audioMuted = mute;
    File f = LittleFS.open("/mute.cfg", "w");
    if (f) { f.write(mute ? 1 : 0); f.close(); }
    Serial.printf("[Audio] %s\n", mute ? "MUTED" : "UNMUTED");
}

bool ui_isMuted() { return audioMuted; }

static void _loadMute() {
    File f = LittleFS.open("/mute.cfg", "r");
    if (f) { audioMuted = (f.read() == 1); f.close(); }
}

// ═══════════════════════════════════════════════════════════
// ES7210 MICROPHONE — 4-channel ADC on T-Deck CYPHER M8K
// I2C address 0x40, I2S input on separate peripheral (I2S_NUM_1)
// Pins: MCLK=GPIO48, LRCK/WS=GPIO21, SCK/BCK=GPIO47, DIN=GPIO14
// ═══════════════════════════════════════════════════════════

#define ES7210_ADDR       0x40
#define MIC_I2S_BCK       47
#define MIC_I2S_WS        21
#define MIC_I2S_DIN       14
#define MIC_I2S_MCLK      48
#define MIC_I2S_CH        I2S_NUM_1  // Official T-Deck uses I2S_NUM_1 for mic

// Audio recording buffer (3 seconds at 16kHz 16-bit = 96000 bytes)
#define MIC_BUF_SAMPLES   48000  // 3s at 16kHz
static int16_t* micBuffer = NULL;
// micBufPos defined earlier (used by voice state machine)
static bool micRecording = false;

// ES7210 register write/read (matching official es7210.cpp)
static bool _es7210WriteReg(uint8_t reg, uint8_t val) {
    Wire.beginTransmission(ES7210_ADDR);
    Wire.write(reg);
    Wire.write(val);
    return Wire.endTransmission() == 0;
}

static uint8_t _es7210ReadReg(uint8_t reg) {
    Wire.beginTransmission(ES7210_ADDR);
    Wire.write(reg);
    Wire.endTransmission(false);
    Wire.requestFrom((uint8_t)ES7210_ADDR, (size_t)1);
    return Wire.available() ? Wire.read() : 0xFF;
}

static void _es7210UpdateRegBit(uint8_t reg, uint8_t mask, uint8_t val) {
    uint8_t old = _es7210ReadReg(reg);
    _es7210WriteReg(reg, (old & ~mask) | (mask & val));
}

// Official ES7210 init — matches LilyGO T-Deck lib/es7210/src/es7210.cpp exactly
static bool _es7210Init() {
    Wire.beginTransmission(ES7210_ADDR);
    if (Wire.endTransmission() != 0) {
        Serial.println("[ES7210] Not found at 0x40");
        return false;
    }
    Serial.println("[ES7210] Found at 0x40, init (official sequence)...");
    
    // Reset: REG00 = 0xFF then 0x41 (official values)
    _es7210WriteReg(0x00, 0xFF);
    _es7210WriteReg(0x00, 0x41);
    // Clock off initial state
    _es7210WriteReg(0x01, 0x1F);
    // Time control (chip state cycle + power on cycle)
    _es7210WriteReg(0x09, 0x30);
    _es7210WriteReg(0x0A, 0x30);
    // Slave mode — no register write needed (default)
    
    // Analog power: vdda=3.3V, VMID=5K start
    _es7210WriteReg(0x40, 0xC3);
    // MIC bias: 2.87V for both pairs
    _es7210WriteReg(0x41, 0x70);
    _es7210WriteReg(0x42, 0x70);
    // ADC OSR
    _es7210WriteReg(0x07, 0x20);
    // Main clock: DLL + doubler, clear state first
    _es7210WriteReg(0x02, 0xC1);
    
    // Config sample rate: 16kHz with MCLK=4.096MHz
    // From coeff table: {4096000, 16000, 0x00, 0x01, 0x01, 0x01, 0x20, 0x00, 0x01, 0x00}
    _es7210WriteReg(0x02, 0xC1);  // adc_div=0x01 | doubler=1<<6 | dll=1<<7
    _es7210WriteReg(0x07, 0x20);  // osr
    _es7210WriteReg(0x04, 0x01);  // lrck_h
    _es7210WriteReg(0x05, 0x00);  // lrck_l
    
    // SDP: I2S normal, 16-bit
    uint8_t sdp = _es7210ReadReg(0x11);
    sdp = (sdp & 0x1F) | 0x60;  // 16-bit
    sdp = (sdp & 0xFC) | 0x00;  // I2S normal
    _es7210WriteReg(0x11, sdp);
    _es7210WriteReg(0x12, 0x00); // ADC1/2→SDOUT1, ADC3/4→SDOUT2
    
    // Mic select: enable all 4 mics (official mic_select sequence)
    for (int i = 0; i < 4; i++) _es7210UpdateRegBit(0x43 + i, 0x10, 0x00);
    _es7210WriteReg(0x4B, 0xFF);
    _es7210WriteReg(0x4C, 0xFF);
    // MIC1+2
    _es7210UpdateRegBit(0x01, 0x0B, 0x00);
    _es7210WriteReg(0x4B, 0x00);
    _es7210UpdateRegBit(0x43, 0x10, 0x10);
    _es7210UpdateRegBit(0x44, 0x10, 0x10);
    // MIC3+4
    _es7210UpdateRegBit(0x01, 0x15, 0x00);
    _es7210WriteReg(0x4C, 0x00);
    _es7210UpdateRegBit(0x45, 0x10, 0x10);
    _es7210UpdateRegBit(0x46, 0x10, 0x10);
    
    // Gain: all mics at 30dB for T-Deck MEMS microphone
    _es7210UpdateRegBit(0x43, 0x0F, 0x0C);  // MIC1 = 30dB
    _es7210UpdateRegBit(0x44, 0x0F, 0x0C);  // MIC2 = 30dB
    _es7210UpdateRegBit(0x45, 0x0F, 0x0C);  // MIC3 = 30dB
    _es7210UpdateRegBit(0x46, 0x0F, 0x0C);  // MIC4 = 30dB
    
    // Start: power on ADC + mic channels (official es7210_start)
    uint8_t clockReg = _es7210ReadReg(0x01);
    _es7210WriteReg(0x01, clockReg);
    _es7210WriteReg(0x06, 0x00);
    _es7210WriteReg(0x47, 0x00);
    _es7210WriteReg(0x48, 0x00);
    _es7210WriteReg(0x49, 0x00);
    _es7210WriteReg(0x4A, 0x00);
    
    // Re-run mic_select after start (official sequence does this)
    for (int i = 0; i < 4; i++) _es7210UpdateRegBit(0x43 + i, 0x10, 0x00);
    _es7210WriteReg(0x4B, 0xFF);
    _es7210WriteReg(0x4C, 0xFF);
    _es7210UpdateRegBit(0x01, 0x0B, 0x00);
    _es7210WriteReg(0x4B, 0x00);
    _es7210UpdateRegBit(0x43, 0x10, 0x10);
    _es7210UpdateRegBit(0x44, 0x10, 0x10);
    _es7210UpdateRegBit(0x01, 0x15, 0x00);
    _es7210WriteReg(0x4C, 0x00);
    _es7210UpdateRegBit(0x45, 0x10, 0x10);
    _es7210UpdateRegBit(0x46, 0x10, 0x10);
    
    Serial.printf("[ES7210] R00=0x%02X R01=0x%02X R02=0x%02X R06=0x%02X R11=0x%02X R40=0x%02X\n",
                  _es7210ReadReg(0x00), _es7210ReadReg(0x01), _es7210ReadReg(0x02),
                  _es7210ReadReg(0x06), _es7210ReadReg(0x11), _es7210ReadReg(0x40));
    Serial.printf("[ES7210] R43=0x%02X R47=0x%02X R4B=0x%02X\n",
                  _es7210ReadReg(0x43), _es7210ReadReg(0x47), _es7210ReadReg(0x4B));
    Serial.println("[ES7210] Init complete");
    return true;
}

// I2S config matching official Microphone.ino EXACTLY
static bool _micI2sInit() {
    i2s_config_t i2s_config = {
        .mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX),
        .sample_rate = MIC_SAMPLE_RATE,
        .bits_per_sample = I2S_BITS_PER_SAMPLE_16BIT,
        .channel_format = I2S_CHANNEL_FMT_ALL_LEFT,
        .communication_format = I2S_COMM_FORMAT_STAND_I2S,
        .intr_alloc_flags = ESP_INTR_FLAG_LEVEL1,
        .dma_buf_count = 8,
        .dma_buf_len = 64,
        .use_apll = false,
        .tx_desc_auto_clear = true,
        .fixed_mclk = 0,
        .mclk_multiple = I2S_MCLK_MULTIPLE_256,
        .bits_per_chan = I2S_BITS_PER_CHAN_16BIT,
#if SOC_I2S_SUPPORTS_TDM
        .chan_mask = (i2s_channel_t)(I2S_TDM_ACTIVE_CH0 | I2S_TDM_ACTIVE_CH1),
        .total_chan = 0,
        .left_align = false,
        .big_edin = false,
        .bit_order_msb = false,
        .skip_msk = false,
#endif
    };
    
    i2s_pin_config_t pin_config = {0};
    pin_config.bck_io_num = MIC_I2S_BCK;
    pin_config.ws_io_num = MIC_I2S_WS;
    pin_config.data_in_num = MIC_I2S_DIN;
    pin_config.mck_io_num = MIC_I2S_MCLK;
    
    esp_err_t err = i2s_driver_install(MIC_I2S_CH, &i2s_config, 0, NULL);
    if (err != ESP_OK) {
        Serial.printf("[Mic] I2S install failed: %d\n", err);
        return false;
    }
    err = i2s_set_pin(MIC_I2S_CH, &pin_config);
    if (err != ESP_OK) {
        Serial.printf("[Mic] I2S pin config failed: %d\n", err);
        i2s_driver_uninstall(MIC_I2S_CH);
        return false;
    }
    i2s_zero_dma_buffer(MIC_I2S_CH);
    Serial.printf("[Mic] I2S_NUM_1 ready (BCK=%d WS=%d DIN=%d MCLK=%d)\n",
                  MIC_I2S_BCK, MIC_I2S_WS, MIC_I2S_DIN, MIC_I2S_MCLK);
    return true;
}

bool mic_init() {
    if (micInitialized) return true;
    
    // ES7210 I2C config first, then I2S (provides MCLK)
    if (!_es7210Init()) return false;
    if (!_micI2sInit()) return false;
    
    // Defensive free: if a prior init attempt allocated but failed later,
    // prevent leak on retry
    if (micBuffer) { free(micBuffer); micBuffer = NULL; }
    micBuffer = (int16_t*)malloc(MIC_BUF_SAMPLES * sizeof(int16_t));
    if (!micBuffer) {
        Serial.println("[Mic] Buffer alloc failed");
        i2s_driver_uninstall(MIC_I2S_CH);
        return false;
    }
    
    // Flush initial DMA
    int16_t junk[128];
    size_t junkRead;
    for (int i = 0; i < 8; i++) {
        i2s_read(MIC_I2S_CH, junk, sizeof(junk), &junkRead, 50);
    }
    
    micInitialized = true;
    Serial.printf("[Mic] Ready (%d samples, %.1fs at %dHz)\n",
                  MIC_BUF_SAMPLES, (float)MIC_BUF_SAMPLES / MIC_SAMPLE_RATE, MIC_SAMPLE_RATE);
    return true;
}

bool mic_isReady() { return micInitialized; }

// Record audio — reads TDM interleaved from I2S_NUM_1, extracts CH0
// Stops early if user presses V/Space/Enter (min 0.5s recording)
#define MIC_MIN_RECORD_MS 500  // Minimum recording before stop allowed
int mic_record(int durationMs) {
    if (!micInitialized) return 0;
    
    int targetSamples = (MIC_SAMPLE_RATE * durationMs) / 1000;
    if (targetSamples > MIC_BUF_SAMPLES) targetSamples = MIC_BUF_SAMPLES;
    int minSamples = (MIC_SAMPLE_RATE * MIC_MIN_RECORD_MS) / 1000;
    
    micBufPos = 0;
    micRecording = true;
    size_t bytesRead = 0;
    uint32_t recStart = millis();
    
    Serial.printf("[Mic] Recording up to %dms (%d samples)...\n", durationMs, targetSamples);
    
    // Raw diagnostic: first 64 bytes (shows TDM interleave pattern)
    {
        uint8_t rawDiag[64];
        size_t rawRead = 0;
        esp_err_t dErr = i2s_read(MIC_I2S_CH, rawDiag, sizeof(rawDiag), &rawRead, 200);
        Serial.printf("[Mic] Raw diag: err=%d, %d bytes: ", dErr, rawRead);
        int nonZero = 0;
        for (int i = 0; i < (int)rawRead && i < 32; i++) {
            Serial.printf("%02X ", rawDiag[i]);
            if (rawDiag[i] != 0) nonZero++;
        }
        Serial.printf(" (nz=%d)\n", nonZero);
    }
    
    // TDM with 2 active channels: I2S gives interleaved [CH0, CH1, CH0, CH1, ...]
    static int16_t tdmBuf[512];  // Static: avoid 1KB stack allocation
    bool stoppedEarly = false;
    uint32_t hardTimeout = recStart + durationMs + 2000;  // Hard safety: duration + 2s grace
    
    while (micBufPos < targetSamples) {
        // Hard wall-clock timeout — prevents infinite loop regardless of I2S behavior
        if (millis() > hardTimeout) {
            Serial.println("[Mic] Hard timeout reached, stopping");
            break;
        }
        int remaining = targetSamples - micBufPos;
        int monoPairs = min(remaining, 256);
        int stereoBytes = monoPairs * 2 * sizeof(int16_t);
        
        esp_err_t err = i2s_read(MIC_I2S_CH, tdmBuf, stereoBytes, &bytesRead, 100);
        if (err != ESP_OK || bytesRead == 0) break;
        
        int stereoSamples = bytesRead / sizeof(int16_t);
        for (int i = 0; i < stereoSamples && micBufPos < targetSamples; i += 2) {
            micBuffer[micBufPos++] = tdmBuf[i];
        }
        
        // Check for early stop (keyboard or trackball press) after minimum recording
        if (micBufPos >= minSamples) {
            char k = readKeyboard();
            if (k == 0) k = _readTrackball();  // Also check trackball click
            if (k == 'v' || k == 'V' || k == ' ' || k == '\n' || k == '\r') {
                stoppedEarly = true;
                Serial.printf("[Mic] Stopped early by user at %dms\n", (int)(millis() - recStart));
                break;
            }
        }
        
        // Update recording time display every ~250ms
        if ((micBufPos % 4000) == 0) {
            float elapsed = (millis() - recStart) / 1000.0f;
            tft.fillRect(scrW / 2 - 60, scrH / 2 + 2, 120, 12, COLOR_RED);
            tft.setCursor(scrW / 2 - 50, scrH / 2 + 2);
            tft.setTextColor(COLOR_TEXT);
            tft.setTextSize(1);
            tft.printf("%.1fs — V to Send", elapsed);
        }
    }
    
    micRecording = false;
    
    int16_t peakPos = 0, peakNeg = 0;
    for (int i = 0; i < micBufPos; i++) {
        if (micBuffer[i] > peakPos) peakPos = micBuffer[i];
        if (micBuffer[i] < peakNeg) peakNeg = micBuffer[i];
    }
    float recSec = (millis() - recStart) / 1000.0f;
    Serial.printf("[Mic] Recorded %d samples in %.1fs (peak: +%d / %d)%s\n", 
                  micBufPos, recSec, peakPos, peakNeg, stoppedEarly ? " [user stop]" : "");
    return micBufPos;
}

// Play back through speaker (I2S_NUM_0)
void mic_playback() {
    if (!micInitialized || micBufPos == 0) {
        Serial.println("[Mic] Nothing to play");
        return;
    }
    _audioInit();
    
    // === DC OFFSET REMOVAL + AMPLIFICATION ===
    // Calculate DC offset (average of all samples)
    int32_t dcSum = 0;
    for (int i = 0; i < micBufPos; i++) dcSum += micBuffer[i];
    int16_t dcOffset = (int16_t)(dcSum / micBufPos);
    
    // Find peak after DC removal to calculate gain
    int16_t maxAbs = 0;
    for (int i = 0; i < micBufPos; i++) {
        int16_t s = micBuffer[i] - dcOffset;
        if (s > maxAbs) maxAbs = s;
        if (-s > maxAbs) maxAbs = -s;
    }
    
    // Amplify to ~96% of full scale (31500 out of 32767)
    float gain = (maxAbs > 0) ? 31500.0f / maxAbs : 1.0f;
    if (gain > 32.0f) gain = 32.0f;  // Cap gain to prevent noise amplification
    
    Serial.printf("[Mic] DC offset=%d, peak=%d, gain=%.1fx\n", dcOffset, maxAbs, gain);
    
    i2s_set_sample_rates(I2S_PORT, MIC_SAMPLE_RATE);
    Serial.printf("[Mic] Playing %d samples at %dHz (amplified)...\n", micBufPos, MIC_SAMPLE_RATE);
    
    // Play with DC removal and amplification applied on-the-fly
    size_t bytesWritten = 0;
    int16_t outBuf[256];
    int pos = 0;
    while (pos < micBufPos) {
        int chunk = min(micBufPos - pos, 256);
        for (int i = 0; i < chunk; i++) {
            int32_t s = (int32_t)(micBuffer[pos + i] - dcOffset);
            s = (int32_t)(s * gain);
            if (s > 32767) s = 32767;
            if (s < -32767) s = -32767;
            outBuf[i] = (int16_t)s;
        }
        i2s_write(I2S_PORT, outBuf, chunk * sizeof(int16_t), &bytesWritten, 100);
        pos += chunk;
    }
    int16_t silence[64] = {0};
    i2s_write(I2S_PORT, silence, sizeof(silence), &bytesWritten, 50);
    i2s_set_sample_rates(I2S_PORT, I2S_SAMPLE_RATE);
    Serial.println("[Mic] Playback complete");
}

// Raw buffer access (for future Codec2)
int16_t* mic_getBuffer() { return micBuffer; }
int mic_getBufferLen() { return micBufPos; }
bool mic_isRecording() { return micRecording; }

// ═══════════════════════════════════════════════════════════
// ACOUSTIC GUNSHOT DETECTION
// Background impulsive transient detector. Reads small I2S chunks
// during idle (not during voice recording), detects amplitude spikes
// above an adaptive noise floor. Pure DSP — no ML models.
//
// Detection principle: gunshots have rise time < 1ms, peak amplitude
// 6-20× above ambient, duration 50-200ms with characteristic decay.
// A 4ms chunk with peak >> noise floor IS an impulsive transient
// by definition. Sustained loud sounds (wind, engines) raise the
// noise floor gradually via slow EMA and don't trigger.
// ═══════════════════════════════════════════════════════════

// gdEnabled, gdDetectionCount, gdSensitivity defined at top of file (forward declaration block)
static float    gdNoiseFloor = 500.0f;     // Adaptive noise floor (EMA of peak)
static uint32_t gdLastDetect = 0;          // millis() of last detection (cooldown)
static uint32_t gdLastTick = 0;            // Rate limit ticks to ~100Hz
static uint8_t  gdConfirmCount = 0;        // Consecutive above-threshold chunks
static uint32_t gdConfirmStart = 0;        // millis() of first confirming hit
static int16_t  gdConfirmPeak = 0;         // Peak amplitude across confirmation window

// Per-sensitivity-level parameters:
//                               mult    absMin  hits  window
static const float   gdMultTable[4]   = { 0,    10.0f,  15.0f,  20.0f };
static const int16_t gdAbsTable[4]    = { 0,    8000,   12000,  16000 };
static const uint8_t gdHitsTable[4]   = { 0,    3,      4,      5     };
static const uint16_t gdWindowTable[4] = { 0,   150,    150,    200   };

// gdSensLabel, gdSensShort defined at top of file (forward declaration block)

void gunshot_setEnabled(bool on) { gdEnabled = on; if (!on) gdSensitivity = GD_SENS_OFF; }
bool gunshot_isEnabled() { return gdEnabled; }
uint32_t gunshot_getDetectionCount() { return gdDetectionCount; }

uint8_t gunshot_getSensitivity() { return gdSensitivity; }
void gunshot_setSensitivity(uint8_t level) {
    if (level > GD_SENS_LOW) level = GD_SENS_OFF;
    gdSensitivity = level;
    gdEnabled = (level != GD_SENS_OFF);
    gdConfirmCount = 0;
    Serial.printf("[Gunshot] Sensitivity: %s\n", gdSensLabel[level]);
    uiState.dirty = true;
}
void gunshot_cycleSensitivity() {
    // OFF → High → Med → Low → OFF
    uint8_t next = gdSensitivity + 1;
    if (next > GD_SENS_LOW) next = GD_SENS_OFF;
    gunshot_setSensitivity(next);
}

void gunshot_tick() {
    if (!gdEnabled || !micInitialized || micRecording) return;
    if (gdSensitivity == GD_SENS_OFF) return;
    
    // Rate limit: read at ~100Hz (every ~10ms) to keep CPU load low
    uint32_t now = millis();
    if (now - gdLastTick < 10) return;
    gdLastTick = now;
    
    // Voice state machine active — don't compete for I2S
    if (vmState != VM_IDLE) return;
    
    // Read a small chunk from I2S (non-blocking, short timeout)
    int16_t tdmChunk[GD_CHUNK_SAMPLES * 2];  // Stereo interleaved
    size_t bytesRead = 0;
    esp_err_t err = i2s_read(MIC_I2S_CH, tdmChunk, sizeof(tdmChunk), &bytesRead, 5);
    if (err != ESP_OK || bytesRead < 4) return;
    
    // Extract CH0 and find peak amplitude
    int stereoSamples = bytesRead / sizeof(int16_t);
    int16_t peak = 0;
    for (int i = 0; i < stereoSamples; i += 2) {
        int16_t sample = tdmChunk[i];
        int16_t absSample = (sample < 0) ? -sample : sample;
        if (absSample > peak) peak = absSample;
    }
    
    // Update adaptive noise floor (slow EMA — adapts over ~5 seconds)
    gdNoiseFloor = gdNoiseFloor * (1.0f - GD_NOISE_ALPHA) + (float)peak * GD_NOISE_ALPHA;
    if (gdNoiseFloor < 100.0f) gdNoiseFloor = 100.0f;
    if (gdNoiseFloor > 10000.0f) gdNoiseFloor = 10000.0f;
    
    // Detection threshold from sensitivity level
    float threshMult = gdMultTable[gdSensitivity];
    int16_t absMin = gdAbsTable[gdSensitivity];
    uint8_t confirmHits = gdHitsTable[gdSensitivity];
    uint16_t confirmWindow = gdWindowTable[gdSensitivity];
    
    float threshold = gdNoiseFloor * threshMult;
    if (threshold < (float)absMin) threshold = (float)absMin;
    
    // Cooldown: skip entirely during cooldown period
    if (now - gdLastDetect < GD_COOLDOWN_MS) {
        gdConfirmCount = 0;
        return;
    }
    
    // ── Multi-sample confirmation ──
    if ((float)peak > threshold) {
        if (gdConfirmCount == 0) {
            gdConfirmStart = now;
            gdConfirmPeak = peak;
            gdConfirmCount = 1;
        } else if (now - gdConfirmStart <= confirmWindow) {
            gdConfirmCount++;
            if (peak > gdConfirmPeak) gdConfirmPeak = peak;
        } else {
            gdConfirmStart = now;
            gdConfirmPeak = peak;
            gdConfirmCount = 1;
        }
    } else {
        gdConfirmCount = 0;
    }
    
    // Not enough consecutive hits yet
    if (gdConfirmCount < confirmHits) return;
    
    // ── GUNSHOT CONFIRMED ──
    gdLastDetect = now;
    gdDetectionCount++;
    gdConfirmCount = 0;  // Reset for next detection
    peak = gdConfirmPeak;  // Use the peak from the confirmation window
    
    // Build alert with GPS
    double lat, lon, alt;
    bool haveGPS = ui_getGPS(&lat, &lon, &alt);
    
    char alertMsg[128];
    if (haveGPS) {
        snprintf(alertMsg, sizeof(alertMsg),
                 "GUNSHOT detected (pk=%d nf=%.0f) at [%.5f,%.5f]",
                 peak, gdNoiseFloor, lat, lon);
    } else {
        snprintf(alertMsg, sizeof(alertMsg),
                 "GUNSHOT detected (pk=%d nf=%.0f) — no GPS",
                 peak, gdNoiseFloor);
    }
    
    ui_addMessage("SHOT", alertMsg, false, false, GROUP_CH_ALERTS);
    ui_beepAlert();
    
    // Broadcast over LoRa (via compose path) if we have GPS and no pending compose
    if (haveGPS && ui_callsignSet() && !composeReady) {
        char composeMsg[100];
        snprintf(composeMsg, sizeof(composeMsg),
                 "GUNSHOT [%.5f,%.5f] pk=%d", lat, lon, peak);
        strncpy(uiState.composeBuffer, composeMsg, sizeof(uiState.composeBuffer) - 1);
        uiState.composeLen = strlen(uiState.composeBuffer);
        uiState.selectedContact = -1;  // Broadcast
        activeGroupCh = GROUP_CH_ALERTS;
        composeReady = true;
    }
    
    // Log to SD card
    if (sdMounted) {
        char ts[32];
        _sdTimestamp(ts, sizeof(ts));
        char logPath[] = "/griddown/logs/gunshot.log";
        File f = SD.open(logPath, FILE_APPEND);
        if (f) {
            if (haveGPS) {
                f.printf("%s,%.5f,%.5f,%d,%.0f\n", ts, lat, lon, peak, gdNoiseFloor);
            } else {
                f.printf("%s,no_gps,no_gps,%d,%.0f\n", ts, peak, gdNoiseFloor);
            }
            f.close();
        }
    }
    
    Serial.printf("[GUNSHOT] CONFIRMED (%s): peak=%d noise=%.0f threshold=%.0f hits=%d count=%lu\n",
                  gdSensLabel[gdSensitivity], peak, gdNoiseFloor, threshold, confirmHits, gdDetectionCount);
}

// ═══════════════════════════════════════════════════════════
// SHARED CRYPTO HELPERS — HKDF (RFC 5869) + constant-time compare
// ═══════════════════════════════════════════════════════════
// HKDF-SHA256 per RFC 5869, implemented directly on mbedTLS HMAC primitives
// rather than mbedtls_hkdf() so it does not depend on MBEDTLS_HKDF_C being
// enabled in the ESP-IDF mbedTLS config.
//
//   PRK  = HMAC-SHA256(salt, IKM)                       [Extract]
//   T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)         [Expand]
//   OKM  = first L bytes of T(1) || T(2) || ...
//
// Verified against the RFC 5869 Appendix A test vectors (see
// test_crypto_hardening.cpp).
static bool _hkdfSha256(const uint8_t* salt, size_t saltLen,
                        const uint8_t* ikm,  size_t ikmLen,
                        const uint8_t* info, size_t infoLen,
                        uint8_t* out, size_t outLen) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || outLen == 0 || outLen > 255 * 32) return false;

    // RFC 5869 §2.2: if salt is absent, use HashLen zero bytes.
    uint8_t zeroSalt[32] = {0};
    if (!salt || saltLen == 0) { salt = zeroSalt; saltLen = 32; }

    // ── Extract ──
    uint8_t prk[32];
    if (mbedtls_md_hmac(md, salt, saltLen, ikm, ikmLen, prk) != 0) return false;

    // ── Expand ──
    uint8_t  t[32];
    size_t   tLen = 0;          // 0 for the first round (T(0) is empty)
    size_t   done = 0;
    uint8_t  counter = 1;
    bool     ok = true;

    while (done < outLen) {
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, md, 1) != 0 ||
            mbedtls_md_hmac_starts(&ctx, prk, sizeof(prk)) != 0 ||
            (tLen && mbedtls_md_hmac_update(&ctx, t, tLen) != 0) ||
            (infoLen && mbedtls_md_hmac_update(&ctx, info, infoLen) != 0) ||
            mbedtls_md_hmac_update(&ctx, &counter, 1) != 0 ||
            mbedtls_md_hmac_finish(&ctx, t) != 0) {
            mbedtls_md_free(&ctx);
            ok = false;
            break;
        }
        mbedtls_md_free(&ctx);

        size_t chunk = (outLen - done < 32) ? (outLen - done) : 32;
        memcpy(out + done, t, chunk);
        done += chunk;
        tLen = 32;
        counter++;
    }

    // Scrub intermediates
    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    if (!ok) memset(out, 0, outLen);
    return ok;
}

// Constant-time comparison — no early return on first mismatch, so timing
// does not leak how many leading bytes matched.
static bool _ctEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

// ═══════════════════════════════════════════════════════════
// DURESS CODE — Hidden distress signal in normal messages
// Operator types 4-digit PIN anywhere in a compose message.
// PIN is stripped from visible text, "duress":true added to JSON.
// Receiving nodes show normal message + silent Alerts channel warning.
//
// ── Storage (v2, hashed) ──
// The PIN is NEVER stored in plaintext and is NEVER written to the display or
// the serial log. On disk:
//     [0xDA][0x02][pinLen][salt(16)][HMAC-SHA256(salt, pin)(32)]  = 51 bytes
// Matching works by scanning the composed text for digit runs of the stored
// length, hashing each candidate, and comparing in constant time.
//
// ── Honest limitation ──
// A 4-digit PIN has only 10,000 possible values. Hashing prevents the PIN
// being *read* off flash (the previous behaviour) and stops publication of
// this source from revealing where to look, but it cannot prevent offline
// brute force by someone holding the device. Longer PINs (up to 8 digits) are
// supported and materially better. Treat a captured device's duress PIN as
// compromised.
// ═══════════════════════════════════════════════════════════

#define DURESS_PIN_FILE   "/duress.cfg"
#define DURESS_MAGIC      0xDA
#define DURESS_VER        0x02
#define DURESS_SALT_LEN   16
#define DURESS_HASH_LEN   32
#define DURESS_PIN_MIN    4
#define DURESS_PIN_MAX    8
#define DURESS_REC_LEN    (3 + DURESS_SALT_LEN + DURESS_HASH_LEN)  // 51

static uint8_t duressSalt[DURESS_SALT_LEN] = {0};
static uint8_t duressHash[DURESS_HASH_LEN] = {0};
static uint8_t duressPinLen = 0;
static bool    duressPinSet = false;

// HMAC-SHA256(salt, pin) → 32-byte verifier.
// A fast MAC (not a slow KDF) is required here: duress_checkAndStrip() must
// hash every candidate digit-run in a composed message, so a deliberately
// slow KDF would add seconds of latency to sending. Given the 4-8 digit
// keyspace, a slow KDF would not meaningfully change brute-force resistance
// anyway — see the limitation note above.
static bool _duressHashPin(const char* pin, size_t pinLen,
                           const uint8_t* salt, uint8_t* out) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return false;
    return mbedtls_md_hmac(md, salt, DURESS_SALT_LEN,
                           (const uint8_t*)pin, pinLen, out) == 0;
}

static void _duressSave() {
    File f = LittleFS.open(DURESS_PIN_FILE, "w");
    if (!f) return;
    if (duressPinSet) {
        uint8_t hdr[3] = { DURESS_MAGIC, DURESS_VER, duressPinLen };
        f.write(hdr, 3);
        f.write(duressSalt, DURESS_SALT_LEN);
        f.write(duressHash, DURESS_HASH_LEN);
    }
    f.close();
}

static void _duressLoad() {
    File f = LittleFS.open(DURESS_PIN_FILE, "r");
    if (!f) return;
    size_t sz = f.size();

    // ── Current hashed format ──
    if (sz >= DURESS_REC_LEN) {
        uint8_t rec[DURESS_REC_LEN];
        f.readBytes((char*)rec, DURESS_REC_LEN);
        f.close();
        if (rec[0] == DURESS_MAGIC && rec[1] == DURESS_VER &&
            rec[2] >= DURESS_PIN_MIN && rec[2] <= DURESS_PIN_MAX) {
            duressPinLen = rec[2];
            memcpy(duressSalt, rec + 3, DURESS_SALT_LEN);
            memcpy(duressHash, rec + 3 + DURESS_SALT_LEN, DURESS_HASH_LEN);
            duressPinSet = true;
            Serial.println("[Duress] PIN loaded (hashed)");
        }
        return;
    }

    // ── Legacy v1 migration: 4 plaintext digits ──
    // Convert in place so the operator's duress PIN keeps working rather than
    // silently becoming unset (a duress feature that has quietly turned itself
    // off is worse than one that is merely weak).
    if (sz >= 4) {
        char buf[8] = {0};
        f.readBytes(buf, 4);
        f.close();
        for (int i = 0; i < 4; i++) {
            if (buf[i] < '0' || buf[i] > '9') return;
        }
        esp_fill_random(duressSalt, DURESS_SALT_LEN);
        if (!_duressHashPin(buf, 4, duressSalt, duressHash)) return;
        duressPinLen = 4;
        duressPinSet = true;
        memset(buf, 0, sizeof(buf));
        _duressSave();
        Serial.println("[Duress] Migrated legacy plaintext PIN to hashed storage.");
        Serial.println("[Duress] Recommend: full erase flash, then re-enter the PIN.");
        return;
    }
    f.close();
}

bool duress_isSet() { return duressPinSet; }

// Returns only whether a PIN is configured. The previous implementation
// returned the first two digits ("12**"), which reduced a 4-digit PIN to 100
// guesses for anyone who glanced at the screen or the serial log.
const char* duress_getHint() { return duressPinSet ? "SET" : "----"; }

void duress_setPin(const char* pin) {
    if (!pin) return;
    size_t len = strlen(pin);
    if (len < DURESS_PIN_MIN || len > DURESS_PIN_MAX) {
        Serial.printf("[Duress] Rejected: PIN must be %d-%d digits\n",
                      DURESS_PIN_MIN, DURESS_PIN_MAX);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        if (pin[i] < '0' || pin[i] > '9') {
            Serial.println("[Duress] Rejected: PIN must be digits only");
            return;
        }
    }

    esp_fill_random(duressSalt, DURESS_SALT_LEN);
    if (!_duressHashPin(pin, len, duressSalt, duressHash)) {
        Serial.println("[Duress] Failed to hash PIN — not set");
        return;
    }
    duressPinLen = (uint8_t)len;
    duressPinSet = true;
    _duressSave();
    Serial.println("[Duress] PIN set (stored hashed; value not logged)");
    uiState.dirty = true;
}

void duress_clearPin() {
    memset(duressSalt, 0, sizeof(duressSalt));
    memset(duressHash, 0, sizeof(duressHash));
    duressPinLen = 0;
    duressPinSet = false;
    LittleFS.remove(DURESS_PIN_FILE);
    Serial.println("[Duress] PIN cleared");
    uiState.dirty = true;
}

// Scan text for any digit run matching the stored PIN length, hash each
// candidate, and compare against the stored verifier in constant time.
// On match, strip that substring and return true.
bool duress_checkAndStrip(char* text) {
    if (!duressPinSet || !text || duressPinLen == 0) return false;
    size_t len = strlen(text);
    if (len < duressPinLen) return false;

    uint8_t cand[DURESS_HASH_LEN];
    for (size_t i = 0; i + duressPinLen <= len; i++) {
        // Candidate must be all digits
        bool allDigits = true;
        for (uint8_t j = 0; j < duressPinLen; j++) {
            if (text[i + j] < '0' || text[i + j] > '9') { allDigits = false; break; }
        }
        if (!allDigits) continue;

        if (!_duressHashPin(text + i, duressPinLen, duressSalt, cand)) continue;
        if (!_ctEqual(cand, duressHash, DURESS_HASH_LEN)) continue;

        // Match — strip the PIN substring
        memmove(text + i, text + i + duressPinLen,
                strlen(text + i + duressPinLen) + 1);

        // Normalise whitespace so the removal leaves no visible trace. If the
        // PIN sat between two spaces, splicing it out leaves a double space —
        // a tell that something was deleted, which would undermine the covert
        // intent of the duress signal.
        if (i > 0 && text[i - 1] == ' ' && text[i] == ' ') {
            memmove(text + i, text + i + 1, strlen(text + i + 1) + 1);
        }
        size_t lead = 0;
        while (text[lead] == ' ') lead++;
        if (lead) memmove(text, text + lead, strlen(text + lead) + 1);
        size_t nlen = strlen(text);
        while (nlen > 0 && text[nlen - 1] == ' ') text[--nlen] = '\0';

        memset(cand, 0, sizeof(cand));
        Serial.println("[Duress] Trigger detected and stripped — DURESS ACTIVE");
        return true;
    }
    memset(cand, 0, sizeof(cand));
    return false;
}

// ═══════════════════════════════════════════════════════════
// CODEC2 — Low-bitrate voice codec (1600bps)
// 320 samples per frame (40ms at 8kHz) → 8 bytes per frame
// Our mic records at 16kHz, so we downsample 2:1 for Codec2
// ═══════════════════════════════════════════════════════════

static struct CODEC2* c2state = NULL;      // Currently active instance (TX mode)
static struct CODEC2* c2state_1600 = NULL; // 1600bps instance
static struct CODEC2* c2state_3200 = NULL; // 3200bps instance

// Codec2 frame parameters (both modes produce 8 bytes per frame)
#define C2_BYTES_PER_FRAME       8
#define C2_SAMPLES_PER_FRAME_1600 320  // 40ms at 8kHz
#define C2_SAMPLES_PER_FRAME_3200 160  // 20ms at 8kHz

// Active samples-per-frame (set based on voice mode)
static int c2SamplesPerFrame = C2_SAMPLES_PER_FRAME_1600;
// Backward-compat alias used throughout encode/decode paths
#define C2_SAMPLES_PER_FRAME c2SamplesPerFrame

// Buffer sizing for worst case (3200 mode: 150 frames for 3s audio)
#define C2_MAX_FRAMES     150
static uint8_t c2EncodedBuf[C2_MAX_FRAMES * C2_BYTES_PER_FRAME];
static int c2EncodedFrames = 0;

// Decoded PCM buffer (8kHz mono, will be upsampled for speaker at 16kHz)
// Both modes produce the same PCM sample count for the same audio duration:
//   1600: 75 frames × 320 samples = 24000
//   3200: 150 frames × 160 samples = 24000
#define C2_DECODED_MAX    24000
static int16_t* c2DecodedBuf = NULL;
static int c2DecodedLen = 0;

bool codec2_init() {
    if (codec2Ready) return true;
    
    // Create 1600bps instance
    c2state_1600 = codec2_create(CODEC2_MODE_1600);
    if (!c2state_1600) {
        Serial.println("[Codec2] Failed to create 1600bps instance");
        return false;
    }
    int spf1600 = codec2_samples_per_frame(c2state_1600);
    int bpf1600 = codec2_bytes_per_frame(c2state_1600);
    Serial.printf("[Codec2] Mode 1600: %d samples/frame, %d bytes/frame\n", spf1600, bpf1600);
    if (spf1600 != C2_SAMPLES_PER_FRAME_1600 || bpf1600 != C2_BYTES_PER_FRAME) {
        Serial.printf("[Codec2] ERROR 1600: expected %d/%d, got %d/%d\n",
                      C2_SAMPLES_PER_FRAME_1600, C2_BYTES_PER_FRAME, spf1600, bpf1600);
        codec2_destroy(c2state_1600); c2state_1600 = NULL;
        return false;
    }
    
    // Create 3200bps instance
    c2state_3200 = codec2_create(CODEC2_MODE_3200);
    if (!c2state_3200) {
        Serial.println("[Codec2] Failed to create 3200bps instance");
        // Non-fatal: 1600 still works, 3200 modes will be unavailable
    } else {
        int spf3200 = codec2_samples_per_frame(c2state_3200);
        int bpf3200 = codec2_bytes_per_frame(c2state_3200);
        Serial.printf("[Codec2] Mode 3200: %d samples/frame, %d bytes/frame\n", spf3200, bpf3200);
        if (spf3200 != C2_SAMPLES_PER_FRAME_3200 || bpf3200 != C2_BYTES_PER_FRAME) {
            Serial.printf("[Codec2] ERROR 3200: expected %d/%d, got %d/%d\n",
                          C2_SAMPLES_PER_FRAME_3200, C2_BYTES_PER_FRAME, spf3200, bpf3200);
            codec2_destroy(c2state_3200); c2state_3200 = NULL;
        }
    }
    
    // Set active codec based on voice mode
    if (voiceMode == VMODE_RANGE || !c2state_3200) {
        c2state = c2state_1600;
        c2SamplesPerFrame = C2_SAMPLES_PER_FRAME_1600;
    } else {
        c2state = c2state_3200;
        c2SamplesPerFrame = C2_SAMPLES_PER_FRAME_3200;
    }
    
    // Defensive free: prevent leak if prior init allocated but failed later
    if (c2DecodedBuf) { free(c2DecodedBuf); c2DecodedBuf = NULL; }
    c2DecodedBuf = (int16_t*)malloc(C2_DECODED_MAX * sizeof(int16_t));
    if (!c2DecodedBuf) {
        Serial.println("[Codec2] Decode buffer alloc failed");
        codec2_destroy(c2state_1600); c2state_1600 = NULL;
        if (c2state_3200) { codec2_destroy(c2state_3200); c2state_3200 = NULL; }
        c2state = NULL;
        return false;
    }
    
    codec2Ready = true;
    Serial.printf("[Codec2] Ready (active: %sbps, mode: %s, 3200: %s)\n",
                  voiceModeBitrates[voiceMode], voiceModeNames[voiceMode],
                  c2state_3200 ? "OK" : "unavailable");
    return true;
}

bool codec2_isReady() { return codec2Ready; }

// ═══════════════════════════════════════════════════════════
// VOICE MODE — Codec2-dependent implementations
// (forward-declared above, defined here after codec2 variables exist)
// ═══════════════════════════════════════════════════════════

static void _voiceModeApply() {
    if (!codec2Ready) return;
    if (voiceMode == VMODE_RANGE) {
        c2state = c2state_1600;
        c2SamplesPerFrame = C2_SAMPLES_PER_FRAME_1600;
    } else {
        // Balanced and Clarity both use 3200
        if (c2state_3200) {
            c2state = c2state_3200;
            c2SamplesPerFrame = C2_SAMPLES_PER_FRAME_3200;
        } else {
            // 3200 not available, fall back to 1600
            c2state = c2state_1600;
            c2SamplesPerFrame = C2_SAMPLES_PER_FRAME_1600;
            Serial.println("[Voice] 3200 unavailable, using 1600");
        }
    }
    Serial.printf("[Voice] Mode: %s (%sbps, %s)\n",
                  voiceModeNames[voiceMode], voiceModeBitrates[voiceMode],
                  voice_useRedundancy() ? "2x redundancy" : "single pass");
}

void ui_cycleVoiceMode() {
    voiceMode = (VoiceMode)((voiceMode + 1) % 3);
    // If 3200 codec unavailable, skip Balanced/Clarity
    if (!c2state_3200 && voiceMode != VMODE_RANGE) {
        voiceMode = VMODE_RANGE;
    }
    _voiceModeApply();
    
    // Persist to LittleFS
    File f = LittleFS.open("/vmode.cfg", "w");
    if (f) { f.write((uint8_t)voiceMode); f.close(); }
}

// Forward declarations for DSP functions (defined in voice section below)
static void _dspNoiseGate(int16_t* buf, int len);
static float _agcGain = 2.0f;  // AGC state — persistent across PTT sessions
static void _dspAGC(int16_t* buf, int len);
static bool _dspVAD(const int16_t* buf, int len);

// ── Biquad IIR anti-alias filter (2nd-order Butterworth, fc=3400Hz, fs=16kHz) ──
// Replaces the weak 3-tap FIR that only gave ~-6dB at Nyquist.
// This gives ~-24dB at 4kHz and ~-48dB at 8kHz, dramatically reducing
// aliasing noise that Codec2 would otherwise waste bits encoding.
struct BiquadState { float x1, x2, y1, y2; };
static BiquadState _aaState = {0, 0, 0, 0};   // TX anti-alias (persistent for streaming)

// Coefficients: 2nd-order Butterworth LPF, fc=3800Hz, fs=16000Hz (TX anti-alias)
// Wider passband than 3400Hz — preserves consonant clarity for Codec2
#define BQ_B0  0.27458f
#define BQ_B1  0.54916f
#define BQ_B2  0.27458f
#define BQ_A1  0.07363f
#define BQ_A2  0.17195f

// RX upsample filter: 2nd-order Butterworth, fc=5500Hz, fs=16000Hz
// Much more permissive — only kills 8kHz spectral images, passes all speech
#define BQ_US_B0  0.48980f
#define BQ_US_B1  0.97960f
#define BQ_US_B2  0.48980f
#define BQ_US_A1 -0.69970f   // Negative (normal for fc > fs/4)
#define BQ_US_A2  0.25945f

static inline float _biquad(BiquadState* s, float x) {
    float y = BQ_B0*x + BQ_B1*s->x1 + BQ_B2*s->x2 + BQ_A1*s->y1 - BQ_A2*s->y2;
    s->x2 = s->x1; s->x1 = x;
    s->y2 = s->y1; s->y1 = y;
    return y;
}

// Separate biquad for RX upsample (wider passband, only kills spectral images)
static inline float _biquadUS(BiquadState* s, float x) {
    float y = BQ_US_B0*x + BQ_US_B1*s->x1 + BQ_US_B2*s->x2 + BQ_US_A1*s->y1 - BQ_US_A2*s->y2;
    s->x2 = s->x1; s->x1 = x;
    s->y2 = s->y1; s->y1 = y;
    return y;
}

static void _aaFilterReset() {
    _aaState = {0, 0, 0, 0};
}

// Encode mic buffer (16kHz) → Codec2 frames (8kHz input required)
// Pipeline: DC removal → anti-alias LPF → decimate 2:1 → noise gate → AGC → pre-emphasis → encode
int codec2_encodeMicBuffer() {
    if (!codec2Ready || !micBuffer || micBufPos == 0) return 0;
    
    uint32_t startMs = millis();
    
    // Step 1: DC offset removal
    int32_t dcSum = 0;
    for (int i = 0; i < micBufPos; i++) dcSum += micBuffer[i];
    int16_t dcOffset = (int16_t)(dcSum / micBufPos);
    
    // Step 2: Biquad anti-alias LPF + decimate 2:1
    // Process ALL 16kHz samples through filter, keep every other one
    _aaFilterReset();
    int16_t* ds = c2DecodedBuf;
    int dsIdx = 0;
    for (int i = 0; i < micBufPos; i++) {
        float s = _biquad(&_aaState, (float)(micBuffer[i] - dcOffset));
        if ((i & 1) == 0 && dsIdx < C2_DECODED_MAX) {
            ds[dsIdx++] = (int16_t)(s > 32767 ? 32767 : (s < -32767 ? -32767 : s));
        }
    }
    int samples8k = dsIdx;
    
    // Step 3: Noise gate
    _dspNoiseGate(ds, samples8k);
    
    // Step 4: AGC (gain persists — converges within ~200ms)
    _dspAGC(ds, samples8k);
    
    // Step 5: Pre-emphasis
    int16_t prev = ds[0];
    for (int i = 1; i < samples8k && i < C2_DECODED_MAX; i++) {
        int32_t emphasized = (int32_t)ds[i] - ((int32_t)prev * 238 / 256);
        prev = ds[i];
        ds[i] = (int16_t)(emphasized > 32767 ? 32767 : (emphasized < -32767 ? -32767 : emphasized));
    }
    ds[0] = 0;
    
    // Step 6: Encode frame by frame (yield every 8)
    c2EncodedFrames = 0;
    int pos = 0;
    while (pos + C2_SAMPLES_PER_FRAME <= samples8k && c2EncodedFrames < C2_MAX_FRAMES) {
        codec2_encode(c2state, &c2EncodedBuf[c2EncodedFrames * C2_BYTES_PER_FRAME], &ds[pos]);
        c2EncodedFrames++;
        pos += C2_SAMPLES_PER_FRAME;
        if ((c2EncodedFrames % 8) == 0) yield();
    }
    
    int totalBytes = c2EncodedFrames * C2_BYTES_PER_FRAME;
    uint32_t encMs = millis() - startMs;
    
    Serial.printf("[Codec2] Encoded %d frames (%d bytes) in %dms (AGC=%.1fx)\n",
                  c2EncodedFrames, totalBytes, encMs, _agcGain);
    return totalBytes;
}

// Decode Codec2 frames → PCM buffer (8kHz, then upsample to 16kHz for playback)
// Internal parametric decode: takes specific codec instance and samples-per-frame
static int _c2DecodeWith(struct CODEC2* codec, int spf, const uint8_t* encoded, int numFrames) {
    if (!codec || numFrames <= 0) return 0;
    if (numFrames > C2_MAX_FRAMES) numFrames = C2_MAX_FRAMES;
    
    uint32_t startMs = millis();
    c2DecodedLen = 0;
    
    for (int f = 0; f < numFrames; f++) {
        if (c2DecodedLen + spf > C2_DECODED_MAX) break;
        codec2_decode(codec, &c2DecodedBuf[c2DecodedLen], &encoded[f * C2_BYTES_PER_FRAME]);
        c2DecodedLen += spf;
        if ((f % 8) == 0 && f > 0) yield();
    }
    
    uint32_t decMs = millis() - startMs;
    Serial.printf("[Codec2] Decoded %d frames → %d samples in %dms (spf=%d)\n",
                  numFrames, c2DecodedLen, decMs, spf);
    return c2DecodedLen;
}

int codec2_decodeToBuffer(const uint8_t* encoded, int numFrames) {
    if (!codec2Ready) return 0;
    return _c2DecodeWith(c2state, c2SamplesPerFrame, encoded, numFrames);
}

// Play decoded Codec2 buffer through speaker (upsample 8kHz → 16kHz)
void codec2_playDecoded() {
    if (!codec2Ready || c2DecodedLen == 0) return;
    
    _audioInit();
    i2s_set_sample_rates(I2S_PORT, MIC_SAMPLE_RATE);  // 16kHz speaker rate
    
    // De-emphasis filter (inverse of pre-emphasis: y[n] = x[n] + 0.93 * y[n-1])
    // Tuned to 0.93 (was 0.97) — reduces boominess on T-Deck's small speaker
    int32_t prevOut = 0;
    for (int i = 0; i < c2DecodedLen; i++) {
        int32_t s = (int32_t)c2DecodedBuf[i] + (prevOut * 238 / 256);  // 238/256 ≈ 0.93
        if (s > 32767) s = 32767;
        if (s < -32767) s = -32767;
        c2DecodedBuf[i] = (int16_t)s;
        prevOut = s;
    }
    
    // Find peak and normalize
    int16_t maxAbs = 0;
    for (int i = 0; i < c2DecodedLen; i++) {
        int16_t sv = c2DecodedBuf[i];
        if (sv > maxAbs) maxAbs = sv;
        if (-sv > maxAbs) maxAbs = -sv;
    }
    float gain = (maxAbs > 0) ? 31500.0f / maxAbs : 1.0f;
    if (gain > 32.0f) gain = 32.0f;
    
    Serial.printf("[Codec2] Playing: %d samples, peak=%d, gain=%.1fx\n",
                  c2DecodedLen, maxAbs, gain);
    
    // Upsample 8kHz → 16kHz with LINEAR INTERPOLATION + biquad LPF
    // Linear interp: between samples A and B, insert (A+B)/2
    // Biquad LPF (same Butterworth as TX anti-alias) kills 8kHz spectral images
    // that the old single-pole IIR (0.75x + 0.25prev) barely attenuated
    size_t bytesWritten = 0;
    static int16_t outBuf[512];
    BiquadState usState = {0, 0, 0, 0};  // Upsample filter (local per playback)
    int pos = 0;
    while (pos < c2DecodedLen) {
        int chunk = min(c2DecodedLen - pos, 256);
        for (int i = 0; i < chunk; i++) {
            int32_t curr = (int32_t)(c2DecodedBuf[pos + i] * gain);
            int32_t next = (pos + i + 1 < c2DecodedLen) 
                         ? (int32_t)(c2DecodedBuf[pos + i + 1] * gain) 
                         : curr;
            // Clamp
            if (curr > 32767) curr = 32767; if (curr < -32767) curr = -32767;
            if (next > 32767) next = 32767; if (next < -32767) next = -32767;
            
            // Original sample → RX biquad (wider passband, preserves speech)
            float f0 = _biquadUS(&usState, (float)curr);
            outBuf[i*2] = (int16_t)(f0 > 32767 ? 32767 : (f0 < -32767 ? -32767 : f0));
            
            // Interpolated midpoint → RX biquad
            float f1 = _biquadUS(&usState, (float)((curr + next) / 2));
            outBuf[i*2+1] = (int16_t)(f1 > 32767 ? 32767 : (f1 < -32767 ? -32767 : f1));
        }
        i2s_write(I2S_PORT, outBuf, chunk * 2 * sizeof(int16_t), &bytesWritten, 100);
        pos += chunk;
    }
    
    // Tail silence to flush I2S DMA
    int16_t silence[64] = {0};
    i2s_write(I2S_PORT, silence, sizeof(silence), &bytesWritten, 50);
    i2s_set_sample_rates(I2S_PORT, I2S_SAMPLE_RATE);
    Serial.println("[Codec2] Playback complete");
}

// Get encoded buffer (for LoRa TX in Phase 3)
const uint8_t* codec2_getEncodedBuf() { return c2EncodedBuf; }
int codec2_getEncodedLen() { return c2EncodedFrames * C2_BYTES_PER_FRAME; }
int codec2_getEncodedFrames() { return c2EncodedFrames; }

// ═══════════════════════════════════════════════════════════
// VOICE PTT — Multi-part Push-to-Talk
// Wire format: [0xAF | seq(1) | total(1) | msgId(1) | csLen(1) | callsign(N) | codec2_frames]
// seq: 0-indexed part number, total: number of parts
// msgId: random byte to correlate parts from same transmission
// PSK encryption wraps the entire inner payload
// ═══════════════════════════════════════════════════════════


// ═══════════════════════════════════════════════════════════
// STREAMING PTT — Record + Encode + TX concurrently
// Each ~0.9s of audio produces one LoRa part transmitted immediately
// Receiver plays each part on arrival (total=0 → streaming mode)
// Also supports batch mode (total>0) for backward compatibility
// ═══════════════════════════════════════════════════════════

// TX constants
#define VOICE_MAX_PARTS        8   // 3200 mode: 150 frames / 23 per part = 7 parts
// 16kHz samples per part depends on codec mode; use smallest (3200) for streaming threshold
#define SAMPLES_PER_PART_1600  (VOICE_FRAMES_PER_PART * C2_SAMPLES_PER_FRAME_1600 * 2)  // 14720
#define SAMPLES_PER_PART_3200  (VOICE_FRAMES_PER_PART * C2_SAMPLES_PER_FRAME_3200 * 2)  // 7360

// Streaming state
bool voiceStreaming = false;
static uint8_t voiceStreamMsgId = 0;
static int voiceStreamPartsSent = 0;
static uint32_t voiceStreamStartMs = 0;
static int voiceStreamWritePos = 0;   // Write position in micBuffer (16kHz mono)
static int voiceStreamEncodePos = 0;  // Next sample to encode from micBuffer

// Ready-to-TX streaming part (one at a time)
static uint8_t voiceStreamPart[255];
static int voiceStreamPartLen = 0;
static bool voiceStreamPartReady = false;

// RX reassembly for batch mode (total>1)
#define VOICE_RX_SLOTS 4
struct VoiceRxSlot {
    char callsign[16];
    uint8_t msgId;
    uint8_t total;
    uint8_t received;
    uint8_t frameBuf[VOICE_MAX_PARTS * VOICE_FRAMES_PER_PART * C2_BYTES_PER_FRAME];
    int frameCount[VOICE_MAX_PARTS];
    int totalFrames;
    uint32_t startTime;
    float rssi;
    bool active;
};
static VoiceRxSlot voiceRxSlots[VOICE_RX_SLOTS];

// Legacy batch TX state (for WS voice_tx and loopback test)
static uint8_t voiceTxParts[VOICE_MAX_PARTS][255];
static int voiceTxPartLen[VOICE_MAX_PARTS];
static int voiceTxPartCount = 0;
static int voiceTxPartNext = 0;
static uint8_t voiceTxMsgId = 0;

// Package already-encoded Codec2 frames into multi-part TX packets
// Called from _vmSend after codec2_encodeMicBuffer() has filled the encode buffer
static int _voicePackageEncoded() {
    const uint8_t* enc = codec2_getEncodedBuf();
    int totalFrames = codec2_getEncodedFrames();
    if (totalFrames == 0) return 0;
    
    voiceTxPartCount = (totalFrames + VOICE_FRAMES_PER_PART - 1) / VOICE_FRAMES_PER_PART;
    if (voiceTxPartCount > VOICE_MAX_PARTS) voiceTxPartCount = VOICE_MAX_PARTS;
    voiceTxPartNext = 0;
    voiceTxMsgId = (uint8_t)(millis() & 0xFF);
    
    const char* cs = myCallsign[0] ? myCallsign : "ANON";
    uint8_t csLen = strlen(cs);
    uint8_t toLen = strlen(voiceTarget);
    int framesLeft = totalFrames, encOff = 0;
    
    for (int p = 0; p < voiceTxPartCount; p++) {
        int ft = min(framesLeft, VOICE_FRAMES_PER_PART);
        int db = ft * C2_BYTES_PER_FRAME;
        int idx = 0;
        voiceTxParts[p][idx++] = _voiceActiveMarker();
        voiceTxParts[p][idx++] = (uint8_t)p;
        voiceTxParts[p][idx++] = (uint8_t)voiceTxPartCount;
        voiceTxParts[p][idx++] = voiceTxMsgId;
        voiceTxParts[p][idx++] = 0;  // hops
        voiceTxParts[p][idx++] = csLen;
        memcpy(&voiceTxParts[p][idx], cs, csLen); idx += csLen;
        voiceTxParts[p][idx++] = toLen;
        if (toLen > 0) { memcpy(&voiceTxParts[p][idx], voiceTarget, toLen); idx += toLen; }
        memcpy(&voiceTxParts[p][idx], &enc[encOff], db); idx += db;
        voiceTxPartLen[p] = idx;
        encOff += db;
        framesLeft -= ft;
    }
    
    Serial.printf("[Voice] Packaged %d frames → %d parts\n", totalFrames, voiceTxPartCount);
    return voiceTxPartCount;
}

// ═══════════════════════════════════════════════════════════
// VOICE DSP — Noise Gate, AGC, VAD
// Applied to 8kHz downsampled audio before Codec2 encoding
// ═══════════════════════════════════════════════════════════

// Noise gate: zero out samples below energy threshold
// Operates on 40-sample blocks (~5ms at 8kHz)
#define NGATE_BLOCK      40
#define NGATE_THRESHOLD  200   // RMS threshold (tune for T-Deck mic noise floor)
#define NGATE_ATTACK_MS  10    // Blocks to open (2 blocks = 10ms)
#define NGATE_RELEASE_MS 40    // Blocks to close (8 blocks = 40ms)

static void _dspNoiseGate(int16_t* buf, int len) {
    int holdOpen = 0;
    for (int b = 0; b < len; b += NGATE_BLOCK) {
        int blockLen = min(NGATE_BLOCK, len - b);
        // Calculate RMS of this block
        int64_t sumSq = 0;
        for (int i = b; i < b + blockLen; i++) {
            sumSq += (int32_t)buf[i] * buf[i];
        }
        int32_t rms = 0;
        if (blockLen > 0) {
            rms = (int32_t)sqrt((double)sumSq / blockLen);
        }
        
        if (rms >= NGATE_THRESHOLD) {
            holdOpen = NGATE_RELEASE_MS / 5;  // Hold gate open
        } else if (holdOpen > 0) {
            holdOpen--;
        } else {
            // Gate closed — zero this block
            for (int i = b; i < b + blockLen; i++) buf[i] = 0;
        }
    }
}

// AGC: Automatic Gain Control with attack/release
#define AGC_TARGET     16000
#define AGC_MAX_GAIN   20.0f
#define AGC_MIN_GAIN   0.5f
#define AGC_ATTACK     0.05f
#define AGC_RELEASE    0.005f

static void _dspAGC(int16_t* buf, int len) {
    for (int i = 0; i < len; i++) {
        // Apply current gain
        int32_t s = (int32_t)(buf[i] * _agcGain);
        
        // Soft clip instead of hard clip (reduces harshness)
        if (s > 30000) s = 30000 + (s - 30000) / 4;
        if (s < -30000) s = -30000 + (s + 30000) / 4;
        if (s > 32767) s = 32767;
        if (s < -32767) s = -32767;
        buf[i] = (int16_t)s;
        
        // Adjust gain based on output level
        int32_t absS = s > 0 ? s : -s;
        if (absS > AGC_TARGET) {
            // Too loud — reduce gain (fast attack)
            _agcGain -= AGC_ATTACK;
        } else {
            // Too quiet — increase gain (slow release)
            _agcGain += AGC_RELEASE;
        }
        
        // Clamp gain range
        if (_agcGain > AGC_MAX_GAIN) _agcGain = AGC_MAX_GAIN;
        if (_agcGain < AGC_MIN_GAIN) _agcGain = AGC_MIN_GAIN;
    }
}

// VAD: Voice Activity Detection — check if segment contains speech
// Uses energy ratio: compare segment RMS to estimated noise floor
// Returns true if speech detected
#define VAD_SILENCE_RMS  300    // Below this = definite silence
#define VAD_SPEECH_RMS   800    // Above this = definite speech
#define VAD_MIN_ACTIVE   0.15f  // At least 15% of segment must be active

static bool _dspVAD(const int16_t* buf, int len) {
    if (len < NGATE_BLOCK) return false;
    
    int activeBlocks = 0;
    int totalBlocks = 0;
    
    for (int b = 0; b < len; b += NGATE_BLOCK) {
        int blockLen = min(NGATE_BLOCK, len - b);
        int64_t sumSq = 0;
        for (int i = b; i < b + blockLen; i++) {
            sumSq += (int32_t)buf[i] * buf[i];
        }
        int32_t rms = (int32_t)sqrt((double)sumSq / blockLen);
        totalBlocks++;
        if (rms > VAD_SPEECH_RMS) activeBlocks++;
    }
    
    float ratio = (totalBlocks > 0) ? (float)activeBlocks / totalBlocks : 0;
    return (ratio >= VAD_MIN_ACTIVE);
}

// ── Helper: encode one segment of micBuffer into a voice packet ──
// Pipeline: DC remove → downsample → noise gate → AGC → pre-emphasis → VAD → encode
static int _encodeSegment(int sampleStart, int sampleCount, uint8_t seq, 
                          uint8_t totalField, uint8_t mid, uint8_t* outBuf) {
    if (sampleCount / 2 < C2_SAMPLES_PER_FRAME) return 0;
    
    // Step 1: DC offset for this segment
    int32_t dcSum = 0;
    for (int i = sampleStart; i < sampleStart + sampleCount && i < MIC_BUF_SAMPLES; i++)
        dcSum += micBuffer[i];
    int16_t dcOff = (int16_t)(dcSum / sampleCount);
    
    // Step 2: Biquad anti-alias LPF + decimate 16kHz→8kHz
    // Filter state persists across segments for seamless streaming
    int16_t* ds = c2DecodedBuf;
    int dsIdx = 0;
    int end = sampleStart + sampleCount;
    if (end > MIC_BUF_SAMPLES) end = MIC_BUF_SAMPLES;
    for (int i = sampleStart; i < end; i++) {
        float s = _biquad(&_aaState, (float)(micBuffer[i] - dcOff));
        if (((i - sampleStart) & 1) == 0 && dsIdx < C2_DECODED_MAX) {
            ds[dsIdx++] = (int16_t)(s > 32767 ? 32767 : (s < -32767 ? -32767 : s));
        }
    }
    int samples8k = dsIdx;
    
    // Step 3: Noise gate — suppress background noise in silent segments
    _dspNoiseGate(ds, samples8k);
    
    // Step 4: AGC — normalize volume across different speaking distances
    _dspAGC(ds, samples8k);
    
    // Step 5: Pre-emphasis (boosts high frequencies for Codec2)
    int16_t prevS = ds[0];
    for (int i = 1; i < samples8k && i < C2_DECODED_MAX; i++) {
        int32_t e = (int32_t)ds[i] - ((int32_t)prevS * 238 / 256);
        prevS = ds[i];
        ds[i] = (int16_t)(e > 32767 ? 32767 : (e < -32767 ? -32767 : e));
    }
    ds[0] = 0;
    
    // Step 6: VAD — skip encoding if this segment is pure silence
    if (!_dspVAD(ds, samples8k)) {
        Serial.printf("[DSP] Segment %d: silence (skipped)\n", seq);
        return 0;  // Don't encode or transmit silence
    }
    
    // Step 7: Encode Codec2 frames (with yield to prevent watchdog)
    uint8_t encBuf[VOICE_FRAMES_PER_PART * C2_BYTES_PER_FRAME];
    int numFrames = 0, pos = 0;
    while (pos + C2_SAMPLES_PER_FRAME <= samples8k && numFrames < VOICE_FRAMES_PER_PART) {
        codec2_encode(c2state, &encBuf[numFrames * C2_BYTES_PER_FRAME], &ds[pos]);
        numFrames++;
        pos += C2_SAMPLES_PER_FRAME;
        if ((numFrames % 8) == 0) yield();
    }
    if (numFrames == 0) return 0;
    
    // Build packet header
    const char* cs = myCallsign[0] ? myCallsign : "ANON";
    uint8_t csLen = strlen(cs);
    uint8_t toLen = strlen(voiceTarget);
    int idx = 0;
    outBuf[idx++] = _voiceActiveMarker();
    outBuf[idx++] = seq;
    outBuf[idx++] = totalField;  // 0=streaming, >0=batch
    outBuf[idx++] = mid;
    outBuf[idx++] = 0;  // hops
    outBuf[idx++] = csLen;
    memcpy(&outBuf[idx], cs, csLen); idx += csLen;
    outBuf[idx++] = toLen;
    if (toLen > 0) { memcpy(&outBuf[idx], voiceTarget, toLen); idx += toLen; }
    memcpy(&outBuf[idx], encBuf, numFrames * C2_BYTES_PER_FRAME);
    idx += numFrames * C2_BYTES_PER_FRAME;
    return idx;
}

// ═══════════════════════════════════════════════════════════
// STREAMING PTT — Start/Tick/Stop
// ═══════════════════════════════════════════════════════════

void voice_streamStart() {
    if (voiceStreaming || !micInitialized || !codec2Ready) return;
    
    voiceStreaming = true;
    voiceStreamMsgId = (uint8_t)(millis() & 0xFF);
    voiceStreamPartsSent = 0;
    voiceStreamStartMs = millis();
    voiceStreamWritePos = 0;
    voiceStreamEncodePos = 0;
    voiceStreamPartReady = false;
    _aaFilterReset();  // Reset anti-alias filter state for clean segment boundaries
    // AGC gain intentionally NOT reset — persists between PTT sessions
    // to avoid the first ~200ms of clipping from an overly aggressive initial gain
    
    // Flush I2S DMA
    int16_t junk[128]; size_t jr;
    for (int i = 0; i < 4; i++) i2s_read(MIC_I2S_CH, junk, sizeof(junk), &jr, 20);
    
    // PTT activation beep — tells sender mic is live
    ui_beep(1200, 50);
    
    // Show PTT banner (clear content area first)
    tft.fillRect(0, 24, scrW, scrH - 24, COLOR_BG);
    tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_RED);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 60, scrH / 2 - 12);
    if (voiceTarget[0]) tft.printf("LIVE → %s", voiceTarget);
    else tft.print("LIVE — Broadcasting");
    tft.setCursor(scrW / 2 - 50, scrH / 2 + 2);
    tft.print("0.0s — V to Stop");
    
    Serial.printf("[Stream] Started (msgId=%02X)\n", voiceStreamMsgId);
}

// Called from loop() — reads I2S non-blocking, encodes parts when ready
void voice_streamTick() {
    if (!voiceStreaming) return;
    
    // Read I2S TDM chunk (short timeout = non-blocking)
    static int16_t tdmBuf[512];  // Static: avoid 1KB stack allocation per loop
    size_t bytesRead = 0;
    esp_err_t err = i2s_read(MIC_I2S_CH, tdmBuf, sizeof(tdmBuf), &bytesRead, 10);
    if (err == ESP_OK && bytesRead > 0) {
        int stereo = bytesRead / sizeof(int16_t);
        for (int i = 0; i < stereo && voiceStreamWritePos < MIC_BUF_SAMPLES; i += 2) {
            micBuffer[voiceStreamWritePos++] = tdmBuf[i];
        }
    }
    
    // Check for stop key
    char k = readKeyboard();
    if (k == 0) k = _readTrackball();
    if (k == 'v' || k == 'V' || k == ' ' || k == '\n' || k == '\r') {
        voice_streamStop();
        return;
    }
    
    // Hard limits
    if (voiceStreamWritePos >= MIC_BUF_SAMPLES || voiceStreamPartsSent >= VOICE_MAX_PARTS) {
        voice_streamStop();
        return;
    }
    
    // Timer display (~250ms update)
    static uint32_t lastTU = 0;
    if (millis() - lastTU > 250) {
        lastTU = millis();
        float el = (millis() - voiceStreamStartMs) / 1000.0f;
        tft.fillRect(scrW / 2 - 60, scrH / 2 + 2, 120, 12, COLOR_RED);
        tft.setTextColor(COLOR_TEXT);
        tft.setTextSize(1);
        tft.setCursor(scrW / 2 - 50, scrH / 2 + 2);
        tft.printf("%.1fs — V to Stop", el);
    }
    
    // Encode a part when enough samples AND no part waiting for TX
    int avail = voiceStreamWritePos - voiceStreamEncodePos;
    int samplesPerPart = (voiceMode == VMODE_RANGE) ? SAMPLES_PER_PART_1600 : SAMPLES_PER_PART_3200;
    if (avail >= samplesPerPart && !voiceStreamPartReady) {
        voiceStreamPartLen = _encodeSegment(
            voiceStreamEncodePos, samplesPerPart,
            voiceStreamPartsSent, 0, voiceStreamMsgId, voiceStreamPart);
        // Always advance encode position (VAD may return 0 for silence)
        voiceStreamEncodePos += samplesPerPart;
        if (voiceStreamPartLen > 0) {
            voiceStreamPartReady = true;
            voiceStreamPartsSent++;
            Serial.printf("[Stream] Part %d ready (%d bytes)\n",
                          voiceStreamPartsSent, voiceStreamPartLen);
        }
    }
}

void voice_streamStop() {
    if (!voiceStreaming) return;
    float dur = (millis() - voiceStreamStartMs) / 1000.0f;
    
    // Encode remaining samples as final part
    int rem = voiceStreamWritePos - voiceStreamEncodePos;
    if (rem >= 640 && !voiceStreamPartReady && voiceStreamPartsSent < VOICE_MAX_PARTS) {
        voiceStreamPartLen = _encodeSegment(
            voiceStreamEncodePos, rem,
            voiceStreamPartsSent, 0, voiceStreamMsgId, voiceStreamPart);
        if (voiceStreamPartLen > 0) {
            voiceStreamPartReady = true;
            voiceStreamPartsSent++;
        }
    }
    
    voiceStreaming = false;
    
    tft.fillRect(0, scrH / 2 - 20, scrW, 40, COLOR_BTN_GREEN);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(1);
    tft.setCursor(scrW / 2 - 55, scrH / 2 - 6);
    tft.printf("TX %.1fs (%d parts)", dur, voiceStreamPartsSent);
    
    const char* cs = voiceTarget[0] ? voiceTarget : "*";
    _addVoiceLog(cs, 0, dur, true);
    
    char label[32];
    snprintf(label, sizeof(label), "[Voice %.1fs]", dur);
    ui_addMessage("You", label, true, false);
    
    Serial.printf("[Stream] Done: %.1fs, %d parts\n", dur, voiceStreamPartsSent);
    uiState.dirty = true;
}

bool voice_isStreaming() { return voiceStreaming; }
bool voice_hasStreamPart() { return voiceStreamPartReady; }
const uint8_t* voice_getStreamPartBuf() { return voiceStreamPart; }
int voice_getStreamPartLen() { return voiceStreamPartLen; }
void voice_clearStreamPart() { voiceStreamPartReady = false; voiceStreamPartLen = 0; }

// ═══════════════════════════════════════════════════════════
// BATCH TX — Legacy (for WS voice_tx and loopback test)
// ═══════════════════════════════════════════════════════════

int voice_prepareTx() {
    if (!codec2Ready || !micInitialized) return 0;
    int samples = mic_record(VOICE_RECORD_MS);
    if (samples == 0) return 0;
    int encBytes = codec2_encodeMicBuffer();
    if (encBytes == 0) return 0;
    
    const uint8_t* enc = codec2_getEncodedBuf();
    int totalFrames = codec2_getEncodedFrames();
    voiceTxPartCount = (totalFrames + VOICE_FRAMES_PER_PART - 1) / VOICE_FRAMES_PER_PART;
    if (voiceTxPartCount > VOICE_MAX_PARTS) voiceTxPartCount = VOICE_MAX_PARTS;
    voiceTxPartNext = 0;
    voiceTxMsgId = (uint8_t)(millis() & 0xFF);
    const char* cs = myCallsign[0] ? myCallsign : "ANON";
    uint8_t csLen = strlen(cs);
    uint8_t toLen = strlen(voiceTarget);
    int framesLeft = totalFrames, encOff = 0;
    for (int p = 0; p < voiceTxPartCount; p++) {
        int ft = min(framesLeft, VOICE_FRAMES_PER_PART);
        int db = ft * C2_BYTES_PER_FRAME;
        int idx = 0;
        voiceTxParts[p][idx++] = _voiceActiveMarker();
        voiceTxParts[p][idx++] = (uint8_t)p;
        voiceTxParts[p][idx++] = (uint8_t)voiceTxPartCount;
        voiceTxParts[p][idx++] = voiceTxMsgId;
        voiceTxParts[p][idx++] = 0;
        voiceTxParts[p][idx++] = csLen;
        memcpy(&voiceTxParts[p][idx], cs, csLen); idx += csLen;
        voiceTxParts[p][idx++] = toLen;
        if (toLen > 0) { memcpy(&voiceTxParts[p][idx], voiceTarget, toLen); idx += toLen; }
        memcpy(&voiceTxParts[p][idx], &enc[encOff], db); idx += db;
        voiceTxPartLen[p] = idx; encOff += db; framesLeft -= ft;
    }
    return voiceTxPartCount;
}
bool voice_hasTxPacket() { return voiceTxPartNext < voiceTxPartCount; }
const uint8_t* voice_getTxBuf() { return (voiceTxPartNext < voiceTxPartCount) ? voiceTxParts[voiceTxPartNext] : NULL; }
int voice_getTxLen() { return (voiceTxPartNext < voiceTxPartCount) ? voiceTxPartLen[voiceTxPartNext] : 0; }
void voice_advanceTx() { if (voiceTxPartNext < voiceTxPartCount) voiceTxPartNext++; }
void voice_rewindTx() { voiceTxPartNext = 0; }  // Reset pointer for redundancy retransmit
void voice_clearTx() { voiceTxPartCount = 0; voiceTxPartNext = 0; }
int voice_getTxPartsTotal() { return voiceTxPartCount; }
int voice_getTxPartsSent() { return voiceTxPartNext; }

// Voice target management
void voice_setTarget(const char* target) {
    if (target) { strncpy(voiceTarget, target, 15); voiceTarget[15] = '\0'; }
    else voiceTarget[0] = '\0';
}
const char* voice_getTarget() { return voiceTarget; }

// ═══════════════════════════════════════════════════════════
// WS VOICE ENCODE (base64 PCM from tablet → multi-part)
// ═══════════════════════════════════════════════════════════

int voice_encodeAndPackage(const uint8_t* b64data, int b64len) {
    if (!codec2Ready || !c2state) return 0;
    uint8_t* pcmRaw = (uint8_t*)malloc(b64len);
    if (!pcmRaw) return 0;
    int pcmBytes = 0;
    {
        static const uint8_t d[] = {
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
            255,255,255,255,255,255,255,255,255,255,255,62,255,255,255,63,
            52,53,54,55,56,57,58,59,60,61,255,255,255,0,255,255,
            255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
            15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,
            255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
            41,42,43,44,45,46,47,48,49,50,51,255,255,255,255,255
        };
        for (int i = 0; i < b64len; i += 4) {
            uint32_t n = 0;
            for (int j = 0; j < 4 && (i+j) < b64len; j++) {
                uint8_t c = b64data[i+j];
                if (c == '=') break;
                if (c >= 128 || d[c] == 255) { free(pcmRaw); return 0; }
                n = (n << 6) | d[c];
            }
            if (pcmBytes < b64len) pcmRaw[pcmBytes++] = (n >> 16) & 0xFF;
            if (pcmBytes < b64len && b64data[i+2] != '=') pcmRaw[pcmBytes++] = (n >> 8) & 0xFF;
            if (pcmBytes < b64len && b64data[i+3] != '=') pcmRaw[pcmBytes++] = n & 0xFF;
        }
    }
    int numSamples = pcmBytes / 2;
    if (numSamples < C2_SAMPLES_PER_FRAME) { free(pcmRaw); return 0; }
    // Store PCM in micBuffer for _encodeSegment
    int16_t* pcm = (int16_t*)pcmRaw;
    int count = min(numSamples, MIC_BUF_SAMPLES);
    // WS sends 8kHz — upsample to 16kHz for _encodeSegment
    // Actually just encode directly since it's already 8kHz
    // Use legacy batch approach for WS
    c2EncodedFrames = 0;
    int pos = 0;
    while (pos + C2_SAMPLES_PER_FRAME <= numSamples && c2EncodedFrames < C2_MAX_FRAMES) {
        codec2_encode(c2state, &c2EncodedBuf[c2EncodedFrames * C2_BYTES_PER_FRAME], &pcm[pos]);
        c2EncodedFrames++;
        pos += C2_SAMPLES_PER_FRAME;
        if ((c2EncodedFrames % 8) == 0) yield();
    }
    free(pcmRaw);
    if (c2EncodedFrames == 0) return 0;
    
    int totalFrames = c2EncodedFrames;
    voiceTxPartCount = (totalFrames + VOICE_FRAMES_PER_PART - 1) / VOICE_FRAMES_PER_PART;
    if (voiceTxPartCount > VOICE_MAX_PARTS) voiceTxPartCount = VOICE_MAX_PARTS;
    voiceTxPartNext = 0;
    voiceTxMsgId = (uint8_t)(millis() & 0xFF);
    const char* cs = myCallsign[0] ? myCallsign : "ANON";
    uint8_t csLen = strlen(cs);
    uint8_t toLen = strlen(voiceTarget);
    int framesLeft = totalFrames, encOff = 0;
    for (int p = 0; p < voiceTxPartCount; p++) {
        int ft = min(framesLeft, VOICE_FRAMES_PER_PART);
        int db = ft * C2_BYTES_PER_FRAME;
        int idx = 0;
        voiceTxParts[p][idx++] = _voiceActiveMarker();
        voiceTxParts[p][idx++] = (uint8_t)p;
        voiceTxParts[p][idx++] = (uint8_t)voiceTxPartCount;
        voiceTxParts[p][idx++] = voiceTxMsgId;
        voiceTxParts[p][idx++] = 0;
        voiceTxParts[p][idx++] = csLen;
        memcpy(&voiceTxParts[p][idx], cs, csLen); idx += csLen;
        voiceTxParts[p][idx++] = toLen;
        if (toLen > 0) { memcpy(&voiceTxParts[p][idx], voiceTarget, toLen); idx += toLen; }
        memcpy(&voiceTxParts[p][idx], &c2EncodedBuf[encOff], db); idx += db;
        voiceTxPartLen[p] = idx; encOff += db; framesLeft -= ft;
    }
    Serial.printf("[Voice] WS: %d frames → %d parts\n", totalFrames, voiceTxPartCount);
    return voiceTxPartCount;
}

String voice_getDecodedB64() {
    if (c2DecodedLen == 0) return "";
    int pcmBytes = c2DecodedLen * sizeof(int16_t);
    const uint8_t* raw = (const uint8_t*)c2DecodedBuf;
    static const char b64c[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    String out;
    out.reserve(((pcmBytes + 2) / 3) * 4);
    for (int i = 0; i < pcmBytes; i += 3) {
        uint32_t n = ((uint32_t)raw[i]) << 16;
        if (i+1 < pcmBytes) n |= ((uint32_t)raw[i+1]) << 8;
        if (i+2 < pcmBytes) n |= raw[i+2];
        out += b64c[(n >> 18) & 0x3F];
        out += b64c[(n >> 12) & 0x3F];
        out += (i+1 < pcmBytes) ? b64c[(n >> 6) & 0x3F] : '=';
        out += (i+2 < pcmBytes) ? b64c[n & 0x3F] : '=';
    }
    return out;
}

// ═══════════════════════════════════════════════════════════
// VOICE RX — Streaming (total=0) + Batch (total>0) receive
// ═══════════════════════════════════════════════════════════

// Per-slot timeout scales with expected parts count.
// Range (4 parts): 15s.  Balanced/Clarity (7 parts): 21s.
// Covers first pass airtime + redundancy arrival + queue interleaving.
static uint32_t _voiceSlotTimeoutMs(uint8_t total) {
    uint32_t t = (uint32_t)total * 3000;
    return t < 15000 ? 15000 : t;
}

static VoiceRxSlot* _voiceRxFindSlot(const char* callsign, uint8_t msgId) {
    for (int i = 0; i < VOICE_RX_SLOTS; i++) {
        if (voiceRxSlots[i].active && voiceRxSlots[i].msgId == msgId &&
            strcmp(voiceRxSlots[i].callsign, callsign) == 0) return &voiceRxSlots[i];
    }
    for (int i = 0; i < VOICE_RX_SLOTS; i++) {
        uint32_t timeout = _voiceSlotTimeoutMs(voiceRxSlots[i].total);
        if (voiceRxSlots[i].active && (millis() - voiceRxSlots[i].startTime > timeout))
            voiceRxSlots[i].active = false;
    }
    for (int i = 0; i < VOICE_RX_SLOTS; i++) {
        if (!voiceRxSlots[i].active) {
            memset(&voiceRxSlots[i], 0, sizeof(VoiceRxSlot));
            voiceRxSlots[i].active = true;
            voiceRxSlots[i].startTime = millis();
            voiceRxSlots[i].msgId = msgId;
            strncpy(voiceRxSlots[i].callsign, callsign, 15);
            return &voiceRxSlots[i];
        }
    }
    int oldest = 0;
    for (int i = 1; i < VOICE_RX_SLOTS; i++)
        if (voiceRxSlots[i].startTime < voiceRxSlots[oldest].startTime) oldest = i;
    memset(&voiceRxSlots[oldest], 0, sizeof(VoiceRxSlot));
    voiceRxSlots[oldest].active = true;
    voiceRxSlots[oldest].startTime = millis();
    voiceRxSlots[oldest].msgId = msgId;
    strncpy(voiceRxSlots[oldest].callsign, callsign, 15);
    return &voiceRxSlots[oldest];
}

bool voice_handleRx(const uint8_t* data, int len, float rssi) {
    if (len < 8 || !voice_isMarker(data[0])) return false;
    
    // Determine which codec mode was used for this packet
    bool is3200 = (data[0] == VOICE_MARKER_3200);
    struct CODEC2* rxCodec = is3200 ? c2state_3200 : c2state_1600;
    int rxSPF = is3200 ? C2_SAMPLES_PER_FRAME_3200 : C2_SAMPLES_PER_FRAME_1600;
    
    // If we don't have the required codec instance, skip
    if (!rxCodec) {
        Serial.printf("[Voice] RX %s packet but no %s decoder available\n",
                      is3200 ? "3200" : "1600", is3200 ? "3200" : "1600");
        return false;
    }
    
    uint8_t seq = data[1];
    uint8_t total = data[2];
    uint8_t msgId = data[3];
    uint8_t hops = data[4];
    uint8_t csLen = data[5];
    
    if (csLen > 15 || 6 + csLen >= len) return false;
    char from[16];
    memcpy(from, &data[6], csLen);
    from[csLen] = '\0';
    
    int toOffset = 6 + csLen;
    if (toOffset >= len) return false;
    uint8_t toLen = data[toOffset];
    char to[16] = {0};
    if (toLen > 0 && toLen < 16 && toOffset + 1 + toLen <= len)
        memcpy(to, &data[toOffset + 1], toLen);
    
    int framesOffset = toOffset + 1 + toLen;
    const uint8_t* frames = &data[framesOffset];
    int framesLen = len - framesOffset;
    int numFrames = framesLen / C2_BYTES_PER_FRAME;
    if (numFrames <= 0) return false;
    
    bool isBroadcast = (toLen == 0);
    bool isForUs = isBroadcast || (myCallsign[0] && strcmp(to, myCallsign) == 0);
    
    Serial.printf("[Voice] RX %s%d from %s→%s (id=%02X h=%d %df RSSI=%.0f)%s\n",
                  total == 0 ? "stream#" : "part ",
                  seq, from, isBroadcast ? "ALL" : to,
                  msgId, hops, numFrames, rssi, isForUs ? "" : " [skip]");
    
    if (!isForUs) return false;
    
    // ── STREAMING MODE (total=0): Play each part immediately ──
    if (total == 0) {
        _c2DecodeWith(rxCodec, rxSPF, frames, numFrames);
        
        float duration = numFrames * (rxSPF / 8000.0f);
        uint16_t bannerColor = isBroadcast ? COLOR_ACCENT : COLOR_GREEN;
        char bl1[48], bl2[48];
        snprintf(bl1, sizeof(bl1), "%s from %s%s", isBroadcast ? "Voice" : "DM", from, hops > 0 ? " (relay)" : "");
        snprintf(bl2, sizeof(bl2), "Part %d  %.1fs  RSSI:%.0f", seq + 1, duration, rssi);
        if (uiState.currentScreen == SCREEN_VOICE) {
            _voiceHeaderPulse(from, !isBroadcast);
        } else {
            _drawRxBanner2(bannerColor, bl1, bl2);
        }
        
        codec2_playDecoded();
        
        // Log on first part only
        if (seq == 0) {
            ui_addPeer(from, rssi, 0, hops);
            char mt[48]; snprintf(mt, sizeof(mt), "[Voice from %s]", from);
            ui_addMessage(from, mt, false, false);
        }
        _addVoiceLog(from, rssi, duration, false);
        // No per-part beep — speech flows continuously across parts
        uiState.dirty = true;
        return true;
    }
    
    // ── SINGLE PART (total=1): Play immediately ──
    if (total == 1) {
        _c2DecodeWith(rxCodec, rxSPF, frames, numFrames);
        float duration = numFrames * (rxSPF / 8000.0f);
        char bl1[48], bl2[48];
        snprintf(bl1, sizeof(bl1), "%s from %s%s", isBroadcast ? "Voice" : "DM", from, hops > 0 ? " (relay)" : "");
        snprintf(bl2, sizeof(bl2), "%.1fs  RSSI:%.0f  hop:%d", duration, rssi, hops);
        if (uiState.currentScreen == SCREEN_VOICE) {
            _voiceHeaderPulse(from, !isBroadcast);
        } else {
            _drawRxBanner2(isBroadcast ? COLOR_ACCENT : COLOR_GREEN, bl1, bl2);
        }
        codec2_playDecoded();
        char mt[48]; snprintf(mt, sizeof(mt), "[Voice %.1fs]", duration);
        ui_addMessage(from, mt, false, false);
        ui_addPeer(from, rssi, 0, hops);
        _addVoiceLog(from, rssi, duration, false);
        ui_rogerBeep();
        uiState.dirty = true;
        return true;
    }
    
    // ── BATCH MODE (total>1): Reassemble then play ──
    if (seq >= total || total > VOICE_MAX_PARTS) return false;
    VoiceRxSlot* slot = _voiceRxFindSlot(from, msgId);
    if (!slot) return false;
    slot->total = total;
    slot->rssi = rssi;
    if (!(slot->received & (1 << seq))) {
        int partOff = seq * VOICE_FRAMES_PER_PART * C2_BYTES_PER_FRAME;
        memcpy(&slot->frameBuf[partOff], frames, numFrames * C2_BYTES_PER_FRAME);
        slot->frameCount[seq] = numFrames;
        slot->received |= (1 << seq);
    }
    int got = 0;
    for (int i = 0; i < total; i++) if (slot->received & (1 << i)) got++;
    char bp[48];
    snprintf(bp, sizeof(bp), "Voice %s: %d/%d", from, got, total);
    if (uiState.currentScreen == SCREEN_VOICE) {
        _voiceHeaderPulse(from, !isBroadcast);
    } else {
        _drawRxBanner1(COLOR_HEADER, bp);
    }
    
    uint8_t allMask = (1 << total) - 1;
    if ((slot->received & allMask) == allMask) {
        c2DecodedLen = 0;
        int decCount = 0;
        for (int p = 0; p < total; p++) {
            int po = p * VOICE_FRAMES_PER_PART * C2_BYTES_PER_FRAME;
            int fc = slot->frameCount[p];
            for (int f = 0; f < fc && c2DecodedLen + rxSPF <= C2_DECODED_MAX; f++) {
                codec2_decode(rxCodec, &c2DecodedBuf[c2DecodedLen], &slot->frameBuf[po + f * C2_BYTES_PER_FRAME]);
                c2DecodedLen += rxSPF;
                if ((++decCount % 8) == 0) yield();
            }
        }
        int tf = 0; for (int p = 0; p < total; p++) tf += slot->frameCount[p];
        float dur = tf * (rxSPF / 8000.0f);
        char bl1[48], bl2[48];
        snprintf(bl1, sizeof(bl1), "%s from %s%s", isBroadcast ? "Voice" : "DM", from, hops > 0 ? " (relay)" : "");
        snprintf(bl2, sizeof(bl2), "%.1fs  RSSI:%.0f  hop:%d", dur, slot->rssi, hops);
        if (uiState.currentScreen == SCREEN_VOICE) {
            _voiceHeaderPulse(from, !isBroadcast);
        } else {
            _drawRxBanner2(isBroadcast ? COLOR_ACCENT : COLOR_GREEN, bl1, bl2);
        }
        codec2_playDecoded();
        char mt[48]; snprintf(mt, sizeof(mt), "[Voice %.1fs]", dur);
        ui_addMessage(from, mt, false, false);
        ui_addPeer(from, slot->rssi, 0, hops);
        _addVoiceLog(from, slot->rssi, dur, false);
        ui_rogerBeep();
        slot->active = false;
        uiState.dirty = true;
        return true;
    }
    return false;
}

// ── Voice RX guard: suppress TX while assembling multi-part voice ──
bool voice_isRxPending() {
    for (int i = 0; i < VOICE_RX_SLOTS; i++) {
        if (voiceRxSlots[i].active && voiceRxSlots[i].total > 1) {
            uint8_t allMask = (1 << voiceRxSlots[i].total) - 1;
            if ((voiceRxSlots[i].received & allMask) != allMask) {
                uint32_t timeout = _voiceSlotTimeoutMs(voiceRxSlots[i].total);
                if (millis() - voiceRxSlots[i].startTime < timeout)
                    return true;
            }
        }
    }
    return false;
}

// ── Expire stale voice RX slots with user feedback ──
void voice_checkRxTimeouts() {
    uint32_t now = millis();
    for (int i = 0; i < VOICE_RX_SLOTS; i++) {
        if (!voiceRxSlots[i].active) continue;
        if (voiceRxSlots[i].total <= 1) continue;  // Only for multi-part
        uint32_t timeout = _voiceSlotTimeoutMs(voiceRxSlots[i].total);
        if (now - voiceRxSlots[i].startTime < timeout) continue;  // Not timed out yet
        
        uint8_t allMask = (1 << voiceRxSlots[i].total) - 1;
        if ((voiceRxSlots[i].received & allMask) != allMask) {
            // Incomplete — show feedback
            int got = 0;
            for (int p = 0; p < voiceRxSlots[i].total; p++)
                if (voiceRxSlots[i].received & (1 << p)) got++;
            
            Serial.printf("[Voice] RX timeout from %s: got %d/%d parts\n",
                          voiceRxSlots[i].callsign, got, voiceRxSlots[i].total);
            
            // Show brief error banner
            char tb[48];
            snprintf(tb, sizeof(tb), "Voice lost %s (%d/%d)", voiceRxSlots[i].callsign, got, voiceRxSlots[i].total);
            if (uiState.currentScreen == SCREEN_VOICE) {
                headerPulseUntil = millis() + 2500;
                headerPulseColor = COLOR_RED;
                strncpy(headerPulseFrom, voiceRxSlots[i].callsign, sizeof(headerPulseFrom) - 1);
                headerPulseFrom[sizeof(headerPulseFrom) - 1] = '\0';
            } else {
                _drawRxBanner1(COLOR_RED, tb);
            }
            uiState.dirty = true;
        }
        voiceRxSlots[i].active = false;
    }
}

#define KB_BRIGHTNESS_CMD 0x01

void ui_setKeyboardBacklight(uint8_t brightness) {
#ifndef NO_KEYBOARD
    kbBrightness = brightness;
    Wire.beginTransmission(KB_I2C_ADDR);
    Wire.write(KB_BRIGHTNESS_CMD);
    Wire.write(brightness);
    Wire.endTransmission();
    
    // Persist setting
    File f = LittleFS.open("/kbbl.cfg", "w");
    if (f) { f.write(brightness); f.close(); }
    
    Serial.printf("[KB] Backlight set to %d\n", brightness);
#endif
}

bool ui_getKeyboardBacklight() { return kbBrightness > 0; }

void ui_toggleKeyboardBacklight() {
    if (kbBrightness > 0) {
        ui_setKeyboardBacklight(0);
    } else {
        ui_setKeyboardBacklight(255);  // Full brightness
    }
}

static void _loadKeyboardBacklight() {
    File f = LittleFS.open("/kbbl.cfg", "r");
    if (f) {
        uint8_t val = f.read();
        f.close();
        if (val > 0) {
            kbBrightness = val;
            // Apply saved brightness
#ifndef NO_KEYBOARD
            Wire.beginTransmission(KB_I2C_ADDR);
            Wire.write(KB_BRIGHTNESS_CMD);
            Wire.write(val);
            Wire.endTransmission();
            Serial.printf("[KB] Backlight restored to %d\n", val);
#endif
        }
    }
}

/**
 * Generate a tone via I2S by writing sine wave samples.
 * This produces actual audio through the T-Deck's speaker amplifier.
 */
void ui_beep(int freqHz, int durationMs) {
    if (audioMuted) return;  // Silent when muted
    if (!audioInitialized) _audioInit();
    if (!audioInitialized) return;
    
    Serial.printf("[Audio] Beep %dHz %dms\n", freqHz, durationMs);
    
    int totalSamples = (I2S_SAMPLE_RATE * durationMs) / 1000;
    int samplesPerCycle = I2S_SAMPLE_RATE / freqHz;
    if (samplesPerCycle < 1) samplesPerCycle = 1;
    
    // Write samples in small chunks
    const int chunkSize = 128;
    int16_t buf[chunkSize];
    int written = 0;
    
    while (written < totalSamples) {
        int toWrite = min(chunkSize, totalSamples - written);
        for (int i = 0; i < toWrite; i++) {
            // Simple square wave at ~70% volume (louder than sine, works better on tiny speakers)
            int pos = (written + i) % samplesPerCycle;
            buf[i] = (pos < samplesPerCycle / 2) ? 22000 : -22000;
        }
        size_t bytesWritten = 0;
        i2s_write(I2S_PORT, buf, toWrite * sizeof(int16_t), &bytesWritten, portMAX_DELAY);
        written += toWrite;
    }
    
    // Brief silence to end the tone cleanly
    memset(buf, 0, sizeof(buf));
    size_t bw = 0;
    i2s_write(I2S_PORT, buf, 64 * sizeof(int16_t), &bw, portMAX_DELAY);
}

void ui_beepMessage() {
    Serial.println("[Audio] Message notification");
    ui_beep(1800, 100);
    delay(60);
    ui_beep(2200, 100);
}

void ui_beepAlert() {
    Serial.println("[Audio] BREAK alert");
    ui_beep(2400, 150);
    delay(50);
    ui_beep(1800, 150);
    delay(50);
    ui_beep(1200, 250);
}

// Two-tone roger beep — signals end of incoming voice transmission
void ui_rogerBeep() {
    if (audioMuted) return;
    ui_beep(1000, 60);
    delay(30);
    ui_beep(1400, 80);
}

// Rising two-tone chirp — distinct from message beep (high-high) and alert (descending)
// Signals: "new RF threat detected" — fires once per new scanner detection
void ui_beepDroneDetect() {
    if (audioMuted) return;
    Serial.println("[Audio] Drone detection alert");
    ui_beep(800, 120);
    delay(40);
    ui_beep(1200, 120);
    delay(40);
    ui_beep(1600, 160);
}

// ═══════════════════════════════════════════════════════════
// SIGNAL QUALITY
// ═══════════════════════════════════════════════════════════

void ui_updateSignal(float rssi, float snr, uint32_t rxCount, uint32_t txCount) {
    sigRSSI = rssi;
    sigSNR = snr;
    sigRxCount = rxCount;
    sigTxCount = txCount;
    sigLastUpdate = millis();
    // Trigger redraw if on status screen
    if (uiState.currentScreen == SCREEN_STATUS) {
        uiState.dirty = true;
    }
}

// RF diagnostics for channel/PSK mismatch detection
void ui_rfRawPacket() {
    rfLastRxAnyMs = millis();
}

void ui_rfDecryptFail() {
    rfDecryptFails++;
    rfLastDecryptFailMs = millis();
}

uint32_t ui_rfLastRxAge() {
    if (rfLastRxAnyMs == 0) return UINT32_MAX;  // Never received
    return (millis() - rfLastRxAnyMs) / 1000;
}

uint32_t ui_rfDecryptFailCount() {
    return rfDecryptFails;
}

// ═══════════════════════════════════════════════════════════
// SD CARD — Message Logging, GPS Tracks, Packet Log, Dead Drop
// ═══════════════════════════════════════════════════════════

static void _sdCleanupOldLogs();  // Forward declaration (defined after sd_logGPS)

static void _sdCreateDirs() {
    if (!sdMounted) return;
    SD.mkdir("/griddown");
    SD.mkdir("/griddown/inbox");
    SD.mkdir("/griddown/outbox");
}

/**
 * Get a date string for filenames (YYYYMMDD).
 * Uses GPS time if available, otherwise millis-based fallback.
 */
static uint32_t sdSessionId = 0;  // Set once at boot

static void _sdDateStr(char* buf, size_t len) {
#ifndef NO_GPS
    if (gps.date.isValid() && gps.date.year() > 2020) {
        snprintf(buf, len, "%04d%02d%02d", gps.date.year(), gps.date.month(), gps.date.day());
        return;
    }
#endif
    // Fallback: use fixed session ID (set at boot) so all logs go to one file
    if (sdSessionId == 0) sdSessionId = millis() / 1000;
    snprintf(buf, len, "session_%lu", sdSessionId);
}

static void _sdTimestamp(char* buf, size_t len) {
#ifndef NO_GPS
    if (gps.time.isValid() && gps.date.isValid() && gps.date.year() > 2020) {
        snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02dZ",
            gps.date.year(), gps.date.month(), gps.date.day(),
            gps.time.hour(), gps.time.minute(), gps.time.second());
        return;
    }
#endif
    snprintf(buf, len, "T+%lu", millis() / 1000);
}

void sd_init() {
    // Deselect other SPI devices before SD init
    digitalWrite(LORA_CS, HIGH);
    digitalWrite(TFT_CS, HIGH);
    
    if (SD.begin(SD_CS)) {
        sdMounted = true;
        _sdCreateDirs();
        
        uint64_t total = SD.totalBytes();
        uint64_t used = SD.usedBytes();
        Serial.printf("[SD] Mounted: %lluMB total, %lluMB used, %lluMB free\n",
            total / (1024*1024), used / (1024*1024), (total - used) / (1024*1024));
        
        // Count existing log entries
        char dateStr[32];
        _sdDateStr(dateStr, sizeof(dateStr));
        char path[64];
        
        snprintf(path, sizeof(path), "/griddown/messages_%s.csv", dateStr);
        if (SD.exists(path)) {
            File f = SD.open(path, "r");
            if (f) { while (f.available()) { if (f.read() == '\n') sdMsgCount++; } f.close(); }
            if (sdMsgCount > 0) sdMsgCount--;  // Subtract CSV header row
        }
        snprintf(path, sizeof(path), "/griddown/packets_%s.csv", dateStr);
        if (SD.exists(path)) {
            File f = SD.open(path, "r");
            if (f) { while (f.available()) { if (f.read() == '\n') sdPktCount++; } f.close(); }
            if (sdPktCount > 0) sdPktCount--;  // Subtract CSV header row
        }
        snprintf(path, sizeof(path), "/griddown/track_%s.csv", dateStr);
        if (SD.exists(path)) {
            File f = SD.open(path, "r");
            if (f) { while (f.available()) { if (f.read() == '\n') sdTrackPts++; } f.close(); }
            if (sdTrackPts > 0) sdTrackPts--;  // Subtract CSV header row
        }
        
        // Check for dead drop inbox
        File inbox = SD.open("/griddown/inbox");
        if (inbox && inbox.isDirectory()) {
            File entry = inbox.openNextFile();
            int imported = 0;
            while (entry) {
                if (!entry.isDirectory() && String(entry.name()).endsWith(".json")) {
                    // Import dead drop message
                    JsonDocument doc;
                    if (!deserializeJson(doc, entry)) {
                        const char* from = doc["from"] | "drop";
                        const char* text = doc["text"] | "";
                        uint8_t ddCh = doc["ch"] | 0;  // Default to General
                        if (strlen(text) > 0) {
                            ui_addMessage(from, text, false, false, ddCh);
                            imported++;
                        }
                    }
                    // Delete after import
                    String fullPath = String("/griddown/inbox/") + entry.name();
                    entry.close();
                    SD.remove(fullPath);
                } else {
                    entry.close();
                }
                entry = inbox.openNextFile();
            }
            inbox.close();
            if (imported > 0) {
                Serial.printf("[SD] Imported %d dead drop messages\n", imported);
            }
        }
    } else {
        sdMounted = false;
        Serial.println("[SD] No SD card detected (CS=39)");
    }
}

bool sd_available() { return sdMounted; }
int sd_getMessageCount() { return sdMsgCount; }
int sd_getPacketCount() { return sdPktCount; }
int sd_getTrackPoints() { return sdTrackPts; }

void sd_logMessage(const char* from, const char* text, bool outgoing, bool encrypted, uint8_t channel) {
    if (!sdMounted) return;
    
    char dateStr[32], ts[32];
    _sdDateStr(dateStr, sizeof(dateStr));
    _sdTimestamp(ts, sizeof(ts));
    
    char path[64];
    snprintf(path, sizeof(path), "/griddown/messages_%s.csv", dateStr);
    
    bool isNew = !SD.exists(path);
    File f = SD.open(path, FILE_APPEND);
    if (!f) return;
    
    if (isNew) {
        f.println("timestamp,direction,from,encrypted,channel,text");
    }
    
    // Escape commas, newlines, and quotes in text for CSV
    char safe[210];
    int si = 0;
    for (int i = 0; text[i] && si < 205; i++) {
        if (text[i] == ',' || text[i] == '\n' || text[i] == '\r' || text[i] == '"') safe[si++] = ' ';
        else safe[si++] = text[i];
    }
    safe[si] = '\0';
    
    const char* chName = (channel < GROUP_CH_COUNT) ? groupChNames[channel] : "?";
    f.printf("%s,%s,%s,%s,%s,%s\n", ts, outgoing ? "TX" : "RX", from, encrypted ? "Y" : "N", chName, safe);
    f.close();
    sdMsgCount++;
}

void sd_logPacket(size_t len, float rssi, float snr, float freq, bool isTx) {
    if (!sdMounted) return;
    
    char dateStr[32], ts[32];
    _sdDateStr(dateStr, sizeof(dateStr));
    _sdTimestamp(ts, sizeof(ts));
    
    char path[64];
    snprintf(path, sizeof(path), "/griddown/packets_%s.csv", dateStr);
    
    bool isNew = !SD.exists(path);
    File f = SD.open(path, FILE_APPEND);
    if (!f) return;
    
    if (isNew) {
        f.println("timestamp,direction,bytes,rssi_dBm,snr,freq_MHz");
    }
    
    f.printf("%s,%s,%d,%.1f,%.1f,%.1f\n", ts, isTx ? "TX" : "RX", len, rssi, snr, freq);
    f.close();
    sdPktCount++;
}

void sd_logGPS() {
    if (!sdMounted) return;
    if (millis() - lastGPSLog < GPS_LOG_INTERVAL_MS) return;
    
#ifndef NO_GPS
    if (!gps.location.isValid()) return;
    
    lastGPSLog = millis();
    
    char dateStr[32], ts[32];
    _sdDateStr(dateStr, sizeof(dateStr));
    _sdTimestamp(ts, sizeof(ts));
    
    char path[64];
    snprintf(path, sizeof(path), "/griddown/track_%s.csv", dateStr);
    
    bool isNew = !SD.exists(path);
    File f = SD.open(path, FILE_APPEND);
    if (!f) return;
    
    if (isNew) {
        f.println("timestamp,latitude,longitude,altitude_m,satellites,speed_kmh,course_deg");
    }
    
    f.printf("%s,%.7f,%.7f,%.1f,%d,%.1f,%.1f\n", ts,
        gps.location.lat(), gps.location.lng(),
        gps.altitude.isValid() ? gps.altitude.meters() : 0.0,
        gps.satellites.value(),
        gps.speed.isValid() ? gps.speed.kmph() : 0.0,
        gps.course.isValid() ? gps.course.deg() : 0.0);
    f.close();
    sdTrackPts++;
    
    // Periodic log cleanup: delete files older than 30 days (check once per hour)
    static uint32_t lastCleanup = 0;
    if (millis() - lastCleanup >= 3600000UL) {
        lastCleanup = millis();
        _sdCleanupOldLogs();
    }
#endif
}

// Delete date-stamped log files older than 30 days.
// Files: messages_YYYYMMDD.csv, packets_YYYYMMDD.csv, track_YYYYMMDD.csv
// Only runs when GPS date is valid (needed to compute "30 days ago").
static void _sdCleanupOldLogs() {
#ifndef NO_GPS
    if (!sdMounted || !gps.date.isValid() || gps.date.year() <= 2020) return;
    
    // Compute cutoff date: today minus 30 days (as YYYYMMDD integer)
    // Simplified: subtract 30 from day, handle month rollback
    int y = gps.date.year(), m = gps.date.month(), d = gps.date.day();
    d -= 30;
    while (d <= 0) {
        m--;
        if (m <= 0) { m = 12; y--; }
        static const int mdays[] = { 0,31,28,31,30,31,30,31,31,30,31,30,31 };
        int md = mdays[m];
        if (m == 2 && (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0))) md++;
        d += md;
    }
    int cutoff = y * 10000 + m * 100 + d;
    
    File dir = SD.open("/griddown");
    if (!dir || !dir.isDirectory()) return;
    
    int deleted = 0;
    File entry = dir.openNextFile();
    while (entry) {
        if (!entry.isDirectory()) {
            String name = entry.name();
            // Match: messages_YYYYMMDD.csv, packets_YYYYMMDD.csv, track_YYYYMMDD.csv
            int dateStart = -1;
            if (name.startsWith("messages_")) dateStart = 9;
            else if (name.startsWith("packets_")) dateStart = 8;
            else if (name.startsWith("track_")) dateStart = 6;
            
            if (dateStart > 0 && name.endsWith(".csv") && name.length() >= (unsigned)(dateStart + 8)) {
                // Extract YYYYMMDD and parse as integer
                String dateStr = name.substring(dateStart, dateStart + 8);
                int fileDate = dateStr.toInt();
                if (fileDate > 20200101 && fileDate < cutoff) {
                    String fullPath = String("/griddown/") + name;
                    entry.close();
                    SD.remove(fullPath);
                    deleted++;
                    Serial.printf("[SD] Cleaned: %s (date %d < cutoff %d)\n", 
                                  fullPath.c_str(), fileDate, cutoff);
                    entry = dir.openNextFile();
                    continue;
                }
            }
        }
        entry.close();
        entry = dir.openNextFile();
    }
    dir.close();
    if (deleted > 0) {
        Serial.printf("[SD] Cleanup: removed %d files older than 30 days\n", deleted);
    }
#endif
}

/**
 * Export a message to the dead drop outbox.
 * Called when user sends a message in standalone mode.
 */
void sd_exportDeadDrop(const char* to, const char* text) {
    if (!sdMounted) return;
    
    char filename[64], ts[32];
    _sdTimestamp(ts, sizeof(ts));
    snprintf(filename, sizeof(filename), "/griddown/outbox/msg_%lu.json", millis());
    
    File f = SD.open(filename, FILE_WRITE);
    if (!f) return;
    
    JsonDocument doc;
    doc["from"] = "tdeck";
    doc["to"] = to;
    doc["text"] = text;
    doc["ts"] = ts;
    doc["ch"] = activeGroupCh;
    serializeJson(doc, f);
    f.close();
    
    Serial.printf("[SD] Dead drop exported: %s\n", filename);
}

// ═══════════════════════════════════════════════════════════
// BOOT DIAGNOSTICS — Crash log + boot counter
// Tracks boot count (LittleFS) and logs reset reason (SD card)
// so field devices leave a trail when they reboot unexpectedly.
// ═══════════════════════════════════════════════════════════


static const char* _resetReasonStr(esp_reset_reason_t reason) {
    switch (reason) {
        case ESP_RST_POWERON:  return "PowerOn";
        case ESP_RST_EXT:      return "ExtReset";
        case ESP_RST_SW:       return "Software";
        case ESP_RST_PANIC:    return "Panic";
        case ESP_RST_INT_WDT:  return "IntWDT";
        case ESP_RST_TASK_WDT: return "TaskWDT";
        case ESP_RST_WDT:      return "OtherWDT";
        case ESP_RST_DEEPSLEEP: return "DeepSleep";
        case ESP_RST_BROWNOUT: return "Brownout";
        case ESP_RST_SDIO:     return "SDIO";
        default:               return "Unknown";
    }
}

void boot_recordStartup() {
    // Read + increment boot counter from LittleFS
    File f = LittleFS.open("/bootcnt.bin", "r");
    if (f && f.size() >= 4) {
        f.read((uint8_t*)&bootCount, 4);
        f.close();
    } else {
        if (f) f.close();
        bootCount = 0;
    }
    bootCount++;
    
    // Write updated counter
    f = LittleFS.open("/bootcnt.bin", "w");
    if (f) { f.write((uint8_t*)&bootCount, 4); f.close(); }
    
    // Get reset reason
    esp_reset_reason_t reason = esp_reset_reason();
    strncpy(lastResetStr, _resetReasonStr(reason), sizeof(lastResetStr) - 1);
    lastResetStr[sizeof(lastResetStr) - 1] = '\0';
    
    Serial.printf("[Boot] Count: %lu, Reset: %s\n", bootCount, lastResetStr);
    
    // Log to SD card if available
    sd_logBoot();
}

uint32_t boot_getCount() { return bootCount; }

const char* boot_getLastResetReason() { return lastResetStr; }

void sd_logBoot() {
    if (!sdMounted) return;
    
    // Ensure directory exists
    if (!SD.exists("/griddown")) SD.mkdir("/griddown");
    if (!SD.exists("/griddown/logs")) SD.mkdir("/griddown/logs");
    
    File f = SD.open("/griddown/logs/boot.log", FILE_APPEND);
    if (!f) return;
    
    char ts[32];
    _sdTimestamp(ts, sizeof(ts));
    f.printf("%s | Boot #%lu | Reset: %s | FW: %s | Heap: %lu\n",
             ts, bootCount, lastResetStr, GRIDDOWN_FW_VERSION,
             (uint32_t)ESP.getFreeHeap());
    f.close();
    
    Serial.println("[SD] Boot event logged");
}

// ═══════════════════════════════════════════════════════════
// CALLSIGN & PEER DISCOVERY
// ═══════════════════════════════════════════════════════════

void ui_setCallsign(const char* callsign) {
    if (!callsign || strlen(callsign) == 0) {
        myCallsign[0] = '\0';
        LittleFS.remove("/callsign.txt");
        Serial.println("[ID] Callsign cleared");
        return;
    }
    strncpy(myCallsign, callsign, sizeof(myCallsign) - 1);
    myCallsign[sizeof(myCallsign) - 1] = '\0';
    // Convert to uppercase
    for (int i = 0; myCallsign[i]; i++) myCallsign[i] = toupper(myCallsign[i]);
    
    File f = LittleFS.open("/callsign.txt", "w");
    if (f) { f.print(myCallsign); f.close(); }
    Serial.printf("[ID] Callsign set: %s\n", myCallsign);
}

const char* ui_getCallsign() { return myCallsign; }
bool ui_callsignSet() { return myCallsign[0] != '\0'; }

static void _loadCallsign() {
    File f = LittleFS.open("/callsign.txt", "r");
    if (f) {
        int n = f.readBytes(myCallsign, sizeof(myCallsign) - 1);
        myCallsign[n] = '\0';
        f.close();
        if (n > 0) Serial.printf("[ID] Callsign loaded: %s\n", myCallsign);
    }
}

void ui_addPeer(const char* callsign, float rssi, float snr, uint8_t hops) {
    if (!callsign || strlen(callsign) == 0) return;
    if (ui_callsignSet() && strcasecmp(callsign, myCallsign) == 0) return;
    
    // Compute link quality: 0-100 weighted score
    // RSSI: -60=100, -120=0 → (rssi+120)/60*50 (50pts max)
    // SNR:  +10=100, -10=0  → (snr+10)/20*30   (30pts max)
    // Hops: 0=20, 1=10, 2+=0                    (20pts max)
    float rssiScore = constrain((rssi + 120.0f) / 60.0f * 50.0f, 0, 50);
    float snrScore  = constrain((snr + 10.0f) / 20.0f * 30.0f, 0, 30);
    float hopScore  = (hops == 0) ? 20.0f : (hops == 1) ? 10.0f : 0.0f;
    uint8_t quality = (uint8_t)constrain(rssiScore + snrScore + hopScore, 0, 100);
    
    // Check if already known
    for (int i = 0; i < peerCount; i++) {
        if (strcasecmp(peers[i].callsign, callsign) == 0) {
            peers[i].lastRSSI = rssi;
            peers[i].lastSNR = snr;
            peers[i].lastHops = hops;
            peers[i].rxCount++;
            peers[i].linkQuality = quality;
            // EMA RSSI smoothing (alpha=0.3)
            if (peers[i].rssiAvg < -150.0f) peers[i].rssiAvg = rssi;
            else peers[i].rssiAvg = peers[i].rssiAvg * 0.7f + rssi * 0.3f;
            peers[i].lastSeen = millis();
            peers[i].active = true;
            return;
        }
    }
    
    // New peer
    int slot = -1;
    if (peerCount < MAX_PEERS) {
        slot = peerCount++;
    } else {
        uint32_t oldest = UINT32_MAX;
        for (int i = 0; i < MAX_PEERS; i++) {
            if (peers[i].lastSeen < oldest) { oldest = peers[i].lastSeen; slot = i; }
        }
    }
    
    if (slot >= 0) {
        strncpy(peers[slot].callsign, callsign, sizeof(peers[slot].callsign) - 1);
        peers[slot].callsign[sizeof(peers[slot].callsign) - 1] = '\0';
        for (int i = 0; peers[slot].callsign[i]; i++) 
            peers[slot].callsign[i] = toupper(peers[slot].callsign[i]);
        peers[slot].lastRSSI = rssi;
        peers[slot].lastSNR = snr;
        peers[slot].rssiAvg = rssi;
        peers[slot].lastHops = hops;
        peers[slot].rxCount = 1;
        peers[slot].linkQuality = quality;
        peers[slot].lastSeen = millis();
        peers[slot].active = true;
        peers[slot].lat = 0;
        peers[slot].lon = 0;
        peers[slot].hasPosition = false;
        peers[slot].battery = 0;
        
        ui_addContact(peers[slot].callsign, peers[slot].callsign);
        
        Serial.printf("[Peer] Discovered: %s (RSSI:%.0f SNR:%.1f hops:%d Q:%d%%)\n", 
                      peers[slot].callsign, rssi, snr, hops, quality);
        ui_beep(1200, 50);
        uiState.dirty = true;
    }
}

int ui_getPeerCount() { return peerCount; }

void ui_updatePeerPosition(const char* callsign, double lat, double lon) {
    if (lat == 0 && lon == 0) return;
    for (int i = 0; i < peerCount; i++) {
        if (strcasecmp(peers[i].callsign, callsign) == 0) {
            peers[i].lat = lat;
            peers[i].lon = lon;
            peers[i].hasPosition = true;
            if (uiState.currentScreen == SCREEN_MAP) uiState.dirty = true;
            return;
        }
    }
}

void ui_updatePeerBattery(const char* callsign, uint8_t bat) {
    for (int i = 0; i < peerCount; i++) {
        if (strcasecmp(peers[i].callsign, callsign) == 0) {
            peers[i].battery = bat;
            return;
        }
    }
}

bool ui_getPeerPosition(int index, char* callsign, double* lat, double* lon, float* rssi, bool* active) {
    if (index < 0 || index >= peerCount) return false;
    strncpy(callsign, peers[index].callsign, 15);
    callsign[15] = '\0';
    *lat = peers[index].lat;
    *lon = peers[index].lon;
    *rssi = peers[index].lastRSSI;
    *active = peers[index].active;
    return peers[index].hasPosition;
}

// ═══════════════════════════════════════════════════════════
// MESH TRACK SHARING — Distributed SA tracks over LoRa
// Sources: AtlasRF (ADS-B), Aerobits (RemoteID), WiFi Sentinel, FPV
// ═══════════════════════════════════════════════════════════

// tracks[], proximityRadius, proximityEnabled, proximityLastAlert
// defined at top of file (forward declaration block)

// Forward declaration (defined after track functions)
static void _proximityCheck(int slot);

void track_update(const char* id, double lat, double lon, float alt,
                  float hdg, float spd, uint8_t src) {
    if (!id || !id[0]) return;
    
    // Find existing slot or empty/oldest slot
    int slot = -1;
    uint32_t oldest = UINT32_MAX;
    int oldestSlot = 0;
    bool isNewTrack = true;
    for (int i = 0; i < TRACK_MAX; i++) {
        if (tracks[i].valid && strcasecmp(tracks[i].id, id) == 0) {
            slot = i;
            isNewTrack = false;
            break;
        }
        if (!tracks[i].valid) {
            if (slot < 0) slot = i;  // First empty
        } else if (tracks[i].lastUpdate < oldest) {
            oldest = tracks[i].lastUpdate;
            oldestSlot = i;
        }
    }
    if (slot < 0) slot = oldestSlot;  // Evict oldest if full
    
    // Store previous altitude for climb/descend detection
    float prevAltitude = tracks[slot].valid ? tracks[slot].alt : alt;
    
    strncpy(tracks[slot].id, id, sizeof(tracks[slot].id) - 1);
    tracks[slot].id[sizeof(tracks[slot].id) - 1] = '\0';
    tracks[slot].lat = lat;
    tracks[slot].lon = lon;
    tracks[slot].prevAlt = prevAltitude;
    tracks[slot].alt = alt;
    tracks[slot].hdg = hdg;
    tracks[slot].spd = spd;
    tracks[slot].src = (src < 5) ? src : TRACK_SRC_UNKNOWN;
    tracks[slot].lastUpdate = millis();
    tracks[slot].valid = true;
    
    // Record trail position (ring buffer, skip if position unchanged)
    if (isNewTrack) {
        tracks[slot].trailHead = 0;
        tracks[slot].trailCount = 0;
    }
    // Only record if moved meaningfully (>5m) to avoid cluttering stationary trails
    bool recordTrail = true;
    if (tracks[slot].trailCount > 0) {
        int prevIdx = (tracks[slot].trailHead - 1 + 8) % 8;
        double dLat = lat - tracks[slot].trailLat[prevIdx];
        double dLon = lon - tracks[slot].trailLon[prevIdx];
        if (dLat * dLat + dLon * dLon < 0.000001) recordTrail = false;  // ~0.1m
    }
    if (recordTrail) {
        tracks[slot].trailLat[tracks[slot].trailHead] = lat;
        tracks[slot].trailLon[tracks[slot].trailHead] = lon;
        tracks[slot].trailHead = (tracks[slot].trailHead + 1) % 8;
        if (tracks[slot].trailCount < 8) tracks[slot].trailCount++;
    }
    
    // Reset alert flag for new tracks
    if (isNewTrack) {
        tracks[slot].alerted = false;
        proximityLastAlert[slot] = 0;
    }
    
    if (uiState.currentScreen == SCREEN_MAP) uiState.dirty = true;
    
    Serial.printf("[Track] %s: %.5f,%.5f alt=%.0fm hdg=%.0f spd=%.0f src=%s\n",
                  id, lat, lon, alt, hdg, spd, track_srcName(src));
    
    // Check proximity alert
    _proximityCheck(slot);
}

void track_expire() {
    uint32_t now = millis();
    for (int i = 0; i < TRACK_MAX; i++) {
        if (tracks[i].valid && (now - tracks[i].lastUpdate) > TRACK_EXPIRE_MS) {
            Serial.printf("[Track] Expired: %s\n", tracks[i].id);
            tracks[i].valid = false;
            tracks[i].alerted = false;
            if (uiState.currentScreen == SCREEN_MAP) uiState.dirty = true;
        }
    }
}

int track_getCount() {
    int n = 0;
    for (int i = 0; i < TRACK_MAX; i++) if (tracks[i].valid) n++;
    return n;
}

bool track_get(int index, SharedTrack* out) {
    if (index < 0 || index >= TRACK_MAX) return false;
    if (!tracks[index].valid) return false;
    *out = tracks[index];
    return true;
}

const char* track_srcName(uint8_t src) {
    switch (src) {
        case TRACK_SRC_ADSB:     return "ADS-B";
        case TRACK_SRC_REMOTEID: return "RmtID";
        case TRACK_SRC_SENTINEL: return "WiFi";
        case TRACK_SRC_FPV:      return "FPV";
        default:                 return "UNK";
    }
}

// ═══════════════════════════════════════════════════════════
// THREAT PROXIMITY ALERTS
// Automatic warnings when shared tracks enter configurable radius.
// Fires once per track entry, with 30s cooldown for re-alerts.
// ═══════════════════════════════════════════════════════════

void     proximity_setRadius(uint32_t meters) {
    if (meters < PROXIMITY_MIN_M) meters = PROXIMITY_MIN_M;
    if (meters > PROXIMITY_MAX_M) meters = PROXIMITY_MAX_M;
    proximityRadius = meters;
}
uint32_t proximity_getRadius() { return proximityRadius; }
void     proximity_setEnabled(bool on) { proximityEnabled = on; }
bool     proximity_isEnabled() { return proximityEnabled; }

// Convert bearing to 2-char cardinal direction
static const char* _bearingToCardinal(double brg) {
    if (brg < 0) brg += 360.0;
    brg = fmod(brg, 360.0);
    if (brg < 22.5 || brg >= 337.5) return "N";
    if (brg < 67.5)  return "NE";
    if (brg < 112.5) return "E";
    if (brg < 157.5) return "SE";
    if (brg < 202.5) return "S";
    if (brg < 247.5) return "SW";
    if (brg < 292.5) return "W";
    return "NW";
}

// Source type to threat label
static const char* _trackThreatLabel(uint8_t src) {
    switch (src) {
        case TRACK_SRC_ADSB:     return "AIRCRAFT";
        case TRACK_SRC_REMOTEID: return "DRONE";
        case TRACK_SRC_SENTINEL: return "DRONE";
        case TRACK_SRC_FPV:      return "FPV";
        default:                 return "CONTACT";
    }
}

static void _proximityCheck(int slot) {
    if (!proximityEnabled) return;
    if (slot < 0 || slot >= TRACK_MAX || !tracks[slot].valid) return;
    
    // Need our GPS position
    double myLat, myLon, myAlt;
    if (!ui_getGPS(&myLat, &myLon, &myAlt)) return;
    
    double dist = _haversine(myLat, myLon, tracks[slot].lat, tracks[slot].lon);
    
    // Outside radius — reset alert so it can re-fire if track re-enters
    if (dist > (double)proximityRadius) {
        tracks[slot].alerted = false;
        return;
    }
    
    // Inside radius — check cooldown
    uint32_t now = millis();
    if (tracks[slot].alerted && (now - proximityLastAlert[slot]) < PROXIMITY_COOLDOWN_MS) {
        return;  // Already alerted recently
    }
    
    // ── FIRE ALERT ──
    tracks[slot].alerted = true;
    proximityLastAlert[slot] = now;
    
    double brg = _bearing(myLat, myLon, tracks[slot].lat, tracks[slot].lon);
    const char* cardinal = _bearingToCardinal(brg);
    const char* label = _trackThreatLabel(tracks[slot].src);
    
    // Build altitude/climb info
    char altInfo[32] = "";
    if (tracks[slot].alt > 0) {
        float altDelta = tracks[slot].alt - tracks[slot].prevAlt;
        if (altDelta < -5.0f) {
            snprintf(altInfo, sizeof(altInfo), ", %.0fm descending", tracks[slot].alt);
        } else if (altDelta > 5.0f) {
            snprintf(altInfo, sizeof(altInfo), ", %.0fm climbing", tracks[slot].alt);
        } else {
            snprintf(altInfo, sizeof(altInfo), ", %.0fm AGL", tracks[slot].alt);
        }
    }
    
    // Format: "DRONE 0.3km NE, 45m descending"
    char alertMsg[128];
    if (dist < 1000) {
        snprintf(alertMsg, sizeof(alertMsg), "%s %.0fm %s%s [%s]",
                 label, dist, cardinal, altInfo, tracks[slot].id);
    } else {
        snprintf(alertMsg, sizeof(alertMsg), "%s %.1fkm %s%s [%s]",
                 label, dist / 1000.0, cardinal, altInfo, tracks[slot].id);
    }
    
    // Push to Alerts channel
    ui_addMessage("PROX", alertMsg, false, false, GROUP_CH_ALERTS);
    
    // Audible warning — distinct from message beep
    ui_beepAlert();
    
    Serial.printf("[Proximity] ALERT: %s (dist=%.0fm, brg=%.0f %s)\n",
                  alertMsg, dist, brg, cardinal);
}

// ═══════════════════════════════════════════════════════════
// TACTICAL WAYPOINTS — Named markers shared across the mesh
// Persisted to LittleFS, survive reboots. Shared via LoRa.
// ═══════════════════════════════════════════════════════════

// waypoints[] and wpAutoCounter defined at top of file (forward declaration block)

const char* wp_iconName(uint8_t icon) {
    switch (icon) {
        case WP_ICON_RALLY:   return "Rally";
        case WP_ICON_HAZARD:  return "Hazard";
        case WP_ICON_LKP:     return "LKP";
        case WP_ICON_CAMP:    return "Camp";
        case WP_ICON_WATER:   return "Water";
        default:              return "WP";
    }
}

void wp_add(const char* name, double lat, double lon, uint8_t icon, const char* creator) {
    if (!name || !name[0]) return;
    
    // Find existing slot with same name (update), or empty, or oldest
    int slot = -1;
    uint32_t oldest = UINT32_MAX;
    int oldestSlot = 0;
    for (int i = 0; i < WAYPOINT_MAX; i++) {
        if (waypoints[i].valid && strcasecmp(waypoints[i].name, name) == 0) {
            slot = i;
            break;
        }
        if (!waypoints[i].valid) {
            if (slot < 0) slot = i;
        } else if (waypoints[i].createdAt < oldest) {
            oldest = waypoints[i].createdAt;
            oldestSlot = i;
        }
    }
    if (slot < 0) slot = oldestSlot;
    
    strncpy(waypoints[slot].name, name, sizeof(waypoints[slot].name) - 1);
    waypoints[slot].name[sizeof(waypoints[slot].name) - 1] = '\0';
    strncpy(waypoints[slot].creator, creator ? creator : "?", sizeof(waypoints[slot].creator) - 1);
    waypoints[slot].creator[sizeof(waypoints[slot].creator) - 1] = '\0';
    waypoints[slot].lat = lat;
    waypoints[slot].lon = lon;
    waypoints[slot].icon = (icon <= WP_ICON_WATER) ? icon : WP_ICON_GENERIC;
    waypoints[slot].createdAt = millis();
    waypoints[slot].valid = true;
    
    if (uiState.currentScreen == SCREEN_MAP) uiState.dirty = true;
    
    Serial.printf("[WP] %s at %.5f,%.5f by %s (icon=%s)\n",
                  name, lat, lon, creator ? creator : "?", wp_iconName(icon));
    
    wp_save();
}

void wp_remove(int index) {
    if (index < 0 || index >= WAYPOINT_MAX) return;
    if (!waypoints[index].valid) return;
    Serial.printf("[WP] Removed: %s\n", waypoints[index].name);
    waypoints[index].valid = false;
    if (uiState.currentScreen == SCREEN_MAP) uiState.dirty = true;
    wp_save();
}

int wp_getCount() {
    int n = 0;
    for (int i = 0; i < WAYPOINT_MAX; i++) if (waypoints[i].valid) n++;
    return n;
}

bool wp_get(int index, SharedWaypoint* out) {
    if (index < 0 || index >= WAYPOINT_MAX) return false;
    if (!waypoints[index].valid) return false;
    *out = waypoints[index];
    return true;
}

void wp_save() {
    File f = LittleFS.open("/waypoints.json", "w");
    if (!f) return;
    JsonDocument doc;
    JsonArray arr = doc.to<JsonArray>();
    for (int i = 0; i < WAYPOINT_MAX; i++) {
        if (!waypoints[i].valid) continue;
        JsonObject obj = arr.add<JsonObject>();
        obj["n"] = waypoints[i].name;
        obj["c"] = waypoints[i].creator;
        obj["la"] = waypoints[i].lat;
        obj["lo"] = waypoints[i].lon;
        obj["ic"] = waypoints[i].icon;
    }
    serializeJson(doc, f);
    f.close();
}

void wp_load() {
    File f = LittleFS.open("/waypoints.json", "r");
    if (!f) return;
    JsonDocument doc;
    if (deserializeJson(doc, f)) { f.close(); return; }
    f.close();
    JsonArray arr = doc.as<JsonArray>();
    int count = 0;
    for (JsonObject obj : arr) {
        if (count >= WAYPOINT_MAX) break;
        const char* n = obj["n"] | "";
        const char* c = obj["c"] | "?";
        if (strlen(n) == 0) continue;
        strncpy(waypoints[count].name, n, 19); waypoints[count].name[19] = '\0';
        strncpy(waypoints[count].creator, c, 15); waypoints[count].creator[15] = '\0';
        waypoints[count].lat = obj["la"] | 0.0;
        waypoints[count].lon = obj["lo"] | 0.0;
        waypoints[count].icon = obj["ic"] | 0;
        waypoints[count].createdAt = millis();
        waypoints[count].valid = true;
        count++;
    }
    // Update auto-counter to avoid name collisions
    for (int i = 0; i < WAYPOINT_MAX; i++) {
        if (!waypoints[i].valid) continue;
        if (strncmp(waypoints[i].name, "WP-", 3) == 0) {
            int num = atoi(waypoints[i].name + 3);
            if (num >= wpAutoCounter) wpAutoCounter = num + 1;
        }
    }
    Serial.printf("[WP] Loaded %d waypoints from flash\n", count);
}

// ═══════════════════════════════════════════════════════════
// MESH RELAY — Packet Deduplication
// Ring buffer of recently seen (pktId, from) pairs.
// Returns true if already seen (skip), false if new (process + relay).
// ═══════════════════════════════════════════════════════════

bool mesh_hasSeenPacket(uint16_t pktId, const char* from) {
    // Check if we've seen this packet
    for (int i = 0; i < MESH_SEEN_SIZE; i++) {
        if (meshSeen[i].pktId == pktId && 
            strcmp(meshSeen[i].from, from) == 0 &&
            (millis() - meshSeen[i].timestamp < 60000)) {  // Expire after 60s
            return true;  // Already seen
        }
    }
    // Not seen — add to ring buffer
    SeenPacket& s = meshSeen[meshSeenHead];
    s.pktId = pktId;
    strncpy(s.from, from, sizeof(s.from) - 1);
    s.from[sizeof(s.from) - 1] = '\0';
    s.timestamp = millis();
    meshSeenHead = (meshSeenHead + 1) % MESH_SEEN_SIZE;
    return false;  // New packet
}

int mesh_getRelayCount() { return meshRelayCount; }
void mesh_incrementRelay() { meshRelayCount++; }

// ═══════════════════════════════════════════════════════════
// STORE AND FORWARD — Queue messages for offline peers
// ═══════════════════════════════════════════════════════════

void snf_storeMessage(const uint8_t* pkt, int len, const char* targetCallsign, uint16_t msgId) {
    if (len <= 0 || len > SNF_MAX_PKT) return;
    
    // Dedup: skip if we already have this msgId stored for this target
    if (msgId != 0) {
        for (int i = 0; i < SNF_MAX_MESSAGES; i++) {
            if (snfQueue[i].valid && snfQueue[i].msgId == msgId &&
                strcasecmp(snfQueue[i].target, targetCallsign) == 0) {
                return;  // Already stored
            }
        }
    }
    
    // Find empty or oldest slot
    int slot = -1;
    uint32_t oldest = UINT32_MAX;
    for (int i = 0; i < SNF_MAX_MESSAGES; i++) {
        if (!snfQueue[i].valid) { slot = i; break; }
        if (snfQueue[i].storedAt < oldest) { oldest = snfQueue[i].storedAt; slot = i; }
    }
    if (slot < 0) return;
    
    memcpy(snfQueue[slot].data, pkt, len);
    snfQueue[slot].len = len;
    strncpy(snfQueue[slot].target, targetCallsign, sizeof(snfQueue[slot].target) - 1);
    snfQueue[slot].target[sizeof(snfQueue[slot].target) - 1] = '\0';
    snfQueue[slot].msgId = msgId;
    snfQueue[slot].storedAt = millis();
    snfQueue[slot].valid = true;
    
    int total = 0;
    for (int i = 0; i < SNF_MAX_MESSAGES; i++) if (snfQueue[i].valid) total++;
    Serial.printf("[S&F] Stored %d bytes for %s (id=%d, %d/%d queued)\n", len, targetCallsign,
                  msgId, total, SNF_MAX_MESSAGES);
}

int snf_getStoredCount(const char* callsign) {
    int count = 0;
    for (int i = 0; i < SNF_MAX_MESSAGES; i++) {
        if (snfQueue[i].valid && strcasecmp(snfQueue[i].target, callsign) == 0) count++;
    }
    return count;
}

int snf_deliverStored(const char* callsign, void (*sendFn)(const uint8_t*, int)) {
    int delivered = 0;
    // Deliver max 4 per beacon cycle to avoid flooding TX queue (16 slots)
    // Remaining messages delivered on next beacon from this peer (~30s)
    for (int i = 0; i < SNF_MAX_MESSAGES && delivered < 4; i++) {
        if (snfQueue[i].valid && strcasecmp(snfQueue[i].target, callsign) == 0) {
            sendFn(snfQueue[i].data, snfQueue[i].len);
            snfQueue[i].valid = false;
            delivered++;
            Serial.printf("[S&F] Delivered stored msg to %s (%d bytes)\n", callsign, snfQueue[i].len);
        }
    }
    return delivered;
}

void snf_expireOld() {
    uint32_t now = millis();
    for (int i = 0; i < SNF_MAX_MESSAGES; i++) {
        if (snfQueue[i].valid && (now - snfQueue[i].storedAt > SNF_EXPIRE_MS)) {
            Serial.printf("[S&F] Expired msg for %s (age %ds)\n", snfQueue[i].target,
                          (now - snfQueue[i].storedAt) / 1000);
            snfQueue[i].valid = false;
        }
    }
}

const char* ui_getSelectedRecipient() {
    if (uiState.selectedContact < 0 || uiState.selectedContact >= contactCount) {
        return "*";  // Broadcast
    }
    return contacts[uiState.selectedContact].name;
}

// Mark peers as inactive if not heard for 5 minutes
static void _peerAging() {
    uint32_t now = millis();
    for (int i = 0; i < peerCount; i++) {
        if (peers[i].active && (now - peers[i].lastSeen > 300000)) {
            peers[i].active = false;
        }
    }
}

// ═══════════════════════════════════════════════════════════
// PSK AES-256-GCM — Standalone Encryption
// Uses ESP32-S3 hardware AES via mbedTLS (already in framework)
// Passphrase → PBKDF2-HMAC-SHA256 (10k iterations) → 256-bit AES key
// Wire format: [nonce(12) | ciphertext(N) | tag(16)]
// Storage: key XOR'd with device-derived wrapping key before write
// ═══════════════════════════════════════════════════════════

#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "esp_random.h"
#include "esp_mac.h"

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   16

// PBKDF2 parameters
#define PSK_KDF_ITERATIONS 10000
// Fixed application-specific salt (all devices in a cluster derive the same
// key from the same passphrase, so per-device salt would break interop)
static const uint8_t PSK_KDF_SALT[] = "GridDown-PSK-v2!";  // 16 bytes
#define PSK_KDF_SALT_LEN 16

// PSK file format version
// v1 (legacy): [key(32) | hint(5)] = 37 bytes, SHA-256 KDF, plaintext
// v2 (current): [0x02 | wrapped_key(32) | hint(5)] = 38 bytes, PBKDF2, device-wrapped
#define PSK_FILE_VERSION 0x02

// ── Device-specific wrapping key ──
// Derived from ESP32 base MAC via SHA-256 with domain separator.
// Protects against offline flash extraction: a raw flash dump from one
// device cannot be loaded onto another to recover the PSK key. An attacker
// needs both the flash contents AND the device's MAC address.
static uint8_t _deviceWrapKey[32] = {0};
static bool _deviceWrapReady = false;

static void _deriveDeviceWrapKey() {
    if (_deviceWrapReady) return;
    
    uint8_t mac[6] = {0};
    esp_base_mac_addr_get(mac);
    
    // SHA-256("GridDown-DeviceWrap" || mac) → 256-bit wrapping key
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    const char* domain = "GridDown-DeviceWrap";
    mbedtls_sha256_update(&ctx, (const uint8_t*)domain, strlen(domain));
    mbedtls_sha256_update(&ctx, mac, 6);
    mbedtls_sha256_finish(&ctx, _deviceWrapKey);
    mbedtls_sha256_free(&ctx);
    
    _deviceWrapReady = true;
    Serial.printf("[PSK] Device wrap key derived (MAC: %02X:%02X:%02X:%02X:%02X:%02X)\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// XOR key with device wrapping key (symmetric — same op for wrap and unwrap)
static void _xorWrap(const uint8_t* src, uint8_t* dst) {
    _deriveDeviceWrapKey();
    for (int i = 0; i < 32; i++) {
        dst[i] = src[i] ^ _deviceWrapKey[i];
    }
}

// Key Check Value — 4 hex chars from SHA-256(pskKey). Lets two operators
// confirm their radios derived the same group key WITHOUT either of them
// revealing passphrase characters. Replaces the previous "hint", which stored
// the first 4 characters of the passphrase in plaintext and displayed them.
static void _pskComputeKcv() {
    if (!pskActive) { pskHint[0] = '\0'; return; }
    uint8_t d[32];
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    const char* dom = "GridDown-PSK-KCV";
    mbedtls_sha256_update(&c, (const uint8_t*)dom, strlen(dom));
    mbedtls_sha256_update(&c, pskKey, 32);
    mbedtls_sha256_finish(&c, d);
    mbedtls_sha256_free(&c);
    snprintf(pskHint, sizeof(pskHint), "%02X%02X", d[0], d[1]);
    memset(d, 0, sizeof(d));
}

// Minimum passphrase length. Raising entropy here buys far more brute-force
// resistance than raising the PBKDF2 iteration count, and unlike an iteration
// change it does NOT alter key derivation, so it cannot break interop with
// radios already in the field.
#define PSK_MIN_PASSPHRASE_LEN 12

void psk_setPassphrase(const char* passphrase) {
    if (!passphrase || strlen(passphrase) == 0) {
        pskActive = false;
        memset(pskKey, 0, 32);
        pskHint[0] = '\0';
        Serial.println("[PSK] Encryption disabled");
        return;
    }
    if (strlen(passphrase) < PSK_MIN_PASSPHRASE_LEN) {
        Serial.printf("[PSK] Rejected: passphrase must be at least %d characters "
                      "(got %u). Encryption unchanged.\n",
                      PSK_MIN_PASSPHRASE_LEN, (unsigned)strlen(passphrase));
        return;   // Leave any existing key intact rather than silently disabling
    }
    
    // Derive 256-bit key from passphrase using PBKDF2-HMAC-SHA256
    // 10k iterations: ~200ms on ESP32-S3 @ 240MHz, acceptable for one-time setup
    mbedtls_md_context_t mdCtx;
    mbedtls_md_init(&mdCtx);
    int ret = mbedtls_md_setup(&mdCtx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret == 0) {
        ret = mbedtls_pkcs5_pbkdf2_hmac(
            &mdCtx,
            (const uint8_t*)passphrase, strlen(passphrase),
            PSK_KDF_SALT, PSK_KDF_SALT_LEN,
            PSK_KDF_ITERATIONS,
            32, pskKey
        );
    }
    mbedtls_md_free(&mdCtx);
    
    if (ret != 0) {
        // Fail closed. The previous behaviour silently fell back to a bare
        // SHA-256 of the passphrase, which derives a DIFFERENT key from every
        // other radio in the cluster — the device would appear encrypted while
        // being unable to talk to anyone.
        Serial.printf("[PSK] PBKDF2 failed (%d) — encryption NOT enabled.\n", ret);
        pskActive = false;
        memset(pskKey, 0, 32);
        pskHint[0] = '\0';
        return;
    }

    pskActive = true;
    _pskComputeKcv();
    
    // Persist to LittleFS — wrapped with device key
    uint8_t wrappedKey[32];
    _xorWrap(pskKey, wrappedKey);
    
    File f = LittleFS.open("/psk.key", "w");
    if (f) {
        uint8_t ver = PSK_FILE_VERSION;
        f.write(&ver, 1);             // Version byte
        f.write(wrappedKey, 32);      // Device-wrapped key
        f.write((uint8_t*)pskHint, 5); // Hint (not sensitive)
        f.close();
    }
    
    Serial.printf("[PSK] PBKDF2 key derived (%d iterations, hint: %s****)\n",
                  PSK_KDF_ITERATIONS, pskHint);
}

bool psk_isEnabled() { return pskActive; }

const char* psk_getPassphraseHint() { return pskHint; }

static void _pskLoadKey() {
    File f = LittleFS.open("/psk.key", "r");
    if (!f) { pskActive = false; return; }
    
    size_t fSize = f.size();
    
    if (fSize == 38) {
        // v2 format: [version(1) | wrapped_key(32) | hint(5)]
        uint8_t ver = f.read();
        if (ver == PSK_FILE_VERSION) {
            uint8_t wrappedKey[32];
            f.read(wrappedKey, 32);
            f.read((uint8_t*)pskHint, 5);
            pskHint[4] = '\0';
            
            // Unwrap with device key
            _xorWrap(wrappedKey, pskKey);
            
            pskActive = true;
            f.close();
            // Recompute the KCV from the key rather than trusting the stored
            // field, so files written by older firmware (which stored the first
            // 4 passphrase characters there) never get displayed.
            _pskComputeKcv();
            Serial.printf("[PSK] v2 key loaded (device-wrapped, KCV %s)\n", pskHint);
            return;
        }
    }
    
    if (fSize >= 37) {
        // Legacy v1 format: [key(32) | hint(5)] — plaintext, SHA-256 KDF
        // Read, re-wrap with device key, and re-save as v2
        f.seek(0);
        f.read(pskKey, 32);
        f.read((uint8_t*)pskHint, 5);
        pskHint[4] = '\0';
        pskActive = true;
        f.close();
        
        // Migrate: re-save as v2 (device-wrapped)
        // NOTE: the derived key bytes are preserved as-is. Devices already
        // sharing a PSK from v1 firmware will continue to interoperate.
        // Only NEW passphrase entries will use PBKDF2 (different key bytes).
        uint8_t wrappedKey[32];
        _xorWrap(pskKey, wrappedKey);
        
        File fw = LittleFS.open("/psk.key", "w");
        if (fw) {
            uint8_t ver = PSK_FILE_VERSION;
            fw.write(&ver, 1);
            fw.write(wrappedKey, 32);
            fw.write((uint8_t*)pskHint, 5);
            fw.close();
            _pskComputeKcv();
            Serial.printf("[PSK] v1→v2 migration complete (KCV %s)\n", pskHint);
        } else {
            _pskComputeKcv();
            Serial.printf("[PSK] v1 key loaded, migration write failed (KCV %s)\n", pskHint);
        }
        return;
    }
    
    // Unrecognized file size
    f.close();
    pskActive = false;
    Serial.printf("[PSK] Unrecognized key file (%d bytes), ignoring\n", fSize);
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Output format: [nonce(12) | ciphertext(plainLen) | tag(16)]
 * Returns total output length, or -1 on error.
 */
int psk_encrypt(const uint8_t* plain, size_t plainLen, uint8_t* out, size_t outMax) {
    if (!pskActive) return -1;
    size_t needed = GCM_NONCE_LEN + plainLen + GCM_TAG_LEN;
    if (needed > outMax) return -1;
    
    // Generate random 12-byte nonce
    esp_fill_random(out, GCM_NONCE_LEN);
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pskKey, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return -1; }
    
    // Encrypt: output ciphertext after nonce, tag at end
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
        plainLen,
        out, GCM_NONCE_LEN,           // nonce
        NULL, 0,                       // no AAD
        plain,                         // plaintext input
        out + GCM_NONCE_LEN,          // ciphertext output
        GCM_TAG_LEN,
        out + GCM_NONCE_LEN + plainLen // tag output
    );
    
    mbedtls_gcm_free(&gcm);
    return (ret == 0) ? (int)needed : -1;
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * Input format: [nonce(12) | ciphertext(N) | tag(16)]
 * Returns plaintext length, or -1 on error (wrong key, tampered).
 */
int psk_decrypt(const uint8_t* cipher, size_t cipherLen, uint8_t* out, size_t outMax) {
    if (!pskActive) return -1;
    if (cipherLen < GCM_NONCE_LEN + GCM_TAG_LEN + 1) return -1;
    
    size_t plainLen = cipherLen - GCM_NONCE_LEN - GCM_TAG_LEN;
    if (plainLen > outMax) return -1;
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, pskKey, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return -1; }
    
    ret = mbedtls_gcm_auth_decrypt(&gcm,
        plainLen,
        cipher, GCM_NONCE_LEN,                         // nonce
        NULL, 0,                                        // no AAD
        cipher + GCM_NONCE_LEN + plainLen, GCM_TAG_LEN, // tag
        cipher + GCM_NONCE_LEN,                         // ciphertext
        out                                             // plaintext output
    );
    
    mbedtls_gcm_free(&gcm);
    return (ret == 0) ? (int)plainLen : -1;
}

// ═══════════════════════════════════════════════════════════
// EPHEMERAL KEY AGREEMENT (ECDH P-256)
// ═══════════════════════════════════════════════════════════
// Provides per-pair session keys with forward secrecy.
// - Keypair regenerated on every boot (ephemeral)
// - Public key included in beacons
// - Session key derived via ECDH + SHA-256 on peer discovery
// - DMs use session key for inner E2E encryption
// - PSK still wraps everything for mesh relay compatibility
// ═══════════════════════════════════════════════════════════

// RNG wrapper for mbedtls (uses ESP32 hardware TRNG)
static int _ephRng(void* ctx, uint8_t* buf, size_t len) {
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

// Forward declaration for b64 functions (implemented in main.cpp)
extern String b64Encode(const uint8_t* data, size_t len);
extern int b64Decode(const char* src, uint8_t* dst, size_t maxLen);

void eph_init() {
    mbedtls_ecp_group_init(&ephGrp);
    mbedtls_mpi_init(&ephPriv);
    mbedtls_ecp_point_init(&ephPub);
    
    int ret = mbedtls_ecp_group_load(&ephGrp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        Serial.printf("[EPH] Failed to load P-256 group: %d\n", ret);
        return;
    }
    
    ret = mbedtls_ecp_gen_keypair(&ephGrp, &ephPriv, &ephPub, _ephRng, NULL);
    if (ret != 0) {
        Serial.printf("[EPH] Keypair generation failed: %d\n", ret);
        return;
    }
    
    // Export uncompressed public key (65 bytes: 0x04 || x(32) || y(32))
    ret = mbedtls_ecp_point_write_binary(&ephGrp, &ephPub,
        MBEDTLS_ECP_PF_UNCOMPRESSED, &ephPubLen, ephPubBytes, sizeof(ephPubBytes));
    if (ret != 0 || ephPubLen != 65) {
        Serial.printf("[EPH] Pubkey export failed: %d (len=%d)\n", ret, ephPubLen);
        return;
    }
    
    ephReady = true;
    Serial.printf("[EPH] P-256 keypair ready (pubkey %d bytes)\n", ephPubLen);
}

const char* eph_getPublicKeyBase64() {
    static String b64Cache;
    if (!ephReady) return NULL;
    if (b64Cache.length() == 0) {
        b64Cache = b64Encode(ephPubBytes, ephPubLen);
    }
    return b64Cache.c_str();
}

bool eph_isReady() { return ephReady; }

// Derive per-pair session key from ECDH shared secret
// Called when a peer's public key is received in a beacon
void eph_onPeerPublicKey(const char* callsign, const uint8_t* peerPub, size_t peerPubLen) {
    if (!ephReady || peerPubLen != 65 || peerPub[0] != 0x04) return;
    
    // Find peer in table
    int idx = -1;
    for (int i = 0; i < peerCount; i++) {
        if (strcasecmp(peers[i].callsign, callsign) == 0) { idx = i; break; }
    }
    if (idx < 0) return;  // Peer not in table yet (will be added by ui_addPeer)
    
    // Skip if we already have a session key with the same pubkey
    if (peers[idx].hasSessionKey && peers[idx].peerPubKeyLen == 65 &&
        memcmp(peers[idx].peerPubKey, peerPub, 65) == 0) {
        return;  // Same pubkey, same session key
    }
    
    // Load peer's public key
    mbedtls_ecp_point peerQ;
    mbedtls_ecp_point_init(&peerQ);
    int ret = mbedtls_ecp_point_read_binary(&ephGrp, &peerQ, peerPub, peerPubLen);
    if (ret != 0) {
        Serial.printf("[EPH] Failed to parse %s pubkey: %d\n", callsign, ret);
        mbedtls_ecp_point_free(&peerQ);
        return;
    }
    
    // Validate pubkey is on the curve (prevents invalid curve attacks)
    ret = mbedtls_ecp_check_pubkey(&ephGrp, &peerQ);
    if (ret != 0) {
        Serial.printf("[EPH] Invalid pubkey from %s: %d\n", callsign, ret);
        mbedtls_ecp_point_free(&peerQ);
        return;
    }
    
    // Compute ECDH shared secret
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    ret = mbedtls_ecdh_compute_shared(&ephGrp, &z, &peerQ, &ephPriv, _ephRng, NULL);
    mbedtls_ecp_point_free(&peerQ);
    if (ret != 0) {
        Serial.printf("[EPH] ECDH failed for %s: %d\n", callsign, ret);
        mbedtls_mpi_free(&z);
        return;
    }
    
    // Export shared secret as 32 bytes
    uint8_t shared[32];
    mbedtls_mpi_write_binary(&z, shared, 32);
    mbedtls_mpi_free(&z);
    
    // Derive session key: SHA-256(shared || sorted(pubA, pubB) || domain)
    // Lexicographic sort ensures both peers derive the same key
    const uint8_t* pkA = ephPubBytes;
    const uint8_t* pkB = peerPub;
    if (memcmp(pkA, pkB, 65) > 0) {
        const uint8_t* tmp = pkA; pkA = pkB; pkB = tmp;
    }
    
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, shared, 32);
    mbedtls_sha256_update(&sha, pkA, 65);
    mbedtls_sha256_update(&sha, pkB, 65);
    const char* domain = "GridDown-E2E-v1";
    mbedtls_sha256_update(&sha, (const uint8_t*)domain, strlen(domain));
    mbedtls_sha256_finish(&sha, peers[idx].sessionKey);
    mbedtls_sha256_free(&sha);
    
    // Zeroize shared secret
    memset(shared, 0, 32);
    
    // Store peer's pubkey and mark session active
    memcpy(peers[idx].peerPubKey, peerPub, 65);
    peers[idx].peerPubKeyLen = 65;
    peers[idx].hasSessionKey = true;
    
    Serial.printf("[EPH] Session key established with %s\n", callsign);
}

// Look up session key for a peer (returns NULL if no session key)
const uint8_t* eph_getSessionKey(const char* callsign) {
    for (int i = 0; i < peerCount; i++) {
        if (strcasecmp(peers[i].callsign, callsign) == 0 && peers[i].hasSessionKey) {
            return peers[i].sessionKey;
        }
    }
    return NULL;
}

bool eph_hasSessionKey(const char* callsign) {
    return eph_getSessionKey(callsign) != NULL;
}

// ── SIGNED ACK — HMAC-SHA256 delivery confirmations ──
// Computes a truncated HMAC-SHA256 tag over a canonical ACK string
// using the per-pair ECDH session key. Prevents ACK forgery by nodes
// that only have the group PSK.
//
// Input format: "GridDown-ACK-v1|<acker>|<sender>|<msgId>"
// Output: 8-byte truncated tag (64-bit, sufficient for low-bandwidth LoRa)

static int _ackComputeTag(const char* acker, const char* sender, uint16_t msgId,
                          const uint8_t* sessionKey, uint8_t* tagOut8) {
    // Build canonical input: "GridDown-ACK-v1|ALPHA|BRAVO|1234"
    char input[96];
    int n = snprintf(input, sizeof(input), "GridDown-ACK-v1|%s|%s|%u", acker, sender, msgId);
    if (n <= 0 || n >= (int)sizeof(input)) return -1;
    
    // HMAC-SHA256
    uint8_t fullTag[32];
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mdInfo) return -1;
    int ret = mbedtls_md_hmac(mdInfo, sessionKey, 32,
                              (const uint8_t*)input, n, fullTag);
    if (ret != 0) return -1;
    
    // Truncate to 8 bytes
    memcpy(tagOut8, fullTag, 8);
    memset(fullTag, 0, sizeof(fullTag));
    return 0;
}

// Sign an ACK: returns base64 tag in sigB64Out, or empty string if no session key.
// acker = the node generating the ACK (us), sender = the original message sender.
bool ack_sign(const char* acker, const char* sender, uint16_t msgId,
              char* sigB64Out, int maxLen) {
    sigB64Out[0] = '\0';
    const uint8_t* sk = eph_getSessionKey(sender);
    if (!sk) return false;
    
    uint8_t tag[8];
    if (_ackComputeTag(acker, sender, msgId, sk, tag) != 0) return false;
    
    String b64 = b64Encode(tag, 8);
    if ((int)b64.length() >= maxLen) return false;
    strncpy(sigB64Out, b64.c_str(), maxLen - 1);
    sigB64Out[maxLen - 1] = '\0';
    return true;
}

// Verify an ACK signature. acker = the node that sent the ACK, sender = us.
// Returns true if sig is valid, false if forged or no session key.
bool ack_verify(const char* acker, const char* sender, uint16_t msgId,
                const char* sigB64) {
    if (!sigB64 || sigB64[0] == '\0') return false;
    
    const uint8_t* sk = eph_getSessionKey(acker);
    if (!sk) return false;
    
    // Decode the received tag
    uint8_t rxTag[8];
    int decLen = b64Decode(sigB64, rxTag, sizeof(rxTag));
    if (decLen != 8) return false;
    
    // Recompute expected tag
    uint8_t expected[8];
    if (_ackComputeTag(acker, sender, msgId, sk, expected) != 0) return false;
    
    // Constant-time comparison
    uint8_t diff = 0;
    for (int i = 0; i < 8; i++) diff |= rxTag[i] ^ expected[i];
    
    memset(expected, 0, sizeof(expected));
    return (diff == 0);
}

// ═══════════════════════════════════════════════════════════
// REMOTE WIPE — Authenticated device erasure via LoRa
// ═══════════════════════════════════════════════════════════
//
// Auth model: wipe key = HMAC-SHA256(pskKey, "GridDown-Wipe-v1")
// Any PSK holder can issue a wipe — same trust boundary as decrypting
// traffic. The wipe key is never transmitted; only a truncated HMAC
// tag over the canonical wipe command string travels over the air.
//
// Replay protection: GPS epoch timestamp, 5-minute validity window.
//
// Wire: {"type":"wipe","from":"ALPHA","to":"BRAVO","ts":1710000000,"sig":"<b64>"}

#define WIPE_TIMESTAMP_WINDOW 300  // 5 minutes

// Derive wipe auth key from PSK (deterministic, both sides compute same key)
static int _wipe_deriveKey(uint8_t wipeKey[32]) {
    if (!psk_isEnabled()) return -1;
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mdInfo) return -1;
    const char* domain = "GridDown-Wipe-v1";
    return mbedtls_md_hmac(mdInfo, pskKey, 32,
                           (const uint8_t*)domain, strlen(domain), wipeKey);
}

// Compute HMAC tag for a wipe command (16-byte truncated = 128-bit)
static int _wipe_computeTag(const char* issuer, const char* target,
                            uint32_t epoch, const uint8_t wipeKey[32],
                            uint8_t tagOut[16]) {
    char input[96];
    int n = snprintf(input, sizeof(input), "GridDown-Wipe-v1|%s|%s|%u",
                     issuer, target, epoch);
    if (n <= 0 || n >= (int)sizeof(input)) return -1;
    
    uint8_t fullTag[32];
    const mbedtls_md_info_t* mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!mdInfo) return -1;
    int ret = mbedtls_md_hmac(mdInfo, wipeKey, 32,
                              (const uint8_t*)input, n, fullTag);
    if (ret != 0) return -1;
    
    memcpy(tagOut, fullTag, 16);
    memset(fullTag, 0, sizeof(fullTag));
    return 0;
}

// Sign a wipe command: returns base64 tag (24 chars for 16 bytes)
bool wipe_sign(const char* issuer, const char* target, uint32_t epoch,
               char* sigB64Out, int maxLen) {
    sigB64Out[0] = '\0';
    uint8_t wipeKey[32];
    if (_wipe_deriveKey(wipeKey) != 0) return false;
    
    uint8_t tag[16];
    if (_wipe_computeTag(issuer, target, epoch, wipeKey, tag) != 0) {
        memset(wipeKey, 0, sizeof(wipeKey));
        return false;
    }
    
    String b64 = b64Encode(tag, 16);
    memset(wipeKey, 0, sizeof(wipeKey));
    memset(tag, 0, sizeof(tag));
    if ((int)b64.length() >= maxLen) return false;
    strncpy(sigB64Out, b64.c_str(), maxLen - 1);
    sigB64Out[maxLen - 1] = '\0';
    return true;
}

// Verify a wipe command signature + timestamp window
// Returns: 0 = valid, -1 = no PSK, -2 = bad sig, -3 = expired timestamp
int wipe_verify(const char* issuer, const char* target, uint32_t epoch,
                const char* sigB64, uint32_t localEpoch) {
    if (!sigB64 || sigB64[0] == '\0') return -2;
    
    uint8_t wipeKey[32];
    if (_wipe_deriveKey(wipeKey) != 0) return -1;
    
    // Timestamp check: must be within WIPE_TIMESTAMP_WINDOW seconds
    int32_t drift = (int32_t)epoch - (int32_t)localEpoch;
    if (drift < 0) drift = -drift;
    if (drift > WIPE_TIMESTAMP_WINDOW) {
        memset(wipeKey, 0, sizeof(wipeKey));
        return -3;
    }
    
    // Decode received tag
    uint8_t rxTag[16];
    int decLen = b64Decode(sigB64, rxTag, sizeof(rxTag));
    if (decLen != 16) { memset(wipeKey, 0, sizeof(wipeKey)); return -2; }
    
    // Recompute expected tag
    uint8_t expected[16];
    if (_wipe_computeTag(issuer, target, epoch, wipeKey, expected) != 0) {
        memset(wipeKey, 0, sizeof(wipeKey));
        return -2;
    }
    memset(wipeKey, 0, sizeof(wipeKey));
    
    // Constant-time comparison
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= rxTag[i] ^ expected[i];
    memset(expected, 0, sizeof(expected));
    
    return (diff == 0) ? 0 : -2;
}

// Execute device wipe: zeroize secrets, delete all persistent data, reboot
void wipe_execute(const char* reason) {
    Serial.printf("[WIPE] === EXECUTING DEVICE WIPE ===\n");
    Serial.printf("[WIPE] Reason: %s\n", reason);
    
    // 1. Zeroize cryptographic material in RAM
    memset(pskKey, 0, sizeof(pskKey));
    pskActive = false;
    pskHint[0] = '\0';
    
    // Zeroize ECDH private key and all session keys
    mbedtls_mpi_free(&ephPriv);
    mbedtls_ecp_point_free(&ephPub);
    memset(ephPubBytes, 0, sizeof(ephPubBytes));
    ephPubLen = 0;
    ephReady = false;
    for (int i = 0; i < peerCount; i++) {
        memset(peers[i].sessionKey, 0, 32);
        peers[i].hasSessionKey = false;
    }
    
    // 2. Zeroize messages in RAM
    for (int i = 0; i < MAX_MESSAGES; i++) {
        memset(&messages[i], 0, sizeof(LocalMessage));
    }
    msgCount = 0; msgHead = 0;
    
    // Zeroize store-and-forward queue
    for (int i = 0; i < SNF_MAX_MESSAGES; i++) {
        memset(&snfQueue[i], 0, sizeof(StoredMessage));
    }
    
    // Zeroize contacts
    memset(contacts, 0, sizeof(Contact) * MAX_CONTACTS);
    contactCount = 0;
    
    // Clear callsign
    memset(myCallsign, 0, sizeof(myCallsign));
    
    Serial.println("[WIPE] RAM zeroized");
    
    // 3. Delete all LittleFS files
    LittleFS.remove("/messages.json");
    LittleFS.remove("/psk.key");
    LittleFS.remove("/callsign.txt");
    LittleFS.remove("/channel.cfg");
    LittleFS.remove("/brightness.cfg");
    LittleFS.remove("/mute.cfg");
    LittleFS.remove("/vmode.cfg");
    LittleFS.remove("/gpsbaud.cfg");
    LittleFS.remove("/kbbl.cfg");
    LittleFS.remove("/bootcnt.bin");
    LittleFS.remove("/waypoints.json");
    LittleFS.remove(DURESS_PIN_FILE);
    LittleFS.remove("/tak_server.cfg");  // COT_TAK_CONFIG_FILE defined in CoT section below
    Serial.println("[WIPE] LittleFS cleared");
    
    // 4. Delete SD card GridDown directory contents
    if (sdMounted) {
        // Delete files in /griddown/ and subdirectories
        const char* subdirs[] = {"/griddown/outbox", "/griddown/inbox", 
                                 "/griddown/logs", "/griddown"};
        for (int d = 0; d < 4; d++) {
            File dir = SD.open(subdirs[d]);
            if (dir && dir.isDirectory()) {
                File entry = dir.openNextFile();
                while (entry) {
                    if (!entry.isDirectory()) {
                        String path = String(subdirs[d]) + "/" + entry.name();
                        entry.close();
                        SD.remove(path);
                    } else {
                        entry.close();
                    }
                    entry = dir.openNextFile();
                }
                dir.close();
            }
        }
        Serial.println("[WIPE] SD card cleared");
    }
    
    // 5. Visual feedback — red screen for 1 second
    tft.fillScreen(COLOR_RED);
    tft.setTextColor(0xFFFF);
    tft.setTextSize(2);
    tft.setCursor(40, scrH / 2 - 16);
    tft.print("DEVICE WIPED");
    tft.setTextSize(1);
    tft.setCursor(60, scrH / 2 + 16);
    tft.print(reason);
    
    Serial.println("[WIPE] === WIPE COMPLETE — REBOOTING ===");
    Serial.flush();
    delay(1500);
    
    ESP.restart();
}

// E2E encrypt with a specific key (session key or any 32-byte AES key)
// Same format as PSK: [nonce(12) | ciphertext(N) | tag(16)]
int e2e_encrypt(const uint8_t* key, const uint8_t* plain, size_t plainLen, uint8_t* out, size_t outMax) {
    size_t needed = GCM_NONCE_LEN + plainLen + GCM_TAG_LEN;
    if (needed > outMax) return -1;
    
    esp_fill_random(out, GCM_NONCE_LEN);
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return -1; }
    
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
        plainLen, out, GCM_NONCE_LEN, NULL, 0,
        plain, out + GCM_NONCE_LEN,
        GCM_TAG_LEN, out + GCM_NONCE_LEN + plainLen);
    
    mbedtls_gcm_free(&gcm);
    return (ret == 0) ? (int)needed : -1;
}

int e2e_decrypt(const uint8_t* key, const uint8_t* cipher, size_t cipherLen, uint8_t* out, size_t outMax) {
    if (cipherLen < GCM_NONCE_LEN + GCM_TAG_LEN + 1) return -1;
    size_t plainLen = cipherLen - GCM_NONCE_LEN - GCM_TAG_LEN;
    if (plainLen > outMax) return -1;
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return -1; }
    
    ret = mbedtls_gcm_auth_decrypt(&gcm, plainLen,
        cipher, GCM_NONCE_LEN, NULL, 0,
        cipher + GCM_NONCE_LEN + plainLen, GCM_TAG_LEN,
        cipher + GCM_NONCE_LEN, out);
    
    mbedtls_gcm_free(&gcm);
    return (ret == 0) ? (int)plainLen : -1;
}

// ═══════════════════════════════════════════════════════════
// CHANNEL SCHEDULE ROTATION (Frequency Hopping)
// ═══════════════════════════════════════════════════════════
// All nodes with the same PSK and GPS time follow the same
// deterministic pseudo-random channel sequence.
// - Hop period: 30 seconds
// - Channel derived from SHA-256(pskKey || slot_number)
// - No hopping without GPS time sync (stays on base channel)
// - No hopping without PSK (stays on base channel)
// ═══════════════════════════════════════════════════════════

static uint32_t fhopLastSlot = 0;      // Last computed 30s time slot
static int      fhopChannel = 0;       // Current hop channel (0 = use base)
static bool     fhopActive = false;    // true = GPS synced + PSK active, hopping engaged

// Derive channel from PSK + time slot using HKDF-SHA256 (RFC 5869).
//
// Previously this was an ad-hoc SHA-256(pskKey || slot || domain) construction.
// It is now a standard KDF so that every cryptographic step in the firmware is
// a named, standards-body-published construction:
//
//   IKM  = group PSK (32 bytes)
//   salt = "GridDown-FHOP-v1"   (application/domain separation)
//   info = slot number, little-endian uint32
//   OKM  = 4 bytes → uint32 → mod 8 → channel 1..8
//
// Four output bytes are consumed rather than one so channel selection is not
// biased by a single byte's modulo residue any more than necessary.
//
// NOTE (interop): this changes the hop sequence relative to firmware that used
// the previous construction. All radios in a cluster must run matching firmware
// to stay synchronised. FHOP already requires a shared PSK and GPS time.
static int _fhopDeriveChannel(uint32_t slot) {
    const uint8_t slotBytes[4] = {
        (uint8_t)(slot & 0xFF), (uint8_t)((slot >> 8) & 0xFF),
        (uint8_t)((slot >> 16) & 0xFF), (uint8_t)((slot >> 24) & 0xFF)
    };
    static const char* FHOP_SALT = "GridDown-FHOP-v1";

    uint8_t okm[4] = {0};
    if (!_hkdfSha256((const uint8_t*)FHOP_SALT, strlen(FHOP_SALT),
                     pskKey, 32,
                     slotBytes, sizeof(slotBytes),
                     okm, sizeof(okm))) {
        // Derivation failure — stay on the base channel rather than hopping to
        // an arbitrary one, which would silently partition the cluster.
        Serial.println("[FHOP] HKDF failed — holding base channel");
        return 0;
    }

    uint32_t v = ((uint32_t)okm[0]) | ((uint32_t)okm[1] << 8) |
                 ((uint32_t)okm[2] << 16) | ((uint32_t)okm[3] << 24);
    memset(okm, 0, sizeof(okm));
    return (int)(v % 8) + 1;
}

void fhop_tick() {
    // Requirements: PSK enabled + GPS time available
    if (!pskActive) {
        if (fhopActive) {
            fhopActive = false;
            fhopChannel = 0;
            Serial.println("[FHOP] Disabled — no PSK");
        }
        return;
    }
    
    uint32_t epoch = _getUtcEpoch();
    if (epoch == 0) {
        // No GPS time yet — stay on base channel
        if (fhopActive) {
            fhopActive = false;
            fhopChannel = 0;
            Serial.println("[FHOP] Paused — GPS time lost");
        }
        return;
    }
    
    // Compute 30-second time slot
    // NOTE: Hop boundary packet loss — a packet in flight (~300ms at SF10) when
    // the 30s hop fires will be missed by the receiver (already on new channel).
    // DMs are covered by the retry system (resends on next slot). Broadcast
    // messages have no retry — ~1% message loss is the accepted tradeoff for
    // the congestion avoidance and casual-intercept resistance that channel
    // rotation provides. NOTE: this is NOT jam resistance — an 8-channel,
    // 30-second rotation confers no meaningful anti-jam capability (the whole
    // 902-928 MHz band is 26 MHz wide and cheaply blanket-jammed). See
    // SECURITY.md; do not describe this feature as anti-jam.
    uint32_t slot = epoch / 30;
    
    if (slot != fhopLastSlot) {
        fhopLastSlot = slot;
        int newCh = _fhopDeriveChannel(slot);

        // Guard: only channels 1-8 are valid. _fhopDeriveChannel() returns 0 if
        // HKDF fails. Engaging with channel 0 would drive _channelToFreq() below
        // CH1 (903.5 MHz) and silently partition the cluster, so disengage and
        // hold the operator's base channel instead.
        if (newCh < 1 || newCh > 8) {
            if (fhopActive) {
                fhopActive = false;
                fhopChannel = 0;
                Serial.println("[FHOP] Disengaged — channel derivation failed, holding base channel");
                uiState.dirty = true;
            }
            return;
        }

        if (!fhopActive || newCh != fhopChannel) {
            int oldCh = fhopChannel;
            fhopChannel = newCh;
            
            if (!fhopActive) {
                fhopActive = true;
                Serial.printf("[FHOP] Engaged — GPS synced, starting on CH%d (slot %lu)\n",
                              newCh, slot);
            } else {
                Serial.printf("[FHOP] Hop CH%d → CH%d (slot %lu, %.1f MHz)\n",
                              oldCh, newCh, slot, _channelToFreq(newCh));
            }
        }
    }
}

int fhop_getCurrentChannel() {
    return fhopActive ? fhopChannel : currentChannel;
}

float fhop_getCurrentFreq() {
    return _channelToFreq(fhop_getCurrentChannel());
}

bool fhop_isActive() { return fhopActive; }

/**
 * Draw signal quality bars + numbers.
 * RSSI range: -30 (excellent) to -120 (no signal)
 * SNR range: -20 (garbage) to +15 (excellent)
 */
static void _drawSignalQuality(int x, int y) {
    // Clear the entire signal quality area first (prevents ghost text from overlays)
    tft.fillRect(x, y, scrW - x, 24, COLOR_BG);
    
    // RSSI to bar count (0-5)
    int bars = 0;
    if (sigRSSI > -60) bars = 5;
    else if (sigRSSI > -75) bars = 4;
    else if (sigRSSI > -90) bars = 3;
    else if (sigRSSI > -105) bars = 2;
    else if (sigRSSI > -115) bars = 1;
    
    // Draw signal bars
    for (int i = 0; i < 5; i++) {
        int barH = 4 + i * 3;
        int barX = x + i * 7;
        int barY = y + (19 - barH);
        uint16_t color = (i < bars) ? 
            (bars >= 4 ? COLOR_GREEN : bars >= 2 ? COLOR_YELLOW : COLOR_RED) : 
            0x2104;  // Dark grey for empty bars
        tft.fillRect(barX, barY, 5, barH, color);
    }
    
    // RSSI + SNR text
    tft.setTextSize(1);
    tft.setCursor(x + 40, y);
    tft.setTextColor(bars >= 3 ? COLOR_GREEN : bars >= 1 ? COLOR_YELLOW : COLOR_RED);
    tft.printf("%.0fdBm", sigRSSI);
    
    tft.setCursor(x + 40, y + 10);
    tft.setTextColor(sigSNR > 5 ? COLOR_GREEN : sigSNR > 0 ? COLOR_YELLOW : COLOR_RED);
    tft.printf("SNR:%.1f", sigSNR);
    
    // RX/TX counts
    tft.setCursor(x + 130, y);
    tft.setTextColor(COLOR_DIM);
    tft.printf("RX:%d TX:%d", sigRxCount, sigTxCount);
    
    // Time since last packet
    if (sigLastUpdate > 0) {
        uint32_t ago = (millis() - sigLastUpdate) / 1000;
        tft.setCursor(x + 130, y + 10);
        if (ago < 60) tft.printf("Last: %ds ago", ago);
        else if (ago < 3600) tft.printf("Last: %dm ago", ago / 60);
        else tft.setTextColor(COLOR_RED), tft.print("No recent RX");
    }
}

// ═══════════════════════════════════════════════════════════
// COT (CURSOR-ON-TARGET) BRIDGE
// Triple output:
//   1. WebSocket JSON: {"type":"cot_event","xml":"..."} on port 8770
//      → GridDown PWA receives and can forward to TAK server
//   2. UDP multicast: raw CoT XML on 239.2.3.1:6969 (TAK SA multicast)
//      → Any ATAK/iTAK/WinTAK on GridDown-Radio WiFi sees events directly
//   3. TCP TAK Server: raw CoT XML + null terminator to configured server
//      → Persistent connection to FreeTAK/TAK Server, auto-reconnect
// ═══════════════════════════════════════════════════════════

// cotEnabled defined at top of file (forward declaration block)

// TAK standard SA multicast group
#define COT_MCAST_ADDR  IPAddress(239, 2, 3, 1)
#define COT_MCAST_PORT  6969

static WiFiUDP cotUdp;
static bool    cotUdpStarted = false;

// TAK Server TCP client state
static WiFiClient cotTcpClient;
static char    cotTakHost[64] = {0};     // Server hostname/IP
static uint16_t cotTakPort = 0;          // Server port (0 = not configured)
// cotTakConfigured defined at top of file (forward declaration block)
static uint32_t cotTakLastAttempt = 0;   // millis() of last connect attempt
static uint32_t cotTakBackoff = 5000;    // Reconnect backoff (ms), grows on failure
static uint8_t  cotTakFailCount = 0;     // Consecutive connection failures
#define COT_TAK_BACKOFF_MIN   5000
#define COT_TAK_BACKOFF_MAX   60000
#define COT_TAK_CONFIG_FILE   "/tak_server.cfg"

// Load TAK server config from LittleFS
static void _cotLoadTakConfig() {
    File f = LittleFS.open(COT_TAK_CONFIG_FILE, "r");
    if (!f || f.size() < 3) { if (f) f.close(); return; }
    char buf[80] = {0};
    int len = f.readBytesUntil('\n', buf, sizeof(buf) - 1);
    f.close();
    if (len < 3) return;
    buf[len] = '\0';
    
    // Format: host:port
    char* colon = strrchr(buf, ':');
    if (!colon) return;
    *colon = '\0';
    uint16_t port = atoi(colon + 1);
    if (port == 0 || port > 65535) return;
    
    strncpy(cotTakHost, buf, sizeof(cotTakHost) - 1);
    cotTakPort = port;
    cotTakConfigured = true;
    Serial.printf("[CoT-TCP] Loaded config: %s:%d\n", cotTakHost, cotTakPort);
}

// Save TAK server config to LittleFS
static void _cotSaveTakConfig() {
    File f = LittleFS.open(COT_TAK_CONFIG_FILE, "w");
    if (!f) return;
    if (cotTakConfigured) {
        f.printf("%s:%d\n", cotTakHost, cotTakPort);
    }
    f.close();
}

bool cot_isEnabled() { return cotMode > 0; }
uint8_t cot_getMode() { return cotMode; }

void cot_setMode(uint8_t mode) {
    if (mode > COT_MODE_ALL) mode = COT_MODE_OFF;
    cotMode = mode;
    cotEnabled = (mode > 0);
    
    // Start UDP multicast TX socket if any mode enabled
    if (cotEnabled && !cotUdpStarted) {
        cotUdp.begin(COT_MCAST_PORT);
        cotUdpStarted = true;
        Serial.printf("[CoT] UDP multicast TX started on 239.2.3.1:%d\n", COT_MCAST_PORT);
    }
    // Load TAK server config on first enable
    if (cotEnabled && !cotTakConfigured) {
        _cotLoadTakConfig();
    }
    // Disconnect TCP if mode doesn't include TCP
    if (mode != COT_MODE_TCP && mode != COT_MODE_ALL && cotTcpClient.connected()) {
        cotTcpClient.stop();
        Serial.println("[CoT-TCP] Disconnected (mode change)");
    }
    Serial.printf("[CoT] Mode: %s\n", cotModeLabel[mode]);
    uiState.dirty = true;
}

void cot_setEnabled(bool on) {
    // Backward compat: on=true → Mcast, on=false → OFF
    cot_setMode(on ? COT_MODE_MCAST : COT_MODE_OFF);
}

void cot_cycleMode() {
    // OFF → Mcast → TCP (if configured) → All (if configured) → OFF
    switch (cotMode) {
        case COT_MODE_OFF:
            cot_setMode(COT_MODE_MCAST);
            break;
        case COT_MODE_MCAST:
            if (cotTakConfigured) cot_setMode(COT_MODE_TCP);
            else cot_setMode(COT_MODE_OFF);  // Skip TCP/All if no server
            break;
        case COT_MODE_TCP:
            cot_setMode(COT_MODE_ALL);
            break;
        case COT_MODE_ALL:
            cot_setMode(COT_MODE_OFF);
            break;
        default:
            cot_setMode(COT_MODE_OFF);
            break;
    }
    if (!audioMuted) ui_beep(cotMode > 0 ? 1500 : 800, 80);
}

void cot_setTakServer(const char* host, uint16_t port) {
    if (!host || strlen(host) == 0 || port == 0) return;
    strncpy(cotTakHost, host, sizeof(cotTakHost) - 1);
    cotTakHost[sizeof(cotTakHost) - 1] = '\0';
    cotTakPort = port;
    cotTakConfigured = true;
    cotTakFailCount = 0;
    cotTakBackoff = COT_TAK_BACKOFF_MIN;
    cotTakLastAttempt = 0;  // Force immediate connect attempt
    // Disconnect existing if any
    if (cotTcpClient.connected()) cotTcpClient.stop();
    _cotSaveTakConfig();
    Serial.printf("[CoT-TCP] Server set: %s:%d\n", cotTakHost, cotTakPort);
    uiState.dirty = true;
}

void cot_clearTakServer() {
    if (cotTcpClient.connected()) cotTcpClient.stop();
    cotTakHost[0] = '\0';
    cotTakPort = 0;
    cotTakConfigured = false;
    cotTakFailCount = 0;
    LittleFS.remove(COT_TAK_CONFIG_FILE);
    Serial.println("[CoT-TCP] Server cleared");
    uiState.dirty = true;
}

bool cot_takConnected() { return cotTcpClient.connected(); }
const char* cot_getTakHost() { return cotTakHost; }
uint16_t cot_getTakPort() { return cotTakPort; }

// Connection manager — call from ui_tick()
void cot_takTick() {
    // Only manage TCP connection if mode includes TCP
    if ((cotMode != COT_MODE_TCP && cotMode != COT_MODE_ALL) || !cotTakConfigured) return;
    
    // Already connected — let cot_rxTick() handle inbound data
    if (cotTcpClient.connected()) {
        return;
    }
    
    // Not connected — attempt reconnect with backoff
    uint32_t now = millis();
    if (now - cotTakLastAttempt < cotTakBackoff) return;
    cotTakLastAttempt = now;
    
    Serial.printf("[CoT-TCP] Connecting to %s:%d...\n", cotTakHost, cotTakPort);
    
    // Non-blocking connect with 3-second timeout
    if (cotTcpClient.connect(cotTakHost, cotTakPort, 3000)) {
        cotTakFailCount = 0;
        cotTakBackoff = COT_TAK_BACKOFF_MIN;
        Serial.printf("[CoT-TCP] Connected to %s:%d\n", cotTakHost, cotTakPort);
        uiState.dirty = true;
        
        // Send initial PLI immediately on connect
        cot_broadcastPLI();
    } else {
        cotTakFailCount++;
        // Exponential backoff: 5s → 10s → 20s → 40s → 60s (cap)
        cotTakBackoff = cotTakBackoff * 2;
        if (cotTakBackoff > COT_TAK_BACKOFF_MAX) cotTakBackoff = COT_TAK_BACKOFF_MAX;
        Serial.printf("[CoT-TCP] Connect failed (%d), retry in %lums\n", 
                      cotTakFailCount, cotTakBackoff);
    }
}

// CoT type strings for SA track sources
static const char* _cotTrackType(uint8_t src) {
    switch (src) {
        case TRACK_SRC_ADSB:     return "a-n-A-C-F";   // Neutral aircraft fixed-wing
        case TRACK_SRC_REMOTEID: return "a-u-A-M-H-Q";  // Unknown aircraft multirotor
        case TRACK_SRC_FPV:      return "a-h-A-M-H-Q";  // Hostile aircraft multirotor
        case TRACK_SRC_SENTINEL: return "a-u-S-X-i";    // Unknown sensor electronic
        default:                 return "a-u-G";         // Unknown ground
    }
}

// Generate ISO8601 timestamp from millis offset
static void _cotTimestamp(char* buf, size_t len, int offsetSec) {
#ifndef NO_GPS
    if (gps.date.isValid() && gps.date.year() > 2020) {
        // Use GPS time + offset
        uint32_t epoch = _getUtcEpoch() + offsetSec;
        // Simplified: just format with GPS date and offset seconds
        int hr = gps.time.hour(), mn = gps.time.minute(), sc = gps.time.second() + offsetSec;
        while (sc >= 60) { sc -= 60; mn++; }
        while (mn >= 60) { mn -= 60; hr++; }
        while (hr >= 24) { hr -= 24; }
        snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02dZ",
                 gps.date.year(), gps.date.month(), gps.date.day(), hr, mn, sc);
        return;
    }
#endif
    snprintf(buf, len, "2025-01-01T00:00:%02dZ", (int)(millis()/1000) % 60);
}

// Send CoT XML via WebSocket + UDP multicast + TCP TAK server
static void _cotSend(const char* cotXml) {
    int xmlLen = strlen(cotXml);
    
    // Path 1: WebSocket to GridDown PWA (JSON-wrapped) — always when enabled
    extern uint8_t wsClientCount;
    if (cotEnabled && wsClientCount > 0) {
        extern void broadcastAll(String& json);
        JsonDocument doc;
        doc["type"] = "cot_event";
        doc["xml"] = cotXml;
        String json;
        serializeJson(doc, json);
        broadcastAll(json);
    }
    
    // Path 2: UDP multicast to 239.2.3.1:6969 — Mcast or All mode
    if ((cotMode == COT_MODE_MCAST || cotMode == COT_MODE_ALL) &&
        cotUdpStarted && WiFi.getMode() != WIFI_OFF) {
        if (cotUdp.beginPacket(COT_MCAST_ADDR, COT_MCAST_PORT)) {
            cotUdp.write((const uint8_t*)cotXml, xmlLen);
            cotUdp.endPacket();
        }
    }
    
    // Path 3: TCP to TAK Server — TCP or All mode
    if ((cotMode == COT_MODE_TCP || cotMode == COT_MODE_ALL) &&
        cotTakConfigured && cotTcpClient.connected()) {
        size_t written = cotTcpClient.write((const uint8_t*)cotXml, xmlLen);
        if (written == (size_t)xmlLen) {
            uint8_t null_term = 0x00;
            cotTcpClient.write(&null_term, 1);
        } else {
            Serial.println("[CoT-TCP] Write failed, connection lost");
            cotTcpClient.stop();
        }
    }
}

void cot_broadcastPLI() {
    if (!cotEnabled) return;
    double lat, lon, alt;
    if (!ui_getGPS(&lat, &lon, &alt)) return;
    if (!ui_callsignSet()) return;
    
    char timeNow[32], timeStale[32];
    _cotTimestamp(timeNow, sizeof(timeNow), 0);
    _cotTimestamp(timeStale, sizeof(timeStale), 120);  // Stale in 2 min
    
    char xml[512];
    snprintf(xml, sizeof(xml),
        "<event version='2.0' uid='GridDown-%s' type='a-f-G-U-C' "
        "time='%s' start='%s' stale='%s' how='h-g-i-g-o'>"
        "<point lat='%.6f' lon='%.6f' hae='%.0f' ce='10' le='10'/>"
        "<detail><contact callsign='%s'/>"
        "<__group name='Cyan' role='Team Member'/>"
        "<precisionlocation geopointsrc='GPS'/>"
        "</detail></event>",
        ui_getCallsign(), timeNow, timeNow, timeStale,
        lat, lon, alt, ui_getCallsign());
    
    _cotSend(xml);
}

void cot_broadcastPeer(const char* callsign, double lat, double lon) {
    if (!cotEnabled || !callsign) return;
    if (lat == 0 && lon == 0) return;
    
    char timeNow[32], timeStale[32];
    _cotTimestamp(timeNow, sizeof(timeNow), 0);
    _cotTimestamp(timeStale, sizeof(timeStale), 120);
    
    char xml[512];
    snprintf(xml, sizeof(xml),
        "<event version='2.0' uid='GridDown-%s' type='a-f-G-U-C' "
        "time='%s' start='%s' stale='%s' how='m-g'>"
        "<point lat='%.6f' lon='%.6f' hae='0' ce='50' le='50'/>"
        "<detail><contact callsign='%s'/>"
        "<__group name='Cyan' role='Team Member'/>"
        "<remarks>Via GridDown mesh relay</remarks>"
        "</detail></event>",
        callsign, timeNow, timeNow, timeStale,
        lat, lon, callsign);
    
    _cotSend(xml);
}

void cot_broadcastTrack(const char* id, double lat, double lon, float alt, uint8_t src) {
    if (!cotEnabled || !id) return;
    if (lat == 0 && lon == 0) return;
    
    char timeNow[32], timeStale[32];
    _cotTimestamp(timeNow, sizeof(timeNow), 0);
    _cotTimestamp(timeStale, sizeof(timeStale), 60);  // Tracks stale faster (1 min)
    
    char xml[512];
    snprintf(xml, sizeof(xml),
        "<event version='2.0' uid='GD-Track-%s' type='%s' "
        "time='%s' start='%s' stale='%s' how='m-g'>"
        "<point lat='%.6f' lon='%.6f' hae='%.0f' ce='25' le='25'/>"
        "<detail><contact callsign='%s'/>"
        "<remarks>GridDown SA track src=%d</remarks>"
        "</detail></event>",
        id, _cotTrackType(src), timeNow, timeNow, timeStale,
        lat, lon, alt, id, src);
    
    _cotSend(xml);
}

void cot_broadcastDuress(const char* callsign, double lat, double lon) {
    if (!cotEnabled || !callsign) return;
    if (lat == 0 && lon == 0) return;
    
    char timeNow[32], timeStale[32];
    _cotTimestamp(timeNow, sizeof(timeNow), 0);
    _cotTimestamp(timeStale, sizeof(timeStale), 300);  // Duress stale after 5 min
    
    char xml[512];
    snprintf(xml, sizeof(xml),
        "<event version='2.0' uid='GD-Duress-%s' type='b-a-o-t-a' "
        "time='%s' start='%s' stale='%s' how='h-e'>"
        "<point lat='%.6f' lon='%.6f' hae='0' ce='50' le='50'/>"
        "<detail><contact callsign='%s'/>"
        "<remarks>DURESS — covert distress from %s</remarks>"
        "</detail></event>",
        callsign, timeNow, timeNow, timeStale,
        lat, lon, callsign, callsign);
    
    _cotSend(xml);
}

// ═══════════════════════════════════════════════════════════
// COT INBOUND LISTENER
// Receives CoT events from ATAK/TAK server and converts to GridDown
// data: peer positions, waypoints, and tracks.
// Listens on UDP multicast 239.2.3.1:6969 and TCP TAK server.
// ═══════════════════════════════════════════════════════════

static WiFiUDP cotRxUdp;
static bool    cotRxStarted = false;

// TCP inbound buffer (TAK server sends null-terminated events)
static char    cotTcpRxBuf[1024] = {0};
static int     cotTcpRxLen = 0;

// Rate limit inbound processing
static uint32_t cotRxLastProcess = 0;
#define COT_RX_INTERVAL_MS  200  // Max 5 inbound events/sec

// Simple XML attribute extractor: find attr='value' and copy value to buf
static bool _cotXmlAttr(const char* xml, const char* attr, char* buf, int bufLen) {
    // Search for attr=' or attr="
    char needle[32];
    snprintf(needle, sizeof(needle), "%s='", attr);
    const char* p = strstr(xml, needle);
    char delim = '\'';
    if (!p) {
        snprintf(needle, sizeof(needle), "%s=\"", attr);
        p = strstr(xml, needle);
        delim = '"';
    }
    if (!p) { buf[0] = '\0'; return false; }
    p += strlen(needle);
    const char* end = strchr(p, delim);
    if (!end) { buf[0] = '\0'; return false; }
    int len = end - p;
    if (len >= bufLen) len = bufLen - 1;
    memcpy(buf, p, len);
    buf[len] = '\0';
    return true;
}

// Process a single inbound CoT XML event
static void _cotProcessInbound(const char* xml) {
    // Must contain <event and <point
    if (!strstr(xml, "<event") || !strstr(xml, "<point")) return;
    
    // Extract key fields
    char uid[48] = {0}, type[32] = {0};
    char latStr[16] = {0}, lonStr[16] = {0}, altStr[16] = {0};
    char callsign[32] = {0};
    
    _cotXmlAttr(xml, "uid", uid, sizeof(uid));
    _cotXmlAttr(xml, "type", type, sizeof(type));
    
    if (strlen(uid) == 0 || strlen(type) == 0) return;
    
    // Filter out our own events (prevent echo loops)
    if (strncmp(uid, "GridDown-", 9) == 0) return;
    if (strncmp(uid, "GD-Track-", 9) == 0) return;
    if (strncmp(uid, "GD-Duress-", 10) == 0) return;
    
    // Extract point coordinates
    const char* pointTag = strstr(xml, "<point");
    if (!pointTag) return;
    // Scope attribute search to just the <point.../> tag (avoid matching event attrs)
    char pointBuf[256] = {0};
    const char* pointEnd = strstr(pointTag, "/>");
    if (!pointEnd) pointEnd = strstr(pointTag, ">");
    if (!pointEnd) return;
    int pointLen = pointEnd - pointTag + 2;
    if (pointLen >= (int)sizeof(pointBuf)) pointLen = sizeof(pointBuf) - 1;
    memcpy(pointBuf, pointTag, pointLen);
    pointBuf[pointLen] = '\0';
    
    _cotXmlAttr(pointBuf, "lat", latStr, sizeof(latStr));
    _cotXmlAttr(pointBuf, "lon", lonStr, sizeof(lonStr));
    _cotXmlAttr(pointBuf, "hae", altStr, sizeof(altStr));
    
    double lat = atof(latStr);
    double lon = atof(lonStr);
    float alt = atof(altStr);
    
    if (lat == 0 && lon == 0) return;  // No valid position
    
    // Extract callsign from <contact callsign='...'/>
    _cotXmlAttr(xml, "callsign", callsign, sizeof(callsign));
    if (strlen(callsign) == 0) {
        // Use uid as fallback callsign
        strncpy(callsign, uid, sizeof(callsign) - 1);
    }
    
    // ── Map CoT type to GridDown action ──
    
    // Friendly/hostile/unknown ground unit → peer position
    // Type format: a-{affil}-G-... (G = ground)
    if (type[0] == 'a' && type[1] == '-' && strlen(type) >= 5 && type[4] == 'G') {
        // Add/update as peer first (RSSI=0, SNR=0, hops=0 — from TAK not LoRa)
        ui_addPeer(callsign, 0, 0, 0);
        ui_updatePeerPosition(callsign, lat, lon);
        Serial.printf("[CoT-RX] Peer: %s at %.5f,%.5f\n", callsign, lat, lon);
        return;
    }
    
    // Aircraft types → track
    // a-{affil}-A-... (A = air)
    if (type[0] == 'a' && type[1] == '-' && strlen(type) >= 5 && type[4] == 'A') {
        // Map affiliation to track source
        uint8_t src = TRACK_SRC_UNKNOWN;
        if (type[2] == 'f' || type[2] == 'n') src = TRACK_SRC_ADSB;    // Friendly/neutral air = ADS-B
        else if (type[2] == 'h') src = TRACK_SRC_FPV;                    // Hostile air = FPV/drone
        else src = TRACK_SRC_REMOTEID;                                    // Unknown air = RemoteID
        track_update(callsign, lat, lon, alt, 0, 0, src);
        Serial.printf("[CoT-RX] Track: %s (%s) at %.5f,%.5f alt=%.0f\n", 
                      callsign, type, lat, lon, alt);
        return;
    }
    
    // Sensor/electronic → track as Sentinel
    // a-{affil}-S-... (S = sensor/space) or a-{affil}-X-... 
    if (type[0] == 'a' && type[1] == '-' && strlen(type) >= 5 && 
        (type[4] == 'S' || type[4] == 'X')) {
        track_update(callsign, lat, lon, alt, 0, 0, TRACK_SRC_SENTINEL);
        Serial.printf("[CoT-RX] Sensor: %s at %.5f,%.5f\n", callsign, lat, lon);
        return;
    }
    
    // Markers/waypoints: b-m-p-* (bits-marker-point)
    if (type[0] == 'b' && strncmp(type, "b-m-p", 5) == 0) {
        // Map marker subtypes to waypoint icons
        uint8_t icon = WP_ICON_GENERIC;
        if (strstr(type, "s-p-i")) icon = WP_ICON_GENERIC;       // Spot/point of interest
        else if (strstr(type, "w-r-d")) icon = WP_ICON_HAZARD;   // Route danger
        else if (strstr(type, "c-c-p")) icon = WP_ICON_CAMP;     // Checkpoint
        
        wp_add(callsign, lat, lon, icon, "TAK");
        
        // Notify on Tactical channel
        char msg[80];
        snprintf(msg, sizeof(msg), "TAK marker: %s at %.5f,%.5f", callsign, lat, lon);
        ui_addMessage("TAK", msg, false, false, GROUP_CH_TACTICAL);
        
        Serial.printf("[CoT-RX] Waypoint: %s at %.5f,%.5f icon=%d\n", callsign, lat, lon, icon);
        return;
    }
    
    // Any other positioned event → track as unknown
    if (lat != 0 || lon != 0) {
        track_update(uid, lat, lon, alt, 0, 0, TRACK_SRC_UNKNOWN);
        Serial.printf("[CoT-RX] Unknown: %s (%s) at %.5f,%.5f\n", uid, type, lat, lon);
    }
}

void cot_rxTick() {
    if (!cotEnabled) return;
    
    uint32_t now = millis();
    if (now - cotRxLastProcess < COT_RX_INTERVAL_MS) return;
    cotRxLastProcess = now;
    
    // ── Start multicast listener on first tick ──
    if (!cotRxStarted) {
        // Join multicast group for receiving
        // beginMulticast binds port + joins IGMP group
        IPAddress mcast(239, 2, 3, 1);
        if (cotRxUdp.beginMulticast(mcast, COT_MCAST_PORT)) {
            cotRxStarted = true;
            Serial.printf("[CoT-RX] Listening on 239.2.3.1:%d\n", COT_MCAST_PORT);
        }
    }
    
    // ── UDP multicast inbound ──
    if (cotRxStarted) {
        int pktSize = cotRxUdp.parsePacket();
        if (pktSize > 0 && pktSize < 1024) {
            char buf[1024];
            int len = cotRxUdp.read(buf, sizeof(buf) - 1);
            if (len > 0) {
                buf[len] = '\0';
                // Quick sanity: must look like CoT XML
                if (strstr(buf, "<event")) {
                    _cotProcessInbound(buf);
                }
            }
        }
    }
    
    // ── TCP TAK server inbound ──
    if (cotTakConfigured && cotTcpClient.connected()) {
        while (cotTcpClient.available() && cotTcpRxLen < (int)sizeof(cotTcpRxBuf) - 1) {
            char c = cotTcpClient.read();
            if (c == '\0') {
                // Null terminator = end of CoT event
                if (cotTcpRxLen > 0) {
                    cotTcpRxBuf[cotTcpRxLen] = '\0';
                    if (strstr(cotTcpRxBuf, "<event")) {
                        _cotProcessInbound(cotTcpRxBuf);
                    }
                    cotTcpRxLen = 0;
                }
            } else {
                cotTcpRxBuf[cotTcpRxLen++] = c;
            }
        }
        // Safety: if buffer full without null terminator, reset
        if (cotTcpRxLen >= (int)sizeof(cotTcpRxBuf) - 1) {
            Serial.println("[CoT-TCP] RX buffer overflow, resetting");
            cotTcpRxLen = 0;
        }
    }
}

// ═══════════════════════════════════════════════════════════
// INIT + TICK
// ═══════════════════════════════════════════════════════════

void ui_init() {
    // TFT — this also initializes the shared SPI bus
    tft.init();
    tft.setRotation(1);  // Landscape (320x240)
    tft.invertDisplay(true);  // T-Deck ST7789 requires inversion for correct colors
    scrW = tft.width();
    scrH = tft.height();
    
#ifdef TFT_BL
    // Set up PWM backlight for dim/bright/off control
    ledcSetup(BACKLIGHT_LEDC_CHANNEL, 5000, 8);  // 5kHz, 8-bit resolution
    ledcAttachPin(TFT_BL, BACKLIGHT_LEDC_CHANNEL);
    ledcWrite(BACKLIGHT_LEDC_CHANNEL, BACKLIGHT_FULL);
    backlightState = 2;
    lastActivityMs = millis();
    Serial.println("[UI] Backlight PWM initialized (dim:30s, off:60s)");
#endif
    
    tft.fillScreen(COLOR_BG);
    
    // Boot splash — branded
    tft.setTextColor(COLOR_GREEN);
    tft.setTextSize(2);
    tft.setCursor(scrW / 2 - 70, scrH / 2 - 30);
    tft.print("GridDown");
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(scrW / 2 - 50, scrH / 2 - 6);
    tft.print("Secure Messenger");
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(scrW / 2 - 48, scrH / 2 + 12);
    tft.printf("Firmware %s", GRIDDOWN_FW_VERSION);
    tft.setCursor(scrW / 2 - 46, scrH / 2 + 28);
    tft.print("BlackAtlas LLC");
    
    // Keyboard I2C
#ifndef NO_KEYBOARD
    Wire.begin(KB_SDA, KB_SCL);
    Serial.println("[UI] Keyboard I2C initialized");
    
    // Init touch controller (GT911 — pure I2C polling, no INT dependency)
    Wire.setClock(400000);  // GT911 needs 400kHz
    if (_touchInit()) {
        Serial.println("[UI] Touch ready (I2C polling)");
    } else {
        Serial.println("[UI] No touch controller — keyboard/trackball only");
    }
#endif

    // Trackball GPIOs
#ifdef TRACKBALL_UP
    pinMode(TRACKBALL_UP, INPUT_PULLUP);
    pinMode(TRACKBALL_DOWN, INPUT_PULLUP);
    pinMode(TRACKBALL_LEFT, INPUT_PULLUP);
    pinMode(TRACKBALL_RIGHT, INPUT_PULLUP);
    pinMode(TRACKBALL_CLICK, INPUT_PULLUP);
    Serial.println("[UI] Trackball initialized");
#endif
    
    // Audio notification
    _audioInit();
    
    // LittleFS for message persistence
    if (LittleFS.begin(true)) {
        _loadMessages();
        _loadCallsign();   // Load saved device identity
        _duressLoad();     // Load saved duress PIN
        _pskLoadKey();      // Load saved PSK encryption key
        _loadMute();        // Load saved audio mute state
        _loadChannel();     // Load saved radio channel
        _loadKeyboardBacklight();  // Load saved keyboard backlight
        _loadBrightness();          // Load saved brightness level
        _loadVoiceMode();           // Load saved voice quality mode
        wp_load();                  // Load saved tactical waypoints
        Serial.println("[UI] LittleFS ready");
    }
    
    // GPS — MUST be after LittleFS.begin() so /gpsbaud.cfg baud cache loads/saves.
    // Without LittleFS, GPS still works but auto-detects baud every boot (~2-7s).
    gps_init();
    
    // SD card for logging (messages, GPS tracks, packets, dead drop)
    sd_init();
    
    // Microphone (ES7210 ADC via I2S) — for future voice/walkie-talkie
    mic_init();  // Non-fatal: if ES7210 not present, voice features are disabled
    
    // Codec2 voice codec (1600 + 3200bps) — requires mic to be initialized
    if (micInitialized) {
        codec2_init();
        _voiceModeApply();  // Set active codec based on loaded voice mode
    }
    
    Serial.printf("[UI] Display: %dx%d\n", scrW, scrH);
    
    // Show splash for 1.5s then let first ui_tick draw the status screen.
    // The pre-clear fillScreen in ui_tick guarantees a clean framebuffer.
    delay(1500);
    uiState.dirty = true;
}

// ═══════════════════════════════════════════════════════════
// STARTUP CHANNEL SCAN — UI Drawing
// Called from main.cpp _startupChannelScan() which does the radio work.
// ═══════════════════════════════════════════════════════════

void ui_drawChannelScanProgress(int pct) {
    tft.fillScreen(COLOR_BG);
    tft.setTextColor(COLOR_TEXT);
    tft.setTextSize(2);
    tft.setCursor(30, 10);
    tft.print("Channel Scan");
    tft.setTextSize(1);
    tft.setTextColor(COLOR_DIM);
    tft.setCursor(30, 35);
    tft.print("Finding active channels...");
    int barW = (scrW - 60) * pct / 100;
    if (barW > 0) tft.fillRect(30, 50, barW, 4, COLOR_BTN_GREEN);
}

void ui_drawChannelScanResults(const ChScanResult* r, int activeCount, int bestCh) {
    tft.fillRect(0, 56, scrW, scrH - 56, COLOR_BG);
    int y = 62;
    for (int ch = 0; ch < 8; ch++) {
        float freq = 906.0f + ch * 2.5f;
        tft.setCursor(10, y);
        if (r[ch].active) {
            tft.setTextColor(COLOR_GREEN);
            tft.printf("CH%d (%.1f) ", ch + 1, freq);
            tft.setTextColor(COLOR_TEXT);
            tft.printf("ACTIVE CAD:%d RSSI:%.0f", r[ch].cadHits, r[ch].peakRSSI);
        } else {
            tft.setTextColor(COLOR_DIM);
            tft.printf("CH%d (%.1f)  quiet", ch + 1, freq);
        }
        y += 14;
    }
    y += 6;
    tft.setCursor(10, y);
    if (activeCount > 0) {
        tft.setTextColor(COLOR_GREEN);
        tft.printf("%d active", activeCount);
        if (bestCh > 0) {
            tft.setTextColor(COLOR_TEXT);
            tft.printf(" best:CH%d", bestCh);
        }
    } else {
        tft.setTextColor(COLOR_YELLOW);
        tft.print("No activity — you may be first");
    }
}

void ui_tick() {
    // Read GPS
    gps_tick();
    
    // Background acoustic monitoring (gunshot detection)
    gunshot_tick();
    cot_takTick();
    cot_rxTick();
    
    // Read keyboard
    char key = readKeyboard();
    if (key) {
        _handleInput(key);
    }
    
    // Read trackball
#ifdef TRACKBALL_UP
    char tbKey = _readTrackball();
    if (tbKey) {
        _handleInput(tbKey);
    }
#endif
    
    // Read touchscreen
#ifndef NO_KEYBOARD
    static bool wasTouched = false;
    static uint32_t lastTouchProcess = 0;
    static char lastTouchAction = 0;
    static uint32_t touchHoldStart = 0;
    static uint32_t lastRepeat = 0;
    static uint32_t lastTouchSeen = 0;
    
    // Drag-to-scroll state (messages screen)
    static bool isDragging = false;
    static int16_t dragStartY = 0;
    static int dragAccum = 0;           // Accumulated Y movement in pixels
    static const int DRAG_THRESHOLD = 12;  // Pixels to move before drag starts
    static const int SCROLL_STEP = 28;     // Pixels per scroll step (= one message line)
    
    bool touching = _touchRead();
    uint32_t now = millis();
    
    if (touching) lastTouchSeen = now;
    bool fingerDown = touching || (now - lastTouchSeen < 150);
    
    // Messages screen drag-to-scroll
    bool inMsgArea = (uiState.currentScreen == SCREEN_MESSAGES && 
                      touchY >= 26 && touchY < scrH - 36);
    
    if (fingerDown && !wasTouched && touching && (now - lastTouchProcess > 150)) {
        lastTouchProcess = now;
        
        if (inMsgArea) {
            // Start potential drag in message area
            dragStartY = touchY;
            dragAccum = 0;
            isDragging = false;
            wasTouched = true;
            lastTouchAction = 0;
        } else {
            // Normal button tap
            tft.fillCircle(touchX, touchY, 4, COLOR_ACCENT);
            char action = _checkTouch(touchX, touchY);
            if (action) {
                Serial.printf("[Touch] Hit action=%d at (%d,%d)\n", action, touchX, touchY);
                _handleInput(action);
                lastTouchAction = action;
                touchHoldStart = now;
                lastRepeat = now;
            }
            wasTouched = true;
            isDragging = false;
        }
    }
    else if (fingerDown && wasTouched && touching) {
        if (inMsgArea || isDragging) {
            // Track finger movement for drag scroll
            int16_t deltaY = dragStartY - touchY;  // Positive = finger moved up = show older
            
            if (!isDragging && abs(deltaY) > DRAG_THRESHOLD) {
                isDragging = true;
                dragAccum = 0;
            }
            
            if (isDragging) {
                dragAccum += (dragStartY - touchY);
                dragStartY = touchY;  // Reset reference point for continuous tracking
                
                // Scroll one step per SCROLL_STEP pixels of movement
                while (dragAccum >= SCROLL_STEP) {
                    dragAccum -= SCROLL_STEP;
                    _handleInput(TB_UP);  // Finger up = older messages
                }
                while (dragAccum <= -SCROLL_STEP) {
                    dragAccum += SCROLL_STEP;
                    _handleInput(TB_DOWN);  // Finger down = newer messages
                }
            }
        }
        else if (lastTouchAction != 0) {
            // Hold-to-repeat for Up/Dn buttons (not drag)
            bool isScroll = (lastTouchAction == TB_UP || lastTouchAction == TB_DOWN);
            if (isScroll) {
                uint32_t holdTime = now - touchHoldStart;
                uint32_t interval = holdTime > 1500 ? 100 : 200;
                if (holdTime > 350 && (now - lastRepeat > interval)) {
                    lastRepeat = now;
                    _handleInput(lastTouchAction);
                }
            }
        }
    }
    else if (!fingerDown && wasTouched) {
        // Finger lifted
        if (inMsgArea && !isDragging && (now - lastTouchProcess < 300)) {
            // Short tap on message area without dragging — could handle tap-to-select later
        }
        wasTouched = false;
        lastTouchAction = 0;
        isDragging = false;
        dragAccum = 0;
    }
#endif
    
    // Redraw if dirty (max 10fps to avoid flicker)
    // Exception: screen transitions always redraw immediately
    // Scan screen: force dirty every 300ms (live spectrum updates)
    static uint32_t lastDraw = 0;
    static Screen lastDrawnScreen = SCREEN_STATUS;
    bool screenChanged = (uiState.currentScreen != lastDrawnScreen);
    
    if (uiState.currentScreen == SCREEN_SCAN) {
        // Previously this forced a full repaint every 300 ms unconditionally.
        // _drawScanScreen() clears and repaints the whole screen, so a blind
        // 3.3 Hz repaint produced constant visible flicker — and it got worse as
        // the screen gained the Remote ID panel and a sixth button.
        //
        // Repaint when something actually CHANGED, plus a slow 1 s tick so the
        // elapsed-time readout still advances. Everything on this screen is
        // derived from these values, so if none has moved the pixels would be
        // identical and the repaint is pure flicker.
        static uint32_t lastScanRedraw = 0;
        static uint32_t lastSweeps = 0xFFFFFFFF;
        static int      lastDets = -1;
        static int      lastRid = -1;
        static uint8_t  lastSrc = 0xFF;
        static bool     lastHelp = false;
        static bool     lastBaseline = false;

        uint32_t sweeps = scan_getSweepCount();
        int      dets   = scan_getActiveDetections();
        uint8_t  src    = rid_getSource();
        int      ridN   = rid_sourceUsesRemoteId(src) ? rid_activeTrackCount(millis()) : 0;
        bool     bl     = scan_baselineAvailable();

        bool changed = (sweeps != lastSweeps) || (dets != lastDets) ||
                       (ridN != lastRid) || (src != lastSrc) ||
                       (scanHelpOverlay != lastHelp) || (bl != lastBaseline);

        // 1 s floor keeps the elapsed clock moving without repainting at 3.3 Hz.
        bool tick = (millis() - lastScanRedraw >= 1000);

        // While the help overlay is displayed, freeze the screen entirely. The
        // overlay is static text, and the scan running behind it would otherwise
        // keep forcing full repaints — each one redrawing the whole scan screen
        // and then the overlay over the top, so the screen underneath flashed
        // through. Only the transition into/out of the overlay needs a repaint.
        if (scanHelpOverlay && scanHelpOverlay == lastHelp) {
            changed = false;
            tick = false;
        }

        if (changed || tick) {
            lastScanRedraw = millis();
            lastSweeps = sweeps; lastDets = dets; lastRid = ridN;
            lastSrc = src; lastHelp = scanHelpOverlay; lastBaseline = bl;
            uiState.dirty = true;
        }
    }
    
    // Phase 7: Refresh Status and Images screens every 500ms while a TX is
    // active so the operator sees live progress and ETA.
    if ((uiState.currentScreen == SCREEN_STATUS || uiState.currentScreen == SCREEN_IMAGES)
        && img_isTxActive()) {
        static uint32_t lastImgRedraw = 0;
        if (millis() - lastImgRedraw >= 500) {
            lastImgRedraw = millis();
            uiState.dirty = true;
        }
    }
    
    if (uiState.dirty && (screenChanged || (millis() - lastDraw) > 200)) {
        lastDraw = millis();
        uiState.dirty = false;
        lastDrawnScreen = uiState.currentScreen;
        
        // Pre-clear: wipe the entire TFT framebuffer BEFORE any draw function
        // runs. On this ST7789/DMA hardware, fillScreen inside draw functions
        // can race with subsequent SPI draw commands, leaving stale pixels from
        // the previous screen visible. This dedicated pre-clear ensures the
        // DMA transfer completes before content draws begin.
        // EXCEPTION: Scan screen handles its own incremental drawing and shares
        // the SPI bus with the SX1262 radio — a large fillScreen DMA during
        // scan would corrupt RSSI reads via bus contention.
        bool settingsSubActive = (uiState.currentScreen == SCREEN_SETTINGS) &&
            (qrDisplayActive || wipeSelectMode || callsignEntryMode || pskEntryMode || duressEntryMode);
        
        if (uiState.currentScreen != SCREEN_SCAN) {
            tft.fillScreen(COLOR_BG);
        }
        
        // Skip base Settings draw when a sub-screen is active — the sub-screen
        // fully repaints. This eliminates the Settings→sub-screen flicker.
        // The pre-clear above still runs to handle DMA sequencing.
        switch (uiState.currentScreen) {
            case SCREEN_STATUS:       _drawStatusScreen(); break;
            case SCREEN_MESSAGES:     _drawMessagesScreen(); break;
            case SCREEN_COMPOSE:      _drawComposeScreen(); break;
            case SCREEN_MAP:          _drawMapScreen(); break;
            case SCREEN_VOICE:        _drawVoiceScreen(); break;
            case SCREEN_CONVERSATION: _drawConversationScreen(); break;
            case SCREEN_PEERS:        _drawPeersScreen(); break;
            case SCREEN_IMAGES:       _drawImagesScreen(); break;
            case SCREEN_DEBUG:        _drawDebugScreen(); break;
            case SCREEN_SETTINGS:     if (!settingsSubActive) _drawSettingsScreen(); break;
            case SCREEN_SCAN:         _drawScanScreen(); break;
            default:                  _drawStatusScreen(); break;
        }
        
        // Settings sub-screen overlays — paint OVER the base settings screen.
        // Same pattern as confirmModal/lockScreen: runs after the main draw,
        // completely overwrites the framebuffer. Proven to render cleanly on
        // this TFT/DMA hardware where in-function returns did not.
        if (uiState.currentScreen == SCREEN_SETTINGS) {
            if (qrDisplayActive)        _drawQRScreen();
            else if (wipeSelectMode)    _drawWipeScreen();
            else if (callsignEntryMode) _drawCallsignScreen();
            else if (pskEntryMode)      _drawPskScreen();
            else if (duressEntryMode)   _drawDuressScreen();
        }
        
        // Confirmation modal overlay
        if (confirmPending) {
            _drawConfirmModal();
        }
        
        // WiFi config prompt overlay (from tablet WebSocket push)
        if (wifiCfgPending) {
            _drawWifiConfigModal();
        }
        
        // Lock overlay takes precedence over everything
        if (screenLocked) {
            _drawLockScreen();
        }
        
        // Draw notification banner on top (if active, skip screens where it overlaps)
        // Voice screen: header pulse provides notification without overlapping RX status
        // Scan screen: has its own header with baseline indicator
        // Messages/Compose: user is already looking at messages
        if (notifyUntil > 0 && millis() < notifyUntil &&
            uiState.currentScreen != SCREEN_MESSAGES &&
            uiState.currentScreen != SCREEN_COMPOSE &&
            uiState.currentScreen != SCREEN_VOICE &&
            uiState.currentScreen != SCREEN_SCAN) {
            _drawNotifyBanner();
        }
    }
    
    // Auto-dismiss notification banner (trigger redraw to clear it)
    if (notifyUntil > 0 && millis() >= notifyUntil) {
        notifyUntil = 0;
        uiState.dirty = true;  // Redraw to clear banner
    }
    
    // Auto-dismiss header pulse (trigger redraw to restore normal header)
    if (headerPulseUntil > 0 && millis() >= headerPulseUntil) {
        headerPulseUntil = 0;
        uiState.dirty = true;  // Redraw to restore header color
    }
    
    // Display sleep disabled — brightness controlled by user via Settings B key
    
    // Compose cursor blink (draw only the cursor, not the whole screen)
    if (uiState.currentScreen == SCREEN_COMPOSE && backlightState > 0) {
        static uint32_t lastCursorToggle = 0;
        static bool cursorVisible = true;
        if (millis() - lastCursorToggle > 500) {
            lastCursorToggle = millis();
            cursorVisible = !cursorVisible;
            // Calculate cursor position
            int cx = 8, cy = 52;
            for (int i = 0; i < uiState.composeLen; i++) {
                if (cx > scrW - 16 || uiState.composeBuffer[i] == '\n') { cx = 8; cy += 12; }
                else cx += 6;
            }
            tft.fillRect(cx, cy, 6, 10, cursorVisible ? COLOR_ACCENT : COLOR_BG);
        }
    }
    
    // Periodic screen refresh (ages, signal quality — 15s is plenty)
    static uint32_t lastStatusRefresh = 0;
    if ((uiState.currentScreen == SCREEN_STATUS || uiState.currentScreen == SCREEN_MAP ||
         uiState.currentScreen == SCREEN_DEBUG) && 
        backlightState > 0 && millis() - lastStatusRefresh > 15000) {
        lastStatusRefresh = millis();
        uiState.dirty = true;
    }
    
    // Periodic GPS track logging to SD card
    sd_logGPS();
    
    // Age out peers not heard for 5 minutes
    static uint32_t lastPeerAge = 0;
    if (millis() - lastPeerAge > 30000) {
        lastPeerAge = millis();
        _peerAging();
        snf_expireOld();  // Also expire old store-forward messages
        track_expire();   // Expire stale SA tracks
    }
}
