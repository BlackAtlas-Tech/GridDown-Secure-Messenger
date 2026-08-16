// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * GridDown T-Deck Standalone UI
 * Display, keyboard, GPS, and local message storage.
 */
#pragma once
#include <Arduino.h>

// Firmware version
#define GRIDDOWN_FW_VERSION "6.70.0"

// Screen IDs
enum Screen {
    SCREEN_STATUS = 0,
    SCREEN_MESSAGES,
    SCREEN_COMPOSE,
    SCREEN_MAP,
    SCREEN_VOICE,
    SCREEN_CONVERSATION,
    SCREEN_PEERS,
    SCREEN_IMAGES,
    SCREEN_DEBUG,
    SCREEN_SETTINGS,
    SCREEN_SCAN
};

// ── 900MHz Drone Scanner ──
// Dual-mode detection: CAD (LoRa protocols) + RSSI (all protocols)
#define SCAN_MAX_CHANNELS  52   // Wideband 902-928 at 500kHz steps
#define SCAN_HISTORY_SWEEPS 10  // Debounce window (sweeps)

// Classification types
#define SCAN_CLASS_NONE       0
#define SCAN_CLASS_LORA_FHSS  1  // ELRS / Crossfire (CAD + multi-channel)
#define SCAN_CLASS_GFSK_FHSS  2  // SiK / RFD900 (RSSI only + multi-channel)
#define SCAN_CLASS_FIXED_LORA 3  // LoRaWAN gateway / Meshtastic (1-2 channels)
#define SCAN_CLASS_ISM_UNK    4  // Unknown ISM device
#define SCAN_CLASS_LORAWAN    5  // LoRaWAN / smart meter infrastructure (CAD in uplink/downlink zones only)

// Scan profiles
#define SCAN_PROFILE_QUICK_LORA  0  // CAD only, SF6/BW500, fastest
#define SCAN_PROFILE_ALL_DRONE   1  // CAD + RSSI + dual-BW, default
#define SCAN_PROFILE_FULL_SPEC   2  // RSSI only, wideband energy detection
#define SCAN_PROFILE_ELRS_DEEP   3  // CAD at SF5-8, catches all ELRS rates
#define SCAN_PROFILE_COUNT       4

struct ScanResult {
    float freq;           // Channel frequency (MHz)
    float rssi;           // Last RSSI reading (dBm, at BW500)
    float rssiNarrow;     // RSSI at BW125 (for dual-BW discrimination)
    float rssiPeak;       // Peak RSSI in current session
    uint8_t cadHits;      // CAD detections in last N sweeps
    uint8_t cadHitsLowSF; // CAD hits at SF5-6/BW500 (ELRS signature)
    uint8_t cadHitsHighSF;// CAD hits at SF7+/BW125 (LoRaWAN signature)
    uint8_t rssiHits;     // RSSI-above-threshold in last N sweeps
    bool active;          // Debounced: 3+ hits in last 10 sweeps
    bool isWideband;      // true if BW500 RSSI >> BW125 (LoRa signature)
    uint8_t infraCount;   // Sweeps this channel was active (for infra detection)
    bool infrastructure;  // Marked as infrastructure (persistent, dimmed)
    uint32_t lastTransientSweep;  // Sweep# when RSSI last exceeded threshold (for slow FHSS)
};

struct ScanDetection {
    uint8_t classification; // SCAN_CLASS_*
    float peakRSSI;         // Strongest signal
    float peakFreq;         // Frequency of strongest signal
    uint8_t channelCount;   // Channels in cluster
    uint32_t firstSeen;     // millis()
    uint32_t lastSeen;      // millis()
    bool valid;
    // Phase 4: RSSI trend tracking
    float rssiHistory[30];  // Ring buffer of peak RSSI per sweep
    uint8_t historyHead;    // Next write position
    uint8_t historyCount;   // Samples written (0-30)
    float trendSlope;       // dB/second (positive = approaching)
    // Hop-rate analysis (LoRa FHSS only)
    float hitRatio;         // Avg CAD hits/sweep across active channels (0.0-1.0)
    uint8_t rateCategory;   // 0=unknown, 1=LR(25Hz), 2=Mid(50Hz), 3=Prox(150Hz), 4=Race(250Hz+)
};

// Trend thresholds
#define SCAN_TREND_APPROACH   0.5f   // dB/s — signal getting stronger
#define SCAN_TREND_RECEDE    -0.5f   // dB/s — signal getting weaker

// Scanner control (implemented in main.cpp, uses radio directly)
void     scan_start();                        // Save radio config, enter scan mode
void     scan_tick();                         // Process one channel (call from loop)
void     scan_stop();                         // Restore radio config, exit scan mode
bool     scan_isActive();                     // Check if scanning
uint32_t scan_getSweepCount();                // Completed sweeps
uint32_t scan_getElapsedMs();                 // Time since scan started
int      scan_getChannelCount();              // Total channels in scan table
int      scan_getActiveDetections();          // Number of debounced active channels
const ScanResult* scan_getResults();          // Pointer to result array
const ScanDetection* scan_getDetections();    // Classified detections (max 4)
float    scan_getNoiseFloor();                // Current adaptive noise floor (dBm)
const char* scan_classLabel(uint8_t cls);     // Human-readable classification name
void     sd_logScanSession();                 // Log detections to SD card
float    scan_estimateRange(float rssi, float txPowerDbm); // FSPL range estimate (meters)
void     scan_setProfile(uint8_t profile);    // Set scan profile (0-3)
uint8_t  scan_getProfile();                   // Get current profile
const char* scan_profileName(uint8_t profile); // Human-readable profile name
void     scan_toggleInfra(int chIdx);         // Toggle infrastructure flag on channel

// Remote ID detection panel (rendered on the Scan screen)
void     ui_drawRemoteIdPanel(int y, int maxRows);

// Live progress during a blocking RF baseline capture (called from main.cpp)
void     ui_baselineProgressTick(uint8_t pct);

// RF Baseline — pre-recorded ambient environment for delta-based detection
void     scan_baselineCapture();              // Run dedicated baseline sweep (~30s), save to LittleFS
bool     scan_baselineLoad();                 // Load baseline from LittleFS (returns true if loaded)
void     scan_baselineClear();                // Delete saved baseline
bool     scan_baselineAvailable();            // Check if baseline is loaded for current scan session
uint8_t  scan_baselineProgress();             // Capture progress (0-100%)

// Group channels (logical channels within a PSK cluster)
#define GROUP_CH_COUNT 4
#define GROUP_CH_GENERAL  0
#define GROUP_CH_COMMAND  1
#define GROUP_CH_TACTICAL 2
#define GROUP_CH_ALERTS   3

// Message stored locally on the T-Deck
struct LocalMessage {
    char from[20];      // Sender fingerprint (truncated)
    char text[200];     // Message text
    uint32_t timestamp; // millis() when created
    bool outgoing;      // true = we sent, false = received
    bool encrypted;     // true = encrypted blob (needs GridDown to decrypt)
    bool delivered;     // true = ACK received (direct messages only)
    bool failed;        // true = retry exhausted, delivery failed
    uint16_t msgId;     // Unique ID for ACK matching (0 = no ACK needed)
    uint8_t channel;    // Group channel (0=General, 1=Command, 2=Tactical, 3=Alerts)
    uint8_t grpAckCount;  // Group broadcast: number of peers that ACKed
    uint8_t grpAckTotal;  // Group broadcast: number of active peers at send time
    uint16_t grpAckPeers; // Bitmask of which peers ACKed (supports up to 16 peers = MAX_PEERS)
};

// Contact entry
struct Contact {
    char name[32];
    char fingerprint[20];
    uint8_t unread;
};

// UI state
struct UIState {
    Screen currentScreen;
    int scrollOffset;
    int selectedIndex;
    char composeBuffer[200];
    int composeLen;
    int selectedContact;
    bool dirty;         // Needs redraw
    int unreadCount;    // Total unread messages
};

// Initialize display, keyboard, GPS
void ui_init();

// Main UI tick — call from loop()
void ui_tick();

// Push a message to the UI (from radio RX or WebSocket)
// channel: 0-3 = explicit channel, 0xFF = use active group channel
void ui_addMessage(const char* from, const char* text, bool outgoing, bool encrypted, uint8_t channel = 0xFF);

// Push a contact to the UI
void ui_addContact(const char* name, const char* fingerprint);

// Get the compose buffer (for sending via radio/WS)
const char* ui_getComposeText();
bool ui_hasComposedMessage();
void ui_clearCompose();

// Group channels
uint8_t  ui_getActiveGroupChannel();          // Current active channel (0-3)
void     ui_cycleGroupChannel();              // Cycle to next channel
void     ui_setActiveGroupChannel(uint8_t ch); // Set active channel
const char* ui_getGroupChannelName(uint8_t ch); // Get channel name

// Get GPS position (if available)
bool ui_getGPS(double* lat, double* lon, double* alt);
uint32_t ui_getUtcEpoch();                          // GPS-synced UTC epoch (0 = no GPS)

// Get UI state for status reporting
Screen ui_getCurrentScreen();
int ui_getMessageCount();
int ui_getContactCount();

// Display sleep/wake
void ui_wake();           // Reset inactivity timer, turn on display
void ui_setSleepTimeout(uint32_t dimMs, uint32_t offMs);

// Screen lock
bool ui_isLocked();           // Is screen locked?
void ui_setLocked(bool lock); // Set lock state

// Screen brightness
void ui_cycleBrightness();    // Cycle through brightness presets
uint8_t ui_getBrightnessLevel(); // Get current level (0-3)

// Audio notification
void ui_beep(int freqHz, int durationMs);
void ui_beepMessage();    // Short beep for incoming message
void ui_beepAlert();      // Longer beep for alerts/BREAK
void ui_rogerBeep();      // Two-tone roger beep after voice RX
void ui_beepDroneDetect(); // Rising chirp for new scanner detection

// Image transfer notification (called from main.cpp on RX completion)
void ui_imageReceived(const char* from, size_t bytes, bool savedToSD);

// Image viewer (Phase 5) — refresh list, prune old files
void images_onEnter();
void img_pruneOldest();
void ui_setMute(bool mute);  // Toggle audio on/off (persisted)
bool ui_isMuted();            // Is audio muted?

// Keyboard backlight (T-Deck ESP32-C3 keyboard controller)
void ui_setKeyboardBacklight(uint8_t brightness);  // 0=off, 1-255=brightness
bool ui_getKeyboardBacklight();                     // Is backlight on?
void ui_toggleKeyboardBacklight();                  // Toggle on/off

// Signal quality (called from main.cpp on RX)
void ui_updateSignal(float rssi, float snr, uint32_t rxCount, uint32_t txCount);

// RF diagnostics for channel/PSK mismatch detection
void ui_rfRawPacket();              // Call on every raw LoRa RX (even undecryptable)
void ui_rfDecryptFail();            // Call when PSK decrypt fails
uint32_t ui_rfLastRxAge();          // Seconds since last raw packet (0 = recent)
uint32_t ui_rfDecryptFailCount();   // Total decrypt failures since boot

// SD Card logging
void sd_init();                    // Initialize SD card on CS pin 39
bool sd_available();               // Is SD card mounted?
void sd_logMessage(const char* from, const char* text, bool outgoing, bool encrypted, uint8_t channel = 0);
void sd_logPacket(size_t len, float rssi, float snr, float freq, bool isTx);
void sd_logGPS();                  // Log current GPS position (call periodically)
int  sd_getMessageCount();         // Number of logged messages
int  sd_getPacketCount();          // Number of logged packets
int  sd_getTrackPoints();          // Number of GPS track points
void sd_exportDeadDrop(const char* to, const char* text);  // Export to outbox for physical transfer

// Boot diagnostics (crash log + boot counter)
void     boot_recordStartup();        // Call once in setup() — increments counter, logs reset reason
uint32_t boot_getCount();             // Total boot count since factory
const char* boot_getLastResetReason(); // Human-readable last reset reason string
void     sd_logBoot();                // Log boot event to SD card (called by boot_recordStartup)

// PSK AES-256-GCM encryption for standalone mode
void psk_setPassphrase(const char* passphrase);  // Derive AES key from passphrase
bool psk_isEnabled();                             // Is a passphrase set?
int  psk_encrypt(const uint8_t* plain, size_t plainLen, uint8_t* out, size_t outMax);
int  psk_decrypt(const uint8_t* cipher, size_t cipherLen, uint8_t* out, size_t outMax);
const char* psk_getPassphraseHint();              // First 4 chars for display

// Standalone identity & peer discovery
void        ui_setCallsign(const char* callsign);  // Set this device's name (persisted)
const char* ui_getCallsign();                       // Get callsign (empty = not set)
bool        ui_callsignSet();                       // Is callsign configured?
void        ui_addPeer(const char* callsign, float rssi, float snr, uint8_t hops);  // Add/update peer with link quality
int         ui_getPeerCount();                      // Number of discovered peers
const char* ui_getSelectedRecipient();              // Who compose is addressed to ("*"=broadcast)

// Channel selection (persisted)
void  ui_setChannel(int channel);     // Set channel 1-8 (each 2.5MHz apart)
int   ui_getChannel();                // Get current channel number
float ui_getChannelFreq();            // Get frequency for current channel

// Unread messages
int   ui_getUnreadCount();            // Number of unread messages
void  ui_clearUnread();               // Reset unread count (entering messages screen)

// ── Mesh Track Sharing ──
// Shared SA tracks distributed over LoRa mesh (AtlasRF, RemoteID, WiFi Sentinel)
#define TRACK_MAX 16           // Max simultaneous tracks
#define TRACK_EXPIRE_MS 120000 // Expire tracks after 2 minutes without update

// Track source types
#define TRACK_SRC_ADSB    0    // ADS-B aircraft (AtlasRF)
#define TRACK_SRC_REMOTEID 1   // FAA Remote ID drone
#define TRACK_SRC_SENTINEL 2   // WiFi Sentinel drone detection
#define TRACK_SRC_FPV     3    // FPV/analog drone
#define TRACK_SRC_UNKNOWN 4    // Unknown source

struct SharedTrack {
    char id[16];         // Track ID (callsign, tail number, MAC fragment)
    double lat, lon;     // Position
    float alt;           // Altitude (meters AGL or MSL depending on source)
    float hdg;           // Heading (degrees, 0=N)
    float spd;           // Speed (m/s)
    uint8_t src;         // Source type (TRACK_SRC_*)
    uint32_t lastUpdate; // millis() of last update
    bool valid;          // Slot in use
    bool alerted;        // true = proximity alert already fired for this track
    float prevAlt;       // Previous altitude (for climb/descend detection)
    // Trail history (last 8 positions for movement visualization)
    double trailLat[8], trailLon[8];
    uint8_t trailHead;   // Next write position (ring buffer)
    uint8_t trailCount;  // Positions recorded (0-8)
};

void         track_update(const char* id, double lat, double lon, float alt,
                          float hdg, float spd, uint8_t src); // Add or update a track
void         track_expire();                  // Remove stale tracks (call periodically)
int          track_getCount();                // Number of active tracks
bool         track_get(int index, SharedTrack* out);  // Get track by index
const char*  track_srcName(uint8_t src);      // Human-readable source name ("ADS-B", etc.)

// Threat proximity alerts — automatic warnings when tracks enter radius
#define PROXIMITY_DEFAULT_M  2000   // Default alert radius in meters
#define PROXIMITY_MIN_M      100    // Minimum configurable radius
#define PROXIMITY_MAX_M      10000  // Maximum configurable radius
#define PROXIMITY_COOLDOWN_MS 30000 // Re-alert cooldown per track (30s)

void     proximity_setRadius(uint32_t meters);  // Set alert radius
uint32_t proximity_getRadius();                 // Get current radius
void     proximity_setEnabled(bool on);         // Enable/disable alerts
bool     proximity_isEnabled();                 // Check if enabled

// ── Tactical Waypoint Sharing ──
// Named markers shared across the mesh, persisted to LittleFS.
#define WAYPOINT_MAX 16

// Waypoint icon types
#define WP_ICON_GENERIC  0  // Default marker
#define WP_ICON_RALLY    1  // Rally point
#define WP_ICON_HAZARD   2  // Danger/hazard
#define WP_ICON_LKP      3  // Last known position
#define WP_ICON_CAMP     4  // Camp/base
#define WP_ICON_WATER    5  // Water source

struct SharedWaypoint {
    char name[20];       // Waypoint name (e.g., "Rally Alpha")
    char creator[16];    // Callsign of creator
    double lat, lon;     // Position
    uint8_t icon;        // Icon type (WP_ICON_*)
    uint32_t createdAt;  // millis() when created locally
    bool valid;          // Slot in use
};

void         wp_add(const char* name, double lat, double lon, uint8_t icon, const char* creator);
void         wp_remove(int index);             // Remove by index
int          wp_getCount();                    // Number of active waypoints
bool         wp_get(int index, SharedWaypoint* out); // Get waypoint by index
void         wp_save();                        // Persist to LittleFS
void         wp_load();                        // Load from LittleFS
const char*  wp_iconName(uint8_t icon);        // Human-readable icon name

// ── Acoustic Gunshot Detection ──
// Background impulsive transient detector on the ES7210 microphone.
// Reads small I2S chunks during idle, detects amplitude spikes above
// adaptive noise floor. No ML — pure DSP threshold detection.
#define GD_COOLDOWN_MS     5000    // Minimum 5s between alerts
#define GD_CHUNK_SAMPLES   64      // ~4ms at 16kHz per tick read
#define GD_NOISE_ALPHA     0.02f   // Noise floor EMA smoothing (slow adaptation)

// Gunshot sensitivity levels: 0=OFF, 1=High, 2=Med, 3=Low
// Each level defines: threshold multiplier, absolute minimum, confirm hits, confirm window
#define GD_SENS_OFF   0
#define GD_SENS_HIGH  1
#define GD_SENS_MED   2
#define GD_SENS_LOW   3

uint8_t  gunshot_getSensitivity();
void     gunshot_setSensitivity(uint8_t level);  // 0=OFF, 1=Hi, 2=Med, 3=Lo
void     gunshot_cycleSensitivity();             // OFF→Hi→Med→Lo→OFF

void     gunshot_tick();                   // Call from main loop (reads I2S, runs detector)
void     gunshot_setEnabled(bool on);
bool     gunshot_isEnabled();
uint32_t gunshot_getDetectionCount();      // Total detections since boot

// ── Duress Code ──
// Hidden distress signal embedded in normal messages. If the operator types
// their 4-digit duress PIN anywhere in a compose message, the PIN is stripped
// from the visible text and a silent "duress":true flag is added to the JSON.
// Receiving nodes display the message normally but push a silent alert.
bool     duress_isSet();                       // Is a duress PIN configured?
void     duress_setPin(const char* pin);       // Set 4-digit PIN (persisted to LittleFS)
void     duress_clearPin();                    // Clear PIN
bool     duress_checkAndStrip(char* text);     // Check text for PIN, strip it, return true if found
const char* duress_getHint();                  // First 2 digits + "**" for display

// Message ACK system (direct messages only)
void     ui_markDelivered(uint16_t msgId);  // Mark a sent message as delivered
void     ui_markFailed(uint16_t msgId);     // Mark a sent message as failed (retries exhausted)
void     ui_markGroupAck(uint16_t msgId, const char* from);  // Record a group broadcast ACK from a peer
int      ui_getActivePeerCount();           // Number of active peers (for group ACK total)
void     ui_setGroupAckTotal(uint16_t msgId, uint8_t total); // Set peer count at send time

// Startup channel scan — UI drawing (called from main.cpp with scan results)
struct ChScanResult {
    int cadHits;
    float peakRSSI;
    bool active;
};
void     ui_drawChannelScanProgress(int pct);  // Draw progress bar (0-100%)
void     ui_drawChannelScanResults(const ChScanResult* results, int activeCount, int bestCh);

// WiFi mode management (defined in main.cpp, called from Settings UI)
#define WIFI_MODE_GD_AP   0
#define WIFI_MODE_GD_STA  1
#define WIFI_MODE_GD_OFF  2
void        wifi_setMode(uint8_t mode);
uint8_t     wifi_getMode();
bool        wifi_staIsConnected();
const char* wifi_getSTASSID();
const char* wifi_modeLabel(uint8_t mode);
void        wifi_setSTACredentials(const char* ssid, const char* pass);
void        wifi_clearSTACredentials();

// WiFi config prompt — tablet pushes credentials via WebSocket
void        ui_showWifiConfigPrompt(const char* ssid, const char* pass, bool switchNow, uint8_t wsClient);
uint16_t ui_getLastMsgId();                 // Get ID of last sent DM for retry
uint16_t ui_nextMsgId();                    // Allocate next unique message ID
void     ui_setLastMsgId(uint16_t id);      // Set msgId on the most recently added message

// Battery history (called from main loop via status update)
void     ui_recordBattery(uint8_t pct);     // Record a battery reading

// Peer position tracking (for map display)
void  ui_updatePeerPosition(const char* callsign, double lat, double lon);
void  ui_updatePeerBattery(const char* callsign, uint8_t bat);
bool  ui_getPeerPosition(int index, char* callsign, double* lat, double* lon, float* rssi, bool* active);

// Mesh relay — packet deduplication
bool  mesh_hasSeenPacket(uint16_t pktId, const char* from);  // Check + add to seen list
int   mesh_getRelayCount();                                   // Total packets relayed
void  mesh_incrementRelay();                                  // Count a relay

// ── CoT (Cursor-on-Target) Bridge ──
// CoT output modes
#define COT_MODE_OFF    0  // No CoT output
#define COT_MODE_MCAST  1  // UDP multicast 239.2.3.1:6969 + WebSocket + RX
#define COT_MODE_TCP    2  // TCP TAK server + WebSocket + RX (no multicast)
#define COT_MODE_ALL    3  // Multicast + TCP + WebSocket + RX

bool  cot_isEnabled();                            // Check if CoT bridge is active (mode > 0)
void  cot_setEnabled(bool on);                    // Toggle CoT bridge (backward compat)
void  cot_setMode(uint8_t mode);                  // Set CoT output mode (COT_MODE_*)
uint8_t cot_getMode();                            // Get current mode
void  cot_cycleMode();                            // OFF→MC→TCP→All→OFF (skips TCP/All if no server)
void  cot_broadcastPLI();                         // Broadcast own position (PLI)
void  cot_broadcastPeer(const char* callsign, double lat, double lon);  // Peer position
void  cot_broadcastTrack(const char* id, double lat, double lon, float alt, uint8_t src); // SA track
void  cot_broadcastDuress(const char* callsign, double lat, double lon); // Duress alert event

// TAK Server TCP client
void  cot_setTakServer(const char* host, uint16_t port);  // Configure TAK server
void  cot_clearTakServer();                                // Disconnect and clear config
bool  cot_takConnected();                                  // Check TCP connection status
void  cot_takTick();                                       // Connection manager (call from ui_tick)
const char* cot_getTakHost();                              // Current server host (empty if none)
uint16_t    cot_getTakPort();                              // Current server port

// Inbound CoT listener
void  cot_rxTick();                                        // Process incoming CoT (UDP mcast + TCP)

// ── Jamming Detection & Auto-Channel Migration ──
void  jam_tick();                         // Monitor noise floor, detect jamming (call from loop)
bool  jam_isJammed();                     // Is current channel jammed?
void  jam_migrateCountdown(int ch, int seconds);  // Start coordinated migration countdown

// Store and forward — hold messages for offline peers
void  snf_storeMessage(const uint8_t* pkt, int len, const char* targetCallsign, uint16_t msgId = 0);
int   snf_getStoredCount(const char* callsign);  // Messages queued for this peer
int   snf_deliverStored(const char* callsign, void (*sendFn)(const uint8_t*, int));  // Deliver + clear
void  snf_expireOld();                            // Remove messages older than 30 min

// ── Ephemeral Key Agreement (ECDH P-256) ──
void  eph_init();                                  // Generate P-256 keypair (call once at boot)
bool  eph_isReady();                               // true = keypair generated
const char* eph_getPublicKeyBase64();              // Base64 pubkey for beacons (88 chars)
void  eph_onPeerPublicKey(const char* callsign,    // Process peer's pubkey from beacon
                          const uint8_t* peerPub, size_t peerPubLen);
const uint8_t* eph_getSessionKey(const char* callsign);  // Per-pair key (NULL if none)
bool  eph_hasSessionKey(const char* callsign);     // true = E2E available for this peer

// ── Signed ACK (HMAC-SHA256 delivery confirmations) ──
bool  ack_sign(const char* acker, const char* sender, uint16_t msgId,
               char* sigB64Out, int maxLen);        // Sign ACK with session key → base64 tag
bool  ack_verify(const char* acker, const char* sender, uint16_t msgId,
                 const char* sigB64);               // Verify ACK signature (false = forged/no key)

// ── Remote Wipe (HMAC-SHA256 authenticated device erasure) ──
bool  wipe_sign(const char* issuer, const char* target, uint32_t epoch,
                char* sigB64Out, int maxLen);        // Sign wipe command → base64 tag
int   wipe_verify(const char* issuer, const char* target, uint32_t epoch,
                  const char* sigB64, uint32_t localEpoch);  // 0=valid, -1=no PSK, -2=bad sig, -3=expired
void  wipe_execute(const char* reason);              // Zeroize secrets, delete data, reboot

int   e2e_encrypt(const uint8_t* key, const uint8_t* plain, size_t plainLen,
                  uint8_t* out, size_t outMax);     // AES-256-GCM with session key
int   e2e_decrypt(const uint8_t* key, const uint8_t* cipher, size_t cipherLen,
                  uint8_t* out, size_t outMax);     // AES-256-GCM decrypt with session key

// ── Channel Schedule Rotation (Frequency Hopping) ──
void  fhop_tick();                                 // Call every loop() — hops when GPS time crosses 30s boundary
int   fhop_getCurrentChannel();                    // Current hop channel (1-8), or base channel if no GPS
bool  fhop_isActive();                             // true = GPS time valid, hopping enabled
float fhop_getCurrentFreq();                       // Current hop frequency in MHz

// Microphone (ES7210 ADC) — Phase 1 Audio Input Foundation
bool     mic_init();               // Initialize ES7210 + I2S RX (call once)
bool     mic_isReady();            // Is microphone initialized?
int      mic_record(int durationMs);  // Record audio (blocking, up to 1.5s)
void     mic_playback();           // Play recorded buffer through speaker
int16_t* mic_getBuffer();          // Get raw PCM buffer pointer
int      mic_getBufferLen();       // Number of samples in buffer
bool     mic_isRecording();        // Currently recording?

// Codec2 voice codec (1600bps) — Phase 2
bool     codec2_init();                    // Initialize codec (call after mic_init)
bool     codec2_isReady();                 // Is codec initialized?
int      codec2_encodeMicBuffer();         // Encode mic buffer → compressed frames
int      codec2_decodeToBuffer(const uint8_t* encoded, int numFrames);  // Decode frames → PCM
void     codec2_playDecoded();             // Play decoded PCM through speaker
const uint8_t* codec2_getEncodedBuf();     // Get encoded buffer pointer
int      codec2_getEncodedLen();           // Encoded data length in bytes
int      codec2_getEncodedFrames();        // Number of encoded frames

// Voice PTT — Push-to-Talk (Phase 3)
// Voice Quality Modes
// Range:    Codec2 1600bps + 2× redundancy (max reliability at distance)
// Balanced: Codec2 3200bps + 2× redundancy (best quality, high airtime)
// Clarity:  Codec2 3200bps + 1× single pass (clear voice, fast turnaround)
enum VoiceMode {
    VMODE_RANGE = 0,     // 1600 + 2× redundancy
    VMODE_BALANCED = 1,  // 3200 + 2× redundancy
    VMODE_CLARITY = 2    // 3200 + 1× single pass
};

VoiceMode ui_getVoiceMode();
void      ui_cycleVoiceMode();         // Cycle through modes (persisted)
bool      voice_useRedundancy();       // true for Range and Balanced
int       voice_getCodecBitrate();     // 1600 or 3200

// Voice Streaming PTT
#define VOICE_MARKER_1600 0xAF
#define VOICE_MARKER_3200 0xB0
#define VOICE_MARKER      VOICE_MARKER_1600  // Backward compat alias
#define VOICE_FRAMES_PER_PART 23
#define VOICE_MESH_MAX_HOPS 2
// Check if a byte is a voice packet marker (either mode)
static inline bool voice_isMarker(uint8_t b) { return b == VOICE_MARKER_1600 || b == VOICE_MARKER_3200; }

void     voice_streamStart();              // Begin streaming recording
void     voice_streamTick();               // Call from loop() — reads I2S, encodes parts
void     voice_streamStop();               // Stop streaming, encode final part
bool     voice_isStreaming();              // Currently streaming?
bool     voice_hasStreamPart();            // A stream part is ready for TX
const uint8_t* voice_getStreamPartBuf();   // Get stream part buffer
int      voice_getStreamPartLen();         // Get stream part length
void     voice_clearStreamPart();          // Clear after TX

// Voice Legacy Batch TX (for WS and loopback test)
int      voice_prepareTx();
bool     voice_hasTxPacket();
const uint8_t* voice_getTxBuf();
int      voice_getTxLen();
void     voice_advanceTx();
void     voice_rewindTx();             // Reset TX pointer for redundancy pass
void     voice_clearTx();
int      voice_getTxPartsTotal();
int      voice_getTxPartsSent();

// Voice common
void     voice_setTarget(const char* target);
const char* voice_getTarget();
bool     voice_handleRx(const uint8_t* data, int len, float rssi);
int      voice_encodeAndPackage(const uint8_t* b64pcm, int b64len);
String   voice_getDecodedB64();
bool     voice_isRxPending();            // True if assembling multi-part voice (suppress TX)
void     voice_checkRxTimeouts();        // Expire stale slots + UI feedback

// BLE status (for UI display)
extern bool bleClientConnected;
extern bool bleInitialized;

// Battery voltage (from main.cpp, for debug display)
extern float batVoltage;

// Radio activity timestamp (from main.cpp, for header activity dot)
extern uint32_t lastRadioActivity;
