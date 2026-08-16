// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * GridDown Secure Messenger — T-Deck LoRa Radio Firmware
 * 
 * Turns a LILYGO T-Deck CYPHER-M8K or T3-S3 into an encrypted
 * radio transport pipe for GridDown Secure Messenger.
 * 
 * The firmware is intentionally simple — a dumb pipe:
 *   - Receives byte arrays from GridDown via WiFi WebSocket
 *   - Transmits them over LoRa SX1262 at 915 MHz
 *   - Receives LoRa packets from the air
 *   - Forwards them to GridDown via WiFi WebSocket
 * 
 * NO encryption happens in firmware. GridDown handles all crypto.
 * NO routing logic. GridDown handles message addressing.
 * NO message parsing. Payloads are opaque byte arrays.
 * 
 * Protocol (WebSocket JSON):
 *   To radio:  {"type":"tx","data":"<base64>","priority":"normal"}
 *   From radio: {"type":"rx","data":"<base64>","rssi":-85,"snr":12.5,"freq":915.0}
 *   Status:    {"type":"status","battery":78,"radio":"idle","clients":1,
 *               "tx_count":42,"rx_count":18,"uptime":3600}
 *   Config:    {"type":"config","freq":915.0,"sf":10,"bw":125.0,"cr":5,"power":14}
 * 
 * License: Same as GridDown (GPL v3 non-commercial / commercial)
 * Copyright 2026 BlackAtlas LLC
 */

#include <Arduino.h>
#include <SPI.h>
#include <WiFi.h>
#include <ESPmDNS.h>
#include <WebSocketsServer.h>
#include <RadioLib.h>
#include <ArduinoJson.h>
#include <NimBLEDevice.h>
#include <LittleFS.h>
#include "ui.h"
#include "soc/rtc_cntl_reg.h"  // For bootloader mode via serial command
#include "esp_random.h"         // For beacon jitter (esp_random)
#include "esp_task_wdt.h"       // Task watchdog timer
#include "esp_system.h"         // esp_reset_reason()
#include "remoteid.h"            // Remote ID (ASTM F3411) drone detection
#include <esp_wifi.h>           // Promiscuous mode for Remote ID WiFi capture

// ── Remote ID: state and forward declarations hoisted here ──
// setup() and handleReceive() appear earlier in this file than the platform
// glue (which must sit after enqueuePacketPrio/cot_*/broadcastAll are defined),
// so these must be visible up front.
static RidRing ridRing;                    // Callback -> parse task handoff

// Duty cycle: 5 s scan window in every 20 s. The 5 s minimum is set by the
// F3411/DULT advertising interval (<=4 s) — a shorter window misses adverts.
#define RID_SCAN_WINDOW_MS   5000
#define RID_SCAN_PERIOD_MS   20000
#define RID_LORA_STALL_MS    120000

void     rid_tick(void);
void     rid_noteLoraRx(void);
void     rid_clearWatchdog(void);
bool     rid_isWatchdogTripped(void);
uint32_t rid_ringDroppedCount(void);
uint32_t rid_parsedCount(void);


// ---- Image transfer: hoist includes, the BULK inter-chunk delay, and the RX
//      handler declarations to the top of the translation unit. handleReceive(),
//      img_txTick(), and _img_rx_finalize() all appear earlier in this file than
//      the originals did, so they must see these symbols up here. The duplicate
//      #include "img_proto.h" further down is a no-op (header guard), and the
//      duplicate #define below is an identical redefinition (allowed). ----
#include "img_proto.h"
#include <SD.h>

#ifndef BULK_INTERCHUNK_DELAY_MS
#define BULK_INTERCHUNK_DELAY_MS 200
#endif

void img_handleHdr(const char* from, img_xfer_id_t xferId, const char* filename,
                   size_t totalSize, uint16_t totalChunks);
void img_handleChunk(const char* from, img_xfer_id_t xferId, uint16_t seq,
                     uint16_t chunkLen, uint16_t chunkCrc,
                     const uint8_t* chunkData, size_t chunkDataLen);
void img_handleDone(const char* from, img_xfer_id_t xferId, const uint8_t* fullHash);
int  img_handleNack(uint16_t xferId, const uint16_t* missing, uint16_t nMissing);
void img_handleAbort(const char* from, img_xfer_id_t xferId, int reason);

// ═══════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════

// WiFi defaults (can be overridden via WebSocket config command)
#define WIFI_AP_SSID      "GridDown-Radio"
// NOTE: there is intentionally no hardcoded default AP password. Every device
// generates its own random password on first boot and persists it to
// /appass.cfg (see _wifiLoadOrCreateApPass). A shipped constant would mean
// every unit in the field shares one publicly-known password protecting the
// WebSocket control channel.
#define WIFI_AP_PASS_FILE "/appass.cfg"
#define WIFI_AP_PASS_LEN  12
#define WIFI_AP_CHANNEL   6
#define WS_PORT           8770

// WiFi operating modes — defined in ui.h (WIFI_MODE_GD_AP, WIFI_MODE_GD_STA, WIFI_MODE_GD_OFF)

static uint8_t wifiModeGD = WIFI_MODE_GD_AP;  // Current mode
static char staSSID[33] = {0};                  // STA credentials
static char staPass[65] = {0};
static bool staConnected = false;
static uint32_t staLastAttempt = 0;
static uint32_t staRetryInterval = 10000;       // Start at 10s, backoff to 60s
static uint8_t staRetryCount = 0;

// LoRa defaults — 915 MHz ISM, SF10, BW125, CR4/5
// SF10/BW125 gives ~1.5 kbps, ~2-5 km LOS range
#define LORA_FREQ         915.0    // MHz (center of US ISM 902-928)
#define LORA_BW           125.0    // kHz bandwidth
#define LORA_SF           10       // Spreading factor (7-12)
#define LORA_CR           5        // Coding rate (5=4/5, 6=4/6, 7=4/7, 8=4/8)
#define LORA_SYNC_WORD    0x47     // 'G' for GridDown (private sync word)
#define LORA_POWER        14       // dBm (max 22, but 14 is plenty for most use)
#define LORA_PREAMBLE     8        // Preamble symbols
#define LORA_MAX_PAYLOAD  255      // Maximum packet size (bytes)

// Duty cycle: minimum ms between transmissions
#define TX_MIN_INTERVAL_MS  2000

// Mesh relay: max hop count for text packets (matches VOICE_MESH_MAX_HOPS)
#define TEXT_MESH_MAX_HOPS  4

// Status broadcast interval
#define STATUS_INTERVAL_MS  10000

// Battery ADC — split-iteration calibrated approach
// GPIO 4 = ADC1_CH3 on ESP32-S3 (works with WiFi active, unlike ADC2)
// Uses analogReadMilliVolts() for eFuse-calibrated accuracy, but spreads
// samples across multiple loop() iterations to avoid blocking.
#ifndef BAT_ADC
#define BAT_ADC 4
#endif
#define BAT_SAMPLES_TOTAL   16    // Total samples per measurement cycle
#define BAT_SAMPLES_PER_TICK 2    // Samples collected per loop() call

// ADC multiplier: compensates for voltage divider ratio AND uncalibrated eFuse.
// The T-Deck CYPHER M8K ESP32-S3 chips report "Default Vref: 0" (no eFuse cal data).
// analogReadMilliVolts() underreads by ~13.5% on these chips.
// Theoretical divider ratio is 2.0, corrected to 2.27 based on measured:
//   Fully charged 4.20V battery → ADC reads 3.70V → correction = 4.20/3.70 = 1.135
//   Effective multiplier = 2.0 × 1.135 = 2.27
// Can be overridden per-device via "!batcal X.XX" serial command (persisted to LittleFS).
#define BAT_ADC_MULTIPLIER_DEFAULT  2.27f
static float batAdcMultiplier = BAT_ADC_MULTIPLIER_DEFAULT;

// T-Deck peripheral power enable (GPIO10 — MUST be HIGH for radio/display/etc)
#ifndef BOARD_POWERON
#define BOARD_POWERON 10
#endif

// ═══════════════════════════════════════════════════════════
// HARDWARE SETUP
// ═══════════════════════════════════════════════════════════

// SX1262 via SPI — shares bus with TFT and SD card
// Use default SPI instance (same one TFT_eSPI uses) to avoid bus conflicts
SX1262 radio = new Module(LORA_CS, LORA_DIO1, LORA_RST, LORA_BUSY);

WebSocketsServer ws = WebSocketsServer(WS_PORT);

// ═══════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════

struct RadioState {
    float freq      = LORA_FREQ;
    float bw        = LORA_BW;
    uint8_t sf      = LORA_SF;
    uint8_t cr      = LORA_CR;
    int8_t power    = LORA_POWER;
    
    bool     rxMode     = false;
    bool     txBusy     = false;
    uint32_t txCount    = 0;
    uint32_t rxCount    = 0;
    uint32_t txErrors   = 0;
    uint32_t lastTxMs   = 0;
    float    lastRSSI   = 0;
    float    lastSNR    = 0;
    
    uint32_t bootTime   = 0;
    uint8_t  batteryPct = 0;
    bool     usbCharging = false;  // True when voltage > 4.25V (USB charge circuit driving ADC pin)
} state;

// TX queue (incoming from WebSocket, waiting for airtime)
// Priority levels (lower number = higher priority):
//   PRIO_HIGH (0)   — DMs, ACKs, voice, duress, emergency, wipe commands
//   PRIO_NORMAL (1) — Group broadcasts, beacons, waypoints, tracks, relay forwards
//   PRIO_BULK (2)   — Image chunks (Phase 2+) — preempted by everything above
#define PRIO_HIGH    0
#define PRIO_NORMAL  1
#define PRIO_BULK    2

struct TxPacket {
    uint8_t  data[LORA_MAX_PAYLOAD];
    size_t   len;
    uint8_t  priority;  // PRIO_HIGH / PRIO_NORMAL / PRIO_BULK
};

#define TX_QUEUE_SIZE 16
TxPacket txQueue[TX_QUEUE_SIZE];
uint8_t  txQueueHead = 0;
uint8_t  txQueueTail = 0;
uint8_t  txQueueCount = 0;

// RX buffer
volatile bool rxFlag = false;

// Connected WebSocket clients
uint8_t wsClientCount = 0;

// Jamming detection state (used by both RX handler and jam_tick)
static bool     jamMigrating = false;      // Migration countdown active
static int      jamMigrateTarget = 0;      // Target channel
static uint32_t jamMigrateTime = 0;        // millis() when switch happens
static uint32_t jamMigrateStarted = 0;     // When countdown started
#define JAM_MIGRATE_COUNTDOWN_S 5          // Seconds before coordinated switch

// Voice activity timestamp for jam suppression — set on every voice packet
// TX or RX. Declared here (before handleReceive) so it's visible everywhere.
uint32_t jamLastVoiceActivity = 0;

// ═══════════════════════════════════════════════════════════
// BLE — Nordic UART Service (NUS) for WiFi-free tablet connection
// Standard NUS UUIDs compatible with nRF Connect, Web Bluetooth, etc.
// ═══════════════════════════════════════════════════════════

#define NUS_SERVICE_UUID        "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define NUS_RX_CHARACTERISTIC   "6e400002-b5a3-f393-e0a9-e50e24dcca9e"  // Write (tablet→T-Deck)
#define NUS_TX_CHARACTERISTIC   "6e400003-b5a3-f393-e0a9-e50e24dcca9e"  // Notify (T-Deck→tablet)

static NimBLEServer* bleServer = nullptr;
static NimBLECharacteristic* bleTxChar = nullptr;
static NimBLECharacteristic* bleRxChar = nullptr;
bool bleClientConnected = false;
bool bleInitialized = false;

// BLE RX buffer for reassembling chunked JSON messages
static String bleRxBuffer;

// Forward declaration
void handleWSMessage(uint8_t clientNum, const char* payload, size_t length);

// BLE connection callbacks
class BLEServerCB : public NimBLEServerCallbacks {
    void onConnect(NimBLEServer* pServer) override {
        bleClientConnected = true;
        Serial.println("[BLE] Client connected");
        // Allow multiple connections (in case reconnect happens fast)
        NimBLEDevice::startAdvertising();
    }
    void onDisconnect(NimBLEServer* pServer) override {
        bleClientConnected = false;
        Serial.println("[BLE] Client disconnected");
        NimBLEDevice::startAdvertising();
    }
};

// BLE RX callback — data from tablet arrives here
class BLERxCB : public NimBLECharacteristicCallbacks {
    void onWrite(NimBLECharacteristic* pCharacteristic) override {
        std::string rxData = pCharacteristic->getValue();
        if (rxData.empty()) return;
        
        // Accumulate data (messages may span multiple BLE packets)
        bleRxBuffer += String(rxData.c_str());
        
        // Safety cap: prevent unbounded growth from malformed data (no newlines)
        if (bleRxBuffer.length() > 4096) {
            Serial.println("[BLE] RX buffer overflow, clearing");
            bleRxBuffer = "";
            return;
        }
        
        // Process complete JSON messages (newline-delimited)
        int nlPos;
        while ((nlPos = bleRxBuffer.indexOf('\n')) >= 0) {
            String msg = bleRxBuffer.substring(0, nlPos);
            bleRxBuffer.remove(0, nlPos + 1);
            
            if (msg.length() > 0) {
                Serial.printf("[BLE] RX: %d bytes\n", msg.length());
                // Route through same handler as WebSocket (clientNum=255 = BLE)
                handleWSMessage(255, msg.c_str(), msg.length());
            }
        }
    }
};

// Send JSON to BLE client via NUS TX characteristic (chunked if needed)
void bleBroadcast(const String& json) {
    if (!bleInitialized || !bleClientConnected || !bleTxChar) return;
    
    String msg = json + "\n";  // Newline delimiter for message framing
    const char* data = msg.c_str();
    int remaining = msg.length();
    int offset = 0;
    
    // BLE MTU limits chunk size (NimBLE negotiates up to 512, typical 244+)
    int mtu = NimBLEDevice::getMTU() - 3;  // -3 for ATT header
    if (mtu < 20) mtu = 20;
    
    while (remaining > 0) {
        int chunk = min(remaining, mtu);
        bleTxChar->setValue((const uint8_t*)(data + offset), chunk);
        bleTxChar->notify();
        offset += chunk;
        remaining -= chunk;
    }
}

// Initialize BLE NUS server
void bleInit() {
    // Build device name from callsign
    char bleName[32];
    if (ui_callsignSet()) {
        snprintf(bleName, sizeof(bleName), "GridDown-%s", ui_getCallsign());
    } else {
        snprintf(bleName, sizeof(bleName), "GridDown-Radio");
    }
    
    NimBLEDevice::init(bleName);
    NimBLEDevice::setMTU(517);  // Request max MTU (reduces chunking)
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);  // Max BLE TX power
    
    bleServer = NimBLEDevice::createServer();
    bleServer->setCallbacks(new BLEServerCB());
    
    // Create Nordic UART Service
    NimBLEService* pService = bleServer->createService(NUS_SERVICE_UUID);
    
    // TX characteristic: T-Deck → tablet (notify)
    bleTxChar = pService->createCharacteristic(
        NUS_TX_CHARACTERISTIC,
        NIMBLE_PROPERTY::NOTIFY
    );
    
    // RX characteristic: tablet → T-Deck (write)
    bleRxChar = pService->createCharacteristic(
        NUS_RX_CHARACTERISTIC,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );
    bleRxChar->setCallbacks(new BLERxCB());
    
    pService->start();
    
    // Advertise NUS service UUID so Web Bluetooth can filter for it
    NimBLEAdvertising* pAdv = NimBLEDevice::getAdvertising();
    pAdv->addServiceUUID(pService->getUUID());
    pAdv->setName(bleName);
    pAdv->start();
    
    bleInitialized = true;
    Serial.printf("[BLE] NUS server started: %s\n", bleName);
}

// Unified broadcast: sends to all WebSocket clients AND BLE client
void broadcastAll(String& json) {
    ws.broadcastTXT(json);
    bleBroadcast(json);
}

// Send to a specific client (WS or BLE)
void sendToClient(uint8_t clientNum, const String& json) {
    if (clientNum == 255) {
        bleBroadcast(json);  // BLE client
    } else {
        // WebSocketsServer::sendTXT takes String& (non-const) — safe cast, it doesn't modify
        ws.sendTXT(clientNum, const_cast<String&>(json));
    }
}

// DM retry state (file scope — accessed by both loop() and handleReceive())
static uint8_t retryBuf[LORA_MAX_PAYLOAD];
static int retryLen = 0;
static uint16_t retryMsgId = 0;
static uint32_t retryLastSend = 0;
static int retryCount = 0;
#define RETRY_INTERVAL_MS 5000  // 5s between retries
#define RETRY_MAX 3

// Forward declarations
void sendStatus(uint8_t clientNum);
void handleWSMessage(uint8_t clientNum, const char* payload, size_t length);
bool enqueuePacket(const uint8_t* data, size_t len, bool highPri);
bool enqueuePacketPrio(const uint8_t* data, size_t len, uint8_t priority);

// ═══════════════════════════════════════════════════════════
// ISR — LoRa receive interrupt
// ═══════════════════════════════════════════════════════════

void ICACHE_RAM_ATTR onLoRaRx() {
    rxFlag = true;
}

// ═══════════════════════════════════════════════════════════
// BASE64 — minimal encode/decode for firmware
// ═══════════════════════════════════════════════════════════

// Using a minimal inline base64 implementation to avoid external deps
static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

String b64Encode(const uint8_t* data, size_t len) {
    String out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = ((uint32_t)data[i]) << 16;
        if (i + 1 < len) n |= ((uint32_t)data[i + 1]) << 8;
        if (i + 2 < len) n |= data[i + 2];
        out += b64chars[(n >> 18) & 0x3F];
        out += b64chars[(n >> 12) & 0x3F];
        out += (i + 1 < len) ? b64chars[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? b64chars[n & 0x3F] : '=';
    }
    return out;
}

int b64Decode(const char* src, uint8_t* dst, size_t maxLen) {
    static const uint8_t d[] = {
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
         52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
        255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
        255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255
    };
    size_t len = strlen(src), out = 0;
    for (size_t i = 0; i < len && out < maxLen; i += 4) {
        uint32_t n = 0;
        int validChars = 0;
        for (int j = 0; j < 4 && (i + j) < len; j++) {
            uint8_t c = (uint8_t)src[i + j];
            if (c == '=') break;
            if (c >= 128 || d[c] == 255) return -1;
            n = (n << 6) | d[c];
            validChars++;
        }
        // Left-align: pad remaining positions so extraction at >>16, >>8 works
        n <<= (4 - validChars) * 6;
        if (out < maxLen && validChars >= 2) dst[out++] = (n >> 16) & 0xFF;
        if (out < maxLen && validChars >= 3) dst[out++] = (n >> 8) & 0xFF;
        if (out < maxLen && validChars >= 4) dst[out++] = n & 0xFF;
    }
    return out;
}

// ═══════════════════════════════════════════════════════════
// RADIO FUNCTIONS
// ═══════════════════════════════════════════════════════════

bool initRadio() {
    // SHARED SPI BUS: Radio (SX1262), TFT (ST7789), and SD card all share the
    // default VSPI bus. Thread safety relies on single-threaded Arduino loop() —
    // no FreeRTOS tasks access SPI concurrently. If multi-task access is ever
    // added (e.g., background SD logging), an SPI mutex will be required.
    //
    // TFT_eSPI initialized the SPI bus but only with MOSI+SCK (no MISO).
    // Radio needs MISO to read register responses. Re-init with all 3 pins.
    SPI.end();
    SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI);
    
    Serial.print("[Radio] Initializing SX1262... ");
    int err = radio.begin(state.freq, state.bw, state.sf, state.cr,
                          LORA_SYNC_WORD, state.power, LORA_PREAMBLE);
    if (err != RADIOLIB_ERR_NONE) {
        Serial.printf("FAILED (err %d)\n", err);
        return false;
    }
    
    // Configure for maximum sensitivity
    radio.setCurrentLimit(60.0);     // mA
    radio.setDio2AsRfSwitch(true);   // Required for most SX1262 modules
    radio.setCRC(true);              // Enable CRC checking
    
    // Set up receive interrupt
    radio.setDio1Action(onLoRaRx);
    
    Serial.printf("OK (%.1f MHz, SF%d, BW%.0f, CR4/%d, %ddBm)\n",
                  state.freq, state.sf, state.bw, state.cr, state.power);
    return true;
}

void startReceive() {
    if (state.txBusy) return;
    int err = radio.startReceive();
    if (err == RADIOLIB_ERR_NONE) {
        state.rxMode = true;
    }
}

void transmitPacket(const uint8_t* data, size_t len) {
    if (len > LORA_MAX_PAYLOAD) {
        Serial.println("[Radio] Packet too large, dropped");
        state.txErrors++;
        return;
    }
    
    state.txBusy = true;
    state.rxMode = false;
    
    // RadioLib 6.6.0 expects non-const pointer
    int err = radio.transmit(const_cast<uint8_t*>(data), len);
    
    if (err == RADIOLIB_ERR_NONE) {
        state.txCount++;
        state.lastTxMs = millis();
        lastRadioActivity = millis();
        Serial.printf("[Radio] TX %d bytes (total: %d)\n", len, state.txCount);
        sd_logPacket(len, 0, 0, state.freq, true);  // Log TX to SD
    } else {
        state.txErrors++;
        Serial.printf("[Radio] TX error: %d\n", err);
    }
    
    state.txBusy = false;
    startReceive();  // Return to receive mode
}

void handleReceive() {
    if (!rxFlag) return;
    rxFlag = false;
    rid_noteLoraRx();   // Evidence for the Remote ID starvation watchdog
    
    // Static to reduce stack pressure — handleReceive is called from single-threaded
    // loop() only, and these 510 bytes of local arrays compound with nested branch
    // arrays (relayPkt, enc, ackPkt, etc.) for ~1KB peak stack usage per call.
    static uint8_t buf[LORA_MAX_PAYLOAD];
    size_t len = 0;
    
    int err = radio.readData(buf, 0);
    if (err != RADIOLIB_ERR_NONE) {
        if (err != RADIOLIB_ERR_CRC_MISMATCH) {
            Serial.printf("[Radio] RX error: %d\n", err);
        }
        startReceive();
        return;
    }
    
    len = radio.getPacketLength();
    state.lastRSSI = radio.getRSSI();
    state.lastSNR  = radio.getSNR();
    state.rxCount++;
    lastRadioActivity = millis();
    
    // Update UI signal quality display
    ui_updateSignal(state.lastRSSI, state.lastSNR, state.rxCount, state.txCount);
    ui_rfRawPacket();  // Track last raw RX for mismatch detection
    ui_wake();  // Wake display on incoming packet
    
    Serial.printf("[Radio] RX %d bytes (RSSI: %.1f, SNR: %.1f)\n",
                  len, state.lastRSSI, state.lastSNR);
    
    // Log packet to SD card
    sd_logPacket(len, state.lastRSSI, state.lastSNR, state.freq, false);
    
    // Forward to all connected WebSocket clients
    String b64 = b64Encode(buf, len);
    
    JsonDocument doc;
    doc["type"]  = "rx";
    doc["data"]  = b64;
    doc["rssi"]  = state.lastRSSI;
    doc["snr"]   = state.lastSNR;
    doc["freq"]  = state.freq;
    doc["len"]   = len;
    doc["ts"]    = millis();
    
    String json;
    serializeJson(doc, json);
    broadcastAll(json);
    
    // Forward to standalone UI — parse and process received packets
    // Also handles: mesh relay, position tracking, store-and-forward delivery
    {
        // Decrypt or parse the packet
        static uint8_t decBuf[LORA_MAX_PAYLOAD];  // Static — safe in single-threaded loop()
        int decLen = 0;
        
        bool looksEncrypted = (len >= 30 && buf[0] == 0xAE);
        
        if (looksEncrypted && psk_isEnabled()) {
            int plainLen = psk_decrypt(buf + 1, len - 1, decBuf, sizeof(decBuf) - 1);
            if (plainLen > 0) {
                decBuf[plainLen] = '\0';
                decLen = plainLen;
            } else {
                Serial.printf("[PSK] Decrypt failed (len=%d, likely noise)\n", len);
                ui_rfDecryptFail();
                startReceive();
                return;
            }
        }
        else if (looksEncrypted && !psk_isEnabled()) {
            Serial.printf("[PSK] Encrypted packet, no PSK set (len=%d)\n", len);
            ui_rfDecryptFail();
            startReceive();
            return;
        }
        else {
            // Unencrypted — use raw buffer
            memcpy(decBuf, buf, len);
            decLen = len;
        }
        
        // ── VOICE PACKET CHECK (binary, not JSON) ──
        // Header: [0xAF/0xB0 | seq | total | msgId | hops | csLen | cs | toLen | to | frames]
        // 0xAF = Codec2 1600bps, 0xB0 = Codec2 3200bps
        if (decLen > 0 && voice_isMarker(decBuf[0])) {
            // Suppress jam detection during voice activity (RX side)
            jamLastVoiceActivity = millis();
            // Note: voice dedup is handled by voice_handleRx() via per-slot
            // received bitmask, NOT by mesh_hasSeenPacket(). Hash-based dedup
            // would kill the redundancy retransmit pass (identical bytes = same hash).
            
            // Voice packet part — reassemble and play when complete
            bool played = voice_handleRx(decBuf, decLen, state.lastRSSI);
            
            // Forward decoded PCM to WebSocket clients only when fully reassembled
            if (played && wsClientCount > 0) {
                // Parse callsign from new header: [0xAF|seq|tot|msgId|hops|csLen|cs|toLen|to|...]
                char wsFrom[16] = {0};
                char wsTo[16] = {0};
                if (decLen >= 7) {
                    uint8_t wsCsLen = decBuf[5];
                    if (wsCsLen > 0 && wsCsLen < 16 && 6 + wsCsLen < decLen) {
                        memcpy(wsFrom, &decBuf[6], wsCsLen);
                        int toOff = 6 + wsCsLen;
                        if (toOff < decLen) {
                            uint8_t wsToLen = decBuf[toOff];
                            if (wsToLen > 0 && wsToLen < 16 && toOff + 1 + wsToLen <= decLen)
                                memcpy(wsTo, &decBuf[toOff + 1], wsToLen);
                        }
                    }
                }
                
                String pcmB64 = voice_getDecodedB64();
                if (pcmB64.length() > 0) {
                    JsonDocument vDoc;
                    vDoc["type"] = "voice_rx";
                    vDoc["from"] = wsFrom;
                    if (wsTo[0]) vDoc["to"] = wsTo;
                    vDoc["data"] = pcmB64;
                    vDoc["rate"] = 8000;
                    vDoc["hops"] = (decLen >= 5) ? decBuf[4] : 0;
                    vDoc["rssi"] = state.lastRSSI;
                    vDoc["snr"] = state.lastSNR;
                    String vJson;
                    serializeJson(vDoc, vJson);
                    broadcastAll(vJson);
                }
            }
            
            // ── MESH VOICE RELAY (max 2 hops) ──
            // Read hop count from header byte 4
            uint8_t hops = (decLen >= 5) ? decBuf[4] : 0;
            
            // Don't relay our own voice packets (check callsign in header)
            bool isOwnVoice = false;
            if (decLen >= 8) {
                uint8_t rcsLen = decBuf[5];
                if (rcsLen > 0 && rcsLen < 16 && 6 + rcsLen < decLen) {
                    char relayFrom[16] = {0};
                    memcpy(relayFrom, &decBuf[6], rcsLen);
                    isOwnVoice = ui_callsignSet() && strcmp(relayFrom, ui_getCallsign()) == 0;
                }
            }
            
            if (!isOwnVoice && hops < VOICE_MESH_MAX_HOPS && !voice_isRxPending()) {
                // Increment hop count in decrypted payload
                decBuf[4] = hops + 1;
                
                // Re-encrypt (or package plaintext) with new hop count
                uint8_t relayPkt[LORA_MAX_PAYLOAD];
                int relayLen = 0;
                
                if (psk_isEnabled()) {
                    uint8_t enc[LORA_MAX_PAYLOAD];
                    int eLen = psk_encrypt(decBuf, decLen, enc, sizeof(enc));
                    if (eLen > 0) {
                        relayPkt[0] = 0xAE;
                        memcpy(relayPkt + 1, enc, eLen);
                        relayLen = eLen + 1;
                    }
                }
                if (relayLen == 0) {
                    // Plaintext relay
                    memcpy(relayPkt, decBuf, decLen);
                    relayLen = decLen;
                }
                
                // Cap relay queue for voice
                int relayInQueue = 0;
                for (int i = 0; i < txQueueCount; i++) {
                    int idx = (txQueueHead + i) % TX_QUEUE_SIZE;
                    if (txQueue[idx].priority != PRIO_HIGH) relayInQueue++;
                }
                if (relayInQueue < 8 && relayLen <= LORA_MAX_PAYLOAD) {
                    enqueuePacket(relayPkt, relayLen, false);
                    mesh_incrementRelay();
                    Serial.printf("[Mesh] Voice relay hop %d→%d (%d bytes)\n", 
                                  hops, hops + 1, relayLen);
                }
            } else if (isOwnVoice) {
                Serial.println("[Mesh] Own voice packet, not relaying");
            } else if (voice_isRxPending()) {
                Serial.println("[Mesh] Voice relay deferred — RX assembly in progress");
            } else {
                Serial.printf("[Mesh] Voice at max hops (%d), not relaying\n", hops);
            }
            
            startReceive();
            return;
        }
        
        // ── JSON PACKET PARSING ──
        char jsonBuf[256];
        int jsonLen = 0;
        
        if (decLen > 0 && decBuf[0] == '{') {
            memcpy(jsonBuf, decBuf, decLen);
            jsonBuf[decLen] = '\0';
            jsonLen = decLen;
        }
        else if (!looksEncrypted) {
            // Try base64 decode for legacy GridDown packets
            jsonLen = b64Decode(b64.c_str(), (uint8_t*)jsonBuf, 255);
            if (jsonLen > 0) jsonBuf[jsonLen] = '\0';
        }
        else {
            // Decrypted but not JSON and not voice — treat as JSON
            memcpy(jsonBuf, decBuf, min(decLen, 255));
            jsonBuf[min(decLen, 255)] = '\0';
            jsonLen = decLen;
        }
        
        if (jsonLen <= 0) { startReceive(); return; }
        
        // Parse JSON
        JsonDocument rxDoc;
        if (deserializeJson(rxDoc, jsonBuf, jsonLen)) { startReceive(); return; }
        
        const char* msgType = rxDoc["type"] | "";
        const char* from = rxDoc["from"] | "?";
        
        // Skip our own packets (heard via relay or echo)
        if (ui_callsignSet() && strcasecmp(from, ui_getCallsign()) == 0) {
            startReceive();
            return;
        }
        
        // ── MESH DEDUP ──
        // Hash from DECRYPTED immutable content fields (from + ts + type + text + id).
        // This is critical because the relay path re-encrypts with a fresh GCM
        // nonce, making raw bytes unique per relay. Hashing raw bytes would fail
        // to dedup the same message relayed by different nodes.
        // The "hops" and "ch" fields are excluded because they change on relay.
        // Uses djb2 hash (much better distribution than FNV-1a with 16-bit prime).
        uint32_t ts = rxDoc["ts"] | 0;
        uint32_t hashAcc = 5381;
        for (const char* p = from; *p; p++) hashAcc = ((hashAcc << 5) + hashAcc) ^ (uint8_t)*p;
        for (const char* p = msgType; *p; p++) hashAcc = ((hashAcc << 5) + hashAcc) ^ (uint8_t)*p;
        hashAcc = ((hashAcc << 5) + hashAcc) ^ (ts & 0xFF);
        hashAcc = ((hashAcc << 5) + hashAcc) ^ ((ts >> 8) & 0xFF);
        hashAcc = ((hashAcc << 5) + hashAcc) ^ ((ts >> 16) & 0xFF);
        hashAcc = ((hashAcc << 5) + hashAcc) ^ ((ts >> 24) & 0xFF);
        // Include text for smsg (two messages from same sender at same millis() are unlikely
        // but possible with canned replies — text distinguishes them)
        const char* textForHash = rxDoc["text"] | "";
        for (int i = 0; textForHash[i] && i < 32; i++) hashAcc = ((hashAcc << 5) + hashAcc) ^ (uint8_t)textForHash[i];
        // Include message ID for ACK dedup (ACKs have no ts/text but unique id)
        uint16_t msgIdForHash = rxDoc["id"] | 0;
        hashAcc = ((hashAcc << 5) + hashAcc) ^ (msgIdForHash & 0xFF);
        hashAcc = ((hashAcc << 5) + hashAcc) ^ ((msgIdForHash >> 8) & 0xFF);
        // Include waypoint name for waypoint dedup (text/id are empty for waypoints)
        const char* nameForHash = rxDoc["name"] | "";
        for (int i = 0; nameForHash[i] && i < 16; i++) hashAcc = ((hashAcc << 5) + hashAcc) ^ (uint8_t)nameForHash[i];
        // Fold 32-bit to 16-bit (XOR upper and lower halves)
        uint16_t pktHash = (uint16_t)((hashAcc >> 16) ^ (hashAcc & 0xFFFF));
        
        if (mesh_hasSeenPacket(pktHash, from)) {
            Serial.printf("[Mesh] Duplicate from %s (hash=%04X), dropped\n", from, pktHash);
            startReceive();
            return;
        }
        
        // ── PROCESS MESSAGE ──
        if (strcmp(msgType, "beacon") == 0) {
            ui_addPeer(from, state.lastRSSI, state.lastSNR, 0);  // Beacons are always direct
            // Update peer battery from beacon
            uint8_t peerBat = rxDoc["bat"] | 0;
            if (peerBat > 0) ui_updatePeerBattery(from, peerBat);
            // Update peer position from beacon GPS
            double bLat = rxDoc["lat"] | 0.0;
            double bLon = rxDoc["lon"] | 0.0;
            if (bLat != 0 || bLon != 0) {
                ui_updatePeerPosition(from, bLat, bLon);
                cot_broadcastPeer(from, bLat, bLon);  // Forward to TAK if CoT enabled
            }
            // Process ECDH public key for ephemeral key agreement
            const char* pkB64 = rxDoc["pk"] | (const char*)NULL;
            if (pkB64 && eph_isReady()) {
                uint8_t pkRaw[65];
                int pkLen = b64Decode(pkB64, pkRaw, sizeof(pkRaw));
                if (pkLen == 65 && pkRaw[0] == 0x04) {
                    eph_onPeerPublicKey(from, pkRaw, pkLen);
                }
            }
            // Deliver any store-and-forward messages for this peer
            int delivered = snf_deliverStored(from, [](const uint8_t* d, int l) {
                enqueuePacket(d, l, true);
            });
            if (delivered > 0) {
                Serial.printf("[S&F] Delivered %d stored messages to %s\n", delivered, from);
            }
        }
        else if (strcmp(msgType, "ack") == 0) {
            uint16_t ackId = rxDoc["id"] | 0;
            if (ackId != 0) {
                const char* sigB64 = rxDoc["sig"] | (const char*)NULL;
                bool verified = false;
                
                if (sigB64) {
                    // Signed ACK — verify HMAC before accepting
                    if (ack_verify(from, ui_getCallsign(), ackId, sigB64)) {
                        verified = true;
                        Serial.printf("[ACK] Verified signed ack id=%d from %s\n", ackId, from);
                    } else {
                        Serial.printf("[ACK] REJECTED — forged sig on ack id=%d from %s\n", ackId, from);
                    }
                } else {
                    // Unsigned ACK — accept for backward compat with pre-signing firmware
                    verified = true;
                    Serial.printf("[ACK] Unsigned ack id=%d from %s (no session key)\n", ackId, from);
                }
                
                if (verified) {
                    ui_markDelivered(ackId);
                    if (retryMsgId == ackId) {
                        retryMsgId = 0; retryLen = 0; retryCount = 0;
                    }
                }
            }
        }
        else if (strcmp(msgType, "grpack") == 0) {
            // Group broadcast ACK — lightweight, unsigned, not retried.
            // Sender records which peers confirmed receipt.
            const char* grpTo = rxDoc["to"] | "";
            uint16_t grpId = rxDoc["id"] | 0;
            if (grpId != 0 && ui_callsignSet() && strcasecmp(grpTo, ui_getCallsign()) == 0) {
                ui_markGroupAck(grpId, from);
                Serial.printf("[GRP-ACK] Received grpack id=%d from %s\n", grpId, from);
            }
        }
        else if (strcmp(msgType, "smsg") == 0) {
            const char* to = rxDoc["to"] | "*";
            const char* text = rxDoc["text"] | "";
            uint16_t rxMsgId = rxDoc["id"] | 0;
            uint8_t rxCh = rxDoc["ch"] | 0;  // Group channel (0=General for old firmware)
            
            // ── E2E inner decryption ──
            // If "e2e":1 flag is present, text is base64(AES-256-GCM(plaintext))
            // encrypted with the per-pair ECDH session key.
            static char e2ePlain[128];
            bool e2eDecrypted = false;
            int e2eFlag = rxDoc["e2e"] | 0;
            if (e2eFlag == 1 && strlen(text) > 0) {
                const uint8_t* sk = eph_getSessionKey(from);
                if (sk) {
                    uint8_t e2eCipher[128];
                    int e2eCipherLen = b64Decode(text, e2eCipher, sizeof(e2eCipher));
                    if (e2eCipherLen > 0) {
                        int plainLen = e2e_decrypt(sk, e2eCipher, e2eCipherLen,
                                                   (uint8_t*)e2ePlain, sizeof(e2ePlain) - 1);
                        if (plainLen > 0) {
                            e2ePlain[plainLen] = '\0';
                            text = e2ePlain;
                            e2eDecrypted = true;
                            Serial.printf("[E2E] DM from %s decrypted (%d chars)\n", from, plainLen);
                        } else {
                            Serial.printf("[E2E] Decrypt failed from %s (wrong session key?)\n", from);
                        }
                    }
                } else {
                    Serial.printf("[E2E] No session key for %s — displaying raw\n", from);
                }
            }
            
            bool forUs = (strcmp(to, "*") == 0) || 
                         (ui_callsignSet() && strcasecmp(to, ui_getCallsign()) == 0);
            
            if (forUs && strlen(text) > 0) {
                char label[32];
                if (strcmp(to, "*") == 0) {
                    snprintf(label, sizeof(label), "%s", from);
                } else {
                    snprintf(label, sizeof(label), "%s>%s", from, to);
                }
                ui_addMessage(label, text, false, e2eDecrypted, rxCh);
                ui_addPeer(from, state.lastRSSI, state.lastSNR, rxDoc["hops"] | 0);
                
                // ── DURESS CHECK: silent distress signal from sender ──
                bool isDuress = rxDoc["duress"] | false;
                if (isDuress) {
                    char duressAlert[128];
                    // Try to get sender's position from peer table
                    double sLat = 0, sLon = 0;
                    for (int p = 0; p < ui_getPeerCount(); p++) {
                        char cs[16]; double pLat, pLon; float pRssi; bool pActive;
                        ui_getPeerPosition(p, cs, &pLat, &pLon, &pRssi, &pActive);
                        if (strcasecmp(cs, from) == 0 && (pLat != 0 || pLon != 0)) {
                            sLat = pLat; sLon = pLon; break;
                        }
                    }
                    if (sLat != 0 || sLon != 0) {
                        snprintf(duressAlert, sizeof(duressAlert),
                                 "DURESS from %s [%.5f,%.5f] — covert distress", from, sLat, sLon);
                    } else {
                        snprintf(duressAlert, sizeof(duressAlert),
                                 "DURESS from %s — covert distress (no GPS)", from);
                    }
                    ui_addMessage("DURESS", duressAlert, false, false, GROUP_CH_ALERTS);
                    ui_beepAlert();
                    
                    // Forward to TAK as alert CoT event
                    if (cot_isEnabled() && (sLat != 0 || sLon != 0)) {
                        cot_broadcastDuress(from, sLat, sLon);
                    }
                    
                    Serial.printf("[DURESS] Alert from %s — covert distress signal received\n", from);
                }
                
                // Send ACK for direct messages
                // If E2E session key exists with the sender, sign the ACK with
                // HMAC-SHA256 to prove the real recipient received it (not just
                // any node with the group PSK).
                if (strcmp(to, "*") != 0 && rxMsgId != 0 && ui_callsignSet()) {
                    JsonDocument ackDoc;
                    ackDoc["type"] = "ack";
                    ackDoc["from"] = ui_getCallsign();
                    ackDoc["to"] = from;
                    ackDoc["id"] = rxMsgId;
                    
                    // Sign with per-pair session key (if available)
                    char sigB64[16];
                    if (ack_sign(ui_getCallsign(), from, rxMsgId, sigB64, sizeof(sigB64))) {
                        ackDoc["sig"] = sigB64;
                        Serial.printf("[ACK] Signed ack id=%d to %s\n", rxMsgId, from);
                    }
                    
                    String ackJson;
                    serializeJson(ackDoc, ackJson);
                    
                    uint8_t ackPkt[LORA_MAX_PAYLOAD];
                    int ackLen = 0;
                    if (psk_isEnabled()) {
                        uint8_t enc[LORA_MAX_PAYLOAD];
                        int eLen = psk_encrypt((const uint8_t*)ackJson.c_str(), ackJson.length(), enc, sizeof(enc));
                        if (eLen > 0) {
                            ackPkt[0] = 0xAE;
                            memcpy(ackPkt + 1, enc, eLen);
                            ackLen = eLen + 1;
                        }
                    }
                    if (ackLen == 0 && (int)ackJson.length() <= LORA_MAX_PAYLOAD) {
                        memcpy(ackPkt, ackJson.c_str(), ackJson.length());
                        ackLen = ackJson.length();
                    }
                    if (ackLen > 0) enqueuePacket(ackPkt, ackLen, true);
                }
                
                // Send lightweight ACK for group broadcast messages
                // Not signed (broadcast, no per-pair key needed), not retried.
                // Small packet: {"type":"grpack","from":"ME","to":"SENDER","id":123}
                if (strcmp(to, "*") == 0 && rxMsgId != 0 && ui_callsignSet()) {
                    JsonDocument grpDoc;
                    grpDoc["type"] = "grpack";
                    grpDoc["from"] = ui_getCallsign();
                    grpDoc["to"] = from;
                    grpDoc["id"] = rxMsgId;
                    
                    String grpJson;
                    serializeJson(grpDoc, grpJson);
                    
                    uint8_t grpPkt[LORA_MAX_PAYLOAD];
                    int grpLen = 0;
                    if (psk_isEnabled()) {
                        uint8_t enc[LORA_MAX_PAYLOAD];
                        int eLen = psk_encrypt((const uint8_t*)grpJson.c_str(), grpJson.length(), enc, sizeof(enc));
                        if (eLen > 0) {
                            grpPkt[0] = 0xAE;
                            memcpy(grpPkt + 1, enc, eLen);
                            grpLen = eLen + 1;
                        }
                    }
                    if (grpLen == 0 && (int)grpJson.length() <= LORA_MAX_PAYLOAD) {
                        memcpy(grpPkt, grpJson.c_str(), grpJson.length());
                        grpLen = grpJson.length();
                    }
                    // Delay slightly to avoid collision with other peers' ACKs
                    // Random 50-300ms jitter based on our callsign hash
                    uint32_t jitter = 50 + (esp_random() % 250);
                    delay(jitter);
                    if (grpLen > 0) enqueuePacket(grpPkt, grpLen, false);  // Low priority
                    Serial.printf("[GRP-ACK] Sent grpack id=%d to %s (jitter=%lums)\n", rxMsgId, from, jitter);
                }
            }
            else if (strcmp(to, "*") != 0 && !forUs) {
                // DM for someone else — check if they're offline, store-and-forward
                bool peerOnline = false;
                for (int i = 0; i < ui_getPeerCount(); i++) {
                    char cs[16]; double lat, lon; float rssi; bool active;
                    ui_getPeerPosition(i, cs, &lat, &lon, &rssi, &active);
                    if (strcasecmp(cs, to) == 0 && active) { peerOnline = true; break; }
                }
                if (!peerOnline) {
                    // Re-serialize and re-encrypt for storage (fresh GCM nonce,
                    // consistent hop count with relay path)
                    String snfJson;
                    serializeJson(rxDoc, snfJson);
                    uint8_t snfPkt[LORA_MAX_PAYLOAD];
                    int snfLen = 0;
                    if (psk_isEnabled()) {
                        uint8_t enc[LORA_MAX_PAYLOAD];
                        int eLen = psk_encrypt((const uint8_t*)snfJson.c_str(),
                                              snfJson.length(), enc, sizeof(enc));
                        if (eLen > 0) {
                            snfPkt[0] = 0xAE;
                            memcpy(snfPkt + 1, enc, eLen);
                            snfLen = eLen + 1;
                        }
                    }
                    if (snfLen == 0) {
                        if ((int)snfJson.length() <= LORA_MAX_PAYLOAD) {
                            memcpy(snfPkt, snfJson.c_str(), snfJson.length());
                            snfLen = snfJson.length();
                        }
                    }
                    if (snfLen > 0) {
                        snf_storeMessage(snfPkt, snfLen, to, rxMsgId);
                    }
                }
            }
        }
        else if (strcmp(msgType, "msg") == 0) {
            ui_addMessage(from, "[GridDown encrypted]", false, true);
        }
        else if (strcmp(msgType, "position") == 0) {
            char posText[64];
            double pLat = rxDoc["lat"] | 0.0;
            double pLon = rxDoc["lon"] | 0.0;
            snprintf(posText, sizeof(posText), "Pos: %.4f, %.4f", pLat, pLon);
            ui_addMessage(from, posText, false, false);
            ui_addPeer(from, state.lastRSSI, state.lastSNR, rxDoc["hops"] | 0);
            if (pLat != 0 || pLon != 0) ui_updatePeerPosition(from, pLat, pLon);
        }
        else if (strcmp(msgType, "break") == 0) {
            ui_addMessage("SYSTEM", "BREAK — Emergency freq active", false, false, GROUP_CH_ALERTS);
            ui_beepAlert();
        }
        else if (strcmp(msgType, "track") == 0) {
            // Shared SA track received via LoRa mesh
            const char* tid = rxDoc["id"] | "";
            double tlat = rxDoc["lat"] | 0.0;
            double tlon = rxDoc["lon"] | 0.0;
            float talt = rxDoc["alt"] | 0.0f;
            float thdg = rxDoc["hdg"] | 0.0f;
            float tspd = rxDoc["spd"] | 0.0f;
            uint8_t tsrc = rxDoc["src"] | TRACK_SRC_UNKNOWN;
            
            if (strlen(tid) > 0 && (tlat != 0 || tlon != 0)) {
                track_update(tid, tlat, tlon, talt, thdg, tspd, tsrc);
                cot_broadcastTrack(tid, tlat, tlon, talt, tsrc);  // Forward to TAK if CoT enabled
                
                // Forward to connected tablets via WS/BLE so PWA can render on full map
                JsonDocument fwd;
                fwd["type"] = "track_rx";
                fwd["from"] = from;
                fwd["id"] = tid;
                fwd["lat"] = tlat;
                fwd["lon"] = tlon;
                fwd["alt"] = talt;
                fwd["hdg"] = thdg;
                fwd["spd"] = tspd;
                fwd["src"] = tsrc;
                String fwdJson;
                serializeJson(fwd, fwdJson);
                broadcastAll(fwdJson);
            }
            // NOTE: Track packets are NOT mesh-relayed. The originating node
            // already broadcast it; re-relay would cause amplification storms
            // since tracks can update every few seconds.
        }
        else if (strcmp(msgType, "waypoint") == 0) {
            // Received a shared tactical waypoint
            const char* wpName = rxDoc["name"] | "";
            double wpLat = rxDoc["lat"] | 0.0;
            double wpLon = rxDoc["lon"] | 0.0;
            uint8_t wpIcon = rxDoc["icon"] | WP_ICON_GENERIC;
            
            if (strlen(wpName) > 0 && (wpLat != 0 || wpLon != 0)) {
                wp_add(wpName, wpLat, wpLon, wpIcon, from);
                
                // Notify user on Tactical channel
                char wpMsg[80];
                snprintf(wpMsg, sizeof(wpMsg), "WP: %s at %.5f,%.5f by %s",
                         wpName, wpLat, wpLon, from);
                ui_addMessage("MAP", wpMsg, false, false, GROUP_CH_TACTICAL);
                
                // Forward to connected tablets
                JsonDocument fwd;
                fwd["type"] = "waypoint_rx";
                fwd["from"] = from;
                fwd["name"] = wpName;
                fwd["lat"] = wpLat;
                fwd["lon"] = wpLon;
                fwd["icon"] = wpIcon;
                String fwdJson;
                serializeJson(fwd, fwdJson);
                broadcastAll(fwdJson);
            }
            // Waypoints relay via mesh (unlike tracks) — they're infrequent
            // and high-value. Relay exclusion is NOT applied.
        }
        
        // ── Image transfer: header (Phase 4 RX entry point) ──
        else if (strcmp(msgType, IMG_TYPE_HDR) == 0) {
            uint16_t xferId = rxDoc["id"] | 0;
            const char* fname = rxDoc["name"] | "image.jpg";
            uint32_t sz = rxDoc["size"] | 0;
            uint16_t chunks = rxDoc["chunks"] | 0;
            if (xferId != 0 && sz > 0) {
                img_handleHdr(from, xferId, fname, (size_t)sz, chunks);
            }
        }
        
        // ── Image transfer: chunk data ──
        else if (strcmp(msgType, IMG_TYPE_CHUNK) == 0) {
            uint16_t xferId = rxDoc["id"] | 0;
            uint16_t seq = rxDoc["seq"] | 0xFFFF;
            uint16_t chunkLen = rxDoc["len"] | 0;
            uint16_t chunkCrc = rxDoc["crc"] | 0;
            const char* dataB64 = rxDoc["d"] | "";
            if (xferId != 0 && seq != 0xFFFF && chunkLen > 0 && strlen(dataB64) > 0) {
                uint8_t binBuf[IMG_CHUNK_PAYLOAD_SIZE + 4];
                int decLen = b64Decode(dataB64, binBuf, sizeof(binBuf));
                if (decLen >= chunkLen) {
                    img_handleChunk(from, xferId, seq, chunkLen, chunkCrc, binBuf, decLen);
                }
            }
        }
        
        // ── Image transfer: done (sender finished, hash for verification) ──
        else if (strcmp(msgType, IMG_TYPE_DONE) == 0) {
            uint16_t xferId = rxDoc["id"] | 0;
            const char* hashHex = rxDoc["hash"] | "";
            if (xferId != 0 && strlen(hashHex) == 64) {
                uint8_t fullHash[32];
                bool valid = true;
                for (int i = 0; i < 32 && valid; i++) {
                    char hi = hashHex[i*2], lo = hashHex[i*2+1];
                    int hv = (hi >= '0' && hi <= '9') ? hi - '0' :
                             (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                             (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
                    int lv = (lo >= '0' && lo <= '9') ? lo - '0' :
                             (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                             (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
                    if (hv < 0 || lv < 0) { valid = false; break; }
                    fullHash[i] = (hv << 4) | lv;
                }
                if (valid) {
                    img_handleDone(from, xferId, fullHash);
                }
            }
        }
        
        // ── Image transfer: NACK from receiver requesting missing chunks ──
        else if (strcmp(msgType, IMG_TYPE_NACK) == 0) {
            uint16_t xferId = rxDoc["id"] | 0;
            JsonArray missArr = rxDoc["miss"];
            if (xferId != 0 && !missArr.isNull()) {
                uint16_t missing[16];
                uint16_t n = 0;
                for (JsonVariant v : missArr) {
                    if (n >= 16) break;
                    missing[n++] = (uint16_t)(v.as<int>());
                }
                if (n > 0) {
                    img_handleNack(xferId, missing, n);
                }
            }
        }
        
        // ── Image transfer: peer-initiated abort ──
        else if (strcmp(msgType, IMG_TYPE_ABORT) == 0) {
            uint16_t xferId = rxDoc["id"] | 0;
            int reason = rxDoc["reason"] | 0;
            img_handleAbort(from, xferId, reason);
        }
        
        // ── Channel migration command (from jam detection) ──
        else if (strcmp(msgType, "migrate") == 0) {
            int targetCh = rxDoc["ch"] | 0;
            int countdown = rxDoc["countdown"] | JAM_MIGRATE_COUNTDOWN_S;
            
            if (targetCh >= 1 && targetCh <= 8 && targetCh != ui_getChannel()) {
                // Only accept if we're not already migrating
                if (!jamMigrating) {
                    char migMsg[80];
                    snprintf(migMsg, sizeof(migMsg),
                             "%s: MIGRATE to CH%d in %ds (jam detected)",
                             from, targetCh, countdown);
                    ui_addMessage("JAM", migMsg, false, false, GROUP_CH_ALERTS);
                    ui_beepAlert();
                    
                    jam_migrateCountdown(targetCh, countdown);
                    Serial.printf("[JAM] Migration command from %s: CH%d in %ds\n",
                                  from, targetCh, countdown);
                }
            }
            // Migrate commands ARE relayed (critical for mesh-wide migration)
        }
        else if (strcmp(msgType, "wipe") == 0) {
            // ── REMOTE WIPE — authenticated device erasure ──
            // Requires: PSK (for wipe key derivation), valid HMAC signature.
            // If GPS time available: full 5-minute replay window enforced.
            // If no GPS: HMAC still verified, timestamp check bypassed.
            // Rationale: the wipe packet is PSK-encrypted on the wire — an attacker
            // who can replay it already has the PSK and could send their own wipe.
            // The replay window is defense-in-depth, not the primary auth.
            const char* target = rxDoc["to"] | "";
            uint32_t ts = rxDoc["ts"] | 0;
            const char* sig = rxDoc["sig"] | (const char*)NULL;
            
            if (ui_callsignSet() && strcasecmp(target, ui_getCallsign()) == 0) {
                uint32_t localEpoch = ui_getUtcEpoch();
                int result;
                if (localEpoch == 0) {
                    // No GPS — verify HMAC only, bypass timestamp window.
                    // Pass ts as localEpoch so drift = 0, window check passes.
                    result = wipe_verify(from, target, ts, sig, ts);
                    if (result == 0) {
                        Serial.printf("[WIPE] VERIFIED from %s (no GPS — replay protection reduced)\n", from);
                    }
                } else {
                    result = wipe_verify(from, target, ts, sig, localEpoch);
                    if (result == 0) {
                        Serial.printf("[WIPE] VERIFIED from %s (GPS-synced, full replay protection)\n", from);
                    }
                }
                
                if (result == 0) {
                    char reason[64];
                    snprintf(reason, sizeof(reason), "Remote wipe by %s", from);
                    wipe_execute(reason);
                    // wipe_execute does not return (reboots)
                } else {
                    Serial.printf("[WIPE] REJECTED from %s (code=%d)\n", from, result);
                }
            }
            // Wipe commands are NOT relayed (targeted, point-to-point)
        }
        
        // ── MESH RELAY ──
        // Rebroadcast for mesh forwarding with hop-count enforcement.
        // Skip: ACKs (point-to-point), beacons (direct-range discovery),
        // tracks (high-frequency updates, originator already broadcast).
        // Wipe commands are NOT relayed (targeted + authenticated).
        // Waypoints ARE relayed (infrequent, high-value).
        // Hop limit matches voice relay (TEXT_MESH_MAX_HOPS = 2).
        // Packets are re-serialized with incremented hops and re-encrypted
        // (new GCM nonce) to prevent replay and enforce hop tracking.
        bool relayable = (strcmp(msgType, "ack") != 0) && 
                         (strcmp(msgType, "grpack") != 0) &&
                         (strcmp(msgType, "beacon") != 0) &&
                         (strcmp(msgType, "track") != 0) &&
                         (strcmp(msgType, "wipe") != 0) &&
                         (strcmp(msgType, IMG_TYPE_HDR) != 0) &&
                         (strcmp(msgType, IMG_TYPE_CHUNK) != 0) &&
                         (strcmp(msgType, IMG_TYPE_DONE) != 0) &&
                         (strcmp(msgType, IMG_TYPE_NACK) != 0) &&
                         (strcmp(msgType, IMG_TYPE_ABORT) != 0) &&
                         (len <= LORA_MAX_PAYLOAD);
        
        // Read hop count (default 0 for backward compat with pre-hop firmware)
        int hops = rxDoc["hops"] | 0;
        
        if (relayable && hops < TEXT_MESH_MAX_HOPS) {
            // Cap: max 8 relay packets in queue at once (leaves room for user TX)
            int relayInQueue = 0;
            for (int i = 0; i < txQueueCount; i++) {
                int idx = (txQueueHead + i) % TX_QUEUE_SIZE;
                if (txQueue[idx].priority != PRIO_HIGH) relayInQueue++;
            }
            if (relayInQueue < 8) {
                // Increment hop count and re-serialize
                rxDoc["hops"] = hops + 1;
                String relayJson;
                serializeJson(rxDoc, relayJson);
                
                // Re-encrypt with fresh GCM nonce (or package plaintext)
                uint8_t relayPkt[LORA_MAX_PAYLOAD];
                int relayLen = 0;
                
                if (psk_isEnabled()) {
                    uint8_t enc[LORA_MAX_PAYLOAD];
                    int eLen = psk_encrypt((const uint8_t*)relayJson.c_str(), 
                                          relayJson.length(), enc, sizeof(enc));
                    if (eLen > 0) {
                        relayPkt[0] = 0xAE;
                        memcpy(relayPkt + 1, enc, eLen);
                        relayLen = eLen + 1;
                    }
                }
                if (relayLen == 0) {
                    // Plaintext relay
                    if ((int)relayJson.length() <= LORA_MAX_PAYLOAD) {
                        memcpy(relayPkt, relayJson.c_str(), relayJson.length());
                        relayLen = relayJson.length();
                    }
                }
                
                if (relayLen > 0) {
                    enqueuePacket(relayPkt, relayLen, false);
                    mesh_incrementRelay();
                    Serial.printf("[Mesh] Relaying %d bytes from %s hop %d→%d (total=%d)\n", 
                                  relayLen, from, hops, hops + 1, mesh_getRelayCount());
                }
            } else {
                Serial.printf("[Mesh] Relay queue full, skipping relay from %s\n", from);
            }
        } else if (relayable && hops >= TEXT_MESH_MAX_HOPS) {
            Serial.printf("[Mesh] Text at max hops (%d), not relaying from %s\n", hops, from);
        }
    }
    
    startReceive();
}

// ═══════════════════════════════════════════════════════════
// TX QUEUE
// ═══════════════════════════════════════════════════════════

// Backward-compatible enqueue: bool highPri → priority enum
bool enqueuePacket(const uint8_t* data, size_t len, bool highPri) {
    return enqueuePacketPrio(data, len, highPri ? PRIO_HIGH : PRIO_NORMAL);
}

// Three-tier priority enqueue. PRIO_BULK is for image chunks (Phase 2+).
bool enqueuePacketPrio(const uint8_t* data, size_t len, uint8_t priority) {
    if (len > LORA_MAX_PAYLOAD || len == 0) {
        Serial.printf("[Queue] Invalid packet len=%d, dropped\n", len);
        return false;
    }
    if (priority > PRIO_BULK) priority = PRIO_NORMAL;  // Defensive default
    if (txQueueCount >= TX_QUEUE_SIZE) {
        // If queue is full, BULK packets get dropped first to make room for higher priority
        if (priority == PRIO_BULK) {
            Serial.println("[Queue] Full, BULK packet dropped");
            return false;
        }
        // For HIGH/NORMAL: try to evict a BULK packet to make room
        for (int i = 0; i < txQueueCount; i++) {
            int idx = (txQueueHead + i) % TX_QUEUE_SIZE;
            if (txQueue[idx].priority == PRIO_BULK) {
                // Replace this BULK slot with the new packet (no shifting needed)
                memcpy(txQueue[idx].data, data, len);
                txQueue[idx].len = len;
                txQueue[idx].priority = priority;
                Serial.printf("[Queue] Full — evicted BULK to make room for prio %d\n", priority);
                return true;
            }
        }
        Serial.println("[Queue] Full, dropping packet");
        return false;
    }
    TxPacket& pkt = txQueue[txQueueTail];
    memcpy(pkt.data, data, len);
    pkt.len = len;
    pkt.priority = priority;
    txQueueTail = (txQueueTail + 1) % TX_QUEUE_SIZE;
    txQueueCount++;
    return true;
}

// Returns count of queued packets at or above the specified priority level.
// (Lower priority number = higher priority. So queueCountAbovePrio(PRIO_BULK)
//  returns how many HIGH+NORMAL packets are waiting.)
uint8_t queueCountAbovePrio(uint8_t threshold) {
    uint8_t n = 0;
    for (int i = 0; i < txQueueCount; i++) {
        int idx = (txQueueHead + i) % TX_QUEUE_SIZE;
        if (txQueue[idx].priority < threshold) n++;
    }
    return n;
}

// ═══════════════════════════════════════════════════════════
// IMAGE TRANSFER — Phase 3: TX state machine + encryption + retry
// ═══════════════════════════════════════════════════════════
// Sends a JPEG image as a sequence of LoRa chunks at PRIO_BULK priority.
// Each chunk is PSK-encrypted (group encryption). Receiver sends NACK with
// missing chunks; sender retransmits up to 3 retry rounds before aborting.
//
// Wire packets (all carry "type" field):
//   img_hdr    — start of transfer (id, total chunks, total bytes, hash, name)
//   img_chunk  — chunk data (id, seq, crc, len, data_b64)
//   img_done   — sender finished, hash for receiver to verify
//   img_nack   — receiver requesting missing chunks (id, list[16])
//   img_abort  — cancel (reason code)

#include "img_proto.h"
#include "mbedtls/sha256.h"

// TX states
typedef enum {
    IMG_TX_IDLE = 0,
    IMG_TX_HEADER,        // Sending img_hdr
    IMG_TX_CHUNKS,        // Streaming img_chunk packets
    IMG_TX_DONE_SENT,     // img_done sent, waiting for NACK or completion timeout
    IMG_TX_RETRY,         // Retransmitting missing chunks from a NACK
    IMG_TX_COMPLETE,      // Transfer succeeded
    IMG_TX_ABORTED        // Transfer failed/cancelled
} img_tx_state_t;

// TX context (singleton — only one outgoing image at a time)
struct ImageTxCtx {
    img_tx_state_t state;
    img_xfer_id_t  xferId;             // Random 16-bit ID for this transfer
    char           filename[IMG_FILENAME_MAX + 1];
    uint8_t*       data;               // Pointer to source bytes (PSRAM-allocated)
    size_t         dataLen;
    uint16_t       totalChunks;
    uint16_t       nextChunkIdx;       // Index of next chunk to transmit
    uint8_t        hash[32];           // SHA-256 of complete image
    
    // Retry state
    uint16_t       retryList[16];      // Chunk indices to retransmit (from NACK)
    uint16_t       retryCount;
    uint16_t       retryRound;         // Current retry pass (max 3)
    
    uint32_t       lastTxMs;           // Timestamp of last chunk emitted
    uint32_t       doneSentMs;         // Timestamp of img_done send
    uint32_t       lastProgressMs;     // For 60s overall timeout
};

static ImageTxCtx imgTx = { IMG_TX_IDLE };

// Forward decl
static bool _img_buildAndQueueHdr();
static bool _img_buildAndQueueChunk(uint16_t chunkIdx);
static bool _img_buildAndQueueDone();
static void _img_abort(img_abort_reason_t reason);
static bool _img_encryptAndSend(const String& jsonPayload);

// Compute SHA-256 of buffer
static void _img_sha256(const uint8_t* data, size_t len, uint8_t* outHash) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, outHash);
    mbedtls_sha256_free(&ctx);
}

// Base64 encoding (existing helper returns String)
// extern declared elsewhere in this file

// ── PUBLIC API ──

// Returns true if a transfer is currently in flight (not idle/complete/aborted)
bool img_isTxActive() {
    return imgTx.state != IMG_TX_IDLE &&
           imgTx.state != IMG_TX_COMPLETE &&
           imgTx.state != IMG_TX_ABORTED;
}

// Stub kept for backward compat with Phase 2 hooks. Preemption is handled
// implicitly by the queue scheduler — bulk packets only emit when nothing
// higher-priority is queued, so we don't need explicit pause/resume.
void img_pauseTx() {}
void img_resumeTx() {}

// Returns transfer progress as a percentage (0-100). 0 if idle.
uint8_t img_txProgress() {
    if (imgTx.state == IMG_TX_IDLE || imgTx.state == IMG_TX_ABORTED) return 0;
    if (imgTx.state == IMG_TX_COMPLETE) return 100;
    if (imgTx.totalChunks == 0) return 0;
    uint32_t pct = (imgTx.nextChunkIdx * 100UL) / imgTx.totalChunks;
    if (pct > 100) pct = 100;
    return (uint8_t)pct;
}

// ── Phase 7: UI accessors ──
// These let ui.cpp read TX state without dereferencing imgTx directly.

// Returns current chunk index (0-based) or 0 if not transmitting chunks.
uint16_t img_txCurrentChunk() {
    if (imgTx.state != IMG_TX_CHUNKS && imgTx.state != IMG_TX_RETRY) return 0;
    return imgTx.nextChunkIdx;
}

// Returns total chunks for the active transfer, or 0 if none.
uint16_t img_txTotalChunks() {
    if (!img_isTxActive()) return 0;
    return imgTx.totalChunks;
}

// Returns retry round (0 = first attempt, 1-3 = retries).
uint8_t img_txRetryRound() {
    if (!img_isTxActive()) return 0;
    return (uint8_t)imgTx.retryRound;
}

// Returns sender's display name for the current transfer (filename used here).
const char* img_txFilename() {
    if (!img_isTxActive()) return "";
    return imgTx.filename;
}

// Returns total payload size in bytes.
size_t img_txTotalBytes() {
    if (!img_isTxActive()) return 0;
    return imgTx.dataLen;
}

// Estimated seconds remaining based on chunk count × inter-chunk delay.
// Worst case (with NACK retry overhead): 2× the optimistic estimate.
uint16_t img_txEtaSeconds() {
    if (!img_isTxActive()) return 0;
    if (imgTx.state == IMG_TX_DONE_SENT) {
        // Waiting on possible NACK — up to 30s but usually completes quickly
        return 30;
    }
    if (imgTx.totalChunks == 0) return 0;
    
    uint32_t remaining;
    if (imgTx.state == IMG_TX_RETRY) {
        remaining = imgTx.retryCount > imgTx.nextChunkIdx
                    ? (imgTx.retryCount - imgTx.nextChunkIdx) : 0;
    } else {
        remaining = imgTx.totalChunks > imgTx.nextChunkIdx
                    ? (imgTx.totalChunks - imgTx.nextChunkIdx) : 0;
    }
    
    // Each chunk: ~200ms inter-chunk + ~50ms airtime = ~250ms
    // Add 1s tail for img_done + possible NACK round-trip
    uint32_t ms = remaining * 250 + 1000;
    return (uint16_t)((ms + 999) / 1000);
}

// Returns true if the TX state machine is in a state where the operator
// can cancel (active transfer, not already aborted/complete).
bool img_txCanCancel() {
    return img_isTxActive();
}

// Begin sending an image. data must remain valid until transfer completes.
// Returns false if another transfer is already active or data invalid.
bool img_beginTx(const uint8_t* data, size_t dataLen, const char* filename) {
    if (img_isTxActive()) {
        Serial.println("[ImgTx] Already active — reject new transfer");
        return false;
    }
    if (dataLen == 0 || dataLen > IMG_MAX_SIZE_BYTES) {
        Serial.printf("[ImgTx] Invalid size %d (max %d)\n", (int)dataLen, IMG_MAX_SIZE_BYTES);
        return false;
    }
    
    imgTx.data = (uint8_t*)data;
    imgTx.dataLen = dataLen;
    imgTx.totalChunks = img_chunk_count(dataLen);
    imgTx.xferId = (uint16_t)(esp_random() & 0xFFFF);
    if (imgTx.xferId == 0) imgTx.xferId = 1;  // 0 reserved
    
    strncpy(imgTx.filename, filename ? filename : "image.jpg", IMG_FILENAME_MAX);
    imgTx.filename[IMG_FILENAME_MAX] = '\0';
    
    _img_sha256(data, dataLen, imgTx.hash);
    
    imgTx.nextChunkIdx = 0;
    imgTx.retryCount = 0;
    imgTx.retryRound = 0;
    imgTx.lastTxMs = 0;
    imgTx.doneSentMs = 0;
    imgTx.lastProgressMs = millis();
    imgTx.state = IMG_TX_HEADER;
    
    Serial.printf("[ImgTx] Begin: id=%04X size=%d chunks=%d hash=%02x%02x%02x%02x...\n",
                  imgTx.xferId, (int)dataLen, imgTx.totalChunks,
                  imgTx.hash[0], imgTx.hash[1], imgTx.hash[2], imgTx.hash[3]);
    return true;
}

// ── On-device SD image send (no tablet/PWA required) ──
// Reads a JPEG from the SD card at `path`, validates it, and begins a LoRa
// transfer using the existing TX state machine. There is no JPEG ENCODER
// on-device (TJpgDec only decodes), so the T-Deck cannot compress: the file
// must already be <= IMG_MAX_SIZE_BYTES. Operators stage pre-sized images
// (~240x180, quality ~35) into /img_send/, or re-share a received image.
enum ImgSendResult {
    IMG_SEND_OK = 0,
    IMG_SEND_ERR_NO_SD,
    IMG_SEND_ERR_NOT_FOUND,
    IMG_SEND_ERR_EMPTY,
    IMG_SEND_ERR_TOO_LARGE,
    IMG_SEND_ERR_NOT_JPEG,
    IMG_SEND_ERR_BUSY,
    IMG_SEND_ERR_OOM,
    IMG_SEND_ERR_READ
};

static const char* img_sendResultStr(ImgSendResult r) {
    switch (r) {
        case IMG_SEND_OK:            return "ok";
        case IMG_SEND_ERR_NO_SD:     return "no SD card";
        case IMG_SEND_ERR_NOT_FOUND: return "file not found";
        case IMG_SEND_ERR_EMPTY:     return "empty file";
        case IMG_SEND_ERR_TOO_LARGE: return "too large (>8KB, pre-size the image)";
        case IMG_SEND_ERR_NOT_JPEG:  return "not a JPEG (missing SOI)";
        case IMG_SEND_ERR_BUSY:      return "transfer in progress";
        case IMG_SEND_ERR_OOM:       return "out of memory";
        case IMG_SEND_ERR_READ:      return "read error";
    }
    return "unknown";
}

ImgSendResult img_loadAndSendFromSD(const char* path) {
    extern bool sdCardMounted();
    if (!sdCardMounted())          return IMG_SEND_ERR_NO_SD;
    if (img_isTxActive())          return IMG_SEND_ERR_BUSY;
    if (!path || path[0] == '\0')  return IMG_SEND_ERR_NOT_FOUND;

    File f = SD.open(path, FILE_READ);
    if (!f)                        return IMG_SEND_ERR_NOT_FOUND;
    if (f.isDirectory()) { f.close(); return IMG_SEND_ERR_NOT_FOUND; }

    size_t fsize = f.size();
    if (fsize == 0)                 { f.close(); return IMG_SEND_ERR_EMPTY; }
    if (fsize > IMG_MAX_SIZE_BYTES) { f.close(); return IMG_SEND_ERR_TOO_LARGE; }

    // Persistent PSRAM buffer — must outlive the transfer (the TX state machine
    // reads from it for the entire duration). Allocated once, reused thereafter.
    static uint8_t* sdSendBuf = nullptr;
    if (!sdSendBuf) {
        sdSendBuf = (uint8_t*)heap_caps_malloc(IMG_MAX_SIZE_BYTES, MALLOC_CAP_SPIRAM);
        if (!sdSendBuf) sdSendBuf = (uint8_t*)malloc(IMG_MAX_SIZE_BYTES);
    }
    if (!sdSendBuf)                { f.close(); return IMG_SEND_ERR_OOM; }

    int readLen = f.read(sdSendBuf, fsize);
    f.close();
    if (readLen <= 0 || (size_t)readLen != fsize) return IMG_SEND_ERR_READ;

    if (readLen < 4 || sdSendBuf[0] != 0xFF || sdSendBuf[1] != 0xD8)
        return IMG_SEND_ERR_NOT_JPEG;

    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;

    if (!img_beginTx(sdSendBuf, (size_t)readLen, base)) return IMG_SEND_ERR_BUSY;

    Serial.printf("[ImgTx] SD send: %s (%d bytes, %d chunks, id=%04X)\n",
                  path, readLen, img_chunk_count(readLen), imgTx.xferId);
    return IMG_SEND_OK;
}

// Thin wrappers so ui.cpp can call the SD-send path without needing the
// ImgSendResult enum definition (kept private to this translation unit).
int img_loadAndSendFromSD_c(const char* path) {
    return (int)img_loadAndSendFromSD(path);
}
const char* img_sendResultStr_c(int r) {
    return img_sendResultStr((ImgSendResult)r);
}

// Cancel an in-progress transfer (operator action)
void img_cancelTx() {
    if (!img_isTxActive()) return;
    Serial.println("[ImgTx] User cancelled");
    _img_abort(IMG_ABORT_USER);
}

// Receive a NACK from a peer — list of chunk indices to retransmit.
// Caller passes parsed JSON values. Returns count of chunks queued for retry.
int img_handleNack(uint16_t xferId, const uint16_t* missing, uint16_t nMissing) {
    if (xferId != imgTx.xferId) return 0;
    if (imgTx.state != IMG_TX_DONE_SENT && imgTx.state != IMG_TX_RETRY) return 0;
    if (nMissing == 0 || nMissing > 16) return 0;
    
    if (imgTx.retryRound >= 3) {
        Serial.println("[ImgTx] Retry limit reached, aborting");
        _img_abort(IMG_ABORT_HASH_FAIL);
        return 0;
    }
    
    imgTx.retryCount = nMissing;
    for (uint16_t i = 0; i < nMissing; i++) imgTx.retryList[i] = missing[i];
    imgTx.retryRound++;
    imgTx.state = IMG_TX_RETRY;
    imgTx.nextChunkIdx = 0;  // Used as cursor into retryList[]
    imgTx.lastProgressMs = millis();
    
    Serial.printf("[ImgTx] NACK round %d: retransmitting %d chunks\n",
                  imgTx.retryRound, nMissing);
    return nMissing;
}

// Called from loop() — drives the TX state machine forward.
// Emits packets at the queue's BULK rate (200ms inter-chunk).
void img_txTick() {
    if (!img_isTxActive()) return;
    
    // Overall transfer timeout: 60s of no progress
    if (millis() - imgTx.lastProgressMs > 60000) {
        Serial.println("[ImgTx] Timeout — no progress for 60s");
        _img_abort(IMG_ABORT_TIMEOUT);
        return;
    }
    
    switch (imgTx.state) {
        case IMG_TX_HEADER:
            // Wait for queue space
            if (txQueueCount >= TX_QUEUE_SIZE - 2) return;
            // Throttle to BULK rate
            if (millis() - imgTx.lastTxMs < BULK_INTERCHUNK_DELAY_MS) return;
            if (_img_buildAndQueueHdr()) {
                imgTx.lastTxMs = millis();
                imgTx.lastProgressMs = millis();
                imgTx.state = IMG_TX_CHUNKS;
                imgTx.nextChunkIdx = 0;
            }
            break;
        
        case IMG_TX_CHUNKS:
            // Emit one chunk per tick (queue's BULK delay enforces airtime spacing)
            if (txQueueCount >= TX_QUEUE_SIZE - 2) return;
            // Yield to higher-priority traffic
            if (queueCountAbovePrio(PRIO_BULK) > 0) return;
            if (millis() - imgTx.lastTxMs < BULK_INTERCHUNK_DELAY_MS) return;
            
            if (imgTx.nextChunkIdx >= imgTx.totalChunks) {
                // All chunks sent — transition to img_done
                imgTx.state = IMG_TX_DONE_SENT;
                break;
            }
            if (_img_buildAndQueueChunk(imgTx.nextChunkIdx)) {
                imgTx.nextChunkIdx++;
                imgTx.lastTxMs = millis();
                imgTx.lastProgressMs = millis();
            }
            break;
        
        case IMG_TX_DONE_SENT:
            // Send img_done if not yet sent
            if (imgTx.doneSentMs == 0) {
                if (txQueueCount >= TX_QUEUE_SIZE - 1) return;
                if (millis() - imgTx.lastTxMs < BULK_INTERCHUNK_DELAY_MS) return;
                if (_img_buildAndQueueDone()) {
                    imgTx.doneSentMs = millis();
                    imgTx.lastTxMs = millis();
                    Serial.printf("[ImgTx] img_done sent, awaiting NACK or completion (round %d)\n",
                                  imgTx.retryRound);
                }
                return;
            }
            // Wait up to 30s for NACK
            if (millis() - imgTx.doneSentMs > 30000) {
                if (imgTx.retryRound >= 3) {
                    Serial.println("[ImgTx] Complete (no NACK after final round)");
                    imgTx.state = IMG_TX_COMPLETE;
                } else {
                    // No NACK arrived — assume successful delivery
                    Serial.println("[ImgTx] Complete (no NACK received)");
                    imgTx.state = IMG_TX_COMPLETE;
                }
            }
            break;
        
        case IMG_TX_RETRY:
            if (txQueueCount >= TX_QUEUE_SIZE - 2) return;
            if (queueCountAbovePrio(PRIO_BULK) > 0) return;
            if (millis() - imgTx.lastTxMs < BULK_INTERCHUNK_DELAY_MS) return;
            
            if (imgTx.nextChunkIdx >= imgTx.retryCount) {
                // Retry pass complete — send img_done again, await possible follow-up NACK
                imgTx.doneSentMs = 0;
                imgTx.state = IMG_TX_DONE_SENT;
                break;
            }
            {
                uint16_t chunkIdx = imgTx.retryList[imgTx.nextChunkIdx];
                if (_img_buildAndQueueChunk(chunkIdx)) {
                    imgTx.nextChunkIdx++;
                    imgTx.lastTxMs = millis();
                    imgTx.lastProgressMs = millis();
                }
            }
            break;
        
        case IMG_TX_COMPLETE:
        case IMG_TX_ABORTED:
        case IMG_TX_IDLE:
            break;
    }
}

// ── PACKET BUILDERS ──

static bool _img_buildAndQueueHdr() {
    JsonDocument doc;
    doc["type"] = IMG_TYPE_HDR;
    doc["from"] = ui_callsignSet() ? ui_getCallsign() : "RADIO";
    doc["id"] = imgTx.xferId;
    doc["name"] = imgTx.filename;
    doc["size"] = (uint32_t)imgTx.dataLen;
    doc["chunks"] = imgTx.totalChunks;
    
    // First 8 bytes of SHA-256 hash (hex string) — full hash sent with img_done
    char hashShort[17];
    snprintf(hashShort, sizeof(hashShort), "%02x%02x%02x%02x%02x%02x%02x%02x",
             imgTx.hash[0], imgTx.hash[1], imgTx.hash[2], imgTx.hash[3],
             imgTx.hash[4], imgTx.hash[5], imgTx.hash[6], imgTx.hash[7]);
    doc["hp"] = hashShort;  // hash prefix (for early dedup)
    
    String json;
    serializeJson(doc, json);
    return _img_encryptAndSend(json);
}

static bool _img_buildAndQueueChunk(uint16_t chunkIdx) {
    uint8_t chunkData[IMG_CHUNK_PAYLOAD_SIZE];
    uint16_t chunkLen = img_chunk_extract(imgTx.data, imgTx.dataLen, chunkIdx, chunkData);
    if (chunkLen == 0) return false;
    
    uint16_t crc = img_crc16(chunkData, chunkLen);
    
    // Base64-encode chunk data for JSON transport (180 bytes → 240 chars)
    String b64Str = b64Encode(chunkData, chunkLen);
    if (b64Str.length() == 0) return false;
    
    JsonDocument doc;
    doc["type"] = IMG_TYPE_CHUNK;
    doc["id"]   = imgTx.xferId;
    doc["seq"]  = chunkIdx;
    doc["len"]  = chunkLen;
    doc["crc"]  = crc;
    doc["d"]    = b64Str.c_str();
    
    String json;
    serializeJson(doc, json);
    return _img_encryptAndSend(json);
}

static bool _img_buildAndQueueDone() {
    JsonDocument doc;
    doc["type"] = IMG_TYPE_DONE;
    doc["id"]   = imgTx.xferId;
    
    char hashHex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(hashHex + i * 2, 3, "%02x", imgTx.hash[i]);
    }
    doc["hash"] = hashHex;
    
    String json;
    serializeJson(doc, json);
    return _img_encryptAndSend(json);
}

// Encrypt the JSON envelope with PSK-AES-256-GCM and enqueue at BULK priority.
static bool _img_encryptAndSend(const String& json) {
    if ((int)json.length() > LORA_MAX_PAYLOAD - 30) {
        Serial.printf("[ImgTx] Packet too large: %d bytes\n", json.length());
        return false;
    }
    
    uint8_t packet[LORA_MAX_PAYLOAD];
    int pktLen = 0;
    
    if (psk_isEnabled()) {
        uint8_t enc[LORA_MAX_PAYLOAD];
        int eLen = psk_encrypt((const uint8_t*)json.c_str(), json.length(), enc, sizeof(enc));
        if (eLen > 0) {
            packet[0] = 0xAE;
            memcpy(packet + 1, enc, eLen);
            pktLen = eLen + 1;
        }
    }
    if (pktLen == 0 && (int)json.length() <= LORA_MAX_PAYLOAD) {
        memcpy(packet, json.c_str(), json.length());
        pktLen = json.length();
    }
    if (pktLen == 0) return false;
    
    return enqueuePacketPrio(packet, pktLen, PRIO_BULK);
}

// Send img_abort packet then transition to ABORTED state
static void _img_abort(img_abort_reason_t reason) {
    JsonDocument doc;
    doc["type"]   = IMG_TYPE_ABORT;
    doc["id"]     = imgTx.xferId;
    doc["reason"] = (int)reason;
    String json;
    serializeJson(doc, json);
    _img_encryptAndSend(json);  // Best-effort — may not get queued if full
    
    Serial.printf("[ImgTx] Aborted: reason=%d\n", reason);
    imgTx.state = IMG_TX_ABORTED;
    imgTx.data = nullptr;  // Caller is responsible for the buffer
}

// ═══════════════════════════════════════════════════════════
// IMAGE RECEIVER — Phase 4: reassembly + SD storage + UI notify
// ═══════════════════════════════════════════════════════════
// Each radio that hears an img_hdr allocates a PSRAM reassembly buffer.
// Up to 2 concurrent transfers from different senders supported.
// On img_done: verify SHA-256, save to /img_recv/<sender>_<timestamp>.jpg,
// notify operator. On incomplete: send NACK with missing chunks.

#define IMG_RX_MAX_SLOTS 2  // PSRAM pressure cap
#define IMG_RX_TIMEOUT_MS 60000

typedef enum {
    IMG_RX_SLOT_FREE = 0,
    IMG_RX_SLOT_RECEIVING,    // Got hdr, collecting chunks
    IMG_RX_SLOT_AWAIT_DONE,   // Got hdr + all chunks, waiting for done
    IMG_RX_SLOT_NACK_SENT,    // Sent NACK, awaiting retransmits
} img_rx_slot_state_t;

struct ImageRxSlot {
    img_rx_slot_state_t state;
    img_xfer_id_t       xferId;
    char                fromCallsign[16];
    char                filename[IMG_FILENAME_MAX + 1];
    uint8_t*            buffer;          // PSRAM-allocated, freed on completion/abort
    size_t              bufferSize;
    uint16_t            totalChunks;
    uint8_t             recvBitmap[IMG_BITMAP_BYTES];
    uint8_t             expectedHash[32];  // From img_done
    bool                hasFullHash;       // True after img_done received
    uint32_t            lastActivityMs;    // For 60s timeout
    uint32_t            createdMs;
};

static ImageRxSlot imgRxSlots[IMG_RX_MAX_SLOTS] = {};

// Forward decls
static void _img_rx_freeSlot(ImageRxSlot* slot);
static void _img_rx_sendNack(ImageRxSlot* slot);
static void _img_rx_finalize(ImageRxSlot* slot);

// Allocate buffer in PSRAM (preferred) or fall back to internal heap
static uint8_t* _img_alloc(size_t bytes) {
    // ESP32-S3 with qio_opi PSRAM: prefer SPIRAM allocation
    uint8_t* buf = (uint8_t*)heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM);
    if (!buf) {
        // Fall back to internal heap (for non-PSRAM builds or PSRAM exhaustion)
        buf = (uint8_t*)malloc(bytes);
    }
    return buf;
}

// Find existing slot for (sender, xferId) or allocate new one
static ImageRxSlot* _img_rx_findOrCreate(const char* from, img_xfer_id_t xferId,
                                         size_t bufferSize, uint16_t totalChunks,
                                         const char* filename) {
    // Check for existing slot
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        ImageRxSlot* s = &imgRxSlots[i];
        if (s->state != IMG_RX_SLOT_FREE && s->xferId == xferId &&
            strcasecmp(s->fromCallsign, from) == 0) {
            return s;  // Already tracking
        }
    }
    // Allocate new slot
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        ImageRxSlot* s = &imgRxSlots[i];
        if (s->state == IMG_RX_SLOT_FREE) {
            s->buffer = _img_alloc(bufferSize);
            if (!s->buffer) {
                Serial.println("[ImgRx] PSRAM alloc failed, slot rejected");
                return nullptr;
            }
            memset(s->buffer, 0, bufferSize);
            s->bufferSize = bufferSize;
            s->totalChunks = totalChunks;
            s->xferId = xferId;
            strncpy(s->fromCallsign, from, sizeof(s->fromCallsign) - 1);
            s->fromCallsign[sizeof(s->fromCallsign) - 1] = '\0';
            strncpy(s->filename, filename ? filename : "image.jpg", IMG_FILENAME_MAX);
            s->filename[IMG_FILENAME_MAX] = '\0';
            img_bitmap_clear(s->recvBitmap);
            s->hasFullHash = false;
            s->lastActivityMs = millis();
            s->createdMs = millis();
            s->state = IMG_RX_SLOT_RECEIVING;
            Serial.printf("[ImgRx] Slot %d: from=%s id=%04X size=%d chunks=%d file=%s\n",
                          i, from, xferId, (int)bufferSize, totalChunks, s->filename);
            return s;
        }
    }
    Serial.println("[ImgRx] All slots in use, rejecting new transfer");
    return nullptr;
}

static void _img_rx_freeSlot(ImageRxSlot* slot) {
    if (!slot) return;
    if (slot->buffer) {
        free(slot->buffer);
        slot->buffer = nullptr;
    }
    memset(slot, 0, sizeof(*slot));
    slot->state = IMG_RX_SLOT_FREE;
}

// Process incoming img_hdr packet
void img_handleHdr(const char* from, img_xfer_id_t xferId, const char* filename,
                   size_t totalSize, uint16_t totalChunks) {
    if (totalSize == 0 || totalSize > IMG_MAX_SIZE_BYTES) {
        Serial.printf("[ImgRx] Reject hdr: size %d out of range\n", (int)totalSize);
        return;
    }
    if (totalChunks == 0 || totalChunks > IMG_MAX_CHUNKS) {
        Serial.printf("[ImgRx] Reject hdr: chunks %d out of range\n", totalChunks);
        return;
    }
    
    ImageRxSlot* slot = _img_rx_findOrCreate(from, xferId, totalSize, totalChunks, filename);
    // If slot is null, _img_rx_findOrCreate already logged the reason
    (void)slot;
}

// Process incoming img_chunk packet
void img_handleChunk(const char* from, img_xfer_id_t xferId, uint16_t seq,
                     uint16_t chunkLen, uint16_t chunkCrc,
                     const uint8_t* chunkData, size_t chunkDataLen) {
    // Find matching slot
    ImageRxSlot* slot = nullptr;
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        if (imgRxSlots[i].state != IMG_RX_SLOT_FREE &&
            imgRxSlots[i].xferId == xferId &&
            strcasecmp(imgRxSlots[i].fromCallsign, from) == 0) {
            slot = &imgRxSlots[i];
            break;
        }
    }
    if (!slot) {
        // Chunk arrived without prior hdr — silently ignore (sender will retry)
        return;
    }
    
    // Validate
    if (seq >= slot->totalChunks) return;
    if (chunkLen == 0 || chunkLen > IMG_CHUNK_PAYLOAD_SIZE) return;
    if (chunkDataLen < chunkLen) return;
    
    // CRC check
    uint16_t computedCrc = img_crc16(chunkData, chunkLen);
    if (computedCrc != chunkCrc) {
        Serial.printf("[ImgRx] Chunk %d CRC mismatch: got %04X expected %04X (drop)\n",
                      seq, computedCrc, chunkCrc);
        return;
    }
    
    // Reassemble
    bool isNew = img_chunk_assemble(slot->buffer, slot->bufferSize,
                                    seq, chunkData, chunkLen, slot->recvBitmap);
    if (isNew) {
        slot->lastActivityMs = millis();
    }
}

// Process incoming img_done packet
void img_handleDone(const char* from, img_xfer_id_t xferId, const uint8_t* fullHash) {
    ImageRxSlot* slot = nullptr;
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        if (imgRxSlots[i].state != IMG_RX_SLOT_FREE &&
            imgRxSlots[i].xferId == xferId &&
            strcasecmp(imgRxSlots[i].fromCallsign, from) == 0) {
            slot = &imgRxSlots[i];
            break;
        }
    }
    if (!slot) return;
    
    memcpy(slot->expectedHash, fullHash, 32);
    slot->hasFullHash = true;
    slot->lastActivityMs = millis();
    
    // Decide: complete + verify, or NACK
    if (img_bitmap_complete(slot->recvBitmap, slot->totalChunks)) {
        slot->state = IMG_RX_SLOT_AWAIT_DONE;
        _img_rx_finalize(slot);
    } else {
        uint16_t recvCount = img_bitmap_count(slot->recvBitmap, slot->totalChunks);
        Serial.printf("[ImgRx] Incomplete (%d/%d), sending NACK\n", recvCount, slot->totalChunks);
        _img_rx_sendNack(slot);
    }
}

// Process incoming img_abort packet
void img_handleAbort(const char* from, img_xfer_id_t xferId, int reason) {
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        if (imgRxSlots[i].state != IMG_RX_SLOT_FREE &&
            imgRxSlots[i].xferId == xferId &&
            strcasecmp(imgRxSlots[i].fromCallsign, from) == 0) {
            Serial.printf("[ImgRx] Sender aborted: from=%s id=%04X reason=%d\n",
                          from, xferId, reason);
            _img_rx_freeSlot(&imgRxSlots[i]);
            return;
        }
    }
}

// Compute SHA-256 to verify received image, save to SD, notify UI
static void _img_rx_finalize(ImageRxSlot* slot) {
    // Verify hash
    uint8_t computedHash[32];
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, slot->buffer, slot->bufferSize);
    mbedtls_sha256_finish(&ctx, computedHash);
    mbedtls_sha256_free(&ctx);
    
    if (slot->hasFullHash && memcmp(computedHash, slot->expectedHash, 32) != 0) {
        Serial.printf("[ImgRx] HASH MISMATCH from=%s id=%04X — requesting full retry\n",
                      slot->fromCallsign, slot->xferId);
        // Treat as if all chunks are bad: clear bitmap and send NACK
        // (sender will retransmit everything)
        img_bitmap_clear(slot->recvBitmap);
        slot->state = IMG_RX_SLOT_RECEIVING;
        slot->hasFullHash = false;
        _img_rx_sendNack(slot);
        return;
    }
    
    // Hash valid (or no hash to verify) — save to SD card
    extern bool sdCardMounted();
    bool savedToSD = false;
    if (sdCardMounted()) {
        char path[80];
        // Build path: /img_recv/<callsign>_<unix-or-ms-timestamp>.jpg
        // Use millis() if no GPS time available
        uint32_t ts = (uint32_t)(millis() / 1000);
        snprintf(path, sizeof(path), "/img_recv/%s_%lu_%04X.jpg",
                 slot->fromCallsign, (unsigned long)ts, slot->xferId);
        
        // Ensure directory exists
        SD.mkdir("/img_recv");
        
        File f = SD.open(path, FILE_WRITE);
        if (f) {
            size_t written = f.write(slot->buffer, slot->bufferSize);
            f.close();
            savedToSD = (written == slot->bufferSize);
            Serial.printf("[ImgRx] Saved %s (%d bytes, hash %s)\n",
                          path, (int)written, slot->hasFullHash ? "verified" : "unchecked");
        } else {
            Serial.printf("[ImgRx] SD open failed: %s\n", path);
        }
    } else {
        Serial.println("[ImgRx] No SD card — image discarded");
    }
    
    // UI notification: brief banner with sound
    extern void ui_imageReceived(const char* from, size_t bytes, bool savedToSD);
    ui_imageReceived(slot->fromCallsign, slot->bufferSize, savedToSD);
    
    // Push image to connected PWA clients via WebSocket (Phase 6).
    // Format: {"type":"image_rx","from":"CMD","name":"img_recv/CMD_3847_ABCD.jpg",
    //          "size":N,"data":"<base64>","verified":true}
    // The PWA can decode the base64 to get the original JPEG bytes for display.
    if (wsClientCount > 0) {
        // Base64 encode the full image. 8KB max image → 11KB base64.
        // Allocate temp buffer in PSRAM since this is a one-shot use.
        size_t b64MaxLen = ((slot->bufferSize + 2) / 3) * 4 + 16;
        char* b64Buf = (char*)heap_caps_malloc(b64MaxLen, MALLOC_CAP_SPIRAM);
        if (!b64Buf) b64Buf = (char*)malloc(b64MaxLen);
        if (b64Buf) {
            String b64 = b64Encode(slot->buffer, slot->bufferSize);
            if (b64.length() > 0) {
                JsonDocument doc;
                doc["type"]     = "image_rx";
                doc["from"]     = slot->fromCallsign;
                doc["name"]     = slot->filename;
                doc["size"]     = slot->bufferSize;
                doc["verified"] = slot->hasFullHash;
                doc["sd"]       = savedToSD;
                doc["data"]     = b64.c_str();
                
                String json;
                serializeJson(doc, json);
                broadcastAll(json);
                Serial.printf("[ImgRx] Pushed to %d PWA client(s) (%d bytes b64)\n",
                              wsClientCount, b64.length());
            }
            free(b64Buf);
        }
    }
    
    // Free the slot
    _img_rx_freeSlot(slot);
}

// Construct and send a NACK packet listing missing chunks
static void _img_rx_sendNack(ImageRxSlot* slot) {
    uint16_t missing[16];
    uint16_t totalMissing = 0;
    uint16_t n = img_missing_chunks(slot->recvBitmap, slot->totalChunks,
                                    missing, 16, &totalMissing);
    if (n == 0) return;  // Nothing missing
    
    JsonDocument doc;
    doc["type"] = IMG_TYPE_NACK;
    doc["id"]   = slot->xferId;
    JsonArray arr = doc["miss"].to<JsonArray>();
    for (uint16_t i = 0; i < n; i++) arr.add(missing[i]);
    
    String json;
    serializeJson(doc, json);
    
    if ((int)json.length() > LORA_MAX_PAYLOAD - 30) {
        Serial.println("[ImgRx] NACK packet too large");
        return;
    }
    
    uint8_t packet[LORA_MAX_PAYLOAD];
    int pktLen = 0;
    if (psk_isEnabled()) {
        uint8_t enc[LORA_MAX_PAYLOAD];
        int eLen = psk_encrypt((const uint8_t*)json.c_str(), json.length(), enc, sizeof(enc));
        if (eLen > 0) {
            packet[0] = 0xAE;
            memcpy(packet + 1, enc, eLen);
            pktLen = eLen + 1;
        }
    }
    if (pktLen == 0 && (int)json.length() <= LORA_MAX_PAYLOAD) {
        memcpy(packet, json.c_str(), json.length());
        pktLen = json.length();
    }
    if (pktLen > 0) {
        // NACK is HIGH priority — sender is waiting and will time out otherwise
        enqueuePacketPrio(packet, pktLen, PRIO_HIGH);
        Serial.printf("[ImgRx] NACK sent: id=%04X missing=%d/%d\n",
                      slot->xferId, n, totalMissing);
        slot->state = IMG_RX_SLOT_NACK_SENT;
        slot->lastActivityMs = millis();
    }
}

// Periodic tick: handle timeouts. Called from main loop.
void img_rxTick() {
    uint32_t now = millis();
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        ImageRxSlot* s = &imgRxSlots[i];
        if (s->state == IMG_RX_SLOT_FREE) continue;
        if (now - s->lastActivityMs > IMG_RX_TIMEOUT_MS) {
            Serial.printf("[ImgRx] Slot %d timeout (from=%s id=%04X)\n",
                          i, s->fromCallsign, s->xferId);
            _img_rx_freeSlot(s);
        }
    }
}

// Status query for !imgstat command
int img_rxActiveCount() {
    int n = 0;
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        if (imgRxSlots[i].state != IMG_RX_SLOT_FREE) n++;
    }
    return n;
}

void img_rxPrintStatus() {
    for (int i = 0; i < IMG_RX_MAX_SLOTS; i++) {
        ImageRxSlot* s = &imgRxSlots[i];
        if (s->state == IMG_RX_SLOT_FREE) continue;
        uint16_t recvCount = img_bitmap_count(s->recvBitmap, s->totalChunks);
        Serial.printf("[ImgRx] Slot %d: from=%s id=%04X chunks=%d/%d state=%d\n",
                      i, s->fromCallsign, s->xferId,
                      recvCount, s->totalChunks, s->state);
    }
}

// Inter-chunk delay for BULK transfers — gives the channel breathing room
// so other radios can get airtime (beacons, FHOP messages, voice).
#define BULK_INTERCHUNK_DELAY_MS  200
static uint32_t lastBulkTxMs = 0;

void processQueue() {
    if (txQueueCount == 0) return;
    if (state.txBusy) return;
    
    // Suppress ALL TX while assembling multi-part voice — the radio must
    // stay in RX mode to catch remaining parts (each part is ~1.5s on air)
    if (voice_isRxPending()) return;
    
    // ── Priority-aware inter-packet interval ──
    // HIGH priority: 500ms (voice, ACKs, DMs need fast turnaround)
    // NORMAL priority: TX_MIN_INTERVAL_MS (default 2s)
    // BULK priority: BULK_INTERCHUNK_DELAY_MS (200ms between image chunks)
    //   AND must not have any HIGH/NORMAL queued (those preempt)
    
    // Find the highest-priority packet in the queue (lowest number wins)
    int sendIdx = -1;
    uint8_t bestPrio = PRIO_BULK + 1;
    for (int i = 0; i < txQueueCount; i++) {
        int idx = (txQueueHead + i) % TX_QUEUE_SIZE;
        if (txQueue[idx].priority < bestPrio) {
            bestPrio = txQueue[idx].priority;
            sendIdx = idx;
            if (bestPrio == PRIO_HIGH) break;  // Can't do better
        }
    }
    if (sendIdx < 0) return;  // Should not happen — queueCount > 0
    
    uint8_t prio = txQueue[sendIdx].priority;
    
    // ── Preemption check for image TX ──
    // If an image transfer is active AND the next packet is BULK,
    // verify nothing higher-priority is waiting. (queueCountAbovePrio
    // returns >0 only if HIGH or NORMAL packets exist.)
    // If higher-priority work exists, the BULK packet waits — this is
    // automatically handled by selecting the lowest-numbered priority above.
    
    // Apply per-priority minimum interval
    uint32_t minInterval;
    if (prio == PRIO_HIGH) {
        minInterval = 500;
    } else if (prio == PRIO_NORMAL) {
        minInterval = TX_MIN_INTERVAL_MS;
    } else {
        // BULK: enforce inter-chunk breathing room
        minInterval = BULK_INTERCHUNK_DELAY_MS;
        // Also enforce: don't send BULK if anything higher just transmitted
        // recently (gives the channel a chance for replies)
        if (millis() - state.lastTxMs < BULK_INTERCHUNK_DELAY_MS) return;
    }
    if (millis() - state.lastTxMs < minInterval) return;
    
    // Track BULK timing separately for image flow control
    if (prio == PRIO_BULK) lastBulkTxMs = millis();
    
    TxPacket& pkt = txQueue[sendIdx];
    transmitPacket(pkt.data, pkt.len);
    
    // Remove from queue — if it was the head, advance head
    if (sendIdx == txQueueHead) {
        txQueueHead = (txQueueHead + 1) % TX_QUEUE_SIZE;
    } else {
        // Swap with head entry, then advance head
        txQueue[sendIdx] = txQueue[txQueueHead];
        txQueueHead = (txQueueHead + 1) % TX_QUEUE_SIZE;
    }
    txQueueCount--;
}

// ═══════════════════════════════════════════════════════════
// WEBSOCKET HANDLERS
// ═══════════════════════════════════════════════════════════

void onWebSocketEvent(uint8_t clientNum, WStype_t type, uint8_t* payload, size_t length) {
    switch (type) {
        case WStype_CONNECTED:
            wsClientCount++;
            Serial.printf("[WS] Client %d connected (total: %d)\n", clientNum, wsClientCount);
            // Send initial status
            sendStatus(clientNum);
            break;
            
        case WStype_DISCONNECTED:
            if (wsClientCount > 0) wsClientCount--;
            Serial.printf("[WS] Client %d disconnected (total: %d)\n", clientNum, wsClientCount);
            break;
            
        case WStype_TEXT:
            handleWSMessage(clientNum, (const char*)payload, length);
            break;
            
        default:
            break;
    }
}

void handleWSMessage(uint8_t clientNum, const char* payload, size_t length) {
    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, payload, length);
    if (err) {
        Serial.printf("[WS] JSON parse error: %s\n", err.c_str());
        return;
    }
    
    const char* type = doc["type"] | "";
    
    if (strcmp(type, "tx") == 0) {
        // Transmit request
        const char* b64data = doc["data"] | "";
        bool highPri = (strcmp(doc["priority"] | "normal", "high") == 0);
        
        uint8_t decoded[LORA_MAX_PAYLOAD];
        int decodedLen = b64Decode(b64data, decoded, LORA_MAX_PAYLOAD);
        
        if (decodedLen > 0) {
            if (enqueuePacket(decoded, decodedLen, highPri)) {
                // ACK the enqueue
                JsonDocument ack;
                ack["type"] = "tx_ack";
                ack["queued"] = txQueueCount;
                ack["len"] = decodedLen;
                String json;
                serializeJson(ack, json);
                sendToClient(clientNum, json);
            }
        }
    }
    else if (strcmp(type, "config") == 0) {
        // Runtime radio reconfiguration
        if (!doc["freq"].isNull())  state.freq  = doc["freq"];
        if (!doc["sf"].isNull())    state.sf    = doc["sf"];
        if (!doc["bw"].isNull())    state.bw    = doc["bw"];
        if (!doc["cr"].isNull())    state.cr    = doc["cr"];
        if (!doc["power"].isNull()) state.power = doc["power"];
        
        // Reinitialize radio with new config
        initRadio();
        startReceive();
        
        Serial.printf("[Config] Updated: %.1f MHz, SF%d, BW%.0f, %ddBm\n",
                      state.freq, state.sf, state.bw, state.power);
    }
    else if (strcmp(type, "ping") == 0) {
        String pong = "{\"type\":\"pong\"}";
        sendToClient(clientNum, pong);
    }
    else if (strcmp(type, "wifi_config") == 0) {
        // Tablet pushes hotspot credentials — show confirmation on T-Deck screen
        const char* ssid = doc["ssid"] | "";
        const char* pass = doc["password"] | "";
        bool switchNow = doc["switch"] | false;
        
        if (strlen(ssid) > 0) {
            ui_showWifiConfigPrompt(ssid, pass, switchNow, clientNum);
        }
    }
    else if (strcmp(type, "voice_tx") == 0) {
        // Tablet sending voice to transmit via LoRa (multi-part)
        const char* pcmB64 = doc["data"] | "";
        const char* target = doc["to"] | "";
        voice_setTarget(target);  // Set target before encoding
        if (strlen(pcmB64) > 0) {
            int numParts = voice_encodeAndPackage((const uint8_t*)pcmB64, strlen(pcmB64));
            if (numParts > 0) {
                // Parts will be sent by the main loop's voice TX handler
                Serial.printf("[Voice] WS TX: %d parts queued\n", numParts);
                String vtAck = "{\"type\":\"voice_tx_ack\"}";
                sendToClient(clientNum, vtAck);
            }
        }
    }
    else if (strcmp(type, "status") == 0) {
        sendStatus(clientNum);
    }
    else if (strcmp(type, "sync_contact") == 0) {
        // GridDown pushing a contact to T-Deck for standalone display
        const char* name = doc["name"] | "Unknown";
        const char* fp = doc["fingerprint"] | "";
        if (strlen(fp) > 0) {
            ui_addContact(name, fp);
            String syncAck = "{\"type\":\"sync_ack\",\"item\":\"contact\"}";
            sendToClient(clientNum, syncAck);
        }
    }
    else if (strcmp(type, "sync_message") == 0) {
        // GridDown pushing a decrypted message to T-Deck display
        const char* from = doc["from"] | "?";
        const char* text = doc["text"] | "";
        bool outgoing = doc["outgoing"] | false;
        if (strlen(text) > 0) {
            ui_addMessage(from, text, outgoing, false);
            String msgAck = "{\"type\":\"sync_ack\",\"item\":\"message\"}";
            sendToClient(clientNum, msgAck);
        }
    }
    else if (strcmp(type, "ui_info") == 0) {
        // GridDown requesting T-Deck UI state
        JsonDocument info;
        info["type"] = "ui_info";
        info["screen"] = (int)ui_getCurrentScreen();
        info["messages"] = ui_getMessageCount();
        info["contacts"] = ui_getContactCount();
        info["has_compose"] = ui_hasComposedMessage();
        double lat, lon, alt;
        info["gps_valid"] = ui_getGPS(&lat, &lon, &alt);
        if (info["gps_valid"]) {
            info["gps_lat"] = lat;
            info["gps_lon"] = lon;
            info["gps_alt"] = alt;
        }
        String json;
        serializeJson(info, json);
        sendToClient(clientNum, json);
    }
    else if (strcmp(type, "track_share") == 0) {
        // Tablet sharing a SA track (AtlasRF, RemoteID, Sentinel) → store + broadcast over LoRa
        const char* tid = doc["id"] | "";
        double tlat = doc["lat"] | 0.0;
        double tlon = doc["lon"] | 0.0;
        float talt = doc["alt"] | 0.0f;
        float thdg = doc["hdg"] | 0.0f;
        float tspd = doc["spd"] | 0.0f;
        uint8_t tsrc = doc["src"] | TRACK_SRC_UNKNOWN;
        
        if (strlen(tid) > 0 && (tlat != 0 || tlon != 0)) {
            // Store locally
            track_update(tid, tlat, tlon, talt, thdg, tspd, tsrc);
            
            // Build LoRa packet for mesh distribution
            JsonDocument trackDoc;
            trackDoc["type"] = "track";
            trackDoc["from"] = ui_callsignSet() ? ui_getCallsign() : "RELAY";
            trackDoc["id"] = tid;
            trackDoc["lat"] = tlat;
            trackDoc["lon"] = tlon;
            trackDoc["alt"] = talt;
            trackDoc["hdg"] = thdg;
            trackDoc["spd"] = tspd;
            trackDoc["src"] = tsrc;
            trackDoc["ts"] = millis();
            
            String trackJson;
            serializeJson(trackDoc, trackJson);
            
            uint8_t packet[LORA_MAX_PAYLOAD];
            int pktLen = 0;
            if (psk_isEnabled()) {
                uint8_t enc[LORA_MAX_PAYLOAD];
                int eLen = psk_encrypt((const uint8_t*)trackJson.c_str(),
                                      trackJson.length(), enc, sizeof(enc));
                if (eLen > 0) {
                    packet[0] = 0xAE;
                    memcpy(packet + 1, enc, eLen);
                    pktLen = eLen + 1;
                }
            }
            if (pktLen == 0 && (int)trackJson.length() <= LORA_MAX_PAYLOAD) {
                memcpy(packet, trackJson.c_str(), trackJson.length());
                pktLen = trackJson.length();
            }
            if (pktLen > 0) {
                enqueuePacket(packet, pktLen, false);
                Serial.printf("[Track] Shared %s via LoRa (%d bytes)\n", tid, pktLen);
            }
            
            // ACK to tablet
            String ack = "{\"type\":\"track_ack\",\"id\":\"" + String(tid) + "\"}";
            sendToClient(clientNum, ack);
        }
    }
    else if (strcmp(type, "waypoint_push") == 0) {
        // GridDown PWA pushing a map marker to T-Deck as a waypoint
        // Protocol: {"type":"waypoint_push","name":"Rally","lat":34.05,"lon":-118.24,"icon":1}
        // Also broadcasts over LoRa mesh so all radios in the group receive it.
        const char* wpName = doc["name"] | "";
        double wpLat = doc["lat"] | 0.0;
        double wpLon = doc["lon"] | 0.0;
        uint8_t wpIcon = doc["icon"] | WP_ICON_GENERIC;
        const char* wpCreator = doc["creator"] | (ui_callsignSet() ? ui_getCallsign() : "PWA");
        
        if (strlen(wpName) > 0 && (wpLat != 0 || wpLon != 0)) {
            // Store locally on T-Deck
            wp_add(wpName, wpLat, wpLon, wpIcon, wpCreator);
            
            // Broadcast over LoRa mesh (same format as /wp command)
            JsonDocument wpDoc;
            wpDoc["type"] = "waypoint";
            wpDoc["from"] = ui_callsignSet() ? ui_getCallsign() : "RELAY";
            wpDoc["name"] = wpName;
            wpDoc["lat"] = wpLat;
            wpDoc["lon"] = wpLon;
            wpDoc["icon"] = wpIcon;
            String wpJson;
            serializeJson(wpDoc, wpJson);
            
            uint8_t packet[LORA_MAX_PAYLOAD];
            int pktLen = 0;
            if (psk_isEnabled()) {
                uint8_t enc[LORA_MAX_PAYLOAD];
                int eLen = psk_encrypt((const uint8_t*)wpJson.c_str(),
                                      wpJson.length(), enc, sizeof(enc));
                if (eLen > 0) {
                    packet[0] = 0xAE;
                    memcpy(packet + 1, enc, eLen);
                    pktLen = eLen + 1;
                }
            }
            if (pktLen == 0 && (int)wpJson.length() <= LORA_MAX_PAYLOAD) {
                memcpy(packet, wpJson.c_str(), wpJson.length());
                pktLen = wpJson.length();
            }
            if (pktLen > 0) {
                enqueuePacket(packet, pktLen, false);
                Serial.printf("[WP] PWA push: %s → LoRa mesh (%d bytes)\n", wpName, pktLen);
            }
            
            String wpAck = "{\"type\":\"waypoint_ack\",\"name\":\"" + String(wpName) + "\"}";
            sendToClient(clientNum, wpAck);
        }
    }
    else if (strcmp(type, "waypoint_delete") == 0) {
        // PWA requesting waypoint removal
        const char* wpName = doc["name"] | "";
        if (strlen(wpName) > 0) {
            for (int i = 0; i < 16; i++) {  // WAYPOINT_MAX
                SharedWaypoint wp;
                if (wp_get(i, &wp) && strcasecmp(wp.name, wpName) == 0) {
                    wp_remove(i);
                    Serial.printf("[WP] PWA delete: %s\n", wpName);
                    break;
                }
            }
            String delAck = "{\"type\":\"waypoint_ack\",\"deleted\":\"" + String(wpName) + "\"}";
            sendToClient(clientNum, delAck);
        }
    }
    else if (strcmp(type, "image_tx") == 0) {
        // PWA pushes a JPEG to transmit over LoRa.
        // Protocol: {"type":"image_tx","data":"<base64>","name":"photo.jpg"}
        // Response:
        //   {"type":"image_tx_ack","name":"photo.jpg","size":N,"chunks":M,"id":"XXXX"}  on success
        //   {"type":"image_tx_err","reason":"<text>"}  on failure
        //
        // Buffer lifetime: image data must remain valid for the entire transfer
        // (~30 seconds for a 5KB image). We keep a static PSRAM-allocated buffer
        // that survives across the TX state machine.
        const char* b64Data = doc["data"] | "";
        const char* fname = doc["name"] | "image.jpg";
        
        if (strlen(b64Data) == 0) {
            String err = "{\"type\":\"image_tx_err\",\"reason\":\"empty data\"}";
            sendToClient(clientNum, err);
        }
        else if (img_isTxActive()) {
            String err = "{\"type\":\"image_tx_err\",\"reason\":\"transfer in progress\"}";
            sendToClient(clientNum, err);
        }
        else {
            // Static PSRAM buffer for incoming JPEG. Allocated once on first use.
            static uint8_t* pwaImgBuf = nullptr;
            if (!pwaImgBuf) {
                pwaImgBuf = (uint8_t*)heap_caps_malloc(IMG_MAX_SIZE_BYTES, MALLOC_CAP_SPIRAM);
                if (!pwaImgBuf) pwaImgBuf = (uint8_t*)malloc(IMG_MAX_SIZE_BYTES);
            }
            if (!pwaImgBuf) {
                String err = "{\"type\":\"image_tx_err\",\"reason\":\"out of memory\"}";
                sendToClient(clientNum, err);
            } else {
                // Decode base64 directly into the PSRAM buffer
                int decodedLen = b64Decode(b64Data, pwaImgBuf, IMG_MAX_SIZE_BYTES);
                if (decodedLen <= 0) {
                    String err = "{\"type\":\"image_tx_err\",\"reason\":\"base64 decode failed\"}";
                    sendToClient(clientNum, err);
                } else if (decodedLen > IMG_MAX_SIZE_BYTES) {
                    String err = "{\"type\":\"image_tx_err\",\"reason\":\"image too large\"}";
                    sendToClient(clientNum, err);
                } else {
                    // Validate JPEG SOI marker (0xFF 0xD8) — reject non-JPEG data
                    if (decodedLen < 4 || pwaImgBuf[0] != 0xFF || pwaImgBuf[1] != 0xD8) {
                        String err = "{\"type\":\"image_tx_err\",\"reason\":\"not a JPEG (missing SOI)\"}";
                        sendToClient(clientNum, err);
                    } else if (img_beginTx(pwaImgBuf, decodedLen, fname)) {
                        // Success — report transfer ID and chunk count
                        JsonDocument ack;
                        ack["type"] = "image_tx_ack";
                        ack["name"] = fname;
                        ack["size"] = decodedLen;
                        ack["chunks"] = img_chunk_count(decodedLen);
                        char idBuf[8];
                        snprintf(idBuf, sizeof(idBuf), "%04X", imgTx.xferId);
                        ack["id"] = idBuf;
                        String ackJson;
                        serializeJson(ack, ackJson);
                        sendToClient(clientNum, ackJson);
                        Serial.printf("[ImgTx] PWA push: %s (%d bytes, %d chunks, id=%s)\n",
                                      fname, decodedLen, img_chunk_count(decodedLen), idBuf);
                    } else {
                        String err = "{\"type\":\"image_tx_err\",\"reason\":\"img_beginTx rejected\"}";
                        sendToClient(clientNum, err);
                    }
                }
            }
        }
    }
    else if (strcmp(type, "image_tx_cancel") == 0) {
        // PWA requesting cancel of active image transfer
        if (img_isTxActive()) {
            img_cancelTx();
            String ack = "{\"type\":\"image_tx_ack\",\"cancelled\":true}";
            sendToClient(clientNum, ack);
        }
    }
    else if (strcmp(type, "image_tx_status") == 0) {
        // PWA polling for progress
        JsonDocument st;
        st["type"] = "image_tx_status";
        st["active"] = img_isTxActive();
        st["progress"] = img_txProgress();
        if (img_isTxActive()) {
            char idBuf[8];
            snprintf(idBuf, sizeof(idBuf), "%04X", imgTx.xferId);
            st["id"] = idBuf;
            st["chunk"] = imgTx.nextChunkIdx;
            st["total"] = imgTx.totalChunks;
            st["retry"] = imgTx.retryRound;
        }
        String stJson;
        serializeJson(st, stJson);
        sendToClient(clientNum, stJson);
    }
}

void sendStatus(uint8_t clientNum) {
    JsonDocument doc;
    doc["type"]      = "status";
    doc["battery"]   = state.batteryPct;
    doc["radio"]     = state.txBusy ? "tx" : (state.rxMode ? "rx" : "idle");
    doc["clients"]   = wsClientCount;
    doc["tx_count"]  = state.txCount;
    doc["rx_count"]  = state.rxCount;
    doc["tx_errors"] = state.txErrors;
    doc["tx_queue"]  = txQueueCount;
    doc["last_rssi"] = state.lastRSSI;
    doc["last_snr"]  = state.lastSNR;
    doc["freq"]      = state.freq;
    doc["sf"]        = state.sf;
    doc["bw"]        = state.bw;
    doc["power"]     = state.power;
    doc["uptime"]    = (millis() - state.bootTime) / 1000;
    doc["wifi_mode"] = wifi_modeLabel(wifiModeGD);
    if (wifiModeGD == WIFI_MODE_GD_STA && staConnected)
        doc["wifi_ip"] = WiFi.localIP().toString();
    else if (wifiModeGD == WIFI_MODE_GD_AP)
        doc["wifi_ip"] = WiFi.softAPIP().toString();
    
    String json;
    serializeJson(doc, json);
    
    if (clientNum == 0xFF) {
        broadcastAll(json);  // Broadcast to all
    } else {
        sendToClient(clientNum, json);
    }
}

// ═══════════════════════════════════════════════════════════
// BATTERY MONITORING
// ═══════════════════════════════════════════════════════════

// Battery smoothing state
static float batEMA = -1.0f;       // Exponential moving average of voltage (-1 = uninitialized)
float batVoltage = 0.0f;           // Last smoothed voltage (extern for UI debug display)
uint32_t lastRadioActivity = 0;    // millis() of last TX or RX (extern for UI header dot)

// LiPo voltage-to-percent lookup (non-linear discharge curve)
// Measured typical single-cell LiPo under light load
static uint8_t _lipoVoltToPct(float v) {
    if (v >= 4.15f) return 100;
    if (v >= 4.10f) return 95;
    if (v >= 4.00f) return 87;
    if (v >= 3.90f) return 75;
    if (v >= 3.80f) return 60;
    if (v >= 3.70f) return 45;  // Nominal voltage — flat plateau
    if (v >= 3.60f) return 30;
    if (v >= 3.50f) return 18;
    if (v >= 3.40f) return 10;
    if (v >= 3.30f) return 5;
    if (v >= 3.20f) return 2;
    return 0;  // Below 3.2V — critically low
}

// Split-iteration battery sampling state
static uint32_t batSampleBuf[BAT_SAMPLES_TOTAL]; // Accumulated mV readings
static int      batSampleIdx = 0;                 // Current sample index
static bool     batFirstRead = true;              // Force blocking on first read at boot
static uint32_t batLastResultMs = 0;              // When last measurement completed

void updateBattery() {
    // Split-iteration approach: collect BAT_SAMPLES_PER_TICK (2) calibrated samples
    // per call (~600μs), accumulate across 8 loop() calls until buffer is full,
    // then compute the result. Called every loop() iteration — returns immediately
    // when not collecting. New cycle starts every 10 seconds.
    
    // Rate limiting: don't start a new cycle until 10s since last result
    // (batSampleIdx > 0 means we're mid-collection, always continue)
    if (batSampleIdx == 0 && !batFirstRead) {
        if (millis() - batLastResultMs < 10000) return;
    }
    
    int samplesToTake = batFirstRead ? BAT_SAMPLES_TOTAL : BAT_SAMPLES_PER_TICK;
    
    for (int i = 0; i < samplesToTake && batSampleIdx < BAT_SAMPLES_TOTAL; i++) {
        batSampleBuf[batSampleIdx++] = analogReadMilliVolts(BAT_ADC);
    }
    
    // Not enough samples yet — return and collect more next loop() iteration
    if (batSampleIdx < BAT_SAMPLES_TOTAL) return;
    
    // Buffer full — compute result
    batSampleIdx = 0;
    batFirstRead = false;
    batLastResultMs = millis();
    
    // Sort for interquartile mean (discard 4 lowest sags + 4 highest spikes)
    // Insertion sort on 16 elements is fast (~256 comparisons worst case)
    for (int i = 1; i < BAT_SAMPLES_TOTAL; i++) {
        uint32_t key = batSampleBuf[i];
        int j = i - 1;
        while (j >= 0 && batSampleBuf[j] > key) { batSampleBuf[j+1] = batSampleBuf[j]; j--; }
        batSampleBuf[j+1] = key;
    }
    uint32_t midSum = 0;
    for (int i = 4; i < 12; i++) midSum += batSampleBuf[i];
    float adcMv = midSum / 8.0f;
    float voltage = adcMv * batAdcMultiplier / 1000.0f;  // Corrected divider ratio, mV to V
    
    // USB charging detection
    bool wasCharging = state.usbCharging;
    state.usbCharging = (voltage > 4.25f);
    
    // Clamp to realistic LiPo range
    if (voltage > 4.3f) voltage = 4.2f;
    
    // USB unplug transition: snap EMA to actual battery voltage
    if (wasCharging && !state.usbCharging) {
        batEMA = voltage;
        Serial.printf("[Battery] USB unplugged, reset to %.2fV\n", voltage);
    }
    
    // Outlier rejection: sag > 0.15V below EMA is transient, not discharge
    if (batEMA > 0 && voltage < batEMA - 0.15f) {
        return;
    }
    
    // EMA smoothing (alpha=0.08 — ~13 readings to settle)
    if (batEMA < 0) {
        batEMA = voltage;
    } else {
        batEMA = 0.08f * voltage + 0.92f * batEMA;
    }
    batVoltage = batEMA;
    
    // Percentage with hysteresis (2-point dead band)
    uint8_t newPct = _lipoVoltToPct(batEMA);
    if (state.batteryPct == 0 || abs((int)newPct - (int)state.batteryPct) >= 2) {
        state.batteryPct = newPct;
    }
}

uint8_t getBatteryPercent() {
    return state.batteryPct;
}

bool isUsbCharging() {
    return state.usbCharging;
}

// ═══════════════════════════════════════════════════════════
// 900 MHz DRONE SCANNER
// Dual-mode: CAD (LoRa preamble detection) + RSSI (energy detection)
// Detects: ELRS, Crossfire (CAD), SiK/RFD900/Holybro (RSSI)
// ═══════════════════════════════════════════════════════════

// Combined frequency table: 902-928 MHz in 500kHz steps (covers all protocols)
static const float scanFreqTable[] = {
    902.0f, 902.5f, 903.0f, 903.5f, 904.0f, 904.5f, 905.0f, 905.5f,
    906.0f, 906.5f, 907.0f, 907.5f, 908.0f, 908.5f, 909.0f, 909.5f,
    910.0f, 910.5f, 911.0f, 911.5f, 912.0f, 912.5f, 913.0f, 913.5f,
    914.0f, 914.5f, 915.0f, 915.5f, 916.0f, 916.5f, 917.0f, 917.5f,
    918.0f, 918.5f, 919.0f, 919.5f, 920.0f, 920.5f, 921.0f, 921.5f,
    922.0f, 922.5f, 923.0f, 923.5f, 924.0f, 924.5f, 925.0f, 925.5f,
    926.0f, 926.5f, 927.0f, 927.5f
};
#define SCAN_FREQ_COUNT 52

// Scanner state
static bool          scanActive = false;
static uint32_t      scanStartMs = 0;
static uint32_t      scanSweepCount = 0;
static int           scanChIdx = 0;        // Current channel index in sweep
static ScanResult    scanResults[SCAN_MAX_CHANNELS];
static ScanDetection scanDetections[4];
static float         scanNoiseFloor = -120.0f;
static uint8_t       scanProfile = SCAN_PROFILE_ALL_DRONE;
static uint8_t       scanDeepSfIdx = 0;    // For ELRS_DEEP: cycles SF5-8

// Saved radio config (restored on scan_stop)
static struct {
    float freq, bw;
    uint8_t sf, cr;
    int8_t power;
} savedRadioConfig;

// RSSI detection threshold: noise floor + 20dB
// (Raised from 15dB to reject thermal noise variance on T-Deck hardware.
// Real drone telemetry at operationally relevant range: ELRS 250mW → -70dBm @1km,
// Crossfire 1W → -60dBm @1km, SiK 100mW → -75dBm @1km. All well above NF+20.)
#define SCAN_RSSI_THRESHOLD_DB  20.0f
// Debounce: 3+ hits in last ~8 sweeps to be "active"
#define SCAN_DEBOUNCE_HITS      3
// Dual-BW discrimination: if BW500 RSSI is 6dB+ above BW125, signal is wideband (LoRa)
#define SCAN_WIDEBAND_DELTA     6.0f
// Infrastructure: if active on 80%+ of last 20 sweeps, mark as infrastructure
#define SCAN_INFRA_THRESHOLD    16  // 80% of 20
// GFSK classification: peak RSSI must exceed NF by this amount to classify.
// Lowered from 25dB to 22dB to close the gap between visible spectrum activity
// (NF+20 display threshold) and classification confidence. The broadband noise
// gate (NF+25 for bypass) remains the primary defense against false positives.
#define SCAN_GFSK_CLASSIFY_DB   22.0f
// Broadband gate bypass: strong-signal exemption for wideband FHSS radios
// (SiK/RFD900 legitimately light up 15%+ of channels at close range)
#define SCAN_STRONG_PEAK_DB     25.0f

// Forward declaration
static void _scanClassify();
static void _scanPushLiveTracks();
static uint32_t scanLivePushTime[4] = {0, 0, 0, 0};
#define SCAN_LIVE_PUSH_INTERVAL_MS 2000

// Uncomment for verbose per-channel scan diagnostics ([Scan] HIT / Sweep lines)
// #define SCAN_DEBUG

bool scan_isActive() { return scanActive; }
uint32_t scan_getSweepCount() { return scanSweepCount; }
uint32_t scan_getElapsedMs() { return scanActive ? (millis() - scanStartMs) : 0; }
int scan_getChannelCount() { return SCAN_FREQ_COUNT; }

void scan_setProfile(uint8_t p) { if (p < SCAN_PROFILE_COUNT) scanProfile = p; }
uint8_t scan_getProfile() { return scanProfile; }

const char* scan_profileName(uint8_t p) {
    switch (p) {
        case SCAN_PROFILE_QUICK_LORA: return "Quick LoRa";
        case SCAN_PROFILE_ALL_DRONE:  return "All Drone";
        case SCAN_PROFILE_FULL_SPEC:  return "Full Spec";
        case SCAN_PROFILE_ELRS_DEEP:  return "ELRS Deep";
        default:                      return "???";
    }
}
const ScanResult* scan_getResults() { return scanResults; }
const ScanDetection* scan_getDetections() { return scanDetections; }
float scan_getNoiseFloor() { return scanNoiseFloor; }

int scan_getActiveDetections() {
    // Count valid detection slots that represent actual threats (drones).
    // Excludes LoRaWAN infrastructure — those are informational, not actionable.
    int n = 0;
    for (int d = 0; d < 4; d++) {
        if (scanDetections[d].valid && scanDetections[d].classification != SCAN_CLASS_LORAWAN) n++;
    }
    return n;
}

void scan_toggleInfra(int chIdx) {
    if (chIdx >= 0 && chIdx < SCAN_FREQ_COUNT) {
        scanResults[chIdx].infrastructure = !scanResults[chIdx].infrastructure;
        if (scanResults[chIdx].infrastructure) {
            scanResults[chIdx].infraCount = SCAN_INFRA_THRESHOLD;  // Lock it
        } else {
            scanResults[chIdx].infraCount = 0;  // Reset
        }
        Serial.printf("[Scanner] Ch %d (%.1f MHz) infra=%d\n", 
                      chIdx, scanResults[chIdx].freq, scanResults[chIdx].infrastructure);
    }
}

// ═══════════════════════════════════════════════════════════
// RF SCANNING BASELINE
// Pre-recorded ambient RF environment for delta-based detection.
// Captures per-channel RSSI median, CAD activity (SF breakdown),
// and infrastructure flags. Saved to LittleFS (~300 bytes).
// When loaded, enables:
//   - Pre-flagged infrastructure from sweep 1 (no 60s learning period)
//   - Per-channel noise floor (tighter thresholds on quiet channels)
//   - Delta detection: "what changed?" vs "what do I see?"
// Graceful fallback: if no baseline loaded, all paths use current behavior.
// ═══════════════════════════════════════════════════════════

#define SCAN_BASELINE_FILE     "/scan_bl.bin"
#define SCAN_BASELINE_MAGIC    0x474442   // "GDB" (GridDown Baseline)
#define SCAN_BASELINE_VERSION  1
#define SCAN_BASELINE_SWEEPS   20         // Sweeps to capture (~6-8 seconds)

struct ScanBaselineChannel {
    float rssiMedian;        // Median RSSI during baseline (per-channel NF)
    uint8_t cadActivity;     // CAD hit count during baseline (0 = quiet)
    uint8_t sfSignature;     // 0=none, 1=low-SF dominant, 2=high-SF dominant, 3=mixed
    bool infrastructure;     // Was flagged as infrastructure during baseline
};

struct ScanBaselineHeader {
    uint32_t magic;
    uint8_t version;
    uint8_t channelCount;
    float globalNF;          // Global median noise floor at capture time
    uint32_t timestamp;      // millis() at capture (relative — for staleness check)
    double lat, lon;         // GPS position at capture (0,0 if no GPS)
};

// Baseline state
static ScanBaselineChannel scanBaseline[SCAN_MAX_CHANNELS];
static ScanBaselineHeader  scanBaselineHdr;
static bool scanBaselineLoaded = false;
static uint8_t scanBaselineProgress_ = 0;  // 0-100%
static bool scanBaselineCapturing = false;

bool scan_baselineAvailable() { return scanBaselineLoaded; }
uint8_t scan_baselineProgress() { return scanBaselineProgress_; }

bool scan_baselineLoad() {
    File f = LittleFS.open(SCAN_BASELINE_FILE, "r");
    if (!f) {
        Serial.println("[Baseline] No saved baseline found");
        scanBaselineLoaded = false;
        return false;
    }
    
    ScanBaselineHeader hdr;
    if (f.read((uint8_t*)&hdr, sizeof(hdr)) != sizeof(hdr)) {
        f.close();
        Serial.println("[Baseline] Header read failed");
        scanBaselineLoaded = false;
        return false;
    }
    if (hdr.magic != SCAN_BASELINE_MAGIC || hdr.version != SCAN_BASELINE_VERSION ||
        hdr.channelCount != SCAN_FREQ_COUNT) {
        f.close();
        Serial.printf("[Baseline] Invalid: magic=0x%X ver=%d ch=%d\n", hdr.magic, hdr.version, hdr.channelCount);
        scanBaselineLoaded = false;
        return false;
    }
    
    size_t dataSize = sizeof(ScanBaselineChannel) * SCAN_FREQ_COUNT;
    if (f.read((uint8_t*)scanBaseline, dataSize) != dataSize) {
        f.close();
        Serial.println("[Baseline] Channel data read failed");
        scanBaselineLoaded = false;
        return false;
    }
    f.close();
    
    scanBaselineHdr = hdr;
    scanBaselineLoaded = true;
    
    int infraCount = 0;
    for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
        if (scanBaseline[i].infrastructure) infraCount++;
    }
    Serial.printf("[Baseline] Loaded: NF=%.1f dBm, %d infra channels, GPS=(%.4f,%.4f)\n",
                  hdr.globalNF, infraCount, hdr.lat, hdr.lon);
    return true;
}

static bool _baselineSave() {
    File f = LittleFS.open(SCAN_BASELINE_FILE, "w");
    if (!f) {
        Serial.println("[Baseline] Save failed — can't open file");
        return false;
    }
    f.write((uint8_t*)&scanBaselineHdr, sizeof(scanBaselineHdr));
    f.write((uint8_t*)scanBaseline, sizeof(ScanBaselineChannel) * SCAN_FREQ_COUNT);
    f.close();
    Serial.printf("[Baseline] Saved: NF=%.1f dBm, %d channels\n", scanBaselineHdr.globalNF, SCAN_FREQ_COUNT);
    return true;
}

void scan_baselineClear() {
    LittleFS.remove(SCAN_BASELINE_FILE);
    scanBaselineLoaded = false;
    Serial.println("[Baseline] Cleared");
}

void scan_baselineCapture() {
    // Runs a dedicated multi-sweep baseline scan.
    // Collects per-channel RSSI medians and CAD activity over SCAN_BASELINE_SWEEPS.
    // Blocks for ~6-8 seconds. Progress reported via scan_baselineProgress().
    
    // Safety: if scan is active, stop it first
    if (scanActive) {
        scan_stop();
        delay(10);
    }
    
    scanBaselineCapturing = true;
    scanBaselineProgress_ = 0;
    
    Serial.println("[Baseline] Starting capture...");
    
    // Save full radio config (same as scan_start)
    float savedFreq = state.freq;
    float savedBW = state.bw;
    uint8_t savedSF = state.sf;
    uint8_t savedCR = state.cr;
    int8_t savedPower = state.power;
    
    radio.clearDio1Action();
    radio.standby();
    
    // Per-channel RSSI accumulator for median computation.
    // STATIC, NOT STACK: float[52][20] is 4160 bytes, and with globalRSSI,
    // sortedGlobal and sorted this function previously placed ~4.6 KB in a single
    // frame. It is reached via loop() -> ui_tick() -> handleKeypress() ->
    // _scanKey(), so that frame sits on top of an already-deep call chain and
    // overflowed the Arduino loop task stack — the cause of the freeze/reboot
    // when capturing a baseline. static costs BSS instead, and this function is
    // one-shot and non-reentrant (guarded by scanBaselineCapturing), so static is safe.
    static float rssiAccum[SCAN_FREQ_COUNT][SCAN_BASELINE_SWEEPS];
    static uint8_t cadCountLow[SCAN_FREQ_COUNT];
    static uint8_t cadCountHigh[SCAN_FREQ_COUNT];
    memset(cadCountLow, 0, sizeof(cadCountLow));
    memset(cadCountHigh, 0, sizeof(cadCountHigh));
    memset(rssiAccum, 0, sizeof(rssiAccum));
    
    // Run sweeps
    for (int sweep = 0; sweep < SCAN_BASELINE_SWEEPS; sweep++) {
        for (int ch = 0; ch < SCAN_FREQ_COUNT; ch++) {
            radio.standby();
            radio.setFrequency(scanFreqTable[ch]);
            
            // CAD at SF6/BW500 (ELRS check)
            radio.setBandwidth(500.0f);
            radio.setSpreadingFactor(6);
            if (radio.scanChannel() == RADIOLIB_LORA_DETECTED) {
                cadCountLow[ch]++;
            }
            
            // CAD at SF10/BW125 (LoRaWAN check) — alternate sweeps
            if (sweep % 2 == 1) {
                radio.setBandwidth(125.0f);
                radio.setSpreadingFactor(10);
                if (radio.scanChannel() == RADIOLIB_LORA_DETECTED) {
                    cadCountHigh[ch]++;
                }
            }
            
            // RSSI measurement (median of 3)
            radio.setBandwidth(500.0f);
            radio.setSpreadingFactor(6);
            radio.startReceive();
            delay(5);
            float s[3];
            for (int j = 0; j < 3; j++) {
                s[j] = radio.getRSSI(false);
                delayMicroseconds(600);
            }
            if (s[0] > s[1]) { float t = s[0]; s[0] = s[1]; s[1] = t; }
            if (s[1] > s[2]) { float t = s[1]; s[1] = s[2]; s[2] = t; }
            if (s[0] > s[1]) { float t = s[0]; s[0] = s[1]; s[1] = t; }
            rssiAccum[ch][sweep] = s[1];
            radio.standby();

            // Feed the watchdog EVERY CHANNEL, not every sweep. Previously this
            // was reset only once per 52-channel sweep, so a slow sweep (CAD at
            // SF10/BW125 is not fast) could approach the 30 s task-WDT timeout
            // and trigger a panic reboot. yield() also lets WiFi/BLE housekeeping
            // run instead of being starved for the whole capture.
            esp_task_wdt_reset();
            yield();
        }

        scanBaselineProgress_ = (uint8_t)((sweep + 1) * 100 / SCAN_BASELINE_SWEEPS);
        esp_task_wdt_reset();

        // Live progress. Without this the display is untouched for the entire
        // 6-8 s capture, which is indistinguishable from a hang even when the
        // capture is working correctly.
        extern void ui_baselineProgressTick(uint8_t pct);
        ui_baselineProgressTick(scanBaselineProgress_);
    }
    
    // Compute per-channel medians and build baseline
    static float globalRSSI[SCAN_FREQ_COUNT];
    for (int ch = 0; ch < SCAN_FREQ_COUNT; ch++) {
        // Sort this channel's RSSI readings
        float sorted[SCAN_BASELINE_SWEEPS];
        memcpy(sorted, rssiAccum[ch], sizeof(float) * SCAN_BASELINE_SWEEPS);
        for (int i = 0; i < SCAN_BASELINE_SWEEPS - 1; i++)
            for (int j = i + 1; j < SCAN_BASELINE_SWEEPS; j++)
                if (sorted[j] < sorted[i]) { float t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t; }
        
        scanBaseline[ch].rssiMedian = sorted[SCAN_BASELINE_SWEEPS / 2];
        scanBaseline[ch].cadActivity = cadCountLow[ch] + cadCountHigh[ch];
        
        // SF signature
        if (cadCountLow[ch] == 0 && cadCountHigh[ch] == 0) {
            scanBaseline[ch].sfSignature = 0;  // No CAD activity
        } else if (cadCountLow[ch] > cadCountHigh[ch] * 2) {
            scanBaseline[ch].sfSignature = 1;  // Low-SF dominant
        } else if (cadCountHigh[ch] > cadCountLow[ch] * 2) {
            scanBaseline[ch].sfSignature = 2;  // High-SF dominant
        } else {
            scanBaseline[ch].sfSignature = 3;  // Mixed
        }
        
        // Infrastructure: CAD detected on 30%+ of sweeps → persistent emitter
        scanBaseline[ch].infrastructure = (scanBaseline[ch].cadActivity >= (SCAN_BASELINE_SWEEPS * 30 / 100));
        
        globalRSSI[ch] = scanBaseline[ch].rssiMedian;
    }
    
    // Global noise floor = median of per-channel medians
    static float sortedGlobal[SCAN_FREQ_COUNT];
    memcpy(sortedGlobal, globalRSSI, sizeof(sortedGlobal));
    for (int i = 0; i < SCAN_FREQ_COUNT - 1; i++)
        for (int j = i + 1; j < SCAN_FREQ_COUNT; j++)
            if (sortedGlobal[j] < sortedGlobal[i]) { float t = sortedGlobal[i]; sortedGlobal[i] = sortedGlobal[j]; sortedGlobal[j] = t; }
    
    // Build header
    scanBaselineHdr.magic = SCAN_BASELINE_MAGIC;
    scanBaselineHdr.version = SCAN_BASELINE_VERSION;
    scanBaselineHdr.channelCount = SCAN_FREQ_COUNT;
    scanBaselineHdr.globalNF = sortedGlobal[SCAN_FREQ_COUNT / 2];
    scanBaselineHdr.timestamp = millis();
    
    double lat = 0, lon = 0, alt = 0;
    if (ui_getGPS(&lat, &lon, &alt)) {
        scanBaselineHdr.lat = lat;
        scanBaselineHdr.lon = lon;
    } else {
        scanBaselineHdr.lat = 0;
        scanBaselineHdr.lon = 0;
    }
    
    // Save to LittleFS
    _baselineSave();
    scanBaselineLoaded = true;
    
    // Restore full radio config (same comprehensive restore as scan_stop)
    radio.standby();
    radio.setFrequency(savedFreq);
    radio.setBandwidth(savedBW);
    radio.setSpreadingFactor(savedSF);
    radio.setCodingRate(savedCR);
    radio.setOutputPower(savedPower);
    radio.setSyncWord(LORA_SYNC_WORD);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.setCRC(true);
    radio.setDio2AsRfSwitch(true);
    radio.setCurrentLimit(60.0f);
    radio.setDio1Action(onLoRaRx);
    startReceive();
    
    int infraCount = 0;
    for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
        if (scanBaseline[i].infrastructure) infraCount++;
    }
    
    scanBaselineCapturing = false;
    scanBaselineProgress_ = 100;
    
    Serial.printf("[Baseline] Capture complete: NF=%.1f dBm, %d infra, %d quiet channels\n",
                  scanBaselineHdr.globalNF, infraCount, SCAN_FREQ_COUNT - infraCount);
}

// Apply loaded baseline to current scan session (called from scan_start)
static void _scanApplyBaseline() {
    if (!scanBaselineLoaded) return;
    
    // Check NF divergence — if current NF is >10dB different from baseline,
    // the environment has changed significantly and baseline may be stale
    float nfDelta = fabsf(scanNoiseFloor - scanBaselineHdr.globalNF);
    if (nfDelta > 10.0f) {
        Serial.printf("[Baseline] WARNING: NF diverged %.1f dB (saved=%.1f, current=%.1f) — baseline may be stale\n",
                      nfDelta, scanBaselineHdr.globalNF, scanNoiseFloor);
        // Still apply — operator can clear if needed — but log the warning
    }
    
    int preInfra = 0, deltaInfra = 0;
    for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
        // Pre-flag infrastructure channels from baseline
        if (scanBaseline[i].infrastructure && !scanResults[i].infrastructure) {
            scanResults[i].infrastructure = true;
            scanResults[i].infraCount = SCAN_INFRA_THRESHOLD;
            preInfra++;
        }
    }
    
    Serial.printf("[Baseline] Applied: %d channels pre-flagged as infrastructure\n", preInfra);
}

void scan_start() {
    if (scanActive) return;
    
    // Save current radio configuration
    savedRadioConfig.freq = state.freq;
    savedRadioConfig.bw = state.bw;
    savedRadioConfig.sf = state.sf;
    savedRadioConfig.cr = state.cr;
    savedRadioConfig.power = state.power;
    
    // Clear results
    memset(scanResults, 0, sizeof(scanResults));
    memset(scanDetections, 0, sizeof(scanDetections));
    memset(scanLivePushTime, 0, sizeof(scanLivePushTime));
    for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
        scanResults[i].freq = scanFreqTable[i];
        scanResults[i].rssi = -130.0f;
        scanResults[i].rssiPeak = -130.0f;
    }
    scanNoiseFloor = -120.0f;
    scanChIdx = 0;
    scanSweepCount = 0;
    scanStartMs = millis();
    
    // Detach the normal LoRa RX interrupt (we're taking over the radio)
    radio.clearDio1Action();
    radio.standby();
    
    // ── Noise calibration sweep ──
    // Multi-sample RSSI measurement across all channels to identify self-interference
    // spurs from the T-Deck's own electronics (ESP32 clocks, SPI bus, WiFi AP).
    // Takes 3 samples per channel using median (rejects SPI noise transients).
    // Channels >12dB above the median baseline are pre-flagged as infrastructure.
    {
        float calRSSI[SCAN_FREQ_COUNT];
        for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
            radio.standby();
            radio.setBandwidth(500.0f);
            radio.setSpreadingFactor(6);
            radio.setFrequency(scanFreqTable[i]);
            radio.startReceive();
            delay(5);  // Extended AGC settle — T-Deck switching noise needs >3ms
            // 3 samples, use median to reject transient SPI noise
            float s[3];
            for (int j = 0; j < 3; j++) {
                s[j] = radio.getRSSI(false);
                delayMicroseconds(800);
            }
            // Sort 3 samples → median is s[1]
            if (s[0] > s[1]) { float t = s[0]; s[0] = s[1]; s[1] = t; }
            if (s[1] > s[2]) { float t = s[1]; s[1] = s[2]; s[2] = t; }
            if (s[0] > s[1]) { float t = s[0]; s[0] = s[1]; s[1] = t; }
            calRSSI[i] = s[1];
            radio.standby();
        }
        // Compute median for baseline
        float sorted[SCAN_FREQ_COUNT];
        memcpy(sorted, calRSSI, sizeof(sorted));
        for (int i = 0; i < SCAN_FREQ_COUNT - 1; i++)
            for (int j = i + 1; j < SCAN_FREQ_COUNT; j++)
                if (sorted[j] < sorted[i]) { float t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t; }
        float calMedian = sorted[SCAN_FREQ_COUNT / 2];
        scanNoiseFloor = calMedian;  // Use calibrated NF from first sweep
        
        // Flag channels that are >12dB above median as self-interference
        // (lowered from 20dB to catch broadband ESP32 switching noise that
        // elevates channels moderately rather than creating sharp spurs)
        int spurCount = 0;
        for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
            if (calRSSI[i] > calMedian + 12.0f) {
                scanResults[i].infrastructure = true;
                scanResults[i].infraCount = SCAN_INFRA_THRESHOLD;
                spurCount++;
                Serial.printf("[Scanner] Cal: ch%d %.1fMHz = %.1f dBm (spur, +%.1f above NF)\n",
                              i, scanFreqTable[i], calRSSI[i], calRSSI[i] - calMedian);
            }
            // Seed initial RSSI from calibration
            scanResults[i].rssi = calRSSI[i];
        }
        Serial.printf("[Scanner] Calibration: NF=%.1f dBm, %d spurs flagged\n", calMedian, spurCount);
    }
    
    // Load and apply RF baseline (if saved) — pre-flags infrastructure from sweep 1
    if (!scanBaselineLoaded) {
        scan_baselineLoad();  // Try loading from LittleFS (no-op if file doesn't exist)
    }
    _scanApplyBaseline();  // Apply if loaded; no-op if not
    
    scanActive = true;
    
    static const char* profileNames[] = {"Quick LoRa", "All Drone", "Full Spectrum", "ELRS Deep"};
    Serial.printf("[Scanner] Started — profile: %s, %d channels, radio in scan mode\n",
                  profileNames[scanProfile], SCAN_FREQ_COUNT);
}

void scan_tick() {
    if (!scanActive) return;
    
    float freq = scanFreqTable[scanChIdx];
    ScanResult& r = scanResults[scanChIdx];
    bool cadDetected = false;
    float rssiWide = -130.0f, rssiNarrow = -130.0f;
    
    radio.standby();
    radio.setFrequency(freq);
    
    switch (scanProfile) {
        case SCAN_PROFILE_QUICK_LORA: {
            // CAD only at SF6/BW500 — fastest, LoRa protocols only
            radio.setBandwidth(500.0f);
            radio.setSpreadingFactor(6);
            if (radio.scanChannel() == RADIOLIB_LORA_DETECTED) {
                cadDetected = true;
                if (r.cadHitsLowSF < 255) r.cadHitsLowSF++;
            }
            // Quick RSSI read for spectrum display
            radio.startReceive();
            delay(5);  // AGC settle (5ms for T-Deck noise)
            rssiWide = radio.getRSSI(false);
            radio.standby();
            break;
        }
        case SCAN_PROFILE_ALL_DRONE: {
            // Multi-SF CAD + multi-sample peak RSSI
            // Rotate between ELRS (SF6/BW500) and mesh LoRa (SF10/BW125)
            // to detect both fast LoRa FHSS and slow fixed-channel LoRa.
            // SF phase is tracked for SF discrimination in the classifier.
            static uint8_t cadRotation = 0;
            bool cadIsLowSF = (cadRotation == 0);
            if (cadIsLowSF) {
                // ELRS / Crossfire: SF6 BW500
                radio.setBandwidth(500.0f);
                radio.setSpreadingFactor(6);
            } else {
                // Meshtastic / GridDown / LoRaWAN: SF10 BW125
                radio.setBandwidth(125.0f);
                radio.setSpreadingFactor(10);
            }
            if (radio.scanChannel() == RADIOLIB_LORA_DETECTED) {
                cadDetected = true;
                // Record which SF class triggered the hit
                if (cadIsLowSF) {
                    if (r.cadHitsLowSF < 255) r.cadHitsLowSF++;
                } else {
                    if (r.cadHitsHighSF < 255) r.cadHitsHighSF++;
                }
            }
            cadRotation = (cadRotation + 1) % 2;
            
            // Wide RSSI (BW500) — 5 samples over ~6ms, use median
            // Median rejects transient SPI bus noise spikes that peak-hold amplifies.
            // SX1262 AGC needs ~3-5ms after startReceive() to settle;
            // 5ms allows for T-Deck switching regulator noise to stabilize.
            radio.setBandwidth(500.0f);
            radio.setSpreadingFactor(6);
            radio.startReceive();
            delay(5);  // Extended AGC settle
            float wSamples[5];
            for (int s = 0; s < 5; s++) {
                wSamples[s] = radio.getRSSI(false);
                delayMicroseconds(600);
            }
            // Sort → median is wSamples[2]
            for (int a = 0; a < 4; a++)
                for (int b = a + 1; b < 5; b++)
                    if (wSamples[b] < wSamples[a]) { float t = wSamples[a]; wSamples[a] = wSamples[b]; wSamples[b] = t; }
            rssiWide = wSamples[2];
            radio.standby();
            
            // Narrow RSSI (BW125) — only probe channels with activity
            float threshold = scanNoiseFloor + SCAN_RSSI_THRESHOLD_DB;
            if (rssiWide > threshold || cadDetected) {
                radio.setBandwidth(125.0f);
                radio.startReceive();
                delay(5);  // AGC settle for BW125
                float nSamples[3];
                for (int s = 0; s < 3; s++) {
                    nSamples[s] = radio.getRSSI(false);
                    delayMicroseconds(600);
                }
                if (nSamples[0] > nSamples[1]) { float t = nSamples[0]; nSamples[0] = nSamples[1]; nSamples[1] = t; }
                if (nSamples[1] > nSamples[2]) { float t = nSamples[1]; nSamples[1] = nSamples[2]; nSamples[2] = t; }
                if (nSamples[0] > nSamples[1]) { float t = nSamples[0]; nSamples[0] = nSamples[1]; nSamples[1] = t; }
                rssiNarrow = nSamples[1];
                radio.standby();
                
                // Wideband discrimination: BW500 >> BW125 = wideband LoRa
                r.rssiNarrow = rssiNarrow;
                r.isWideband = (rssiWide - rssiNarrow) > SCAN_WIDEBAND_DELTA;
            }
            break;
        }
        case SCAN_PROFILE_FULL_SPEC: {
            // RSSI only — no CAD, 5-sample median rejects SPI noise transients
            radio.setBandwidth(500.0f);
            radio.setSpreadingFactor(7);
            radio.startReceive();
            delay(5);  // AGC settle (5ms for T-Deck noise)
            float fSamples[5];
            for (int s = 0; s < 5; s++) {
                fSamples[s] = radio.getRSSI(false);
                delayMicroseconds(600);
            }
            for (int a = 0; a < 4; a++)
                for (int b = a + 1; b < 5; b++)
                    if (fSamples[b] < fSamples[a]) { float t = fSamples[a]; fSamples[a] = fSamples[b]; fSamples[b] = t; }
            rssiWide = fSamples[2];
            radio.standby();
            break;
        }
        case SCAN_PROFILE_ELRS_DEEP: {
            // CAD at rotating SF (5→6→7→8) — catches all ELRS rate modes
            static const uint8_t deepSFs[] = {5, 6, 7, 8};
            uint8_t sf = deepSFs[scanDeepSfIdx];
            radio.setBandwidth(500.0f);
            radio.setSpreadingFactor(sf);
            if (radio.scanChannel() == RADIOLIB_LORA_DETECTED) {
                cadDetected = true;
                if (r.cadHitsLowSF < 255) r.cadHitsLowSF++;  // SF5-8 are all ELRS-class
            }
            // RSSI
            radio.startReceive();
            delay(5);  // AGC settle (5ms for T-Deck noise)
            rssiWide = radio.getRSSI(false);
            radio.standby();
            break;
        }
    }
    
    // Update results
    r.rssi = rssiWide;
    if (rssiWide > r.rssiPeak) r.rssiPeak = rssiWide;
    if (cadDetected && r.cadHits < 255) r.cadHits++;
    float threshold = scanNoiseFloor + SCAN_RSSI_THRESHOLD_DB;
    if (rssiWide > threshold) {
        if (r.rssiHits < 255) r.rssiHits++;
        r.lastTransientSweep = scanSweepCount;  // Cross-channel transient tracking
#ifdef SCAN_DEBUG
        // Diagnostic: log individual RSSI hits (rate-limited to 1/sec per channel)
        static uint32_t lastHitLog[SCAN_MAX_CHANNELS] = {0};
        uint32_t now = millis();
        if (now - lastHitLog[scanChIdx] > 1000) {
            lastHitLog[scanChIdx] = now;
            Serial.printf("[Scan] HIT ch%d %.1fMHz rssi=%.1f (NF=%.0f +%.1fdB) hits=%d\n",
                          scanChIdx, freq, rssiWide, scanNoiseFloor, rssiWide - scanNoiseFloor, r.rssiHits);
        }
#endif
    }
    
    // Advance channel
    scanChIdx++;
    if (scanChIdx >= SCAN_FREQ_COUNT) {
        scanChIdx = 0;
        scanSweepCount++;
        
        // Rotate SF for ELRS Deep profile (one SF per full sweep)
        if (scanProfile == SCAN_PROFILE_ELRS_DEEP) {
            scanDeepSfIdx = (scanDeepSfIdx + 1) % 4;
        }
        
        // Adaptive noise floor (median)
        float sorted[SCAN_MAX_CHANNELS];
        for (int i = 0; i < SCAN_FREQ_COUNT; i++) sorted[i] = scanResults[i].rssi;
        for (int i = 1; i < SCAN_FREQ_COUNT; i++) {
            float key = sorted[i]; int j = i - 1;
            while (j >= 0 && sorted[j] > key) { sorted[j+1] = sorted[j]; j--; }
            sorted[j+1] = key;
        }
        scanNoiseFloor = sorted[SCAN_FREQ_COUNT / 2];
        
        // ── Sweep diagnostic (every 5 sweeps) ──
#ifdef SCAN_DEBUG
        if (scanSweepCount % 5 == 0) {
            float threshold = scanNoiseFloor + SCAN_RSSI_THRESHOLD_DB;
            int aboveThresh = 0;
            float peakRSSI = -200;
            int peakCh = -1;
            int transientTotal = 0;
            uint32_t recentW = (scanSweepCount > 30) ? scanSweepCount - 30 : 0;
            for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
                if (scanResults[i].rssi > threshold) {
                    aboveThresh++;
                    if (scanResults[i].rssi > peakRSSI) {
                        peakRSSI = scanResults[i].rssi;
                        peakCh = i;
                    }
                }
                if (scanResults[i].lastTransientSweep >= recentW && scanResults[i].lastTransientSweep > 0) {
                    transientTotal++;
                }
            }
            Serial.printf("[Scan] Sweep %lu: NF=%.0f thresh=%.0f above=%d transient=%d",
                          scanSweepCount, scanNoiseFloor, threshold, aboveThresh, transientTotal);
            if (peakCh >= 0)
                Serial.printf(" peak=%.1fdBm@%.1fMHz", peakRSSI, scanFreqTable[peakCh]);
            Serial.println();
        }
#endif
        
        // Decay hit counters — CAD every 2 sweeps, RSSI every 3
        // (faster RSSI decay prevents broadband noise from accumulating
        // false hits across many channels simultaneously)
        if (scanSweepCount % 2 == 0) {
            for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
                if (scanResults[i].cadHits > 0) scanResults[i].cadHits--;
                if (scanResults[i].cadHitsLowSF > 0) scanResults[i].cadHitsLowSF--;
                if (scanResults[i].cadHitsHighSF > 0) scanResults[i].cadHitsHighSF--;
            }
        }
        if (scanSweepCount % 3 == 0) {
            for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
                if (scanResults[i].rssiHits > 0) scanResults[i].rssiHits--;
            }
        }
        
        // Update active + infrastructure flags
        for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
            scanResults[i].active = (scanResults[i].cadHits >= SCAN_DEBOUNCE_HITS) ||
                                   (scanResults[i].rssiHits >= SCAN_DEBOUNCE_HITS);
            
            // Infrastructure learning: channel active on 80%+ of sweeps → infrastructure
            if (scanResults[i].active) {
                if (scanResults[i].infraCount < 255) scanResults[i].infraCount++;
            } else if (scanResults[i].infraCount > 0) {
                scanResults[i].infraCount--;  // Decay when inactive
            }
            // Mark as infrastructure after 20+ sweeps of sustained presence
            if (scanSweepCount >= 20 && scanResults[i].infraCount >= SCAN_INFRA_THRESHOLD) {
                scanResults[i].infrastructure = true;
            }
        }
        
        _scanClassify();
        _scanPushLiveTracks();
    }
}

// Classify detection patterns into drone protocol categories
static void _scanClassify() {
    // Phase 3 classifier: preserves temporal data across sweeps, ages stale detections.
    // Does NOT memset — updates existing slots or creates new ones.
    
    uint32_t now = millis();
    
    // ── Gather channel statistics (skip infrastructure) ──
    bool newDetectionThisSweep = false;  // Fires drone alert tone once per new detection
    int cadActiveCount = 0, rssiOnlyCount = 0;
    int widebandRSSI = 0, narrowbandRSSI = 0;  // Dual-BW discrimination counters
    float cadPeakRSSI = -200, cadPeakFreq = 0, cadMinRSSI = 0;
    float rssiPeakRSSI = -200, rssiPeakFreq = 0, rssiMinRSSI = 0;
    
    // Delta detection: count channels that are NEW since baseline
    // (had zero CAD activity in baseline but now have debounced CAD hits)
    int cadDeltaCount = 0;  // Channels with CAD that were quiet in baseline
    int rssiDeltaCount = 0; // Channels with RSSI hits that were quiet in baseline
    
    for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
        if (!scanResults[i].active) continue;
        if (scanResults[i].infrastructure) continue;  // Skip known infrastructure
        
        // Baseline delta check: was this channel quiet in the baseline?
        bool baselineQuiet = false;
        if (scanBaselineLoaded) {
            baselineQuiet = (scanBaseline[i].cadActivity == 0 &&
                            scanBaseline[i].rssiMedian < (scanBaselineHdr.globalNF + 10.0f));
        }
        
        if (scanResults[i].cadHits >= SCAN_DEBOUNCE_HITS) {
            cadActiveCount++;
            if (baselineQuiet) cadDeltaCount++;
            if (scanResults[i].rssiPeak > cadPeakRSSI) {
                cadPeakRSSI = scanResults[i].rssiPeak;
                cadPeakFreq = scanResults[i].freq;
            }
            if (cadMinRSSI == 0 || scanResults[i].rssiPeak < cadMinRSSI) {
                cadMinRSSI = scanResults[i].rssiPeak;
            }
        } else if (scanResults[i].rssiHits >= SCAN_DEBOUNCE_HITS) {
            rssiOnlyCount++;
            if (baselineQuiet) rssiDeltaCount++;
            if (scanResults[i].rssiPeak > rssiPeakRSSI) {
                rssiPeakRSSI = scanResults[i].rssiPeak;
                rssiPeakFreq = scanResults[i].freq;
            }
            if (rssiMinRSSI == 0 || scanResults[i].rssiPeak < rssiMinRSSI) {
                rssiMinRSSI = scanResults[i].rssiPeak;
            }
            // Dual-BW counting for RSSI-only channels
            if (scanResults[i].isWideband) widebandRSSI++;
            else narrowbandRSSI++;
        }
    }
    
    // ── Helper: find existing detection by classification, or empty slot ──
    auto findSlot = [&](uint8_t cls) -> int {
        // Look for existing detection of this type
        for (int d = 0; d < 4; d++) {
            if (scanDetections[d].valid && scanDetections[d].classification == cls) return d;
        }
        // Find empty slot
        for (int d = 0; d < 4; d++) {
            if (!scanDetections[d].valid) return d;
        }
        return -1;  // All slots occupied with other types
    };
    
    // ── Classify: LoRa FHSS with frequency-zone + SF discrimination + sub-band matching ──
    //
    // Three independent discriminators, each adding confidence:
    //
    // 1. FREQUENCY ZONE: LoRaWAN US915 has a dead zone at 915.0–923.2 MHz.
    //    Any CAD in the gap = drone. All in uplink/downlink = likely infra.
    //
    // 2. SF DISCRIMINATION: ELRS uses SF5-6 exclusively (BW500).
    //    LoRaWAN uplink uses SF7-12 (BW125). If most CAD hits are at low SF,
    //    it's drone. If most are high SF, it's infrastructure.
    //
    // 3. SUB-BAND CLUSTERING: LoRaWAN gateways typically listen on one sub-band
    //    (8 channels within 1.6 MHz). ELRS hops across the full 26 MHz.
    //    If all CAD hits cluster within 2 MHz, it's LoRaWAN.
    //
    if (cadActiveCount >= 3) {
        float spread = cadPeakRSSI - cadMinRSSI;
        if (spread < 15.0f) {
            // ── Zone analysis ──
            int zoneUplink = 0;    // 902.0 – 914.9 MHz
            int zoneGap = 0;       // 915.0 – 923.2 MHz (LoRaWAN dead zone)
            int zoneDownlink = 0;  // 923.3 – 928.0 MHz
            
            // ── SF discrimination ──
            int totalLowSF = 0;    // SF5-6 hits (ELRS signature)
            int totalHighSF = 0;   // SF7+ hits (LoRaWAN signature)
            
            // ── Sub-band clustering ──
            float cadMinFreq = 999.0f, cadMaxFreq = 0.0f;
            
            for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
                if (!scanResults[i].active) continue;
                if (scanResults[i].infrastructure) continue;
                if (scanResults[i].cadHits < SCAN_DEBOUNCE_HITS) continue;
                
                float f = scanResults[i].freq;
                if (f < 915.0f)       zoneUplink++;
                else if (f < 923.3f)  zoneGap++;
                else                  zoneDownlink++;
                
                totalLowSF += scanResults[i].cadHitsLowSF;
                totalHighSF += scanResults[i].cadHitsHighSF;
                
                if (f < cadMinFreq) cadMinFreq = f;
                if (f > cadMaxFreq) cadMaxFreq = f;
            }
            
            float cadFreqSpan = cadMaxFreq - cadMinFreq;  // MHz
            int totalSFHits = totalLowSF + totalHighSF;
            float lowSFRatio = (totalSFHits > 0) ? (float)totalLowSF / (float)totalSFHits : 0.5f;
            
            // Sub-band: LoRaWAN gateway sub-bands are 1.6 MHz wide.
            // If all CAD channels fit within 2.0 MHz → single sub-band pattern
            bool subbandClustered = (cadFreqSpan <= 2.0f);
            
            Serial.printf("[Scanner] LoRa analysis: zone(up=%d gap=%d dn=%d) SF(low=%d high=%d ratio=%.0f%%) span=%.1fMHz subband=%s delta=%d/%d\n",
                          zoneUplink, zoneGap, zoneDownlink,
                          totalLowSF, totalHighSF, lowSFRatio * 100.0f,
                          cadFreqSpan, subbandClustered ? "YES" : "no",
                          cadDeltaCount, cadActiveCount);
            
            // ── Decision tree ──
            // Priority 1: Gap zone presence → DRONE (absolute, no LoRaWAN there)
            if (zoneGap > 0) {
                int slot = findSlot(SCAN_CLASS_LORA_FHSS);
                if (slot >= 0) {
                    if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_LORA_FHSS) {
                        scanDetections[slot].firstSeen = now;
                        newDetectionThisSweep = true;
                    }
                    scanDetections[slot].classification = SCAN_CLASS_LORA_FHSS;
                    scanDetections[slot].peakRSSI = cadPeakRSSI;
                    scanDetections[slot].peakFreq = cadPeakFreq;
                    scanDetections[slot].channelCount = cadActiveCount;
                    scanDetections[slot].lastSeen = now;
                    scanDetections[slot].valid = true;
                }
            }
            // Priority 2: No gap channels, but dominant low-SF → DRONE
            // ELRS hops through uplink zone too; if SF5-6 CAD dominates,
            // it's ELRS even though it's in the LoRaWAN frequency range.
            // Requires >60% low-SF hits for confident classification.
            else if (lowSFRatio > 0.60f && !subbandClustered) {
                int slot = findSlot(SCAN_CLASS_LORA_FHSS);
                if (slot >= 0) {
                    if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_LORA_FHSS) {
                        scanDetections[slot].firstSeen = now;
                        newDetectionThisSweep = true;
                    }
                    scanDetections[slot].classification = SCAN_CLASS_LORA_FHSS;
                    scanDetections[slot].peakRSSI = cadPeakRSSI;
                    scanDetections[slot].peakFreq = cadPeakFreq;
                    scanDetections[slot].channelCount = cadActiveCount;
                    scanDetections[slot].lastSeen = now;
                    scanDetections[slot].valid = true;
                    
                    Serial.printf("[Scanner] DRONE: low-SF dominant (%.0f%%) + wide spread (%.1fMHz) in uplink zone\n",
                                  lowSFRatio * 100.0f, cadFreqSpan);
                }
            }
            // Priority 3: High-SF dominant AND sub-band clustered → strong LoRaWAN
            else if (lowSFRatio <= 0.40f && subbandClustered) {
                int slot = findSlot(SCAN_CLASS_LORAWAN);
                if (slot >= 0) {
                    if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_LORAWAN) {
                        scanDetections[slot].firstSeen = now;
                    }
                    scanDetections[slot].classification = SCAN_CLASS_LORAWAN;
                    scanDetections[slot].peakRSSI = cadPeakRSSI;
                    scanDetections[slot].peakFreq = cadPeakFreq;
                    scanDetections[slot].channelCount = cadActiveCount;
                    scanDetections[slot].lastSeen = now;
                    scanDetections[slot].valid = true;
                    
                    Serial.printf("[Scanner] LoRaWAN: high-SF (%.0f%% low) + sub-band clustered (%.1fMHz span)\n",
                                  lowSFRatio * 100.0f, cadFreqSpan);
                }
            }
            // Priority 4: High-SF dominant, spread across band → LoRaWAN multi-gateway
            else if (lowSFRatio <= 0.40f) {
                int slot = findSlot(SCAN_CLASS_LORAWAN);
                if (slot >= 0) {
                    if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_LORAWAN) {
                        scanDetections[slot].firstSeen = now;
                    }
                    scanDetections[slot].classification = SCAN_CLASS_LORAWAN;
                    scanDetections[slot].peakRSSI = cadPeakRSSI;
                    scanDetections[slot].peakFreq = cadPeakFreq;
                    scanDetections[slot].channelCount = cadActiveCount;
                    scanDetections[slot].lastSeen = now;
                    scanDetections[slot].valid = true;
                    
                    Serial.printf("[Scanner] LoRaWAN: high-SF (%.0f%% low) multi-gateway spread (%.1fMHz span)\n",
                                  lowSFRatio * 100.0f, cadFreqSpan);
                }
            }
            // Priority 5: Ambiguous — mixed SF, no gap, wide spread
            // If baseline is loaded and MOST active channels are new (delta),
            // this is likely a new emitter → classify as drone.
            // Otherwise, default conservatively to LoRaWAN infrastructure.
            else {
                bool deltaUpgrade = (scanBaselineLoaded && cadDeltaCount > 0 &&
                                     cadDeltaCount >= (cadActiveCount * 60 / 100));
                
                if (deltaUpgrade) {
                    // Majority of CAD channels were QUIET in baseline → new emitter
                    int slot = findSlot(SCAN_CLASS_LORA_FHSS);
                    if (slot >= 0) {
                        if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_LORA_FHSS) {
                            scanDetections[slot].firstSeen = now;
                            newDetectionThisSweep = true;
                        }
                        scanDetections[slot].classification = SCAN_CLASS_LORA_FHSS;
                        scanDetections[slot].peakRSSI = cadPeakRSSI;
                        scanDetections[slot].peakFreq = cadPeakFreq;
                        scanDetections[slot].channelCount = cadActiveCount;
                        scanDetections[slot].lastSeen = now;
                        scanDetections[slot].valid = true;
                        
                        Serial.printf("[Scanner] DELTA DRONE: %d/%d channels NEW since baseline — upgrading to drone\n",
                                      cadDeltaCount, cadActiveCount);
                    }
                } else {
                    int slot = findSlot(SCAN_CLASS_LORAWAN);
                    if (slot >= 0) {
                        if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_LORAWAN) {
                            scanDetections[slot].firstSeen = now;
                        }
                        scanDetections[slot].classification = SCAN_CLASS_LORAWAN;
                        scanDetections[slot].peakRSSI = cadPeakRSSI;
                        scanDetections[slot].peakFreq = cadPeakFreq;
                        scanDetections[slot].channelCount = cadActiveCount;
                        scanDetections[slot].lastSeen = now;
                        scanDetections[slot].valid = true;
                        
                        Serial.printf("[Scanner] AMBIGUOUS LoRa: SF=%.0f%% span=%.1fMHz delta=%d/%d — defaulting to infra\n",
                                      lowSFRatio * 100.0f, cadFreqSpan, cadDeltaCount, cadActiveCount);
                    }
                }
            }
        }
    }
    // Fixed LoRa: 1-2 CAD channels — apply zone + SF heuristic
    else if (cadActiveCount >= 1 && cadActiveCount <= 2) {
        bool anyInGap = false;
        int fixedLowSF = 0, fixedHighSF = 0;
        for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
            if (!scanResults[i].active) continue;
            if (scanResults[i].infrastructure) continue;
            if (scanResults[i].cadHits < SCAN_DEBOUNCE_HITS) continue;
            float f = scanResults[i].freq;
            if (f >= 915.0f && f < 923.3f) anyInGap = true;
            fixedLowSF += scanResults[i].cadHitsLowSF;
            fixedHighSF += scanResults[i].cadHitsHighSF;
        }
        
        // Gap zone OR dominant low-SF → potential drone
        bool isDrone = anyInGap || (fixedLowSF > fixedHighSF);
        uint8_t fixedClass = isDrone ? SCAN_CLASS_FIXED_LORA : SCAN_CLASS_LORAWAN;
        int slot = findSlot(fixedClass);
        if (slot >= 0) {
            if (!scanDetections[slot].valid || scanDetections[slot].classification != fixedClass) {
                scanDetections[slot].firstSeen = now;
                if (isDrone) newDetectionThisSweep = true;
            }
            scanDetections[slot].classification = fixedClass;
            scanDetections[slot].peakRSSI = cadPeakRSSI;
            scanDetections[slot].peakFreq = cadPeakFreq;
            scanDetections[slot].channelCount = cadActiveCount;
            scanDetections[slot].lastSeen = now;
            scanDetections[slot].valid = true;
        }
    }
    
    // ── Broadband noise rejection ──
    // If >15% of non-infrastructure channels are RSSI-active AND the peak signal
    // is weak (near threshold), suppress RSSI-only detection paths.
    // EXEMPTION: If peak RSSI is strong (NF+25dB+, SCAN_STRONG_PEAK_DB), this is a real
    // wideband FHSS radio (SiK/RFD900 hops across ~50 channels — legitimately activates
    // 15%+ of the band at close range). Broadband noise never produces a strong peak.
    int nonInfraCount = 0;
    int totalActive = cadActiveCount + rssiOnlyCount;
    for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
        if (!scanResults[i].infrastructure) nonInfraCount++;
    }
    bool manyChannelsActive = (nonInfraCount > 0 && totalActive > (nonInfraCount * 15 / 100));
    bool strongPeak = (rssiPeakRSSI > (scanNoiseFloor + SCAN_STRONG_PEAK_DB));
    bool broadbandNoise = manyChannelsActive && !strongPeak;
    if (broadbandNoise) {
        rssiOnlyCount = 0;  // Suppress GFSK path — only CAD detections survive
        Serial.printf("[Scanner] Broadband noise gate: %d/%d ch active, peak=%.0f (weak) — RSSI paths suppressed\n",
                      totalActive, nonInfraCount, rssiPeakRSSI);
    } else if (manyChannelsActive && strongPeak) {
        Serial.printf("[Scanner] Broadband gate BYPASSED: %d/%d ch active but peak=%.0f dBm (strong signal)\n",
                      totalActive, nonInfraCount, rssiPeakRSSI);
    }
    
    // ── Classify: GFSK FHSS (SiK / RFD900 / Holybro) ──
    // Path A: Per-channel debounced (works for fast FHSS with tight RSSI spread)
    // SiK hops across ~50 channels at ~50 hops/sec — individual channels may only
    // debounce to 3 hits sporadically. Requires peak > NF+22dB to reject noise.
    bool gfskDetected = false;
    if (rssiOnlyCount >= 3 && rssiPeakRSSI > (scanNoiseFloor + SCAN_GFSK_CLASSIFY_DB)) {
        float spread = rssiPeakRSSI - rssiMinRSSI;
        if (spread < 25.0f) {  // SiK/RFD900 varies ~10-20dB across channels due to hop timing
            int slot = findSlot(SCAN_CLASS_GFSK_FHSS);
            if (slot >= 0) {
                if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_GFSK_FHSS) {
                    scanDetections[slot].firstSeen = now;
                    newDetectionThisSweep = true;
                }
                scanDetections[slot].classification = SCAN_CLASS_GFSK_FHSS;
                scanDetections[slot].peakRSSI = rssiPeakRSSI;
                scanDetections[slot].peakFreq = rssiPeakFreq;
                scanDetections[slot].channelCount = rssiOnlyCount;
                scanDetections[slot].lastSeen = now;
                scanDetections[slot].valid = true;
                gfskDetected = true;
            }
        }
    }
    // Path B: Cross-channel transient detection (fallback for slow/wide-spread FHSS)
    // Runs when Path A didn't produce a detection — either too few debounced channels
    // or RSSI spread too wide (hopping signal varies >15dB across channels).
    // Counts unique channels with RSSI hit in last 10 sweeps (reduced from 30 —
    // 30 sweeps accumulated too many random noise transients across 52 channels).
    // Requires 6+ channels AND peak RSSI at least NF+22dB to reject threshold-edge noise.
    // Suppressed when broadband noise is detected (same gate as Path A).
    if (!gfskDetected && !broadbandNoise && scanSweepCount >= 10) {
        int transientChCount = 0;
        float transientPeakRSSI = -200, transientPeakFreq = 0;
        float transientMinRSSI = 0;
        float transientMinFreq = 999, transientMaxFreq = 0;  // Frequency span tracking
        int transientNarrowCount = 0;  // Channels with narrowband RSSI signature
        uint32_t recentWindow = (scanSweepCount > 10) ? scanSweepCount - 10 : 0;
        
        for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
            if (scanResults[i].infrastructure) continue;
            if (scanResults[i].cadHits >= SCAN_DEBOUNCE_HITS) continue;  // Skip LoRa channels
            
            // Channel had transient RSSI hit within last 10 sweeps
            if (scanResults[i].lastTransientSweep >= recentWindow && scanResults[i].lastTransientSweep > 0) {
                transientChCount++;
                if (scanResults[i].rssiPeak > transientPeakRSSI) {
                    transientPeakRSSI = scanResults[i].rssiPeak;
                    transientPeakFreq = scanResults[i].freq;
                }
                if (transientMinRSSI == 0 || scanResults[i].rssiPeak < transientMinRSSI) {
                    transientMinRSSI = scanResults[i].rssiPeak;
                }
                // Frequency span
                if (scanResults[i].freq < transientMinFreq) transientMinFreq = scanResults[i].freq;
                if (scanResults[i].freq > transientMaxFreq) transientMaxFreq = scanResults[i].freq;
                // Narrowband ratio (BW500 ≈ BW125 means narrowband signal)
                if (!scanResults[i].isWideband) transientNarrowCount++;
            }
        }
        
        // 6+ unique channels with transient RSSI AND peak at least NF+22dB
        // (rejects weak threshold-edge noise that randomly hits different channels)
        if (transientChCount >= 6 && transientPeakRSSI > (scanNoiseFloor + SCAN_GFSK_CLASSIFY_DB)) {
            float spread = transientPeakRSSI - transientMinRSSI;
            float freqSpan = transientMaxFreq - transientMinFreq;  // MHz
            
            // Distinguish genuine FHSS from LoRa sidelobe leakage:
            // - Real FHSS (SiK/RFD900): 50 channels across 26 MHz, relatively uniform power
            // - LoRa sidelobe leakage: 3-8 channels within ~3 MHz of TX freq, steep power gradient
            //
            // Frequency span is the primary discriminator:
            //   <5 MHz = sidelobe leakage from a single strong narrowband TX
            //   ≥5 MHz = genuine frequency hopping across the band
            
            if (freqSpan < 5.0f) {
                // Narrow cluster — likely LoRa sidelobe leakage from a strong TX
                // Classify as Fixed LoRa (same as CAD-detected single-channel LoRa)
                int slot = findSlot(SCAN_CLASS_FIXED_LORA);
                if (slot >= 0) {
                    if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_FIXED_LORA) {
                        scanDetections[slot].firstSeen = now;
                        newDetectionThisSweep = true;
                    }
                    scanDetections[slot].classification = SCAN_CLASS_FIXED_LORA;
                    scanDetections[slot].peakRSSI = transientPeakRSSI;
                    scanDetections[slot].peakFreq = transientPeakFreq;
                    scanDetections[slot].channelCount = transientChCount;
                    scanDetections[slot].lastSeen = now;
                    scanDetections[slot].valid = true;
                    
                    Serial.printf("[Scanner] LoRa sidelobe: %d channels within %.1f MHz (peak %.1f dBm @ %.1f MHz)\n",
                                  transientChCount, freqSpan, transientPeakRSSI, transientPeakFreq);
                }
            } else if (spread < 25.0f) {
                // Wide spread across band with consistent power — genuine FHSS
                int slot = findSlot(SCAN_CLASS_GFSK_FHSS);
                if (slot >= 0) {
                    if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_GFSK_FHSS) {
                        scanDetections[slot].firstSeen = now;
                        newDetectionThisSweep = true;
                    }
                    scanDetections[slot].classification = SCAN_CLASS_GFSK_FHSS;
                    scanDetections[slot].peakRSSI = transientPeakRSSI;
                    scanDetections[slot].peakFreq = transientPeakFreq;
                    scanDetections[slot].channelCount = transientChCount;
                    scanDetections[slot].lastSeen = now;
                    scanDetections[slot].valid = true;
                    
                    Serial.printf("[Scanner] Slow FHSS: %d channels across %.1f MHz (peak %.1f dBm, %d%% narrowband)\n",
                                  transientChCount, freqSpan, transientPeakRSSI,
                                  transientChCount > 0 ? (transientNarrowCount * 100 / transientChCount) : 0);
                }
            }
        }
    }
    
    // Sub-threshold FHSS awareness log: if we see multi-channel RSSI activity
    // above the display threshold but below the classification threshold, log it.
    // This is the "I see something but can't commit" case — operator awareness
    // without a false-positive-prone alert. Rate-limited to once per 10 seconds.
    if (!gfskDetected && !broadbandNoise && rssiOnlyCount >= 3 &&
        rssiPeakRSSI > (scanNoiseFloor + SCAN_RSSI_THRESHOLD_DB) &&
        rssiPeakRSSI <= (scanNoiseFloor + SCAN_GFSK_CLASSIFY_DB)) {
        static uint32_t lastSubThreshLog = 0;
        if (now - lastSubThreshLog > 10000) {
            lastSubThreshLog = now;
            Serial.printf("[Scanner] Sub-threshold FHSS: %d ch active, peak=%.0f dBm (NF+%.0f) — possible drone at range\n",
                          rssiOnlyCount, rssiPeakRSSI, rssiPeakRSSI - scanNoiseFloor);
        }
    }
    
    // ISM Unknown: 1-2 RSSI-only channels
    else if (rssiOnlyCount >= 1 && rssiOnlyCount <= 2) {
        int slot = findSlot(SCAN_CLASS_ISM_UNK);
        if (slot >= 0) {
            if (!scanDetections[slot].valid || scanDetections[slot].classification != SCAN_CLASS_ISM_UNK) {
                scanDetections[slot].firstSeen = now;
            }
            scanDetections[slot].classification = SCAN_CLASS_ISM_UNK;
            scanDetections[slot].peakRSSI = rssiPeakRSSI;
            scanDetections[slot].peakFreq = rssiPeakFreq;
            scanDetections[slot].channelCount = rssiOnlyCount;
            scanDetections[slot].lastSeen = now;
            scanDetections[slot].valid = true;
        }
    }
    
    // ── Fire drone detection alert tone ──
    // Once on first detection, then repeat every 30s while any detection persists
    static uint32_t lastDroneBeep = 0;
    if (newDetectionThisSweep) {
        ui_beepDroneDetect();
        lastDroneBeep = now;
        Serial.println("[Scanner] NEW detection — drone alert tone fired");
    } else {
        // Periodic re-alert for persistent detections (every 30s)
        bool anyActive = false;
        for (int d = 0; d < 4; d++) if (scanDetections[d].valid) anyActive = true;
        if (anyActive && (now - lastDroneBeep) > 30000) {
            ui_beepDroneDetect();
            lastDroneBeep = now;
            Serial.println("[Scanner] Persistent detection — periodic alert");
        }
    }
    
    // ── Age out stale detections (not refreshed in 10s — slow FHSS needs time) ──
    for (int d = 0; d < 4; d++) {
        if (scanDetections[d].valid && (now - scanDetections[d].lastSeen) > 10000) {
            Serial.printf("[Scanner] Detection %d (%d) aged out\n", d, scanDetections[d].classification);
            scanDetections[d].valid = false;
            scanDetections[d].historyCount = 0;
            scanDetections[d].historyHead = 0;
        }
    }
    
    // ── Record RSSI history and compute trend for active detections ──
    for (int d = 0; d < 4; d++) {
        if (!scanDetections[d].valid) continue;
        
        // Push current peakRSSI into ring buffer
        ScanDetection& det = scanDetections[d];
        det.rssiHistory[det.historyHead] = det.peakRSSI;
        det.historyHead = (det.historyHead + 1) % 30;
        if (det.historyCount < 30) det.historyCount++;
        
        // Compute linear regression slope (dB per sample)
        // Then convert to dB/second using sweep rate
        if (det.historyCount >= 6) {
            // Least-squares: slope = (N*sum(x*y) - sum(x)*sum(y)) / (N*sum(x^2) - sum(x)^2)
            int N = det.historyCount;
            float sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
            for (int i = 0; i < N; i++) {
                // Read from oldest to newest
                int idx = (det.historyHead - N + i + 30) % 30;
                float x = (float)i;
                float y = det.rssiHistory[idx];
                sumX += x;
                sumY += y;
                sumXY += x * y;
                sumX2 += x * x;
            }
            float denom = (float)N * sumX2 - sumX * sumX;
            if (denom != 0) {
                float slopePerSample = ((float)N * sumXY - sumX * sumY) / denom;
                // Convert to dB/second: sweeps take ~300ms each, so ~3.3 samples/sec
                float sweepRate = (scanSweepCount > 1 && scan_getElapsedMs() > 0) ?
                    (float)scanSweepCount / ((float)scan_getElapsedMs() / 1000.0f) : 3.3f;
                det.trendSlope = slopePerSample * sweepRate;
            } else {
                det.trendSlope = 0;
            }
        } else {
            det.trendSlope = 0;
        }
    }
    
    // ── Hop-rate analysis (LoRa FHSS detections only) ──
    // Uses per-channel cadHits / sweepCount ratio to estimate FHSS hop rate.
    // Fast-hopping links (250-500Hz ELRS) revisit each channel every 128-256ms,
    // producing hit ratios ~0.5-1.0 per sweep. Slow links (25Hz) revisit every
    // ~2.5s, giving ratios ~0.05. Requires 5+ sweeps for stable estimates.
    if (scanSweepCount >= 5) {
        for (int d = 0; d < 4; d++) {
            if (!scanDetections[d].valid) { scanDetections[d].rateCategory = 0; continue; }
            if (scanDetections[d].classification != SCAN_CLASS_LORA_FHSS) {
                scanDetections[d].rateCategory = 0;
                scanDetections[d].hitRatio = 0;
                continue;
            }
            
            // Compute average cadHits/sweepCount across active CAD channels
            float totalRatio = 0;
            int cadChannels = 0;
            for (int i = 0; i < SCAN_FREQ_COUNT; i++) {
                if (!scanResults[i].active || scanResults[i].infrastructure) continue;
                if (scanResults[i].cadHits >= SCAN_DEBOUNCE_HITS) {
                    float ratio = (float)scanResults[i].cadHits / (float)scanSweepCount;
                    if (ratio > 1.0f) ratio = 1.0f;
                    totalRatio += ratio;
                    cadChannels++;
                }
            }
            
            float avgRatio = (cadChannels > 0) ? totalRatio / cadChannels : 0;
            scanDetections[d].hitRatio = avgRatio;
            
            // Map to rate category:
            // ELRS 900MHz uses ~64 hopping channels across 902-928 band.
            // 500Hz → each ch revisited every 128ms → ratio ~0.8-1.0 per 150ms sweep
            // 250Hz → revisit every 256ms → ratio ~0.5-0.7
            // 150Hz → revisit every 427ms → ratio ~0.25-0.40
            //  50Hz → revisit every 1280ms → ratio ~0.08-0.15
            //  25Hz → revisit every 2560ms → ratio ~0.03-0.07
            if (avgRatio > 0.50f) scanDetections[d].rateCategory = 4;       // 250Hz+ (FPV race)
            else if (avgRatio > 0.25f) scanDetections[d].rateCategory = 3;  // ~150Hz (FPV prox)
            else if (avgRatio > 0.10f) scanDetections[d].rateCategory = 2;  // ~50Hz (mid-range)
            else if (avgRatio > 0.02f) scanDetections[d].rateCategory = 1;  // ~25Hz (long-range)
            else scanDetections[d].rateCategory = 0;                        // Unknown
        }
    }
}

// Classification label helper (implemented in ui.cpp, declared in ui.h)
// scan_classLabel() is defined in ui.cpp

// ── Real-time scan-to-track fusion ──
// Pushes active FHSS detections as live tracks to local buffer, WebSocket, and CoT.
// Rate-limited: at most once per 2 seconds per detection slot.
// Does NOT LoRa broadcast (radio in scan mode) — that happens on scan_stop.

static void _scanPushLiveTracks() {
    uint32_t now = millis();
    
    for (int d = 0; d < 4; d++) {
        if (!scanDetections[d].valid) continue;
        // Only push FHSS detections (actual drone control links)
        if (scanDetections[d].classification != SCAN_CLASS_LORA_FHSS &&
            scanDetections[d].classification != SCAN_CLASS_GFSK_FHSS) continue;
        // Rate limit per slot
        if (now - scanLivePushTime[d] < SCAN_LIVE_PUSH_INTERVAL_MS) continue;
        scanLivePushTime[d] = now;
        
        double lat, lon, alt;
        bool haveGPS = ui_getGPS(&lat, &lon, &alt);
        
        // Build track ID (same format as scan_stop uses)
        char trackId[16];
        const char* prefix = (scanDetections[d].classification == SCAN_CLASS_LORA_FHSS) ? "FPV" : "TEL";
        snprintf(trackId, sizeof(trackId), "%s-%.0f", prefix, scanDetections[d].peakFreq);
        
        // 1. Update local track buffer (Map screen, proximity alerts)
        if (haveGPS) {
            track_update(trackId, lat, lon, 0, 0, 0, TRACK_SRC_FPV);
        }
        
        // 2. Push to connected tablets via WebSocket (WiFi runs independently of SX1262)
        extern uint8_t wsClientCount;
        if (wsClientCount > 0 && haveGPS) {
            JsonDocument fwd;
            fwd["type"] = "track_rx";
            fwd["from"] = ui_callsignSet() ? ui_getCallsign() : "SCAN";
            fwd["id"] = trackId;
            fwd["lat"] = lat;
            fwd["lon"] = lon;
            fwd["alt"] = 0;
            fwd["hdg"] = 0;
            fwd["spd"] = 0;
            fwd["src"] = (int)TRACK_SRC_FPV;
            // Extra scan metadata for PWA
            fwd["rssi"] = scanDetections[d].peakRSSI;
            fwd["freq"] = scanDetections[d].peakFreq;
            fwd["chCount"] = scanDetections[d].channelCount;
            fwd["trend"] = scanDetections[d].trendSlope;
            fwd["scanLive"] = true;
            fwd["hitRatio"] = scanDetections[d].hitRatio;
            fwd["rateCategory"] = scanDetections[d].rateCategory;
            String fwdJson;
            serializeJson(fwd, fwdJson);
            extern void broadcastAll(String& json);
            broadcastAll(fwdJson);
        }
        
        // 3. Forward to TAK via CoT bridge
        if (haveGPS) {
            cot_broadcastTrack(trackId, lat, lon, 0, TRACK_SRC_FPV);
        }
        
        Serial.printf("[ScanLive] %s %.0fdBm %.1fMHz %dch slope:%.1f rate:%d(%.0f%%)\n",
                      trackId, scanDetections[d].peakRSSI, scanDetections[d].peakFreq,
                      scanDetections[d].channelCount, scanDetections[d].trendSlope,
                      scanDetections[d].rateCategory, scanDetections[d].hitRatio * 100);
    }
}

// SD logging triggered via sd_logScanSession() in ui.cpp

void scan_stop() {
    if (!scanActive) return;
    
    // Log scan session to SD card (before radio restoration)
    sd_logScanSession();
    
    // Restore radio configuration first (needed for LoRa broadcast)
    radio.standby();
    radio.setFrequency(savedRadioConfig.freq);
    radio.setBandwidth(savedRadioConfig.bw);
    radio.setSpreadingFactor(savedRadioConfig.sf);
    radio.setCodingRate(savedRadioConfig.cr);
    radio.setOutputPower(savedRadioConfig.power);
    radio.setSyncWord(LORA_SYNC_WORD);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.setCRC(true);
    radio.setDio2AsRfSwitch(true);
    radio.setCurrentLimit(60.0f);
    radio.setDio1Action(onLoRaRx);
    startReceive();
    
    // Generate tracks, alerts, and LoRa broadcasts for drone detections
    for (int d = 0; d < 4; d++) {
        if (!scanDetections[d].valid) continue;
        if (scanDetections[d].classification != SCAN_CLASS_LORA_FHSS &&
            scanDetections[d].classification != SCAN_CLASS_GFSK_FHSS) continue;
        
        double lat, lon, alt;
        bool haveGPS = ui_getGPS(&lat, &lon, &alt);
        
        // Create FPV track at scanner's GPS position
        char trackId[16];
        const char* prefix = (scanDetections[d].classification == SCAN_CLASS_LORA_FHSS) ? "FPV" : "TEL";
        snprintf(trackId, sizeof(trackId), "%s-%.0f", prefix, scanDetections[d].peakFreq);
        
        if (haveGPS) {
            track_update(trackId, lat, lon, 0, 0, 0, TRACK_SRC_FPV);
        }
        
        // Alert on Alerts channel — marked outgoing=true to prevent notification
        // banner, message beep, and unread counter (this is self-generated, not incoming)
        uint32_t durSec = (scanDetections[d].lastSeen - scanDetections[d].firstSeen) / 1000;
        char alertMsg[140];
        const char* label = (scanDetections[d].classification == SCAN_CLASS_LORA_FHSS) ? "LoRa FHSS" : "GFSK Telem";
        const char* rateStr = "";
        if (scanDetections[d].rateCategory == 1) rateStr = " 25Hz-LR";
        else if (scanDetections[d].rateCategory == 2) rateStr = " 50Hz";
        else if (scanDetections[d].rateCategory == 3) rateStr = " 150Hz-FPV";
        else if (scanDetections[d].rateCategory == 4) rateStr = " 250Hz+Race";
        snprintf(alertMsg, sizeof(alertMsg), "SCAN: %s%s %.0fdBm %.1fMHz (%dch %lus)",
                 label, rateStr, scanDetections[d].peakRSSI, scanDetections[d].peakFreq,
                 scanDetections[d].channelCount, durSec);
        ui_addMessage("SCAN", alertMsg, true, false, GROUP_CH_ALERTS);
        
        // Broadcast track over LoRa mesh so other nodes see it
        if (haveGPS && ui_callsignSet()) {
            JsonDocument trackDoc;
            trackDoc["type"] = "track";
            trackDoc["from"] = ui_getCallsign();
            trackDoc["id"] = trackId;
            trackDoc["lat"] = lat;
            trackDoc["lon"] = lon;
            trackDoc["alt"] = 0;
            trackDoc["hdg"] = 0;
            trackDoc["spd"] = 0;
            trackDoc["src"] = TRACK_SRC_FPV;
            trackDoc["ts"] = millis();
            
            String trackJson;
            serializeJson(trackDoc, trackJson);
            
            uint8_t packet[LORA_MAX_PAYLOAD];
            int pktLen = 0;
            if (psk_isEnabled()) {
                uint8_t enc[LORA_MAX_PAYLOAD];
                int eLen = psk_encrypt((const uint8_t*)trackJson.c_str(),
                                      trackJson.length(), enc, sizeof(enc));
                if (eLen > 0) {
                    packet[0] = 0xAE;
                    memcpy(packet + 1, enc, eLen);
                    pktLen = eLen + 1;
                }
            }
            if (pktLen == 0 && (int)trackJson.length() <= LORA_MAX_PAYLOAD) {
                memcpy(packet, trackJson.c_str(), trackJson.length());
                pktLen = trackJson.length();
            }
            if (pktLen > 0) {
                enqueuePacket(packet, pktLen, false);
                Serial.printf("[Scanner] Broadcast %s via LoRa (%d bytes)\n", trackId, pktLen);
            }
        }
    }
    
    scanActive = false;
    
    int activeCount = scan_getActiveDetections();
    Serial.printf("[Scanner] Stopped — %d sweeps, %d detections, radio restored\n",
                  scanSweepCount, activeCount);
}

// ═══════════════════════════════════════════════════════════
// JAMMING DETECTION & AUTO-CHANNEL MIGRATION
// Monitors noise floor on current channel. If sustained 20+ dB
// above baseline, sweeps all 8 channels, broadcasts coordinated
// migration command to quietest alternative.
// ═══════════════════════════════════════════════════════════

// Noise floor tracking
static float  jamNoiseBaseline = -120.0f;  // Slow EMA of noise floor (dBm)
static float  jamNoiseCurrent  = -120.0f;  // Fast EMA of recent readings
static bool   jamDetected = false;
static uint32_t jamDetectStart = 0;        // When jamming was first detected
static uint32_t jamLastCheck = 0;          // Last noise floor sample time
static uint32_t jamLastAlert = 0;          // Cooldown for alerts
static uint8_t  jamSampleCount = 0;        // Warm-up counter

// jamLastVoiceActivity declared near top of file (before handleReceive)
#define JAM_VOICE_SUPPRESS_MS 8000  // Suppress jam detection for 8s after any voice packet

// Migration state declared at top of file (forward declaration block)

#define JAM_CHECK_INTERVAL_MS   500   // Sample noise floor every 500ms
#define JAM_BASELINE_ALPHA      0.02f // Slow EMA for baseline (adapts over minutes)
#define JAM_CURRENT_ALPHA       0.15f // Fast EMA for current noise (was 0.3 — too responsive to single-packet spikes)
#define JAM_THRESHOLD_DB        20.0f // dB above baseline = jamming
#define JAM_SUSTAIN_MS          10000 // Must be sustained 10s to confirm (was 3s — too
                                      // sensitive for two radios on the same desk)
#define JAM_COOLDOWN_MS         60000 // 60s between jam alerts
#define JAM_WARMUP_SAMPLES      20    // 10s of samples before detection active
// JAM_MIGRATE_COUNTDOWN_S defined at top of file

bool jam_isJammed() { return jamDetected; }

void jam_migrateCountdown(int ch, int seconds) {
    if (ch < 1 || ch > 8 || ch == ui_getChannel()) return;
    jamMigrating = true;
    jamMigrateTarget = ch;
    jamMigrateStarted = millis();
    jamMigrateTime = millis() + (seconds * 1000);
    
    char msg[80];
    snprintf(msg, sizeof(msg), "MIGRATE to CH%d (%.1fMHz) in %ds",
             ch, 906.0f + (ch - 1) * 2.5f, seconds);
    ui_addMessage("JAM", msg, false, false, GROUP_CH_ALERTS);
    Serial.printf("[JAM] Migration countdown: CH%d in %ds\n", ch, seconds);
}

// Sweep all 8 channels and return quietest (lowest RSSI)
static int _jamFindQuietChannel() {
    float bestRssi = 999.0f;
    int bestCh = -1;
    int currentCh = ui_getChannel();
    
    // Save current radio config
    float savedFreq = state.freq;
    
    for (int ch = 1; ch <= 8; ch++) {
        float freq = 906.0f + (ch - 1) * 2.5f;
        radio.standby();
        radio.setFrequency(freq);
        radio.startReceive();
        delay(5);  // AGC settle (5ms for T-Deck noise) for valid RSSI_INST
        
        // Take 4 RSSI samples, average them
        float sum = 0;
        for (int s = 0; s < 4; s++) {
            sum += radio.getRSSI(false);
            delay(1);
        }
        float avg = sum / 4.0f;
        
        Serial.printf("[JAM] CH%d (%.1fMHz): %.1f dBm%s\n", 
                      ch, freq, avg, (ch == currentCh) ? " (current)" : "");
        
        // Skip current jammed channel
        if (ch == currentCh) continue;
        
        if (avg < bestRssi) {
            bestRssi = avg;
            bestCh = ch;
        }
    }
    
    // Restore radio to current channel
    radio.standby();
    radio.setFrequency(savedFreq);
    startReceive();
    
    Serial.printf("[JAM] Quietest: CH%d at %.1f dBm\n", bestCh, bestRssi);
    return bestCh;
}

void jam_tick() {
    // Don't monitor during scan (radio is in scanner mode)
    if (scanActive) return;
    
    uint32_t now = millis();
    
    // ── Migration countdown ──
    if (jamMigrating) {
        if (now >= jamMigrateTime) {
            // Execute channel switch
            Serial.printf("[JAM] Executing migration to CH%d\n", jamMigrateTarget);
            ui_setChannel(jamMigrateTarget);
            
            char msg[64];
            snprintf(msg, sizeof(msg), "Switched to CH%d (%.1fMHz)",
                     jamMigrateTarget, 906.0f + (jamMigrateTarget - 1) * 2.5f);
            ui_addMessage("JAM", msg, false, false, GROUP_CH_ALERTS);
            ui_beepAlert();
            
            // Reset jam detection state for new channel
            jamNoiseBaseline = -120.0f;
            jamNoiseCurrent = -120.0f;
            jamDetected = false;
            jamSampleCount = 0;
            jamMigrating = false;
            jamMigrateTarget = 0;
        }
        return;  // Don't sample noise during migration countdown
    }
    
    // ── Noise floor sampling ──
    if (now - jamLastCheck < JAM_CHECK_INTERVAL_MS) return;
    jamLastCheck = now;
    
    // Read instantaneous RSSI (noise floor when no packet is being received)
    if (state.txBusy) return;  // Don't sample during TX
    
    // Suppress during ALL voice activity (TX and RX).
    // jamLastVoiceActivity is set on every voice packet sent or received
    // in the main RX handler and TX loop — no gaps, no assembly state dependency.
    // The 8-second window covers inter-packet gaps, redundancy pass transitions,
    // and post-voice EMA decay.
    if (now - jamLastVoiceActivity < JAM_VOICE_SUPPRESS_MS) {
        jamDetectStart = 0;  // Reset sustain timer
        return;
    }
    
    float rssi = radio.getRSSI(false);
    
    // Update EMAs
    if (jamSampleCount < JAM_WARMUP_SAMPLES) {
        // Warm-up: seed both EMAs with early samples
        jamSampleCount++;
        if (jamSampleCount == 1) {
            jamNoiseBaseline = rssi;
            jamNoiseCurrent = rssi;
        } else {
            jamNoiseBaseline = jamNoiseBaseline * 0.8f + rssi * 0.2f;
            jamNoiseCurrent = rssi;
        }
        return;  // Don't trigger during warm-up
    }
    
    jamNoiseCurrent = jamNoiseCurrent * (1.0f - JAM_CURRENT_ALPHA) + rssi * JAM_CURRENT_ALPHA;
    
    // Only update baseline when NOT jammed (so baseline stays at normal level)
    if (!jamDetected) {
        jamNoiseBaseline = jamNoiseBaseline * (1.0f - JAM_BASELINE_ALPHA) + rssi * JAM_BASELINE_ALPHA;
    }
    
    float delta = jamNoiseCurrent - jamNoiseBaseline;
    
    // ── Jam detection ──
    if (delta >= JAM_THRESHOLD_DB) {
        if (!jamDetected) {
            if (jamDetectStart == 0) {
                jamDetectStart = now;  // Start sustain timer
            } else if (now - jamDetectStart >= JAM_SUSTAIN_MS) {
                // CONFIRMED: sustained jamming
                jamDetected = true;
                
                if (now - jamLastAlert >= JAM_COOLDOWN_MS) {
                    jamLastAlert = now;
                    
                    char alertMsg[120];
                    snprintf(alertMsg, sizeof(alertMsg),
                             "RF JAM on CH%d! NF jumped %.0f→%.0fdBm (+%.0fdB)",
                             ui_getChannel(), jamNoiseBaseline, jamNoiseCurrent, delta);
                    ui_addMessage("JAM", alertMsg, false, false, GROUP_CH_ALERTS);
                    ui_beepAlert();
                    
                    Serial.printf("[JAM] DETECTED: baseline=%.1f current=%.1f delta=%.1f\n",
                                  jamNoiseBaseline, jamNoiseCurrent, delta);
                    
                    // Sweep all channels to find quietest alternative
                    int bestCh = _jamFindQuietChannel();
                    
                    if (bestCh > 0 && bestCh != ui_getChannel()) {
                        // Broadcast migration command to all mesh peers
                        JsonDocument migDoc;
                        migDoc["type"] = "migrate";
                        migDoc["from"] = ui_callsignSet() ? ui_getCallsign() : "ANON";
                        migDoc["ch"] = bestCh;
                        migDoc["countdown"] = JAM_MIGRATE_COUNTDOWN_S;
                        migDoc["ts"] = millis();
                        migDoc["hops"] = 0;
                        
                        String migJson;
                        serializeJson(migDoc, migJson);
                        
                        uint8_t packet[LORA_MAX_PAYLOAD];
                        int pktLen = 0;
                        if (psk_isEnabled()) {
                            uint8_t enc[LORA_MAX_PAYLOAD];
                            int eLen = psk_encrypt((const uint8_t*)migJson.c_str(),
                                                   migJson.length(), enc, sizeof(enc));
                            if (eLen > 0) {
                                packet[0] = 0xAE;
                                memcpy(packet + 1, enc, eLen);
                                pktLen = eLen + 1;
                            }
                        }
                        if (pktLen == 0 && (int)migJson.length() <= LORA_MAX_PAYLOAD) {
                            memcpy(packet, migJson.c_str(), migJson.length());
                            pktLen = migJson.length();
                        }
                        if (pktLen > 0) {
                            enqueuePacket(packet, pktLen, true);  // High priority
                            Serial.printf("[JAM] Broadcast: migrate to CH%d in %ds\n",
                                          bestCh, JAM_MIGRATE_COUNTDOWN_S);
                        }
                        
                        // Start own countdown
                        jam_migrateCountdown(bestCh, JAM_MIGRATE_COUNTDOWN_S);
                    }
                }
            }
        }
    } else {
        // Noise returned to normal
        jamDetectStart = 0;
        if (jamDetected) {
            jamDetected = false;
            char msg[80];
            snprintf(msg, sizeof(msg), "JAM cleared on CH%d — NF back to %.0fdBm",
                     ui_getChannel(), jamNoiseCurrent);
            ui_addMessage("JAM", msg, false, false, GROUP_CH_ALERTS);
            Serial.printf("[JAM] Cleared: NF=%.1f baseline=%.1f\n", jamNoiseCurrent, jamNoiseBaseline);
        }
    }
}

// ═══════════════════════════════════════════════════════════
// SETUP & LOOP
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// WIFI MODE MANAGEMENT
// Toggle between AP (standalone), STA (join tablet hotspot), or OFF.
// Single radio — never both simultaneously. Persisted to LittleFS.
// ═══════════════════════════════════════════════════════════

static void _wifiSaveMode() {
    File f = LittleFS.open("/wifi_mode.cfg", "w");
    if (f) { f.write(wifiModeGD); f.close(); }
}

static void _wifiLoadMode() {
    File f = LittleFS.open("/wifi_mode.cfg", "r");
    if (f) { wifiModeGD = f.read(); f.close(); }
    if (wifiModeGD > WIFI_MODE_GD_OFF) wifiModeGD = WIFI_MODE_GD_AP;
}

static void _wifiSaveSTA() {
    File f = LittleFS.open("/wifi_sta.cfg", "w");
    if (f) {
        f.write((uint8_t*)staSSID, 33);
        f.write((uint8_t*)staPass, 65);
        f.close();
    }
}

static void _wifiLoadSTA() {
    File f = LittleFS.open("/wifi_sta.cfg", "r");
    if (f) {
        f.read((uint8_t*)staSSID, 33);
        f.read((uint8_t*)staPass, 65);
        f.close();
        staSSID[32] = '\0';
        staPass[64] = '\0';
    }
}

static bool mdnsRunning = false;

static void _mdnsStart() {
    if (mdnsRunning) return;
    if (MDNS.begin("griddown-radio")) {
        MDNS.addService("ws", "tcp", WS_PORT);
        MDNS.addServiceTxt("ws", "tcp", "type", "radio");
        MDNS.addServiceTxt("ws", "tcp", "fw", "6.67.0");
        if (ui_callsignSet()) {
            MDNS.addServiceTxt("ws", "tcp", "callsign", ui_getCallsign());
        }
        mdnsRunning = true;
        Serial.printf("[mDNS] Registered: griddown-radio.local (%s)\n",
                      WiFi.localIP().toString().c_str());
    } else {
        Serial.println("[mDNS] Failed to start");
    }
}

static void _mdnsStop() {
    if (!mdnsRunning) return;
    MDNS.end();
    mdnsRunning = false;
    Serial.println("[mDNS] Stopped");
}

// ── Per-device AP password ──
// Generated once on first boot from the hardware RNG and persisted. Uses an
// unambiguous alphabet (no 0/O/1/l/I) because operators read this off the
// T-Deck screen and type it into a tablet.
static char apPassword[WIFI_AP_PASS_LEN + 1] = {0};

static void _wifiLoadOrCreateApPass() {
    if (apPassword[0] != '\0') return;   // Already loaded this boot

    // Try to load existing password
    File f = LittleFS.open(WIFI_AP_PASS_FILE, "r");
    if (f) {
        size_t n = f.readBytes(apPassword, WIFI_AP_PASS_LEN);
        f.close();
        apPassword[n] = '\0';
        // WPA2 requires >= 8 characters; anything shorter is unusable
        if (n >= 8) return;
        apPassword[0] = '\0';            // Corrupt/short — regenerate below
    }

    // Generate a new random password
    static const char alphabet[] =
        "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    const size_t alphaLen = sizeof(alphabet) - 1;
    uint8_t rnd[WIFI_AP_PASS_LEN];
    esp_fill_random(rnd, sizeof(rnd));
    for (int i = 0; i < WIFI_AP_PASS_LEN; i++) {
        apPassword[i] = alphabet[rnd[i] % alphaLen];
    }
    apPassword[WIFI_AP_PASS_LEN] = '\0';

    File w = LittleFS.open(WIFI_AP_PASS_FILE, "w");
    if (w) {
        w.write((const uint8_t*)apPassword, WIFI_AP_PASS_LEN);
        w.close();
        Serial.println("[WiFi] Generated a new per-device AP password.");
        Serial.println("[WiFi] Find it on the T-Deck: Settings > WiFi.");
    } else {
        // Cannot persist — the password would change every boot, which is worse
        // than useless. Surface it loudly rather than failing silently.
        Serial.println("[WiFi] WARNING: could not persist AP password to LittleFS.");
        Serial.println("[WiFi] It will change on every reboot until this is fixed.");
    }
}

// Accessor for the UI (Settings > WiFi) so the operator can read the password.
const char* wifi_getApPassword() {
    _wifiLoadOrCreateApPass();
    return apPassword;
}

static void _wifiStartAP() {
    _wifiLoadOrCreateApPass();
    WiFi.mode(WIFI_AP);
    WiFi.softAP(WIFI_AP_SSID, apPassword, WIFI_AP_CHANNEL);
    staConnected = false;
    Serial.printf("[WiFi] AP mode: %s (IP: %s)\n", WIFI_AP_SSID, WiFi.softAPIP().toString().c_str());
}

static void _wifiStartSTA(bool bootWait) {
    if (staSSID[0] == '\0') {
        Serial.println("[WiFi] STA mode — no credentials configured, falling back to AP");
        wifiModeGD = WIFI_MODE_GD_AP;
        _wifiSaveMode();
        _wifiStartAP();
        return;
    }
    WiFi.mode(WIFI_STA);
    WiFi.setHostname("griddown-radio");
    WiFi.begin(staSSID, staPass);
    staConnected = false;
    staLastAttempt = millis();
    staRetryCount = 0;
    staRetryInterval = 10000;
    Serial.printf("[WiFi] STA mode: connecting to '%s'%s\n", staSSID,
                  bootWait ? " (blocking 10s)..." : " (background)...");
    
    // Only block at boot — runtime switches connect in background via _wifiTick()
    if (bootWait) {
        uint32_t start = millis();
        while (WiFi.status() != WL_CONNECTED && millis() - start < 10000) {
            delay(200);
            esp_task_wdt_reset();
        }
    }
    
    if (WiFi.status() == WL_CONNECTED) {
        staConnected = true;
        Serial.printf("[WiFi] STA connected. IP: %s (CH%d)\n",
                      WiFi.localIP().toString().c_str(), WiFi.channel());
        _mdnsStart();
    } else if (bootWait) {
        Serial.printf("[WiFi] STA connect timeout — will retry in background\n");
    }
}

static void _wifiStartOFF() {
    WiFi.mode(WIFI_OFF);
    staConnected = false;
    Serial.println("[WiFi] OFF — WiFi disabled, BLE/LoRa only");
}

// Called from setup() — reads config and starts appropriate mode
static void _wifiInit() {
    _wifiLoadMode();
    _wifiLoadSTA();
    
    switch (wifiModeGD) {
        case WIFI_MODE_GD_STA:  _wifiStartSTA(true); break;  // Boot: block up to 10s
        case WIFI_MODE_GD_OFF:  _wifiStartOFF(); break;
        default:                _wifiStartAP();   break;
    }
}

// Called from loop() — non-blocking STA reconnect with exponential backoff
static void _wifiTick() {
    if (wifiModeGD != WIFI_MODE_GD_STA) return;
    
    bool nowConnected = (WiFi.status() == WL_CONNECTED);
    
    // Detect disconnect
    if (staConnected && !nowConnected) {
        staConnected = false;
        staRetryCount = 0;
        staRetryInterval = 10000;
        _mdnsStop();
        Serial.println("[WiFi] STA disconnected — reconnecting...");
    }
    
    // Detect fresh connect
    if (!staConnected && nowConnected) {
        staConnected = true;
        staRetryCount = 0;
        Serial.printf("[WiFi] STA reconnected. IP: %s (CH%d)\n",
                      WiFi.localIP().toString().c_str(), WiFi.channel());
        _mdnsStart();
    }
    
    // Retry logic (non-blocking)
    if (!staConnected && millis() - staLastAttempt > staRetryInterval) {
        staLastAttempt = millis();
        staRetryCount++;
        
        // Exponential backoff: 10s, 30s, 60s, then cap at 60s
        if (staRetryCount <= 1) staRetryInterval = 10000;
        else if (staRetryCount <= 2) staRetryInterval = 30000;
        else staRetryInterval = 60000;
        
        Serial.printf("[WiFi] STA retry #%d (next in %lus)...\n",
                      staRetryCount, staRetryInterval / 1000);
        WiFi.reconnect();
    }
}

// Runtime mode switch — called from Settings UI
void wifi_setMode(uint8_t mode) {
    if (mode == wifiModeGD) return;
    
    // Stop mDNS before mode change
    _mdnsStop();
    
    // Tear down current mode
    if (wifiModeGD == WIFI_MODE_GD_AP) {
        WiFi.softAPdisconnect(true);
    } else if (wifiModeGD == WIFI_MODE_GD_STA) {
        WiFi.disconnect(true);
    }
    
    wifiModeGD = mode;
    _wifiSaveMode();
    
    // Start new mode
    switch (mode) {
        case WIFI_MODE_GD_STA:  _wifiStartSTA(false); break;  // Runtime: non-blocking
        case WIFI_MODE_GD_OFF:  _wifiStartOFF(); break;
        default:                _wifiStartAP();   break;
    }
    
    // Restart WebSocket server (binds to new interface)
    extern WebSocketsServer ws;
    ws.close();
    if (mode != WIFI_MODE_GD_OFF) {
        ws.begin();
        Serial.printf("[WS] Server restarted on port %d\n", WS_PORT);
    }
}

void wifi_setSTACredentials(const char* ssid, const char* pass) {
    strncpy(staSSID, ssid, 32); staSSID[32] = '\0';
    strncpy(staPass, pass, 64); staPass[64] = '\0';
    _wifiSaveSTA();
    Serial.printf("[WiFi] STA credentials saved: SSID='%s'\n", staSSID);
}

void wifi_clearSTACredentials() {
    memset(staSSID, 0, sizeof(staSSID));
    memset(staPass, 0, sizeof(staPass));
    LittleFS.remove("/wifi_sta.cfg");
    Serial.println("[WiFi] STA credentials cleared");
}

uint8_t wifi_getMode() { return wifiModeGD; }
bool wifi_staIsConnected() { return staConnected; }
const char* wifi_getSTASSID() { return staSSID; }
IPAddress wifi_getSTAIP() { return WiFi.localIP(); }

const char* wifi_modeLabel(uint8_t mode) {
    switch (mode) {
        case WIFI_MODE_GD_AP:  return "AP";
        case WIFI_MODE_GD_STA: return "STA";
        case WIFI_MODE_GD_OFF: return "OFF";
        default:               return "?";
    }
}

// ═══════════════════════════════════════════════════════════
// CHANNEL SCAN ON STARTUP
// ═══════════════════════════════════════════════════════════

static void _startupChannelScan() {
    Serial.println("[ChScan] Scanning channels 1-8...");
    
    ui_drawChannelScanProgress(0);  // Show "Scanning..." screen
    
    radio.clearDio1Action();
    radio.standby();
    
    ChScanResult chResults[8];
    memset(chResults, 0, sizeof(chResults));
    
    // Scan each channel: 10 CAD probes + RSSI measurement
    for (int ch = 0; ch < 8; ch++) {
        float freq = 906.0f + ch * 2.5f;
        radio.standby();
        radio.setFrequency(freq);
        radio.setBandwidth(125.0f);
        radio.setSpreadingFactor(10);
        
        // CAD probes — detect LoRa preambles
        for (int p = 0; p < 10; p++) {
            if (radio.scanChannel() == RADIOLIB_LORA_DETECTED) {
                chResults[ch].cadHits++;
            }
            delay(5);
        }
        
        // RSSI measurement (median of 5)
        radio.startReceive();
        delay(5);
        float samples[5];
        for (int s = 0; s < 5; s++) {
            samples[s] = radio.getRSSI(false);
            delayMicroseconds(600);
        }
        radio.standby();
        for (int a = 0; a < 4; a++)
            for (int b = a + 1; b < 5; b++)
                if (samples[b] < samples[a]) { float t = samples[a]; samples[a] = samples[b]; samples[b] = t; }
        chResults[ch].peakRSSI = samples[2];
        chResults[ch].active = (chResults[ch].cadHits >= 2);
        
        ui_drawChannelScanProgress((ch + 1) * 100 / 8);
        
        Serial.printf("[ChScan] CH%d (%.1f MHz): CAD=%d RSSI=%.0f %s\n",
                      ch + 1, freq, chResults[ch].cadHits, chResults[ch].peakRSSI,
                      chResults[ch].active ? "ACTIVE" : "quiet");
        
        esp_task_wdt_reset();
    }
    
    // Display results via UI
    int activeCount = 0, bestCh = -1, bestHits = 0;
    for (int ch = 0; ch < 8; ch++) {
        if (chResults[ch].active) {
            activeCount++;
            if (chResults[ch].cadHits > bestHits) {
                bestHits = chResults[ch].cadHits;
                bestCh = ch + 1;
            }
        }
    }
    
    ui_drawChannelScanResults(chResults, activeCount, bestCh);
    
    Serial.printf("[ChScan] Complete: %d active, strongest=CH%d\n",
                  activeCount, bestCh > 0 ? bestCh : ui_getChannel());
    
    // Restore radio to operating config
    radio.standby();
    radio.setFrequency(state.freq);
    radio.setBandwidth(state.bw);
    radio.setSpreadingFactor(state.sf);
    radio.setCodingRate(state.cr);
    radio.setOutputPower(state.power);
    radio.setSyncWord(LORA_SYNC_WORD);
    radio.setPreambleLength(LORA_PREAMBLE);
    radio.setCRC(true);
    radio.setDio2AsRfSwitch(true);
    radio.setCurrentLimit(60.0f);
    radio.setDio1Action(onLoRaRx);
    startReceive();
    
    delay(2500);  // Show results for 2.5 seconds
}

void setup() {
    Serial.begin(115200);
    // Wait for USB CDC serial to be ready (ESP32-S3 needs time to enumerate)
    uint32_t serialWait = millis();
    while (!Serial && (millis() - serialWait < 3000)) { delay(10); }
    delay(500);
    
    Serial.println("\n═══════════════════════════════════════");
    Serial.println("  GridDown Radio — T-Deck LoRa Firmware");
    Serial.printf("  v%s | 915 MHz | BlackAtlas LLC\n", GRIDDOWN_FW_VERSION);
    Serial.println("═══════════════════════════════════════\n");
    
    // CRITICAL: Enable peripheral power on T-Deck (GPIO10)
    // Without this, the radio, display, keyboard, and GPS won't receive power
    pinMode(BOARD_POWERON, OUTPUT);
    digitalWrite(BOARD_POWERON, HIGH);
    delay(100); // Allow peripherals to power up
    Serial.println("[Power] Peripherals enabled (GPIO10 HIGH)");
    
    // CRITICAL: Deselect ALL SPI devices before initializing any of them.
    // The T-Deck shares one SPI bus (MOSI=41, MISO=38, SCK=40) across
    // TFT (CS=12), Radio (CS=9), and SD card (CS=39). Without deselecting,
    // SPI init commands meant for one device can corrupt another.
    pinMode(LORA_CS, OUTPUT);
    digitalWrite(LORA_CS, HIGH);
    pinMode(TFT_CS, OUTPUT);
    digitalWrite(TFT_CS, HIGH);
    pinMode(39, OUTPUT);    // SD card CS
    digitalWrite(39, HIGH);
    Serial.println("[SPI] All chip selects deasserted");
    
    state.bootTime = millis();
    
    // Initialize battery ADC hardware
    analogReadResolution(12);
    analogSetPinAttenuation(BAT_ADC, ADC_11db);  // 0-3.1V range for 2:1 divider
    
    // Initialize display + LittleFS (must be before battery multiplier load)
    ui_init();
    
    // Load persisted battery calibration multiplier (after LittleFS is mounted)
    {
        File f = LittleFS.open("/batcal.cfg", "r");
        if (f && f.size() == sizeof(float)) {
            float saved;
            f.read((uint8_t*)&saved, sizeof(float));
            if (saved >= 1.5f && saved <= 3.5f) {
                batAdcMultiplier = saved;
                Serial.printf("[Battery] Calibration loaded: %.3f\n", batAdcMultiplier);
            }
            f.close();
        }
    }
    
    // First battery read (blocking) — uses loaded multiplier
    updateBattery();
    Serial.printf("[Battery] %d%% (%.2fV, mul=%.2f)%s\n", state.batteryPct, batVoltage,
                  batAdcMultiplier, state.usbCharging ? " [USB]" : "");
    
    // Record boot event (increments counter, logs reset reason to LittleFS + SD)
    boot_recordStartup();
    
    // Apply saved channel frequency to radio state
    state.freq = ui_getChannelFreq();
    Serial.printf("[Radio] Channel %d → %.1f MHz\n", ui_getChannel(), state.freq);
    
    // Initialize LoRa radio — uses SPI bus already initialized by TFT_eSPI
    if (!initRadio()) {
        Serial.println("[FATAL] Radio init failed. Halting.");
        while (true) { delay(1000); }  // WDT not yet armed; safe infinite halt
        // NOTE: If WDT init is ever moved before this point, add esp_task_wdt_reset() here
    }
    
    // Initialize WiFi (AP, STA, or OFF based on persisted config)
    _wifiInit();

    // Remote ID detection: init tracks + ring. Capture stays OFF until the
    // operator selects a source that uses it (decision A: 900 MHz is default).
    rid_init();
    rid_ringInit(&ridRing);
    rid_dutySetRequested(RID_SCAN_WINDOW_MS, RID_SCAN_PERIOD_MS);
    
    // Start WebSocket server (unless WiFi is OFF)
    if (wifiModeGD != WIFI_MODE_GD_OFF) {
        ws.begin();
        ws.onEvent(onWebSocketEvent);
        Serial.printf("[WS] Server started on port %d\n", WS_PORT);
    }
    
    // Start listening for LoRa packets BEFORE BLE init
    startReceive();
    
    // Generate ephemeral ECDH P-256 keypair for per-peer session keys
    eph_init();
    
    // Start BLE Nordic UART Service (after WiFi+LoRa are stable)
    bleInit();
    
    // Boot diagnostic summary
    Serial.println("\n══════ BOOT SUMMARY ══════");
    Serial.printf("  Radio: CH%d (%.1f MHz) SF%d BW%.0f %ddBm\n", 
                  ui_getChannel(), state.freq, state.sf, state.bw, state.power);
    Serial.printf("  Callsign: %s\n", ui_callsignSet() ? ui_getCallsign() : "(not set)");
    Serial.printf("  PSK: %s\n", psk_isEnabled() ? "ENABLED" : "disabled");
    Serial.printf("  EPH: %s\n", eph_isReady() ? "P-256 ECDH ready" : "disabled");
    Serial.printf("  FHOP: %s\n", psk_isEnabled() ? "Armed (waiting for GPS sync)" : "disabled (no PSK)");
    if (wifiModeGD == WIFI_MODE_GD_AP) {
        Serial.printf("  WiFi: AP %s (IP: %s)\n", WIFI_AP_SSID, WiFi.softAPIP().toString().c_str());
    } else if (wifiModeGD == WIFI_MODE_GD_STA) {
        Serial.printf("  WiFi: STA '%s' (%s)\n", staSSID,
                      staConnected ? WiFi.localIP().toString().c_str() : "connecting...");
        if (mdnsRunning) Serial.println("  mDNS: griddown-radio.local");
    } else {
        Serial.println("  WiFi: OFF");
    }
    Serial.printf("  BLE: %s\n", bleInitialized ? "OK" : "FAILED");
    Serial.printf("  Battery: %d%%\n", state.batteryPct);
    Serial.printf("  Boot #%lu, Last reset: %s\n", boot_getCount(), boot_getLastResetReason());
    Serial.println("══════════════════════════\n");
    
    // Quick channel scan — shows which channels have LoRa activity
    _startupChannelScan();
    
    // Initialize task watchdog — auto-reboots if loop() blocks for >30s
    // (SPI bus contention, I2S timeout, LittleFS stall, etc.)
    esp_task_wdt_init(30, true);  // 30s timeout, panic=true → auto-reboot
    esp_task_wdt_add(NULL);       // Add current task (Arduino loopTask)
    Serial.println("[WDT] Task watchdog enabled (30s timeout)");
    
    Serial.println("[Ready] Waiting for connections...\n");
}

// ════════════════════════════════════════════════════════════
// REMOTE ID DETECTION — platform glue
// ════════════════════════════════════════════════════════════
// The parsing and tracking logic lives in remoteid.cpp (no platform deps, host
// testable). This section owns only the ESP-IDF plumbing: promiscuous WiFi
// capture, BLE observer scanning, the duty-cycle scheduler, and the LoRa
// starvation watchdog.
//
// CRITICAL ORDERING PRINCIPLE: LoRa RX/TX is the product. Remote ID capture is
// the lowest priority consumer of CPU and radio time, and is disabled
// automatically if LoRa RX latency degrades (see _ridWatchdog).

static bool     ridWifiActive   = false;    // Promiscuous capture engaged
static bool     ridBleActive    = false;    // BLE observer scanning
static bool     ridDisabledByWatchdog = false;
static uint32_t ridLastLoraRxMs = 0;        // Fed by handleReceive()
static uint32_t ridFramesParsed = 0;
static uint32_t ridBadFrames    = 0;

// Auto-disable backstop: a quiet channel is normal, so the stall threshold is
// deliberately conservative (see RID_LORA_STALL_MS, hoisted above).

// Promiscuous callback. Runs in the WiFi task: filter, copy, return. No parsing,
// no allocation, no logging.
static void IRAM_ATTR _ridPromiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;              // Management frames only
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (!pkt) return;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len < 40 || len > 1024) return;

    // 802.11 management header is 24 bytes; beacons add a 12-byte fixed body
    // (timestamp, beacon interval, capability) before the IE list.
    const uint8_t* payload = pkt->payload;
    uint8_t subtype = (uint8_t)((payload[0] >> 4) & 0x0F);
    uint16_t ieOffset;
    if (subtype == 0x08) {          // Beacon
        ieOffset = 24 + 12;
    } else if (subtype == 0x0D) {   // Action (carries NaN service discovery)
        ieOffset = 24;
    } else {
        return;                     // Not a frame class that carries Remote ID
    }
    if (len <= ieOffset) return;

    // Cheap pre-filter: only enqueue if an ASTM vendor IE is actually present.
    // This keeps the ring free for useful frames in dense RF environments.
    uint16_t off = 0;
    uint16_t ridLen = rid_extractFromBeaconIe(payload + ieOffset,
                                              (uint16_t)(len - ieOffset), &off);
    if (ridLen == 0) return;

    rid_ringPush(&ridRing, payload + ieOffset + off, ridLen,
                 (subtype == 0x08) ? RID_TRANSPORT_WIFI_BEACON : RID_TRANSPORT_WIFI_NAN,
                 pkt->rx_ctrl.rssi);
}

// Enable/disable promiscuous capture. Safe to call repeatedly.
// NOTE: promiscuous capture in AP mode observes the AP's own channel. This is
// fine here and is why the feature works with the tablet connected:
// WIFI_AP_CHANNEL is 6, which is where Remote ID WiFi traffic lives.
static void _ridSetWifiCapture(bool on) {
    if (on == ridWifiActive) return;
    if (on) {
        if (wifiModeGD == WIFI_MODE_GD_OFF) return;   // No radio to borrow
        esp_wifi_set_promiscuous_rx_cb(&_ridPromiscuousCb);
        if (esp_wifi_set_promiscuous(true) == ESP_OK) {
            ridWifiActive = true;
            Serial.println("[RID] WiFi capture ON (channel follows AP/STA)");
        }
    } else {
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        ridWifiActive = false;
        Serial.println("[RID] WiFi capture OFF");
    }
}

// ── BLE observer — COMPILED OUT BY DEFAULT IN THIS BUILD ──
// platformio.ini defines CONFIG_BT_NIMBLE_ROLE_OBSERVER_DISABLED (and CENTRAL),
// which is a deliberate footprint decision: NimBLE without the central/observer
// roles saves roughly 60 KB flash and 30 KB RAM versus Bluedroid, and the T-Deck
// only needs the peripheral role for the tablet NUS link. With those roles
// disabled, NimBLEScan / NimBLEAdvertisedDeviceCallbacks / NimBLEDevice::getScan()
// do not exist.
//
// Consequence: Remote ID capture over BLE is unavailable in the default build.
// This is a smaller loss than it sounds, because the WiFi path carries Remote ID
// at near-full rate — WIFI_AP_CHANNEL is 6, which is where Remote ID WiFi Beacon
// and NaN traffic lives, so promiscuous capture needs no channel compromise.
// Drones that broadcast ONLY over Bluetooth will be missed.
//
// TO ENABLE BLE Remote ID capture:
//   1. Remove -DCONFIG_BT_NIMBLE_ROLE_OBSERVER_DISABLED from platformio.ini
//   2. Rebuild and MEASURE flash/RAM headroom before shipping
//   3. Re-measure the achieved BLE duty cycle with the tablet connected
// Deliberately not done here: it changes the BLE stack footprint in a build that
// is already large, and that is a decision to make with numbers in hand.
#if !defined(CONFIG_BT_NIMBLE_ROLE_OBSERVER_DISABLED)
class RidScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
    void onResult(NimBLEAdvertisedDevice* dev) override {
        if (!dev) return;
        const uint8_t* pl = dev->getPayload();
        size_t plLen = dev->getPayloadLength();
        if (!pl || plLen < 6) return;
        uint16_t off = 0;
        uint16_t ridLen = rid_extractFromBleAdv(pl, (uint16_t)plLen, &off);
        if (ridLen == 0) return;
        rid_ringPush(&ridRing, pl + off, ridLen,
                     RID_TRANSPORT_BLE_LEGACY, (int8_t)dev->getRSSI());
    }
};
static RidScanCallbacks* ridScanCb = nullptr;

static void _ridSetBleCapture(bool on) {
    if (on == ridBleActive) return;
    NimBLEScan* scan = NimBLEDevice::getScan();
    if (!scan) return;
    if (on) {
        if (!ridScanCb) ridScanCb = new RidScanCallbacks();
        scan->setAdvertisedDeviceCallbacks(ridScanCb, /*wantDuplicates*/ true);
        scan->setActiveScan(false);      // PASSIVE — never transmit scan requests
        scan->setInterval(160);          // 100 ms
        scan->setWindow(160);            // 100 ms — continuous within our window
        scan->start(0, nullptr, false);  // Indefinite; gated by our duty cycle
        ridBleActive = true;
        Serial.println("[RID] BLE observer ON (passive)");
    } else {
        scan->stop();
        ridBleActive = false;
        Serial.println("[RID] BLE observer OFF");
    }
}
#else
// Observer role unavailable — WiFi-only Remote ID capture.
static void _ridSetBleCapture(bool on) {
    if (on && !ridBleActive) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            Serial.println("[RID] BLE capture unavailable (NimBLE observer role disabled at build time)");
            Serial.println("[RID] WiFi Remote ID capture is active; BLE-only drones will be missed");
        }
    }
    ridBleActive = false;    // Never claim a capability we do not have
}
#endif

// Drain the ring and update the track table. Low priority; bounded work per call
// so it can never monopolise the loop.
static void _ridDrainRing() {
    RidRingSlot slot;
    int budget = 8;                       // Bounded work per invocation
    while (budget-- > 0 && rid_ringPop(&ridRing, &slot)) {
        int idx = rid_processPayload(slot.data, slot.len, slot.transport,
                                     slot.rssi, millis());
        if (idx >= 0) ridFramesParsed++; else ridBadFrames++;
    }
}

// Announce a track to the mesh and to TAK. Direct-only (decision C): Remote ID
// arrives at ~1 Hz per drone and relaying it would flood the channel.
static void _ridAnnounce(int idx) {
    const RemoteIdTrack* t = rid_getTrack(idx);
    if (!t) return;

    // LoRa mesh alert — compact, rate limited by rid_shouldSendAlert()
    JsonDocument d;
    d["t"]  = "rid";                      // Short key: airtime matters
    d["id"] = t->uasId;
    if (t->hasPosition) { d["la"] = t->lat; d["lo"] = t->lon; d["al"] = t->altGeoM; }
    if (t->hasOperator) { d["ola"] = t->opLat; d["olo"] = t->opLon; }
    d["ut"] = t->uaType;
    String payload; serializeJson(d, payload);
    // Encrypt with the group PSK and enqueue at BULK priority (yields to DMs,
    // voice, beacons and ACKs). The earlier version passed a String straight to
    // enqueuePacketPrio and would have transmitted UNENCRYPTED.
    _img_encryptAndSend(payload);

    // TAK/CoT — reuse the existing track bridge
    if (cot_isEnabled() && t->hasPosition) {
        cot_broadcastTrack(t->uasId, t->lat, t->lon, t->altGeoM, TRACK_SRC_REMOTEID);
    }

    // Tablet
    if (wsClientCount > 0) {
        JsonDocument w;
        w["type"]      = "remoteid";
        w["uasId"]     = t->uasId;
        w["operatorId"]= t->operatorId;
        w["uaType"]    = t->uaType;
        w["rssi"]      = t->rssi;
        if (t->hasPosition) { w["lat"] = t->lat; w["lon"] = t->lon; w["alt"] = t->altGeoM;
                              w["speedCms"] = t->speedCms; w["heading"] = t->headingDeg; }
        if (t->hasOperator) { w["opLat"] = t->opLat; w["opLon"] = t->opLon; }
        w["transports"]  = t->transportMask;
        w["correlated"]  = t->correlated900;
        String wj; serializeJson(w, wj);
        broadcastAll(wj);
    }

    rid_markAlertSent(idx, millis());
    Serial.printf("[RID] Announced %s%s\n", t->uasId, t->correlated900 ? " (+900MHz)" : "");
}

// Auto-disable if Remote ID capture appears to be starving LoRa. Failing toward
// being a radio is always the correct trade for this product.
static void _ridWatchdog() {
    if (!rid_sourceUsesRemoteId(rid_getSource())) return;
    if (ridDisabledByWatchdog) return;
    if (ui_getPeerCount() == 0) return;             // Quiet channel is not evidence
    if (ridLastLoraRxMs == 0) return;
    if (millis() - ridLastLoraRxMs > RID_LORA_STALL_MS) {
        Serial.println("[RID] LoRa RX stalled — disabling Remote ID capture (watchdog)");
        _ridSetWifiCapture(false);
        _ridSetBleCapture(false);
        ridDisabledByWatchdog = true;
        ui_addMessage("SYSTEM", "Remote ID disabled: LoRa priority", true, false, GROUP_CH_ALERTS);
    }
}

// Called from loop(). Owns the duty cycle and the announce pass.
void rid_tick() {
    static uint32_t windowStart = 0;
    static bool     inScanWindow = false;

    bool want = rid_sourceUsesRemoteId(rid_getSource()) && !ridDisabledByWatchdog;

    if (!want) {
        if (ridWifiActive) _ridSetWifiCapture(false);
        if (ridBleActive)  _ridSetBleCapture(false);
        inScanWindow = false;
        return;
    }

    uint32_t now = millis();
    if (windowStart == 0) windowStart = now;
    uint32_t phase = now - windowStart;

    // WiFi capture runs continuously: it costs no extra radio time because the
    // radio is already parked on the AP/STA channel.
    if (!ridWifiActive) _ridSetWifiCapture(true);

    // BLE observer is duty-cycled: it genuinely contends with advertising, the
    // tablet connection, and WiFi coexistence.
    if (!inScanWindow && phase < RID_SCAN_WINDOW_MS) {
        _ridSetBleCapture(true);
        inScanWindow = true;
    } else if (inScanWindow && phase >= RID_SCAN_WINDOW_MS) {
        _ridSetBleCapture(false);
        inScanWindow = false;
        rid_dutyRecord(RID_SCAN_WINDOW_MS, RID_SCAN_PERIOD_MS);
    }
    if (phase >= RID_SCAN_PERIOD_MS) windowStart = now;

    _ridDrainRing();
    rid_ageTracks(now);

    // Fusion (decision D)
    bool has900 = rid_sourceUses900(rid_getSource()) && (scan_getActiveDetections() > 0);
    rid_correlate900(has900, now);

    // Announce new or significantly moved tracks
    for (int i = 0; i < RID_MAX_TRACKS; i++) {
        if (rid_getTrack(i) && rid_shouldSendAlert(i, now)) _ridAnnounce(i);
    }
}

// Re-enable after a watchdog trip (operator action via the UI or serial).
void rid_clearWatchdog() {
    ridDisabledByWatchdog = false;
    Serial.println("[RID] Watchdog cleared");
}
bool rid_isWatchdogTripped() { return ridDisabledByWatchdog; }
uint32_t rid_ringDroppedCount() { return rid_ringDropped(&ridRing); }
uint32_t rid_parsedCount()      { return ridFramesParsed; }
void rid_noteLoraRx()           { ridLastLoraRxMs = millis(); }

void loop() {
    rid_tick();   // Remote ID capture, duty cycle, fusion, announce
    // Service WebSocket
    ws.loop();
    
    // WiFi STA reconnect handler (non-blocking, exponential backoff)
    _wifiTick();
    
    // ── Serial command parser (for PuTTY / terminal access) ──
    // Accumulates chars until newline, then processes command
    static char serialCmd[80] = {0};
    static int serialCmdLen = 0;
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (serialCmdLen > 0) {
                serialCmd[serialCmdLen] = '\0';
                if (strcmp(serialCmd, "!dfu") == 0 || strcmp(serialCmd, "!boot") == 0) {
                    Serial.println("[System] Entering USB bootloader via serial command...");
                    Serial.println("[System] Run: pio run -e tdeck -t upload");
                    Serial.println("[System] Power cycle to cancel.");
                    Serial.flush();
                    delay(200);
                    SET_PERI_REG_MASK(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
                    esp_restart();
                }
                else if (strcmp(serialCmd, "!reboot") == 0) {
                    Serial.println("[System] Rebooting...");
                    Serial.flush();
                    delay(100);
                    esp_restart();
                }
                else if (strcmp(serialCmd, "!info") == 0) {
                    Serial.printf("[Info] Firmware: %s\n", GRIDDOWN_FW_VERSION);
                    Serial.printf("[Info] Uptime: %lus\n", millis() / 1000);
                    Serial.printf("[Info] Free heap: %lu\n", (uint32_t)ESP.getFreeHeap());
                    Serial.printf("[Info] TX: %lu  RX: %lu  Errors: %lu\n",
                                  state.txCount, state.rxCount, state.txErrors);
                    Serial.printf("[Info] Freq: %.1f MHz  Battery: %d%%\n",
                                  state.freq, state.batteryPct);
                    Serial.printf("[Info] Boots: %lu  Last reset: %s\n",
                                  boot_getCount(), boot_getLastResetReason());
                }
                else if (strcmp(serialCmd, "!help") == 0) {
                    Serial.println("[Help] Serial commands:");
                    Serial.println("  !dfu    — Reboot into USB bootloader (flash mode)");
                    Serial.println("  !boot   — Same as !dfu");
                    Serial.println("  !reboot — Soft reboot");
                    Serial.println("  !info   — Show firmware/radio status");
                    Serial.println("  !tak IP:PORT — Set TAK server (e.g. !tak 192.168.1.5:8087)");
                    Serial.println("  !tak off — Disconnect and clear TAK server");
                    Serial.println("  !tak     — Show current TAK server status");
                    Serial.println("  !wipe local — Wipe THIS device (immediate, no confirmation)");
                    Serial.println("  !wipe <callsign> — Send remote wipe to target");
                    Serial.println("  !batcal X.XX — Set battery ADC multiplier (default 2.27)");
                    Serial.println("  !batcal — Show current multiplier and raw ADC mV");
                    Serial.println("  !sendimg <path> — Send image from SD/LittleFS over LoRa (test)");
                    Serial.println("  !sendimg test — Send a synthetic 5KB test pattern");
                    Serial.println("  !sendimg cancel — Cancel in-progress image transfer");
                    Serial.println("  !imgstat — Show image TX state and progress");
                    Serial.println("  !help   — This help");
                }
                else if (strcmp(serialCmd, "!wipe local") == 0) {
                    Serial.println("[WIPE] Local wipe via serial command");
                    wipe_execute("Local wipe (serial)");
                    // Does not return
                }
                else if (strncmp(serialCmd, "!wipe ", 6) == 0 && serialCmdLen > 6) {
                    const char* target = serialCmd + 6;
                    uint32_t epoch = ui_getUtcEpoch();
                    if (epoch == 0) {
                        Serial.println("[WIPE] Cannot send remote wipe — no GPS time");
                    } else if (!psk_isEnabled()) {
                        Serial.println("[WIPE] Cannot send remote wipe — no PSK configured");
                    } else if (!ui_callsignSet()) {
                        Serial.println("[WIPE] Cannot send remote wipe — callsign not set");
                    } else {
                        char sigB64[28];
                        if (wipe_sign(ui_getCallsign(), target, epoch, sigB64, sizeof(sigB64))) {
                            JsonDocument wipeDoc;
                            wipeDoc["type"] = "wipe";
                            wipeDoc["from"] = ui_getCallsign();
                            wipeDoc["to"] = target;
                            wipeDoc["ts"] = epoch;
                            wipeDoc["sig"] = sigB64;
                            String wipeJson;
                            serializeJson(wipeDoc, wipeJson);
                            
                            uint8_t pkt[LORA_MAX_PAYLOAD];
                            int pktLen = 0;
                            if (psk_isEnabled()) {
                                uint8_t enc[LORA_MAX_PAYLOAD];
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
                                Serial.printf("[WIPE] Remote wipe sent to %s (epoch=%u)\n", target, epoch);
                                char alertMsg[64];
                                snprintf(alertMsg, sizeof(alertMsg), "WIPE sent to %s", target);
                                ui_addMessage("SYSTEM", alertMsg, true, false, GROUP_CH_ALERTS);
                            } else {
                                Serial.println("[WIPE] Failed to encrypt wipe command");
                            }
                        } else {
                            Serial.println("[WIPE] Failed to sign wipe command");
                        }
                    }
                }
                else if (strncmp(serialCmd, "!tak", 4) == 0) {
                    if (serialCmdLen == 4 || strcmp(serialCmd + 4, " ") == 0) {
                        // !tak — show status
                        if (cot_getTakPort() > 0) {
                            Serial.printf("[CoT-TCP] Server: %s:%d %s\n",
                                cot_getTakHost(), cot_getTakPort(),
                                cot_takConnected() ? "(connected)" : "(disconnected)");
                        } else {
                            Serial.println("[CoT-TCP] No TAK server configured");
                        }
                    }
                    else if (strcmp(serialCmd + 4, " off") == 0) {
                        cot_clearTakServer();
                    }
                    else if (serialCmd[4] == ' ') {
                        // Parse host:port
                        char host[64] = {0};
                        uint16_t port = 8087;  // Default FreeTAK port
                        char* arg = serialCmd + 5;
                        char* colon = strrchr(arg, ':');
                        if (colon) {
                            *colon = '\0';
                            port = atoi(colon + 1);
                            if (port == 0) port = 8087;
                        }
                        strncpy(host, arg, sizeof(host) - 1);
                        if (strlen(host) > 0) {
                            cot_setTakServer(host, port);
                            if (!cot_isEnabled()) {
                                cot_setMode(COT_MODE_TCP);
                                Serial.println("[CoT] Auto-enabled CoT bridge (TCP mode)");
                            }
                        }
                    }
                }
                else if (strncmp(serialCmd, "!batcal ", 8) == 0 && serialCmdLen > 8) {
                    float newMul = atof(serialCmd + 8);
                    if (newMul >= 1.5f && newMul <= 3.5f) {
                        batAdcMultiplier = newMul;
                        batEMA = -1.0f;  // Reset EMA to re-settle with new multiplier
                        // Persist to LittleFS
                        File f = LittleFS.open("/batcal.cfg", "w");
                        if (f) { f.write((uint8_t*)&batAdcMultiplier, sizeof(float)); f.close(); }
                        Serial.printf("[Battery] Multiplier set to %.3f (persisted)\n", batAdcMultiplier);
                    } else {
                        Serial.printf("[Battery] Invalid multiplier %.2f (must be 1.50-3.50)\n", newMul);
                    }
                }
                else if (strcmp(serialCmd, "!batcal") == 0) {
                    // Show current calibration and raw ADC reading
                    uint32_t raw = analogReadMilliVolts(BAT_ADC);
                    Serial.printf("[Battery] Multiplier: %.3f (default: %.3f)\n", batAdcMultiplier, BAT_ADC_MULTIPLIER_DEFAULT);
                    Serial.printf("[Battery] Raw ADC: %lu mV, computed voltage: %.2fV\n", raw, raw * batAdcMultiplier / 1000.0f);
                    Serial.printf("[Battery] Current: %d%% (%.2fV)%s\n", state.batteryPct, batVoltage,
                                  state.usbCharging ? " [USB]" : "");
                    Serial.println("[Battery] To calibrate: charge fully, unplug USB, read voltage with multimeter,");
                    Serial.println("          then: !batcal <multimeter_V * 1000 / raw_mV>");
                }
                else if (strcmp(serialCmd, "!sendimg test") == 0) {
                    // Synthesize a 5KB test pattern in a persistent buffer.
                    // Buffer must remain valid for the entire transfer.
                    static uint8_t testImgBuf[5000];
                    static bool testImgInit = false;
                    if (!testImgInit) {
                        // Synthetic JPEG-like pattern: SOI markers, deterministic body
                        testImgBuf[0] = 0xFF; testImgBuf[1] = 0xD8;
                        for (int i = 2; i < 4998; i++) {
                            testImgBuf[i] = (uint8_t)((i * 7 + 13) & 0xFF);
                        }
                        testImgBuf[4998] = 0xFF; testImgBuf[4999] = 0xD9;
                        testImgInit = true;
                    }
                    if (img_beginTx(testImgBuf, 5000, "test.jpg")) {
                        Serial.println("[ImgTx] Test transfer started (5000 bytes, 28 chunks)");
                    } else {
                        Serial.println("[ImgTx] Failed to start (transfer in progress?)");
                    }
                }
                else if (strcmp(serialCmd, "!sendimg cancel") == 0) {
                    img_cancelTx();
                    Serial.println("[ImgTx] Cancel requested");
                }
                else if (strncmp(serialCmd, "!sendimg ", 9) == 0) {
                    // Send a JPEG from the SD card by path (no tablet required).
                    const char* path = serialCmd + 9;
                    while (*path == ' ') path++;
                    ImgSendResult r = img_loadAndSendFromSD(path);
                    if (r == IMG_SEND_OK) {
                        Serial.printf("[ImgTx] Sending %s (id=%04X, %d chunks)\n",
                                      path, imgTx.xferId, imgTx.totalChunks);
                    } else {
                        Serial.printf("[ImgTx] Send failed: %s — %s\n",
                                      path, img_sendResultStr(r));
                    }
                }
                else if (strcmp(serialCmd, "!imgstat") == 0) {
                    const char* stateStr = "?";
                    switch (imgTx.state) {
                        case IMG_TX_IDLE:      stateStr = "IDLE"; break;
                        case IMG_TX_HEADER:    stateStr = "SENDING_HDR"; break;
                        case IMG_TX_CHUNKS:    stateStr = "SENDING_CHUNKS"; break;
                        case IMG_TX_DONE_SENT: stateStr = "AWAITING_NACK"; break;
                        case IMG_TX_RETRY:     stateStr = "RETRY"; break;
                        case IMG_TX_COMPLETE:  stateStr = "COMPLETE"; break;
                        case IMG_TX_ABORTED:   stateStr = "ABORTED"; break;
                    }
                    Serial.printf("[ImgTx] State: %s\n", stateStr);
                    if (img_isTxActive()) {
                        Serial.printf("[ImgTx] id=%04X file=%s size=%d chunks=%d/%d retry=%d/3 progress=%d%%\n",
                                      imgTx.xferId, imgTx.filename, (int)imgTx.dataLen,
                                      imgTx.nextChunkIdx, imgTx.totalChunks,
                                      imgTx.retryRound, img_txProgress());
                    }
                    Serial.printf("[ImgRx] Active receives: %d/%d\n",
                                  img_rxActiveCount(), IMG_RX_MAX_SLOTS);
                    img_rxPrintStatus();
                }
                serialCmdLen = 0;
            }
        } else if (serialCmdLen < 78 && c >= 32) {
            serialCmd[serialCmdLen++] = c;
        }
    }
    
    // ── SCAN MODE BYPASS ──
    // When scanning, the SX1262 is exclusively owned by the scanner.
    // Skip all normal radio operations but keep UI, battery, and WDT alive.
    if (scanActive) {
        scan_tick();
        ui_tick();
        updateBattery();  // Split-iteration: ~600μs per call, self-rate-limited
        // Record battery history at reduced rate during scan
        static uint32_t lastScanBat = 0;
        if (millis() - lastScanBat >= 5000) {
            lastScanBat = millis();
            ui_recordBattery(state.batteryPct);
        }
        esp_task_wdt_reset();
        delay(1);
        return;  // Skip handleReceive, processQueue, beacon, voice, compose
    }
    
    // Check for received LoRa packets
    handleReceive();
    
    // Process TX queue (normal duty cycle)
    processQueue();
    
    // Expire stale voice RX slots (shows "Voice lost" banner if incomplete)
    voice_checkRxTimeouts();
    
    // Battery: split-iteration sampling (2 samples per loop, ~600μs, self-rate-limited to 10s cycles)
    updateBattery();
    
    // Periodic status broadcast + battery history recording (every STATUS_INTERVAL_MS)
    static uint32_t lastStatus = 0;
    if (millis() - lastStatus >= STATUS_INTERVAL_MS) {
        lastStatus = millis();
        ui_recordBattery(state.batteryPct);
        if (wsClientCount > 0) {
            sendStatus(0xFF);
        }
    }
    
    // Standalone UI tick (display, keyboard, GPS)
    ui_tick();
    
    // Jamming detection (runs every 500ms, skipped during scan)
    jam_tick();
    
    // Image transfer state machine (Phase 3) — drives chunk emission at BULK rate
    img_txTick();
    
    // Image RX timeout watchdog (Phase 4) — frees stale slots after 60s no progress
    img_rxTick();
    
    // Channel change detection — reconfigure radio if channel changed in Settings
    // Also handles frequency hopping: fhop_tick computes the current hop channel
    // from PSK + GPS time, and if it differs from the radio's current frequency,
    // the radio is reconfigured to the new channel.
    fhop_tick();
    float targetFreq = fhop_getCurrentFreq();
    if (fabsf(state.freq - targetFreq) > 0.1f) {
        state.freq = targetFreq;
        radio.standby();
        radio.setFrequency(state.freq);
        startReceive();
        if (fhop_isActive()) {
            Serial.printf("[Radio] FHOP → CH%d (%.1f MHz)\n", fhop_getCurrentChannel(), state.freq);
        } else {
            Serial.printf("[Radio] Channel → CH%d (%.1f MHz)\n", fhop_getCurrentChannel(), state.freq);
        }
    }
    
    // Beacon TX — announce presence periodically (standalone only)
    // Base interval: 30s. Jitter: ±5s (randomized per cycle to prevent
    // synchronized beaconing when multiple devices boot at the same time).
    // Backoff: skip beacon if TX queue is more than half full (>8 of 16 slots)
    // to avoid starving user messages and relays.
    static uint32_t lastBeacon = 0;
    static uint32_t beaconInterval = 30000;
    if (wsClientCount == 0 && ui_callsignSet() && millis() - lastBeacon >= beaconInterval) {
        // Randomize next interval: 25-35s (base 30 ± 5s jitter)
        beaconInterval = 25000 + (esp_random() % 10001);
        
        if (txQueueCount > TX_QUEUE_SIZE / 2) {
            // Queue congested — skip this beacon cycle, try again next interval
            lastBeacon = millis();
            Serial.printf("[Beacon] Deferred — TX queue %d/%d\n", txQueueCount, TX_QUEUE_SIZE);
        } else {
            lastBeacon = millis();
            JsonDocument beaconDoc;
            beaconDoc["type"] = "beacon";
            beaconDoc["from"] = ui_getCallsign();
            beaconDoc["ts"] = millis();
            beaconDoc["bat"] = state.batteryPct;
            double lat, lon, alt;
            if (ui_getGPS(&lat, &lon, &alt)) {
                beaconDoc["lat"] = lat;
                beaconDoc["lon"] = lon;
            }
            // Include ECDH public key for ephemeral key agreement
            if (eph_isReady()) {
                beaconDoc["pk"] = eph_getPublicKeyBase64();
            }
            String beaconJson;
            serializeJson(beaconDoc, beaconJson);
            
            uint8_t packet[LORA_MAX_PAYLOAD];
            int pktLen = 0;
            if (psk_isEnabled()) {
                uint8_t encrypted[LORA_MAX_PAYLOAD];
                int encLen = psk_encrypt((const uint8_t*)beaconJson.c_str(), beaconJson.length(),
                                        encrypted, sizeof(encrypted));
                if (encLen > 0) {
                    packet[0] = 0xAE;
                    memcpy(packet + 1, encrypted, encLen);
                    pktLen = encLen + 1;
                }
            }
            if (pktLen == 0 && (int)beaconJson.length() <= LORA_MAX_PAYLOAD) {
                memcpy(packet, beaconJson.c_str(), beaconJson.length());
                pktLen = beaconJson.length();
            }
            if (pktLen > 0) enqueuePacket(packet, pktLen, false);
            Serial.printf("[Beacon] TX as %s on CH%d (next in %lums)\n", 
                          ui_getCallsign(), ui_getChannel(), beaconInterval);
            cot_broadcastPLI();  // Forward own position to TAK if CoT enabled
        }
    }
    
    // DM retry system — resend unacknowledged direct messages
    if (retryMsgId != 0 && retryLen > 0 && retryCount < RETRY_MAX) {
        if (millis() - retryLastSend >= RETRY_INTERVAL_MS) {
            retryLastSend = millis();
            retryCount++;
            enqueuePacket(retryBuf, retryLen, true);  // High priority
            Serial.printf("[Retry] DM id=%d attempt %d/%d\n", retryMsgId, retryCount, RETRY_MAX);
        }
    } else if (retryMsgId != 0 && retryCount >= RETRY_MAX) {
        Serial.printf("[Retry] DM id=%d gave up after %d attempts\n", retryMsgId, RETRY_MAX);
        ui_markFailed(retryMsgId);
        retryMsgId = 0;
        retryLen = 0;
        retryCount = 0;
    }
    
    // Check for composed messages from keyboard
    if (ui_hasComposedMessage()) {
        const char* text = ui_getComposeText();
        if (text && strlen(text) > 0) {
            // If GridDown is connected via WebSocket, send compose event
            if (wsClientCount > 0) {
                JsonDocument compDoc;
                compDoc["type"] = "compose";
                compDoc["text"] = text;
                compDoc["ch"] = ui_getActiveGroupChannel();
                // Include GPS if available
                double lat, lon, alt;
                if (ui_getGPS(&lat, &lon, &alt)) {
                    compDoc["gps_lat"] = lat;
                    compDoc["gps_lon"] = lon;
                }
                String json;
                serializeJson(compDoc, json);
                broadcastAll(json);
            } else {
                // Standalone mode: encrypt (if PSK set) and TX via LoRa
                const char* recipient = ui_getSelectedRecipient();
                const char* sender = ui_callsignSet() ? ui_getCallsign() : "ANON";
                
                // ── TAK server command: /tak IP:PORT or /tak off ──
                if (strncmp(text, "/tak ", 5) == 0) {
                    char arg[64] = {0};
                    strncpy(arg, text + 5, sizeof(arg) - 1);
                    // Trim trailing whitespace
                    int l = strlen(arg);
                    while (l > 0 && arg[l-1] == ' ') arg[--l] = '\0';
                    
                    if (strcasecmp(arg, "off") == 0) {
                        cot_clearTakServer();
                        ui_addMessage("SYSTEM", "TAK server cleared", false, false);
                    } else {
                        char host[64] = {0};
                        uint16_t port = 8087;
                        char* colon = strrchr(arg, ':');
                        if (colon) {
                            *colon = '\0';
                            port = atoi(colon + 1);
                            if (port == 0) port = 8087;
                        }
                        strncpy(host, arg, sizeof(host) - 1);
                        if (strlen(host) > 0) {
                            cot_setTakServer(host, port);
                            if (!cot_isEnabled()) cot_setMode(COT_MODE_TCP);
                            char msg[80];
                            snprintf(msg, sizeof(msg), "TAK server: %s:%d", host, port);
                            ui_addMessage("SYSTEM", msg, false, false);
                        }
                    }
                }
                // ── Waypoint command: /wp Name [lat lon] ──
                else if (strncmp(text, "/wp ", 4) == 0) {
                    char wpName[20] = {0};
                    double wpLat = 0, wpLon = 0;
                    // Try parsing: /wp Name lat lon
                    int parsed = sscanf(text + 4, "%19s %lf %lf", wpName, &wpLat, &wpLon);
                    if (parsed >= 1 && strlen(wpName) > 0) {
                        // If no coords provided, use GPS
                        if (parsed < 3 || (wpLat == 0 && wpLon == 0)) {
                            double lat, lon, alt;
                            if (ui_getGPS(&lat, &lon, &alt)) {
                                wpLat = lat; wpLon = lon;
                            }
                        }
                        if (wpLat != 0 || wpLon != 0) {
                            // Store locally (idempotent — Map W key may have already added it)
                            wp_add(wpName, wpLat, wpLon, WP_ICON_GENERIC, sender);
                            
                            // Build LoRa waypoint packet
                            JsonDocument wpDoc;
                            wpDoc["type"] = "waypoint";
                            wpDoc["from"] = sender;
                            wpDoc["name"] = wpName;
                            wpDoc["lat"] = wpLat;
                            wpDoc["lon"] = wpLon;
                            wpDoc["icon"] = WP_ICON_GENERIC;
                            wpDoc["ts"] = millis();
                            wpDoc["hops"] = 0;
                            
                            String wpJson;
                            serializeJson(wpDoc, wpJson);
                            
                            uint8_t packet[LORA_MAX_PAYLOAD];
                            int pktLen = 0;
                            if (psk_isEnabled()) {
                                uint8_t enc[LORA_MAX_PAYLOAD];
                                int eLen = psk_encrypt((const uint8_t*)wpJson.c_str(),
                                                      wpJson.length(), enc, sizeof(enc));
                                if (eLen > 0) {
                                    packet[0] = 0xAE;
                                    memcpy(packet + 1, enc, eLen);
                                    pktLen = eLen + 1;
                                }
                            }
                            if (pktLen == 0 && (int)wpJson.length() <= LORA_MAX_PAYLOAD) {
                                memcpy(packet, wpJson.c_str(), wpJson.length());
                                pktLen = wpJson.length();
                            }
                            if (pktLen > 0) {
                                enqueuePacket(packet, pktLen, false);
                                Serial.printf("[WP] Broadcast: %s at %.5f,%.5f\n", wpName, wpLat, wpLon);
                            }
                        }
                    }
                    // Add sent message to UI
                    char sentLabel[32];
                    snprintf(sentLabel, sizeof(sentLabel), "You");
                    ui_addMessage(sentLabel, text, true, false, GROUP_CH_TACTICAL);
                    
                } else {
                // ── Normal message TX ──
                // Check for duress PIN before sending
                char txText[200];
                strncpy(txText, text, sizeof(txText) - 1);
                txText[sizeof(txText) - 1] = '\0';
                bool isDuress = duress_checkAndStrip(txText);
                
                bool isDM = (strcmp(recipient, "*") != 0);
                
                JsonDocument txDoc;
                txDoc["type"] = "smsg";
                txDoc["from"] = sender;
                txDoc["to"] = recipient;
                txDoc["text"] = txText;  // Use stripped text (PIN removed if duress)
                txDoc["ts"] = millis();
                txDoc["hops"] = 0;
                txDoc["ch"] = ui_getActiveGroupChannel();
                if (isDuress) txDoc["duress"] = true;  // Silent flag — stripped before display on RX
                
                // Assign msgId for ACK tracking (DM retry + group broadcast receipts)
                uint16_t msgId = ui_nextMsgId();
                txDoc["id"] = msgId;
                
                // ── E2E inner encryption for DMs with ECDH session key ──
                // Text is encrypted with per-pair session key, then base64-encoded
                // and placed in the "text" field. The "e2e" flag tells the receiver
                // to decrypt the inner layer before displaying.
                // Outer PSK encryption still wraps everything for mesh relay.
                // Messages >50 chars fall back to PSK-only (LoRa payload constraint).
                bool usedE2E = false;
                if (isDM && eph_hasSessionKey(recipient) && strlen(txText) <= 50) {
                    const uint8_t* sk = eph_getSessionKey(recipient);
                    uint8_t e2eBuf[128];
                    int e2eLen = e2e_encrypt(sk, (const uint8_t*)txText, strlen(txText),
                                            e2eBuf, sizeof(e2eBuf));
                    if (e2eLen > 0) {
                        String e2eB64 = b64Encode(e2eBuf, e2eLen);
                        txDoc["text"] = e2eB64;
                        txDoc["e2e"] = 1;
                        usedE2E = true;
                        Serial.printf("[E2E] DM to %s: %d chars → %d bytes E2E\n",
                                      recipient, (int)strlen(txText), e2eLen);
                    }
                } else if (isDM && eph_hasSessionKey(recipient) && strlen(txText) > 50) {
                    Serial.printf("[E2E] DM to %s: %d chars exceeds 50-char E2E limit, PSK-only\n",
                                  recipient, (int)strlen(txText));
                }
                
                String txJson;
                serializeJson(txDoc, txJson);
                
                uint8_t packet[LORA_MAX_PAYLOAD];
                int pktLen = 0;
                
                if (psk_isEnabled()) {
                    uint8_t encrypted[LORA_MAX_PAYLOAD];
                    int encLen = psk_encrypt((const uint8_t*)txJson.c_str(), txJson.length(),
                                            encrypted, sizeof(encrypted));
                    if (encLen > 0) {
                        packet[0] = 0xAE;
                        memcpy(packet + 1, encrypted, encLen);
                        pktLen = encLen + 1;
                        Serial.printf("[PSK] Encrypted %d bytes → %d bytes\n", txJson.length(), pktLen);
                    }
                }
                
                if (pktLen == 0) {
                    String b64 = b64Encode((const uint8_t*)txJson.c_str(), txJson.length());
                    pktLen = b64Decode(b64.c_str(), packet, LORA_MAX_PAYLOAD);
                }
                
                if (pktLen > 0) {
                    enqueuePacket(packet, pktLen, isDM);  // DMs get high priority
                    
                    // Store DM for retry
                    if (isDM && pktLen <= LORA_MAX_PAYLOAD) {
                        memcpy(retryBuf, packet, pktLen);
                        retryLen = pktLen;
                        retryMsgId = msgId;
                        retryLastSend = millis();
                        retryCount = 0;
                        Serial.printf("[DM] Queued id=%d to %s (retry enabled)\n", msgId, recipient);
                    }
                }
                
                char sentLabel[32];
                if (strcmp(recipient, "*") == 0) {
                    snprintf(sentLabel, sizeof(sentLabel), "You");
                } else {
                    snprintf(sentLabel, sizeof(sentLabel), "You>%s", recipient);
                }
                ui_addMessage(sentLabel, txText, true, usedE2E);  // Show stripped text locally
                ui_setLastMsgId(msgId);  // Tag message with ID for delivery tracking
                if (isDM) {
                    // DM retry is handled above
                } else {
                    // Group broadcast — record how many active peers should ACK
                    int activePeers = ui_getActivePeerCount();
                    if (activePeers > 0) {
                        ui_setGroupAckTotal(msgId, (uint8_t)activePeers);
                        Serial.printf("[GRP-ACK] Broadcast id=%d expecting %d peer ACKs\n", msgId, activePeers);
                    }
                }
                sd_exportDeadDrop(recipient, txText);  // Dead drop copy
            }
            ui_clearCompose();
        }
    }
    }
    
    // Feed task watchdog + small yield for non-compose path
    // (compose path already yielded via ui_clearCompose)
    
    // Voice PTT TX
    // Range + Balanced: sends all parts, then repeats the entire set once for redundancy
    // Clarity: sends all parts once (single pass, no redundancy)
    static int voiceTxPass = 0;  // 0=first pass, 1=repeat pass
    if (voice_hasTxPacket()) {
        jamLastVoiceActivity = millis();  // Suppress jam detection during voice TX
        const uint8_t* voicePkt = voice_getTxBuf();
        int voiceLen = voice_getTxLen();
        
        if (voicePkt && voiceLen > 0) {
            uint8_t packet[LORA_MAX_PAYLOAD];
            int pktLen = 0;
            
            if (psk_isEnabled()) {
                uint8_t enc[LORA_MAX_PAYLOAD];
                int eLen = psk_encrypt(voicePkt, voiceLen, enc, sizeof(enc));
                if (eLen > 0) {
                    packet[0] = 0xAE;
                    memcpy(packet + 1, enc, eLen);
                    pktLen = eLen + 1;
                }
            }
            
            if (pktLen == 0) {
                memcpy(packet, voicePkt, voiceLen);
                pktLen = voiceLen;
            }
            
            if (pktLen > 0 && pktLen <= LORA_MAX_PAYLOAD) {
                enqueuePacket(packet, pktLen, true);
            }
            
            voice_advanceTx();
            
            if (!voice_hasTxPacket()) {
                if (voiceTxPass == 0 && voice_useRedundancy()) {
                    // First pass done — rewind for redundancy pass (Range + Balanced)
                    voiceTxPass = 1;
                    voice_rewindTx();
                    Serial.printf("[Voice] Pass 1 done, starting redundancy pass\n");
                } else {
                    // Done (either redundancy pass complete, or Clarity single-pass)
                    const char* passLabel = voiceTxPass > 0 ? "x2 redundancy" : "single pass";
                    voiceTxPass = 0;
                    Serial.printf("[Voice] All %d parts sent (%s, %dbps)\n", 
                                  voice_getTxPartsTotal(), passLabel,
                                  voice_getCodecBitrate());
                    voice_clearTx();
                }
            }
        }
    }
    
    // Feed task watchdog + small yield
    esp_task_wdt_reset();
    delay(1);
}
