// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
// Build: g++ -std=c++17 -o test_crypto_hardening test_crypto_hardening.cpp \
//          -lmbedcrypto
//
// Verifies the security-hardening changes:
//   1. HKDF-SHA256 against the official RFC 5869 Appendix A test vectors
//   2. FHOP channel derivation: range, determinism, key/slot sensitivity, distribution
//   3. Duress PIN: salted-hash storage, scan-and-strip, constant-time compare,
//      no plaintext retention, length rules, legacy migration
//   4. AP password: length, alphabet (no ambiguous glyphs), uniqueness
//   5. PSK KCV: non-reversible, stable, differs across keys

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

// ── Test infra ──
static int passed = 0, failed = 0;
static std::vector<std::string> failures;
#define ASSERT(c, d) do { if (c) { printf("  [PASS] %s\n", d); passed++; } \
    else { printf("  [FAIL] %s  (line %d)\n", d, __LINE__); failed++; failures.push_back(d); } } while(0)
#define SECTION(n) printf("\n-- %s --\n", n)

static std::string hex(const uint8_t* p, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) { s += h[p[i] >> 4]; s += h[p[i] & 15]; }
    return s;
}
static std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> v;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        v.push_back((uint8_t)strtol(s.substr(i, 2).c_str(), nullptr, 16));
    return v;
}

// ═══════════════════════════════════════════════════════════
// CODE UNDER TEST — mirrors the firmware implementations exactly
// ═══════════════════════════════════════════════════════════

static bool _hkdfSha256(const uint8_t* salt, size_t saltLen,
                        const uint8_t* ikm,  size_t ikmLen,
                        const uint8_t* info, size_t infoLen,
                        uint8_t* out, size_t outLen) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md || outLen == 0 || outLen > 255 * 32) return false;

    uint8_t zeroSalt[32] = {0};
    if (!salt || saltLen == 0) { salt = zeroSalt; saltLen = 32; }

    uint8_t prk[32];
    if (mbedtls_md_hmac(md, salt, saltLen, ikm, ikmLen, prk) != 0) return false;

    uint8_t t[32];
    size_t tLen = 0, done = 0;
    uint8_t counter = 1;
    bool ok = true;

    while (done < outLen) {
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        if (mbedtls_md_setup(&ctx, md, 1) != 0 ||
            mbedtls_md_hmac_starts(&ctx, prk, sizeof(prk)) != 0 ||
            (tLen && mbedtls_md_hmac_update(&ctx, t, tLen) != 0) ||
            (infoLen && mbedtls_md_hmac_update(&ctx, info, infoLen) != 0) ||
            mbedtls_md_hmac_update(&ctx, &counter, 1) != 0 ||
            mbedtls_md_hmac_finish(&ctx, t) != 0) {
            mbedtls_md_free(&ctx); ok = false; break;
        }
        mbedtls_md_free(&ctx);
        size_t chunk = (outLen - done < 32) ? (outLen - done) : 32;
        memcpy(out + done, t, chunk);
        done += chunk; tLen = 32; counter++;
    }
    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
    if (!ok) memset(out, 0, outLen);
    return ok;
}

static bool _ctEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

// FHOP derivation (mirrors _fhopDeriveChannel)
static int fhopDerive(const uint8_t pskKey[32], uint32_t slot) {
    const uint8_t slotBytes[4] = {
        (uint8_t)(slot & 0xFF), (uint8_t)((slot >> 8) & 0xFF),
        (uint8_t)((slot >> 16) & 0xFF), (uint8_t)((slot >> 24) & 0xFF)
    };
    static const char* FHOP_SALT = "GridDown-FHOP-v1";
    uint8_t okm[4] = {0};
    if (!_hkdfSha256((const uint8_t*)FHOP_SALT, strlen(FHOP_SALT),
                     pskKey, 32, slotBytes, sizeof(slotBytes),
                     okm, sizeof(okm))) return 0;
    uint32_t v = ((uint32_t)okm[0]) | ((uint32_t)okm[1] << 8) |
                 ((uint32_t)okm[2] << 16) | ((uint32_t)okm[3] << 24);
    return (int)(v % 8) + 1;
}

// ── Duress (mirrors firmware) ──
#define DURESS_SALT_LEN 16
#define DURESS_HASH_LEN 32
#define DURESS_PIN_MIN  4
#define DURESS_PIN_MAX  8

struct DuressState {
    uint8_t salt[DURESS_SALT_LEN] = {0};
    uint8_t hash[DURESS_HASH_LEN] = {0};
    uint8_t pinLen = 0;
    bool    set = false;
};

static bool duressHashPin(const char* pin, size_t pinLen,
                          const uint8_t* salt, uint8_t* out) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return false;
    return mbedtls_md_hmac(md, salt, DURESS_SALT_LEN,
                           (const uint8_t*)pin, pinLen, out) == 0;
}

// Deterministic pseudo-random salt for reproducible tests
static void fakeFillRandom(uint8_t* buf, size_t n, uint32_t seed) {
    for (size_t i = 0; i < n; i++) { seed = seed * 1103515245u + 12345u; buf[i] = (uint8_t)(seed >> 16); }
}

static bool duressSetPin(DuressState& st, const char* pin, uint32_t seed = 7) {
    if (!pin) return false;
    size_t len = strlen(pin);
    if (len < DURESS_PIN_MIN || len > DURESS_PIN_MAX) return false;
    for (size_t i = 0; i < len; i++) if (pin[i] < '0' || pin[i] > '9') return false;
    fakeFillRandom(st.salt, DURESS_SALT_LEN, seed);
    if (!duressHashPin(pin, len, st.salt, st.hash)) return false;
    st.pinLen = (uint8_t)len; st.set = true;
    return true;
}

static bool duressCheckAndStrip(DuressState& st, char* text) {
    if (!st.set || !text || st.pinLen == 0) return false;
    size_t len = strlen(text);
    if (len < st.pinLen) return false;
    uint8_t cand[DURESS_HASH_LEN];
    for (size_t i = 0; i + st.pinLen <= len; i++) {
        bool allDigits = true;
        for (uint8_t j = 0; j < st.pinLen; j++)
            if (text[i+j] < '0' || text[i+j] > '9') { allDigits = false; break; }
        if (!allDigits) continue;
        if (!duressHashPin(text + i, st.pinLen, st.salt, cand)) continue;
        if (!_ctEqual(cand, st.hash, DURESS_HASH_LEN)) continue;
        memmove(text + i, text + i + st.pinLen, strlen(text + i + st.pinLen) + 1);
        if (i > 0 && text[i-1] == ' ' && text[i] == ' ')
            memmove(text + i, text + i + 1, strlen(text + i + 1) + 1);
        size_t lead = 0;
        while (text[lead] == ' ') lead++;
        if (lead) memmove(text, text + lead, strlen(text + lead) + 1);
        size_t nlen = strlen(text);
        while (nlen > 0 && text[nlen-1] == ' ') text[--nlen] = '\0';
        return true;
    }
    return false;
}

// ── AP password generation (mirrors firmware) ──
#define WIFI_AP_PASS_LEN 12
static std::string genApPassword(uint32_t seed) {
    static const char alphabet[] =
        "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    const size_t alphaLen = sizeof(alphabet) - 1;
    uint8_t rnd[WIFI_AP_PASS_LEN];
    fakeFillRandom(rnd, sizeof(rnd), seed);
    std::string out;
    for (int i = 0; i < WIFI_AP_PASS_LEN; i++) out += alphabet[rnd[i] % alphaLen];
    return out;
}

// ── PSK KCV (mirrors firmware) ──
static std::string pskKcv(const uint8_t key[32]) {
    uint8_t d[32];
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    const char* dom = "GridDown-PSK-KCV";
    mbedtls_sha256_update(&c, (const uint8_t*)dom, strlen(dom));
    mbedtls_sha256_update(&c, key, 32);
    mbedtls_sha256_finish(&c, d);
    mbedtls_sha256_free(&c);
    char buf[8]; snprintf(buf, sizeof(buf), "%02X%02X", d[0], d[1]);
    return std::string(buf);
}

// ═══════════════════════════════════════════════════════════
int main() {
    printf("============================================================\n");
    printf("  GridDown Security Hardening Tests\n");
    printf("============================================================\n");

    // ───────────────────────────────────────────────────────
    SECTION("1. HKDF-SHA256 vs RFC 5869 Appendix A official vectors");
    {
    // A.1 Basic test case with SHA-256
    {
    auto ikm  = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    auto salt = unhex("000102030405060708090a0b0c");
    auto info = unhex("f0f1f2f3f4f5f6f7f8f9");
    uint8_t okm[42];
    bool ok = _hkdfSha256(salt.data(), salt.size(), ikm.data(), ikm.size(),
                          info.data(), info.size(), okm, 42);
    const char* want = "3cb25f25faacd57a90434f64d0362f2a"
                       "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                       "34007208d5b887185865";
    ASSERT(ok, "A.1 HKDF call succeeds");
    ASSERT(hex(okm, 42) == want, "A.1 OKM matches RFC 5869 vector (L=42)");
    }
    // A.2 Test with longer inputs/outputs (L=82)
    {
    std::string ikmH, saltH, infoH;
    for (int i = 0; i < 80; i++) { char b[4]; snprintf(b,4,"%02x",i); ikmH += b; }
    for (int i = 0x60; i < 0x60+80; i++) { char b[4]; snprintf(b,4,"%02x",i); saltH += b; }
    for (int i = 0xb0; i < 0xb0+80; i++) { char b[4]; snprintf(b,4,"%02x",i); infoH += b; }
    auto ikm=unhex(ikmH), salt=unhex(saltH), info=unhex(infoH);
    uint8_t okm[82];
    bool ok = _hkdfSha256(salt.data(), salt.size(), ikm.data(), ikm.size(),
                          info.data(), info.size(), okm, 82);
    const char* want = "b11e398dc80327a1c8e7f78c596a4934"
                       "4f012eda2d4efad8a050cc4c19afa97c"
                       "59045a99cac7827271cb41c65e590e09"
                       "da3275600c2f09b8367793a9aca3db71"
                       "cc30c58179ec3e87c14c01d5c1f3434f"
                       "1d87";
    ASSERT(ok, "A.2 HKDF call succeeds (multi-block expand)");
    ASSERT(hex(okm, 82) == want, "A.2 OKM matches RFC 5869 vector (L=82)");
    }
    // A.3 Test with zero-length salt and info
    {
    auto ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    uint8_t okm[42];
    bool ok = _hkdfSha256(nullptr, 0, ikm.data(), ikm.size(), nullptr, 0, okm, 42);
    const char* want = "8da4e775a563c18f715f802a063c5a31"
                       "b8a11f5c5ee1879ec3454e5f3c738d2d"
                       "9d201395faa4b61a96c8";
    ASSERT(ok, "A.3 HKDF call succeeds (empty salt/info)");
    ASSERT(hex(okm, 42) == want, "A.3 OKM matches RFC 5869 vector (empty salt/info)");
    }
    }

    // ───────────────────────────────────────────────────────
    SECTION("2. FHOP channel derivation");
    {
    uint8_t k1[32], k2[32];
    fakeFillRandom(k1, 32, 111);
    fakeFillRandom(k2, 32, 222);

    // Range: must always be 1..8 (channel 0 would drive freq below CH1)
    bool inRange = true;
    for (uint32_t slot = 0; slot < 5000; slot++) {
        int ch = fhopDerive(k1, slot);
        if (ch < 1 || ch > 8) { inRange = false; break; }
    }
    ASSERT(inRange, "All 5000 slots yield a channel in 1..8 (never 0)");

    // Determinism
    ASSERT(fhopDerive(k1, 12345) == fhopDerive(k1, 12345), "Same key+slot is deterministic");

    // Key sensitivity — different PSK must give a different sequence
    int diffs = 0;
    for (uint32_t slot = 0; slot < 200; slot++)
        if (fhopDerive(k1, slot) != fhopDerive(k2, slot)) diffs++;
    ASSERT(diffs > 150, "Different PSK yields a substantially different sequence");

    // Slot sensitivity — sequence must actually change over time
    int changes = 0;
    for (uint32_t slot = 1; slot < 200; slot++)
        if (fhopDerive(k1, slot) != fhopDerive(k1, slot-1)) changes++;
    ASSERT(changes > 140, "Channel changes across consecutive slots");

    // Distribution across 8 channels (chi-square-ish sanity)
    std::map<int,int> hist;
    for (uint32_t slot = 0; slot < 80000; slot++) hist[fhopDerive(k1, slot)]++;
    int mn = 1e9, mx = 0;
    for (int c = 1; c <= 8; c++) { mn = std::min(mn, hist[c]); mx = std::max(mx, hist[c]); }
    ASSERT(hist.size() == 8, "All 8 channels are used");
    ASSERT(mn > 9000 && mx < 11000, "Distribution is near-uniform (expect 10000/ch)");
    printf("      per-channel counts: ");
    for (int c = 1; c <= 8; c++) printf("%d ", hist[c]);
    printf("(min=%d max=%d)\n", mn, mx);
    }

    // ───────────────────────────────────────────────────────
    SECTION("3. Duress PIN — hashed storage and matching");
    {
    DuressState st;
    ASSERT(duressSetPin(st, "4729"), "Set a valid 4-digit PIN");
    ASSERT(st.set && st.pinLen == 4, "State reflects PIN set, length recorded");

    // The PIN must not appear anywhere in the persisted state
    std::string blob((const char*)st.salt, DURESS_SALT_LEN);
    blob += std::string((const char*)st.hash, DURESS_HASH_LEN);
    ASSERT(blob.find("4729") == std::string::npos,
           "Plaintext PIN does NOT appear in stored salt+hash");

    // Salt must make the hash unique per device even for the same PIN
    DuressState st2;
    duressSetPin(st2, "4729", /*different seed*/ 99);
    ASSERT(memcmp(st.hash, st2.hash, DURESS_HASH_LEN) != 0,
           "Same PIN with different salt yields a different hash");

    // Match and strip
    { char t[64]; strcpy(t, "meet at ridge 4729 now");
      ASSERT(duressCheckAndStrip(st, t), "PIN embedded mid-message is detected");
      ASSERT(strcmp(t, "meet at ridge now") == 0, "PIN stripped, text preserved"); }

    { char t[64]; strcpy(t, "4729");
      ASSERT(duressCheckAndStrip(st, t), "PIN alone is detected");
      ASSERT(strcmp(t, "") == 0, "Text empty after stripping"); }

    { char t[64]; strcpy(t, "status green 4728");
      ASSERT(!duressCheckAndStrip(st, t), "Near-miss PIN does NOT trigger");
      ASSERT(strcmp(t, "status green 4728") == 0, "Text unmodified on no-match"); }

    { char t[64]; strcpy(t, "no digits here");
      ASSERT(!duressCheckAndStrip(st, t), "Text with no digit run does not trigger"); }

    { char t[128]; strcpy(t, "1234 5678 9012 4729 3456");
      ASSERT(duressCheckAndStrip(st, t), "PIN found among many digit runs"); }

    // Trailing-space trim
    { char t[64]; strcpy(t, "rally point 4729   ");
      ASSERT(duressCheckAndStrip(st, t), "Detected with trailing spaces");
      ASSERT(strcmp(t, "rally point") == 0, "Trailing whitespace trimmed"); }

    // Length rules
    DuressState bad;
    ASSERT(!duressSetPin(bad, "123"),       "3-digit PIN rejected (below min)");
    ASSERT(!duressSetPin(bad, "123456789"), "9-digit PIN rejected (above max)");
    ASSERT(!duressSetPin(bad, "12a4"),      "Non-digit PIN rejected");
    ASSERT(!duressSetPin(bad, ""),          "Empty PIN rejected");

    // Longer PINs supported (higher entropy)
    DuressState st8;
    ASSERT(duressSetPin(st8, "84213970"), "8-digit PIN accepted");
    { char t[64]; strcpy(t, "obs post 84213970 clear");
      ASSERT(duressCheckAndStrip(st8, t), "8-digit PIN detected");
      ASSERT(strcmp(t, "obs post clear") == 0, "8-digit PIN stripped correctly"); }
    // A 4-digit substring of an 8-digit PIN must not trigger
    { char t[64]; strcpy(t, "value 8421 only");
      ASSERT(!duressCheckAndStrip(st8, t), "Substring of longer PIN does not trigger"); }

    // No-trace check: removal must not leave a double space or edge whitespace
    { char t[64]; strcpy(t, "4729 move now");
      ASSERT(duressCheckAndStrip(st, t), "PIN at start detected");
      ASSERT(strcmp(t, "move now") == 0, "Leading space trimmed after strip"); }
    { char t[64]; strcpy(t, "value4729here");
      ASSERT(duressCheckAndStrip(st, t), "PIN with no surrounding spaces detected");
      ASSERT(strcmp(t, "valuehere") == 0, "No spurious space inserted"); }
    { char t[80]; strcpy(t, "a 4729 b");
      duressCheckAndStrip(st, t);
      ASSERT(strstr(t, "  ") == NULL, "No double space left anywhere (no tell)"); }

    // Unset state never triggers
    DuressState off;
    { char t[64]; strcpy(t, "anything 1234");
      ASSERT(!duressCheckAndStrip(off, t), "No PIN configured → never triggers"); }
    }

    SECTION("3b. Duress legacy migration (plaintext v1 → hashed v2)");
    {
    // Simulate reading a legacy 4-byte plaintext file
    const char legacy[5] = "5150";
    DuressState st;
    fakeFillRandom(st.salt, DURESS_SALT_LEN, 55);
    bool ok = duressHashPin(legacy, 4, st.salt, st.hash);
    st.pinLen = 4; st.set = ok;
    ASSERT(ok && st.set, "Legacy PIN migrates to hashed form");
    char t[64]; strcpy(t, "checkpoint 5150 passed");
    ASSERT(duressCheckAndStrip(st, t), "Migrated PIN still triggers (feature preserved)");
    ASSERT(strcmp(t, "checkpoint passed") == 0, "Migrated PIN strips correctly");
    }

    // ───────────────────────────────────────────────────────
    SECTION("4. AP password generation");
    {
    std::string p = genApPassword(1234);
    ASSERT(p.size() == 12, "Password is 12 characters");
    ASSERT(p.size() >= 8, "Meets WPA2 minimum length (>=8)");

    // No ambiguous glyphs — operators read this off a small screen
    const std::string banned = "0O1lI";
    bool clean = true;
    for (char c : p) if (banned.find(c) != std::string::npos) clean = false;
    ASSERT(clean, "Contains no ambiguous characters (0 O 1 l I)");

    // Uniqueness across devices
    std::set<std::string> uniq;
    for (uint32_t s = 1; s <= 500; s++) uniq.insert(genApPassword(s * 7919));
    ASSERT(uniq.size() == 500, "500 devices generate 500 distinct passwords");

    // Not the old shipped default
    bool anyDefault = false;
    for (const auto& s : uniq) if (s == "griddown900") anyDefault = true;
    ASSERT(!anyDefault, "Never generates the old hardcoded default");
    printf("      sample: %s\n", p.c_str());
    }

    // ───────────────────────────────────────────────────────
    SECTION("5. PSK Key Check Value");
    {
    uint8_t k1[32], k2[32];
    fakeFillRandom(k1, 32, 4242);
    fakeFillRandom(k2, 32, 4243);
    std::string a = pskKcv(k1), b = pskKcv(k2);
    ASSERT(a.size() == 4, "KCV is 4 hex characters");
    ASSERT(a == pskKcv(k1), "KCV is stable for the same key");
    ASSERT(a != b, "KCV differs for different keys");

    // Must not reveal passphrase material: KCV is derived from the key, and the
    // key is a PBKDF2 output — check the KCV is not a prefix of the key itself.
    char keyHexPrefix[8];
    snprintf(keyHexPrefix, sizeof(keyHexPrefix), "%02X%02X", k1[0], k1[1]);
    ASSERT(a != std::string(keyHexPrefix), "KCV is not simply the key prefix");
    printf("      KCV(k1)=%s  KCV(k2)=%s\n", a.c_str(), b.c_str());
    }

    printf("\n============================================================\n");
    printf("  Results: %d/%d passed\n", passed, passed + failed);
    printf("============================================================\n");
    if (failed) { printf("\nFailures:\n"); for (auto& f : failures) printf("  - %s\n", f.c_str()); }
    return failed == 0 ? 0 : 1;
}
