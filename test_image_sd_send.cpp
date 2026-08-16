// SPDX-FileCopyrightText: 2025-2026 BlackAtlas LLC
// SPDX-License-Identifier: GPL-3.0-or-later
// Build: g++ -std=c++17 -w -o t test_image_sd_send.cpp
// Tests the on-device SD image-send guard logic (img_loadAndSendFromSD).
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include "src/img_proto.h"

static bool g_sdMounted = true, g_txActive = false;
static std::map<std::string, std::vector<uint8_t>> g_fs;
static bool g_beginCalled = false; static std::string g_beginName; static size_t g_beginLen = 0;
enum R { OK=0, E_NO_SD, E_NOT_FOUND, E_EMPTY, E_TOO_LARGE, E_NOT_JPEG, E_BUSY, E_OOM, E_READ };
static uint8_t buf[IMG_MAX_SIZE_BYTES];
static R load(const char* path) {
    if (!g_sdMounted) return E_NO_SD;
    if (g_txActive)   return E_BUSY;
    if (!path || !*path) return E_NOT_FOUND;
    auto it = g_fs.find(path); if (it == g_fs.end()) return E_NOT_FOUND;
    size_t n = it->second.size();
    if (n == 0) return E_EMPTY;
    if (n > IMG_MAX_SIZE_BYTES) return E_TOO_LARGE;
    memcpy(buf, it->second.data(), n);
    if (n < 4 || buf[0]!=0xFF || buf[1]!=0xD8) return E_NOT_JPEG;
    const char* b = strrchr(path,'/'); b = b?b+1:path;
    g_beginCalled=true; g_beginName=b; g_beginLen=n; g_txActive=true; return OK;
}
static std::vector<uint8_t> jpg(size_t n){ std::vector<uint8_t> v(n,0x55); if(n>=2){v[0]=0xFF;v[1]=0xD8;} if(n>=4){v[n-2]=0xFF;v[n-1]=0xD9;} return v; }
static void reset(){ g_sdMounted=true; g_txActive=false; g_fs.clear(); g_beginCalled=false; g_beginName.clear(); g_beginLen=0; }
static int P=0,F=0;
#define A(c,d) do{ if(c){printf("  [PASS] %s\n",d);P++;} else {printf("  [FAIL] %s (line %d)\n",d,__LINE__);F++;} }while(0)
int main(){
    printf("=== GridDown On-Device SD Image Send ===\n");
    reset(); g_fs["/img_send/recon.jpg"]=jpg(5000);
    A(load("/img_send/recon.jpg")==OK, "Valid 5KB JPEG from outbox accepted");
    A(g_beginName=="recon.jpg", "Basename derived correctly");
    A(g_beginLen==5000, "Full length passed to TX");
    reset(); g_fs["/img_recv/ALPHA_1_AB.jpg"]=jpg(3200);
    A(load("/img_recv/ALPHA_1_AB.jpg")==OK, "Re-share of received image accepted");
    reset(); g_sdMounted=false; g_fs["/img_send/x.jpg"]=jpg(100);
    A(load("/img_send/x.jpg")==E_NO_SD, "No SD card rejected");
    A(!g_beginCalled, "TX not started without SD");
    reset(); g_txActive=true; g_fs["/img_send/x.jpg"]=jpg(100);
    A(load("/img_send/x.jpg")==E_BUSY, "Concurrent transfer rejected");
    reset(); A(load("/img_send/missing.jpg")==E_NOT_FOUND, "Missing file rejected");
    A(load("")==E_NOT_FOUND, "Empty path rejected");
    A(load(nullptr)==E_NOT_FOUND, "Null path rejected");
    reset(); g_fs["/img_send/e.jpg"]={};
    A(load("/img_send/e.jpg")==E_EMPTY, "Zero-byte file rejected");
    reset(); g_fs["/img_send/big.jpg"]=jpg(IMG_MAX_SIZE_BYTES+1);
    A(load("/img_send/big.jpg")==E_TOO_LARGE, "Oversize (>8KB) rejected — no on-device compression");
    reset(); g_fs["/img_send/max.jpg"]=jpg(IMG_MAX_SIZE_BYTES);
    A(load("/img_send/max.jpg")==OK, "Exactly 8KB accepted");
    reset(); { std::vector<uint8_t> p(100,0); p[0]=0x89;p[1]=0x50;p[2]=0x4E;p[3]=0x47; g_fs["/img_send/f.jpg"]=p; }
    A(load("/img_send/f.jpg")==E_NOT_JPEG, "PNG masquerading as .jpg rejected");
    reset(); g_fs["/img_send/t.jpg"]=std::vector<uint8_t>{0xFF,0xD8,0xFF};
    A(load("/img_send/t.jpg")==E_NOT_JPEG, "3-byte file rejected");
    reset(); g_fs["/img_send/m.jpg"]=std::vector<uint8_t>{0xFF,0xD8,0xFF,0xD9};
    A(load("/img_send/m.jpg")==OK, "4-byte minimal JPEG accepted");
    reset(); g_fs["photo.jpg"]=jpg(800);
    A(load("photo.jpg")==OK && g_beginName=="photo.jpg", "Path without slash handled");
    printf("\nResults: %d/%d passed\n", P, P+F);
    return F?1:0;
}
