#include "updater.h"

#include <ArduinoJson.h>
#include <Ed25519.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <Update.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <cstring>

#include "esp_ota_ops.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "timekeeper.h"
#include "update_pubkey.h"
#include "update_selftest.h"

// ─── Fork configuration (override in platformio.ini build_flags; secure defaults) ────────────────
// Where the signed update manifest is fetched from.
#ifndef VULNCAST_UPDATE_MANIFEST_URL
#define VULNCAST_UPDATE_MANIFEST_URL "https://vulnerscom.github.io/VulnCast/update.json"
#endif
// Require a valid Ed25519 signature on the manifest. 1 = recommended (only firmware signed by the
// offline private key installs). Set 0 to run signature-free — for a fork that self-hosts updates
// without managing a signing key; integrity then rests on TLS (cert bundle) + the manifest's sha256.
#ifndef VULNCAST_OTA_REQUIRE_SIGNATURE
#define VULNCAST_OTA_REQUIRE_SIGNATURE 1
#endif
// Discovery cadence (ms) and the first-check delay after boot.
#ifndef VULNCAST_OTA_CHECK_INTERVAL_MS
#define VULNCAST_OTA_CHECK_INTERVAL_MS 3600000UL
#endif
#ifndef VULNCAST_OTA_FIRST_CHECK_MS
#define VULNCAST_OTA_FIRST_CHECK_MS 120000UL
#endif

// Arduino-ESP32 3.x auto-confirms a freshly-flashed image before setup() unless we defer. Returning
// true here keeps the new image in PENDING_VERIFY so WE decide (after a health check) whether to mark
// it valid or roll back. Without this override, boot-health verification is effectively disabled.
extern "C" bool verifyRollbackLater() { return true; }

// Survives soft-reset / crash / OTA reboot (not power loss) — a three-strikes guard against an image
// that boots into PENDING_VERIFY, wedges, and reboots without ever confirming health.
RTC_NOINIT_ATTR uint32_t g_otaBootMagic;
RTC_NOINIT_ATTR uint32_t g_otaBootAttempts;
constexpr uint32_t kBootMagic = 0x564C4E01;  // "VLN\1"
constexpr uint32_t kMaxPendingBoots = 3;

namespace {

Preferences otaPrefs;  // NVS "ota": snoozeUntil (uint32 epoch), skipVer (String), pendVer (String)
                       // Touched from both cores; NVS has an internal per-partition lock, and the two
                       // sides (hourly fetch-task discover/install vs rare UI-loop snooze/mark-valid)
                       // almost never overlap. If that changes, add a mutex.

const char *kManifestUrl = VULNCAST_UPDATE_MANIFEST_URL;
constexpr uint32_t kFirstDelayMs = VULNCAST_OTA_FIRST_CHECK_MS;
constexpr uint32_t kCheckIntervalMs = VULNCAST_OTA_CHECK_INTERVAL_MS;
constexpr time_t kClockSynced = 1600000000;    // epoch past which the wall clock is plausible
constexpr uint32_t kVerifyWindowMs = 240000UL;  // health-check window: > the Wi-Fi reconnect give-up (180s)

// The default full Mozilla CA bundle embedded in the mbedtls lib (CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y,
// DEFAULT_FULL). Covers every GitHub root (USERTrust ECC + ISRG Root X1) and survives leaf rotation.
extern const uint8_t rootca_crt_bundle_start[] asm("_binary_x509_crt_bundle_start");
extern const uint8_t rootca_crt_bundle_end[] asm("_binary_x509_crt_bundle_end");

// The single place OTA's TLS policy lives: bundle-validated HTTPS, GitHub-required UA, follow the
// github.com -> objects.githubusercontent.com redirect for release assets.
bool beginHttps(WiFiClientSecure &client, HTTPClient &https, const char *url, uint32_t readTimeoutMs,
                bool insecure) {
#ifdef VULNCAST_OTA_TEST
    if (insecure) {
        client.setInsecure();  // LOCAL TEST ONLY — compiled out of release
    } else
#endif
        client.setCACertBundle(rootca_crt_bundle_start,
                               (size_t)(rootca_crt_bundle_end - rootca_crt_bundle_start));
    (void)insecure;
    https.setConnectTimeout(8000);
    https.setTimeout(readTimeoutMs);
    https.setUserAgent("VulnCast/" VULNCAST_FW_VERSION);  // GitHub requires a User-Agent
    https.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);
    return https.begin(client, url);
}

// Numeric "X.Y.Z" compare: is a strictly greater than b?
bool semverGt(const String &a, const String &b) {
    int ai = 0, bi = 0;
    for (int part = 0; part < 3; ++part) {
        long av = 0, bv = 0;
        while (ai < (int)a.length() && isdigit((unsigned char)a[ai])) av = av * 10 + (a[ai++] - '0');
        while (bi < (int)b.length() && isdigit((unsigned char)b[bi])) bv = bv * 10 + (b[bi++] - '0');
        if (av != bv) return av > bv;
        if (ai < (int)a.length() && a[ai] == '.') ai++;
        if (bi < (int)b.length() && b[bi] == '.') bi++;
    }
    return false;
}

bool hexToBytes(const String &hex, uint8_t *out, size_t outLen) {
    if (hex.length() != outLen * 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < outLen; ++i) {
        int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

}  // namespace

Updater updater;

void Updater::begin() {
    otaPrefs.begin("ota", false);
    if (g_otaBootMagic != kBootMagic) {  // cold power-on -> RTC is garbage; reset the pending-boot counter
        g_otaBootMagic = kBootMagic;
        g_otaBootAttempts = 0;
    }
    _pendVer = otaPrefs.getString("pendVer", "");

    esp_ota_img_states_t st = ESP_OTA_IMG_UNDEFINED;
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_get_state_partition(running, &st);

    if (st == ESP_OTA_IMG_PENDING_VERIFY) {
        // Freshly-installed image (verifyRollbackLater deferred confirmation). Prove health or revert.
        g_otaBootAttempts++;
        if (g_otaBootAttempts >= kMaxPendingBoots) {
            Serial.printf("[ota] %u pending-verify boots without a health OK — rolling back now\n",
                          (unsigned)g_otaBootAttempts);
            esp_ota_mark_app_invalid_rollback_and_reboot();  // does not return
        }
        _verifyPending = true;
        _verifyDeadline = millis() + kVerifyWindowMs;
        Serial.printf("[ota] booted PENDING_VERIFY image %s (attempt %u/%u) — verifying health\n",
                      VULNCAST_FW_VERSION, (unsigned)g_otaBootAttempts, (unsigned)kMaxPendingBoots);
        return;
    }

    // Already-valid boot. Detect a rollback: we recorded pendVer before rebooting into the new image,
    // but we're running a DIFFERENT version -> the bootloader reverted us (the new image failed to boot).
    g_otaBootAttempts = 0;
    if (_pendVer.length()) {
        bool rolledBack = (_pendVer != String(VULNCAST_FW_VERSION));
        if (rolledBack) {
            Serial.printf("[ota] ROLLBACK detected: attempted %s, running %s\n", _pendVer.c_str(),
                          VULNCAST_FW_VERSION);
            otaPrefs.putString("skipVer", _pendVer);  // don't auto-offer the broken version again
            _bootWasRollback = true;                  // _pendVer stays = the failed version (for the screen)
        }
        otaPrefs.remove("pendVer");  // the attempt is resolved either way
        if (!rolledBack) _pendVer = "";
    }
}

void Updater::factoryReset() {
    otaPrefs.clear();  // wipe NVS "ota" (snoozeUntil, skipVer, pendVer)
    _phase = IDLE;
    _pct = 0;
    _newVer[0] = 0;
    _err[0] = 0;
    _pendVer = "";
    _bootWasRollback = false;
    _verifyPending = false;
}

bool Updater::snoozed() {
    uint32_t until = otaPrefs.getUInt("snoozeUntil", 0);
    if (!until) return false;
    time_t nowEpoch = timeKeeper.now();
    if (nowEpoch < kClockSynced) return false;  // clock unsynced -> can't judge the window; allow checks
    return (uint32_t)nowEpoch < until;
}

void Updater::snoozeOneDay() {
    time_t nowEpoch = timeKeeper.now();
    if (nowEpoch > kClockSynced) otaPrefs.putUInt("snoozeUntil", (uint32_t)nowEpoch + 86400UL);
    dismissAvailable();
}

void Updater::dismissAvailable() {
    if (_phase == AVAILABLE) _phase = IDLE;
}

void Updater::tick() {
    // Only discover while idle: never interrupt a pending offer or an in-flight install.
    if (_phase != IDLE && _phase != FAILED) return;
    bool force = _forceCheck;
    uint32_t now = millis();
    if (!force) {
        if (!_checkedOnce) {
            if (now < kFirstDelayMs) return;
        } else if (now - _lastCheck < kCheckIntervalMs) {
            return;
        }
        if (snoozed()) return;
    }
    if (WiFi.status() != WL_CONNECTED) {
        if (force) Serial.println("[ota] forced check skipped — Wi-Fi offline");
        return;  // keep _forceCheck set; retry once online
    }
    _forceCheck = false;
    _lastCheck = now;
    _checkedOnce = true;
    discover();
}

void Updater::requestCheck() { _forceCheck = true; }

// Verify a compiled-in Ed25519 vector (signed by the release private key over the same
// "version\nurl\nsize\nsha256hex" layout as a real manifest) against UPDATE_PUBKEY. Proves the
// on-device verifier matches the host signer and catches a corrupted/wrong public key; also confirms a
// tampered signature is rejected. Vector generated by: scripts/sign_manifest.py ... --emit-c.
bool Updater::selfTest() {
    static const uint8_t kSelfTestMsg[SELFTEST_MSG_LEN] = SELFTEST_MSG;
    static const uint8_t kSelfTestSig[64] = SELFTEST_SIG;
    bool good = Ed25519::verify(kSelfTestSig, UPDATE_PUBKEY, kSelfTestMsg, sizeof(kSelfTestMsg));
    uint8_t bad[64];
    memcpy(bad, kSelfTestSig, sizeof(bad));
    bad[0] ^= 0x01;  // flip one bit -> must be rejected
    bool rejected = !Ed25519::verify(bad, UPDATE_PUBKEY, kSelfTestMsg, sizeof(kSelfTestMsg));
    Serial.printf("[ota] crypto self-test: valid-sig=%s tampered-rejected=%s\n",
                  good ? "PASS" : "FAIL", rejected ? "PASS" : "FAIL");
    return good && rejected;
}

bool Updater::fetchManifest(String &body) {
    WiFiClientSecure client;
    HTTPClient https;
    if (!beginHttps(client, https, kManifestUrl, 8000, false)) {
        Serial.println("[ota] manifest begin() failed");
        return false;
    }
    int code = https.GET();
    if (code != HTTP_CODE_OK) {
        Serial.printf("[ota] manifest GET -> %d %s\n", code,
                      code < 0 ? https.errorToString(code).c_str() : "(http status)");
        https.end();
        return false;
    }
    body = https.getString();
    https.end();
    return body.length() > 0 && body.length() < 4096;  // manifest is tiny; bound it
}

// The release signs the canonical string "version\nurl\nsize\nsha256hex" (see scripts/sign_manifest.py).
// Signing this instead of the 1.7 MB image keeps ed25519's internal SHA-512 over a few dozen bytes; the
// image itself is bound because its sha256 (covered here) must match byte-for-byte at install time.
bool Updater::verifyManifest(const String &ver, const String &url, uint32_t size, const String &sha256hex,
                             const String &sigB64) {
    uint8_t sig[64];
    size_t siglen = 0;
    if (mbedtls_base64_decode(sig, sizeof(sig), &siglen, (const uint8_t *)sigB64.c_str(),
                              sigB64.length()) != 0 ||
        siglen != 64) {
        return false;  // malformed base64 / wrong length
    }
    String msg = ver + "\n" + url + "\n" + String(size) + "\n" + sha256hex;
    return Ed25519::verify(sig, UPDATE_PUBKEY, (const uint8_t *)msg.c_str(), msg.length());
}

bool Updater::discover() {
    _phase = CHECKING;
    String body;
    if (!fetchManifest(body)) {
        _phase = IDLE;  // network hiccup / offline -> silently retry next interval
        return false;
    }
    JsonDocument doc;
    if (deserializeJson(doc, body)) {
        _phase = IDLE;
        return false;
    }
    String ver = doc["version"] | "";
    String url = doc["url"] | "";
    String sha = doc["sha256"] | "";
    String sig = doc["sig"] | "";
    uint32_t size = doc["size"] | 0;
    if (ver.isEmpty() || sha.length() != 64 || !url.startsWith("https://")) {
        _phase = IDLE;  // reject missing/short fields and non-HTTPS asset URLs
        return false;
    }
#if VULNCAST_OTA_REQUIRE_SIGNATURE
    if (sig.isEmpty() || !verifyManifest(ver, url, size, sha, sig)) {
        Serial.println("[ota] manifest signature INVALID — ignoring");
        _phase = IDLE;
        return false;
    }
#else
    (void)sig;  // signature-free build (VULNCAST_OTA_REQUIRE_SIGNATURE=0): integrity via TLS + sha256
#endif
    // Authentic manifest. Offer only if strictly newer and not a version the user chose to skip.
    String skip = otaPrefs.getString("skipVer", "");
    if (semverGt(ver, VULNCAST_FW_VERSION) && ver != skip) {
        snprintf(_newVer, sizeof(_newVer), "%s", ver.c_str());
        _url = url;
        _sha256 = sha;
        _size = size;
        _phase = AVAILABLE;
        Serial.printf("[ota] update available: %s -> %s (%u bytes)\n", VULNCAST_FW_VERSION,
                      _newVer, (unsigned)size);
        return true;
    }
    Serial.printf("[ota] up to date (running %s, manifest %s)\n", VULNCAST_FW_VERSION, ver.c_str());
    _phase = IDLE;
    return false;
}

void Updater::startInstall() {
    if (_phase != AVAILABLE) return;
    if (_url.isEmpty() || _sha256.length() != 64) {
        fail("no image to install");
        return;
    }
    _err[0] = 0;
    _pct = 0;
    _phase = DOWNLOADING;
    _installReq = true;  // the fetch task runs serviceInstall() on its next wake
    Serial.printf("[ota] install requested: %s (%u bytes)\n", _newVer, (unsigned)_size);
}

void Updater::fail(const char *msg) {
    snprintf(_err, sizeof(_err), "%s", msg);
    _phase = FAILED;
    Serial.printf("[ota] install failed: %s\n", msg);
}

bool Updater::verifyDeadlinePassed() const {
    return _verifyPending && (int32_t)(millis() - _verifyDeadline) >= 0;
}

void Updater::markHealthyIfPending() {
    if (!_verifyPending) return;
#ifdef VULNCAST_OTA_FAILHEALTH
    return;  // TEST: simulate a broken image that never passes health -> forces a rollback
#endif
    esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
    if (e != ESP_OK) {  // don't clear _verifyPending — retry next loop / next boot re-enters verify mode
        Serial.printf("[ota] mark-valid failed (%s) — will retry\n", esp_err_to_name(e));
        return;
    }
    _verifyPending = false;
    otaPrefs.remove("pendVer");
    g_otaBootAttempts = 0;
    Serial.printf("[ota] new image %s verified healthy — marked valid\n", VULNCAST_FW_VERSION);
}

void Updater::rollbackAndReboot() {
    if (!_verifyPending) {  // only a PENDING_VERIFY image may roll back; never invalidate a good running app
        Serial.println("[ota] rollback ignored — not running a pending-verify image");
        return;
    }
    Serial.println("[ota] health check failed — rolling back to the previous version");
    esp_ota_mark_app_invalid_rollback_and_reboot();  // reboots into the previous slot on success
    // Only reached when rollback is impossible (no valid previous image). We can't go back, so accept the
    // running image rather than leave it unconfirmed (the bootloader would otherwise abort it next boot).
    Serial.println("[ota] rollback impossible (no previous image) — accepting current image");
    esp_ota_mark_app_valid_cancel_rollback();
    _verifyPending = false;
    otaPrefs.remove("pendVer");
    g_otaBootAttempts = 0;
}

// Runs entirely on the core-0 fetch task (blocks for the whole ~1.7 MB transfer). The UI loop stays
// live on core 1 and paints progress from _phase/_pct. Reboots on success; sets FAILED otherwise.
void Updater::serviceInstall() {
    if (!_installReq) return;
    _installReq = false;
    _phase = DOWNLOADING;
    _pct = 0;

    WiFiClientSecure client;
    HTTPClient https;
    if (!beginHttps(client, https, _url.c_str(), 20000, _insecureTest)) {
        fail("connect failed");
        return;
    }
    int code = https.GET();
    if (code != HTTP_CODE_OK) {
        char m[24];
        snprintf(m, sizeof(m), "HTTP %d", code);
        fail(m);
        https.end();
        return;
    }

    int total = https.getSize();
    if (total <= 0) total = (int)_size;  // fall back to the manifest's size
    if (!Update.begin(total > 0 ? (size_t)total : UPDATE_SIZE_UNKNOWN, U_FLASH)) {
        fail(Update.errorString());
        https.end();
        return;
    }

    WiFiClient *stream = https.getStreamPtr();
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);  // 0 = SHA-256
    static uint8_t buf[2048];
    int written = 0;
    uint32_t lastData = millis();
    const char *streamErr = nullptr;
    while (https.connected() && (total <= 0 || written < total)) {
        size_t avail = stream->available();
        if (avail) {
            int n = stream->readBytes(buf, avail > sizeof(buf) ? sizeof(buf) : avail);
            if (n <= 0) break;
            if ((int)Update.write(buf, n) != n) {
                streamErr = "flash write failed";
                break;
            }
            mbedtls_sha256_update(&sha, buf, n);
            written += n;
            if (total > 0) _pct = (uint8_t)((int64_t)written * 100 / total);
            lastData = millis();
        } else if (millis() - lastData > 20000) {
            streamErr = "download stalled";
            break;
        } else {
            delay(2);  // yield so the socket refills + core-0 system tasks run
        }
    }
    https.end();
    if (!streamErr && total > 0 && written != total) streamErr = "incomplete download";
    if (streamErr) {  // one cleanup path: always release the SHA engine + abort the OTA
        mbedtls_sha256_free(&sha);
        Update.abort();
        fail(streamErr);
        return;
    }

    // Integrity gate: the streamed bytes must hash to the manifest's SIGNED sha256. A swapped/altered
    // image is rejected here (even though the signature covered the sha256, not the image directly).
    _phase = VERIFYING;
    _pct = 100;
    uint8_t digest[32], expected[32];
    mbedtls_sha256_finish(&sha, digest);
    mbedtls_sha256_free(&sha);
    if (!hexToBytes(_sha256, expected, 32) || memcmp(digest, expected, sizeof(digest)) != 0) {
        Update.abort();
        fail("sha256 mismatch — image rejected");
        return;
    }

    // Finalize: Update.end() validates the ESP image (magic + its own SHA digest) and sets the boot
    // partition. Only AFTER it succeeds do we record the attempted version — so a crash during finalize
    // can never leave a stale pendVer that mis-detects a rollback for a version that never installed.
    _phase = INSTALLING;
    if (!Update.end(true) || !Update.isFinished()) {
        fail(Update.errorString());
        return;
    }
    otaPrefs.putString("pendVer", _newVer);
    _phase = DONE;
    _pct = 100;
    Serial.printf("[ota] installed %s — rebooting to verify\n", _newVer);
    delay(1200);  // let the UI paint DONE
    ESP.restart();
}

void Updater::devPreviewAvailable() {
    snprintf(_newVer, sizeof(_newVer), "%s", "9.9.9");
    _url = "";
    _sha256 = "";
    _size = 1763120;
    _phase = AVAILABLE;
}

void Updater::devPreviewRollback() {
    _pendVer = "9.9.9";  // pretend this version was attempted and reverted (screen preview only)
}

#ifdef VULNCAST_OTA_TEST
void Updater::testInstall(const String &url, const String &sha256hex, uint32_t size) {
    snprintf(_newVer, sizeof(_newVer), "%s", "9.9.9-test");
    _url = url;
    _sha256 = sha256hex;
    _size = size;
    _insecureTest = true;
    _phase = AVAILABLE;
    Serial.printf("[ota] TEST install from %s\n", url.c_str());
    startInstall();
}
#endif
