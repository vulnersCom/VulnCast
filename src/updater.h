// Secure background firmware auto-update for VulnCast.
//
// Anonymous, hourly check of a signed manifest published on GitHub Pages
// (default https://vulnerscom.github.io/VulnCast/update.json — see VULNCAST_UPDATE_MANIFEST_URL).
// The manifest carries the latest version, the app-image URL, its size, its SHA-256, and an Ed25519
// signature over the canonical string "version\nurl\nsize\nsha256hex". The device verifies the
// signature against a PUBLIC key baked into the firmware (include/update_pubkey.h) — so a compromised
// CDN/TLS/cert cannot ship firmware the device will run. Only the offline private key (never on the
// device) can sign a release.
//
// Fork knobs (override in platformio.ini build_flags — see updater.cpp):
//   VULNCAST_UPDATE_MANIFEST_URL   — where the manifest is fetched from
//   VULNCAST_OTA_REQUIRE_SIGNATURE — 1 (default) = require a valid Ed25519 signature; 0 = signature-free
//   VULNCAST_OTA_CHECK_INTERVAL_MS — discovery cadence
//
// Discovery + download run on the core-0 network task (never the UI loop); the UI only reads
// phase()/percent() and issues actions. No credentials are baked in.
#pragma once

#include <Arduino.h>

class Updater {
public:
    enum Phase {
        IDLE = 0,     // nothing pending
        CHECKING,     // fetching/verifying the manifest
        AVAILABLE,    // a newer, signature-verified version is offered to the user
        DOWNLOADING,  // streaming the image to flash
        VERIFYING,    // hashing/validating the written image
        INSTALLING,   // finalizing + setting the boot partition
        DONE,         // installed OK; reboot imminent
        FAILED,       // download/verify/install failed
    };

    void begin();          // read persisted OTA state + detect a fresh/rolled-back boot (verify state machine)
    void tick();           // core-0 fetch task: self-throttled hourly discovery; no-op if snoozed/offline
    void serviceInstall(); // core-0 fetch task: perform a pending download+verify+install (blocks; reboots on success)
    void factoryReset();   // wipe NVS "ota" (snoozeUntil/skipVer/pendVer) + in-RAM state — for a factory reset

    // Boot verify / rollback.
    bool verifyPending() const { return _verifyPending; }     // running a freshly-installed image awaiting a health OK
    void markHealthyIfPending();                              // health passed -> confirm the image (cancel rollback)
    bool verifyDeadlinePassed() const;                        // health not proven in time -> caller rolls back
    void rollbackAndReboot();                                // mark the image invalid + reboot to the previous one
    bool bootWasRollback() const { return _bootWasRollback; } // this boot is a revert after a failed update
    String pendingVersion() const { return _pendVer; }        // version we attempted (for the failed screen; UI-thread only)

    // UI queries (read-only; safe from the UI loop). Cross-task fields (_newVer/_err) are fixed char
    // buffers written on the fetch task and read here — a torn read yields stale text, never a crash.
    Phase phase() const { return _phase; }
    bool available() const { return _phase == AVAILABLE; }
    String currentVersion() const { return String(VULNCAST_FW_VERSION); }
    String availableVersion() const { return String(_newVer); }
    uint32_t availableSize() const { return _size; }
    uint8_t percent() const { return _pct; }
    const char *error() const { return _err; }

    // UI actions.
    void snoozeOneDay();      // "Try again tomorrow" — suppress offers for ~24h
    void dismissAvailable();  // drop the current offer back to IDLE (navigated away undecided)
    void startInstall();      // request download+verify+install (runs on the fetch task; shows progress)
    bool installPending() const { return _installReq; }  // fetch task: an install has been requested

    // Dev/preview (console jumps 'U' / 'B'): fake an offer / a post-rollback state for screen preview.
    void devPreviewAvailable();
    void devPreviewRollback();
    // Debug/diagnostics (console 'u').
    void requestCheck();  // force a discovery on the next fetch-task wake (bypass throttle/snooze)
    bool selfTest();      // verify a compiled-in Ed25519 test vector against UPDATE_PUBKEY (crypto sanity)
#ifdef VULNCAST_OTA_TEST
    // LOCAL TEST ONLY (compiled out of release): install from an arbitrary URL over unvalidated TLS,
    // trusting a caller-supplied sha256 instead of a signed manifest. Never enabled in a shipped build.
    void testInstall(const String &url, const String &sha256hex, uint32_t size);
#endif

private:
    // Cross-task signalling fields are volatile; the two Strings the UI displays are fixed char buffers
    // (no heap realloc -> no dangling pointer if the fetch task rewrites them mid-read).
    volatile Phase _phase = IDLE;
    volatile uint32_t _size = 0;
    volatile uint8_t _pct = 0;
    char _newVer[24] = {0};  // offered version — written on fetch, read by UI
    char _err[96] = {0};     // last error text — written on fetch, read by UI
    // _url/_sha256 are Strings, made safe by the volatile _phase gate (NOT by being single-core): the
    // fetch task mutates them only while _phase==CHECKING, then flips to AVAILABLE; tick() won't re-enter
    // discover() unless _phase is IDLE/FAILED. The UI loop only reads them (via startInstall) while
    // AVAILABLE — when they are quiescent. Keep that gate if you touch these.
    String _url;             // app-image URL
    String _sha256;          // expected image SHA-256 hex
    uint32_t _lastCheck = 0;
    bool _checkedOnce = false;
    volatile bool _forceCheck = false;  // console 'u' -> discover on the next tick regardless of throttle

    // Install + boot-verify state.
    volatile bool _installReq = false;   // startInstall() -> the fetch task should run serviceInstall()
    volatile bool _verifyPending = false;// this boot runs a freshly-installed image awaiting a health OK
    uint32_t _verifyDeadline = 0;        // millis() by which health must be proven, else roll back
    bool _bootWasRollback = false;       // begin() detected we were reverted after a failed update
    bool _insecureTest = false;          // test path only (VULNCAST_OTA_TEST): skip TLS cert validation
    String _pendVer;                     // NVS "pendVer": the version we last tried to install (UI-thread reads)

    bool discover();                     // fetch + verify manifest; may set AVAILABLE
    bool fetchManifest(String &body);    // HTTPS GET the manifest (cert bundle + UA)
    // Verify the Ed25519 signature over "version\nurl\nsize\nsha256hex".
    bool verifyManifest(const String &ver, const String &url, uint32_t size, const String &sha256hex,
                        const String &sigB64);
    bool snoozed();                      // within the "try again tomorrow" window?
    void fail(const char *msg);          // set FAILED + record the reason (install path)
};

extern Updater updater;
