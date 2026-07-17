// Modern WiFi + provisioning/diagnostics stack for VulnCast.
//
// Goals:
//  - WPA2/WPA3 (SAE) / PMF, multiple known networks in NVS, connect-to-strongest.
//  - Captive-portal provisioning: SoftAP auto-opens a web page; live rescan every
//    ~10 s; deduped SSIDs; enter WiFi password AND the Vulners API key.
//  - The stored API key is NEVER disclosed (write-only field; status only).
//  - When connected, a diagnostics page stays up (WiFi state, switch network,
//    Vulners key status). Periodic roam/reconnect to the strongest AP.
#pragma once

#include <Arduino.h>
#include <WiFi.h>
#include <vector>

// A scanned Wi-Fi network for the on-device settings list (deduped, sorted by RSSI).
struct WifiNet {
    String ssid;
    int rssi = 0;
    bool secure = true;
};

// SoftAP SSID + WPA2 password for the first-boot / fallback provisioning portal. Shared so the AP,
// the on-device setup screen, and its Wi-Fi QR all advertise the same credential (>= 8 chars for WPA2).
constexpr char kPortalSsid[] = "VulnCast-Setup";
constexpr char kPortalPass[] = "vulncast-setup";

class WifiManager {
public:
    void begin();
    void seedIfEmpty(const String &ssid, const String &pass);
    int savedCount() const { return (int)_ssids.size(); }
    void factoryReset();  // erase all saved networks + fast-reconnect cache (caller reboots afterwards)

    void beginConnectTo(const String &preferSsid);  // non-blocking manual join (keyboard) via the FSM
    // Non-blocking boot connect, driven from loop() on the UI thread (WiFi ops must
    // stay single-threaded — running scan/begin on a side task hard-freezes the driver).
    void beginConnect();                       // kick an async scan
    int serviceConnect();                      // call each loop: 0 pending · 1 connected · -1 failed
    bool addNetwork(const String &ssid, const String &pass);

    void startPortal(const String &apSsid);  // AP + captive portal
    void startDiagnostics();                  // STA diagnostics server + mDNS
    void stopPortal();
    void loop();                              // service DNS/server/scan/roam (non-blocking)
    void serviceKeyCheck();                   // blocking HTTPS key validation — CORE-0 TASK ONLY

    bool inPortal() const { return _mode == MODE_PORTAL; }
    bool portalConnected() const { return _portalConnected; }
    // True exactly once after a sustained reconnect failure has raised the setup portal, so the UI
    // loop knows to switch to the setup screen (runtime bootstrap fallback).
    bool takeReconnectPortalEvent();
    bool connected() const;
    bool apiKeyValid() const { return _apiKeyValid; }
    bool apiKeyChecked() const { return _apiKeyChecked; }

    String apUrl() const { return "http://192.168.4.1"; }
    String lastSsid() const { return _lastSsid; }
    const std::vector<WifiNet> &networks() const { return _scanNets; }  // deduped scan for the device list

private:
    enum Mode { MODE_IDLE, MODE_PORTAL, MODE_DIAG };

    std::vector<String> _ssids;
    std::vector<String> _pass;
    Mode _mode = MODE_IDLE;
    bool _portalConnected = false;
    bool _serverStarted = false;
    String _apSsid;
    String _lastSsid;

    // Async scan cache (non-blocking).
    uint32_t _lastScanKick = 0;
    bool _scanning = false;
    String _scanJson = "[]";
    std::vector<WifiNet> _scanNets;  // deduped, RSSI-sorted cache for the on-device list
    int _bestRssiCurrent = -1000;

    // Roaming / reconnect.
    uint32_t _lastRoam = 0;

    // Non-blocking boot-connect state machine (serviceConnect()).
    // Connect-FIRST, scan-only-on-failure: on boot we try the last-good AP directly (using its
    // cached channel+BSSID for a directed join) with no upfront scan; a full scan is a last
    // resort only if every saved network fails to associate directly.
    enum ConnState { CN_IDLE, CN_SETTLE, CN_SCANNING, CN_TRYING, CN_OK, CN_FAIL };
    ConnState _cn = CN_IDLE;
    std::vector<int> _cnCands;     // saved-network indices to try, last-good first
    size_t _cnTry = 0;             // which candidate we're attempting
    uint32_t _cnStart = 0;         // millis() the current attempt began (or the settle began)
    uint32_t _cnPerTry = 4500;     // per-candidate wait budget (fast-fail cuts it shorter)
    bool _cnScanned = false;       // the fallback scan has already been spent this boot
    bool _cnDirected = false;      // the current attempt used the cached channel+BSSID
    bool _cnForcePlain = false;    // next startAttempt must use a plain (all-channel) begin
    int _cnNextIdx = -1;           // CN_SETTLE target: >=0 candidate k, -1 scan, -2 restart ladder
    int _cnRetries = 0;            // all-channel retries spent on the current candidate
    uint32_t _cnBootStart = 0;     // millis() the whole boot connect began (portal budget)

    // Fast-reconnect cache (persisted to NVS): the AP that last worked, so boot skips the scan.
    String _bootSsid;              // last-good SSID to try first
    uint8_t _cacheBssid[6] = {0};  // cached BSSID of the last-good AP
    int _cacheChannel = 0;         // cached channel of the last-good AP
    bool _haveCache = false;       // a valid last-good BSSID/channel cache exists

    // Event-driven link state. onEvent handlers run on the async 'arduino_events' task, which on
    // the S3 shares core 1 with loopTask. They MUST stay trivial: only plain single-word volatile
    // writes, NO critical sections and NO radio calls — a portENTER_CRITICAL here disables core-1
    // interrupts and, if it lands mid e-paper draw, starves the I2S/RMT DMA and WEDGES the panel.
    // loop()/serviceConnect() is the sole owner of begin/scan/reconnect/disconnect, and reads the
    // cache via the live WiFi API (valid while connected), so no multi-field payload is shared.
    volatile bool _online = false;         // GOT_IP .. DISCONNECTED/LOST_IP (aligned word = atomic)
    volatile bool _evGotIp = false;        // a GOT_IP edge is pending for the FSM
    volatile bool _evDisconnected = false; // a DISCONNECTED edge is pending for the FSM
    volatile bool _linkDown = false;       // steady-state: link dropped, reconnect owed
    volatile uint8_t _evReason = 0;        // last DISCONNECTED reason (single byte = atomic)
    WiFiEventId_t _evId = 0;               // registered handler id (for removeEvent on teardown)

    // Steady-state reconnect backoff (MODE_DIAG), reason-classified + exponential.
    int _reconnAttempts = 0;       // failed retries since the last GOT_IP (backoff exponent)
    int _consecCredFail = 0;       // consecutive credential-class failures (portal at >=3)
    uint32_t _nextRetryAt = 0;     // millis() of the next allowed reconnect attempt
    uint32_t _linkDownSince = 0;   // millis() the link first dropped in steady state (0 = link up)
    bool _reconnPortalEvent = false;  // reconnect gave up -> portal raised; UI must show the setup screen

    // Disconnect-reason action buckets (see classifyReason).
    enum ReasonClass { RC_TRANSIENT, RC_NO_AP, RC_CREDENTIAL };
    static ReasonClass classifyReason(uint8_t reason);

    void startAttempt(size_t k);   // begin WiFi to candidate k (directed if cached + last-good)
    // WiFi.begin wrapper: directed = channel-only join (cached channel, nullptr BSSID — pinning a
    // BSSID is rejected reason 203 by mesh APs). Pure begin(), no added work (timing-sensitive).
    void beginToAp(const String &ssid, const String &pass, bool directed);
    void rememberConnected();      // capture + persist SSID/BSSID/channel after a successful link
    void onWifiEvent(WiFiEvent_t e, WiFiEventInfo_t info);  // pure flag-setter (async task)

    // Vulners key status (the key itself is never held here).
    bool _apiKeyChecked = false;   // a DEFINITIVE answer (valid or 401) was received
    bool _apiKeyValid = false;
    uint32_t _lastKeyCheck = 0;    // millis() of the last validation attempt (for retry)

    void load();
    void persist();
    String passFor(const String &ssid) const;

    void ensureServer();
    void serviceScan();
    String buildScanJson(int n);
    void maybeRoam();

    void handleRoot();       // hub page
    void handleWifiPage();   // /wifi subpage
    void handleApiKeyPage(); // /apikey subpage (GET)
    void handleScan();
    void handleConnect();
    void handleApiKey();
    void handleStatus();
    void handleCaptive();
};

extern WifiManager wifiManager;
