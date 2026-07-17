#include "wifi_manager.h"

#include <ArduinoJson.h>
#include <DNSServer.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <WebServer.h>
#include <WiFi.h>
#include <algorithm>

#include "channels.h"
#include "config.h"
#include "gfx.h"
#include "timekeeper.h"
#include "vulners.h"
#include "web_ui.h"

namespace {

Preferences wprefs;
const char *kNs = "wifinet";
const int kMaxNet = 6;
const uint32_t kReconnGiveUpMs = 180000;  // sustained down time before reconnect gives up -> setup portal
WebServer server(80);
DNSServer dns;
WifiManager *self = nullptr;

String key(const char *prefix, int i) { return String(prefix) + String(i); }

// Hub + subpage bodies. One web UI, identical in AP (captive) and STA modes; the
// shared chrome (web_ui) adds the brand + top status bar + document close. The
// Vulners key field is write-only: the stored key is never sent back.
const char kHubBody[] PROGMEM = R"WEB(
<div class=nav>
<a class=navbtn href="/channels"><span class=ic><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg></span><span><div class=nt>Manage channels</div><div class=ns>Feeds, refresh &amp; champions</div></span><span class=chev>&rarr;</span></a>
<a class=navbtn href="/wifi"><span class=ic><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round"><path d="M2 8.5a15 15 0 0 1 20 0M5 12a10 10 0 0 1 14 0M8 15.5a5 5 0 0 1 8 0"/><circle cx="12" cy="19" r="1.1" fill="#ff7a4d" stroke="none"/></svg></span><span><div class=nt>Setup WiFi</div><div class=ns>Networks &amp; connection</div></span><span class=chev>&rarr;</span></a>
<a class=navbtn href="/time"><span class=ic><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><span><div class=nt>Setup Time</div><div class=ns>Auto NTP &amp; timezone</div></span><span class=chev>&rarr;</span></a>
<a class=navbtn href="/apikey"><span class=ic><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round"><circle cx="8" cy="8" r="4.5"/><path d="M11.5 11.5L20 20M17 17l2-2M15 15l2-2"/></svg></span><span><div class=nt>Setup Vulners API key</div><div class=ns>Validate &amp; store the key</div></span><span class=chev>&rarr;</span></a>
</div>)WEB";

const char kWifiBody[] PROGMEM = R"WEB(
<a class=back href="/">&larr; Back</a>
<div class=card><h2>WiFi network</h2>
<label>Network</label><select id=ssid class=full></select>
<label>Or hidden SSID</label><input id=custom placeholder="(optional)">
<label>Password</label><input id=pass type=password placeholder="WPA2 / WPA3 password" autocomplete="off" autocapitalize="off" spellcheck="false" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other">
<button class=wide onclick=connect()>Save and connect</button><div id=wmsg style=margin-top:8px></div>
<small>Rescanning every 10s&hellip;</small></div>
<script>
function el(i){return document.getElementById(i)}
async function scan(){try{let a=await(await fetch('/scan')).json();let s=el('ssid');let sig=a.map(n=>n.ssid).join('|');if(s.dataset.sig==sig)return;s.dataset.sig=sig;let cur=s.value;s.innerHTML='';a.forEach(n=>{let o=document.createElement('option');o.value=n.ssid;o.textContent=n.ssid+'  '+n.rssi+'dBm '+(n.lock?'(lock)':'');s.appendChild(o)});if(cur)s.value=cur}catch(e){}}
async function connect(){el('wmsg').textContent='Connecting…';let b=new URLSearchParams();b.set('ssid',el('ssid').value);b.set('custom',el('custom').value);b.set('pass',el('pass').value);let s=await(await fetch('/connect',{method:'POST',body:b})).json();el('wmsg').innerHTML=s.ok?'<span class=ok>Connected &mdash; IP '+s.ip+'</span>':'<span class=bad>'+(s.message||'failed')+'</span>'}
scan();setInterval(scan,10000);
</script>)WEB";

const char kApiKeyBody[] PROGMEM = R"WEB(
<a class=back href="/">&larr; Back</a>
<div class=card><h2>Vulners API key</h2>
<label>Key (write-only &mdash; the stored key is never shown)</label>
<input id=key type=password placeholder="paste key to set/replace" autocomplete="off" autocapitalize="off" spellcheck="false" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other">
<button class=wide onclick=savekey()>Validate and save</button><div id=kmsg style=margin-top:8px></div>
<small>The key is validated against Vulners before it is stored in NVS.</small></div>
<script>
function el(i){return document.getElementById(i)}
async function st(){try{let s=await(await fetch('/status')).json();el('key').placeholder=s.apiKeySet?'configured - paste to replace':'not set - paste key'}catch(e){}}
async function savekey(){el('kmsg').textContent='Validating…';let b=new URLSearchParams();b.set('key',el('key').value);let s=await(await fetch('/apikey',{method:'POST',body:b})).json();el('key').value='';el('kmsg').innerHTML=s.valid?'<span class=ok>Key valid and saved</span>':'<span class=bad>'+(s.message||'invalid')+'</span>';st()}
st();
</script>)WEB";

}  // namespace

WifiManager wifiManager;

// Classify a disconnect reason into an action bucket. Default is TRANSIENT so an unknown/0 reason
// (arduino-esp32 delivers reason 0, which is not in the enum) or a future IDF sub-reason degrades
// gracefully. AUTH_EXPIRE(2) is deliberately TRANSIENT — it fires on healthy band-steering/PMF nets.
WifiManager::ReasonClass WifiManager::classifyReason(uint8_t r) {
    switch (r) {
        case WIFI_REASON_NO_AP_FOUND:  // 201: SSID absent / cached AP moved
            return RC_NO_AP;
        case WIFI_REASON_AUTH_FAIL:            // 202
        case WIFI_REASON_HANDSHAKE_TIMEOUT:    // 204
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:   // 15
        case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT: // 16
        case WIFI_REASON_IE_IN_4WAY_DIFFERS:       // 17
        case WIFI_REASON_802_1X_AUTH_FAILED:       // 23
            return RC_CREDENTIAL;  // wrong PSK / EAP — but never declare bad on a single shot
        default:
            return RC_TRANSIENT;   // beacon timeout, assoc leave, auth expire, unspecified, reason 0
    }
}

void WifiManager::begin() {
    wprefs.begin(kNs, false);
    self = this;
    load();

    // Modern STA one-time config (before any WiFi.begin). WPA3-SAE + PMF-Optional are already
    // active via core defaults; setMinSecurity is a self-documenting downgrade floor (never lower
    // it — that would accept open/rogue impersonators). We OWN reconnect, so IDF auto-reconnect is
    // OFF; persistent(false) stops rewriting the IDF credential NVS on every begin (flash wear).
    WiFi.persistent(false);
    WiFi.mode(WIFI_STA);
    WiFi.setHostname("vulncast");
    WiFi.setSleep(WIFI_PS_NONE);
    WiFi.setScanMethod(WIFI_FAST_SCAN);
    WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);
    WiFi.setMinSecurity(WIFI_AUTH_WPA2_PSK);
    WiFi.setAutoReconnect(false);

    // Register ONE event handler for all events (pure flag-setter; the radio is only ever mutated
    // from loop()). GOT_IP is the real "online" edge; STA_CONNECTED carries the BSSID/channel to
    // cache; DISCONNECTED carries the reason that drives retry.
    _evId = WiFi.onEvent([](WiFiEvent_t e, WiFiEventInfo_t info) {
        if (self) self->onWifiEvent(e, info);
    });
}

// Pure flag-setter on the async 'arduino_events' task (core 1). ONLY single-word volatile writes —
// no critical sections (would wedge an in-flight e-paper draw), no radio calls, no drawing.
void WifiManager::onWifiEvent(WiFiEvent_t e, WiFiEventInfo_t info) {
    switch (e) {
        case ARDUINO_EVENT_WIFI_STA_GOT_IP:  // TRULY online (IPv4 up)
            _online = true;
            _evGotIp = true;
            break;
        case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
            _evReason = info.wifi_sta_disconnected.reason;  // single byte -> atomic
            _online = false;
            _evDisconnected = true;
            _linkDown = true;
            break;
        case ARDUINO_EVENT_WIFI_STA_LOST_IP:
            _online = false;
            _linkDown = true;
            break;
        default:
            break;
    }
}

void WifiManager::load() {
    _ssids.clear();
    _pass.clear();
    int count = wprefs.getInt("count", 0);
    for (int i = 0; i < count && i < kMaxNet; ++i) {
        String s = wprefs.getString(key("ssid", i).c_str(), "");
        if (s.isEmpty()) continue;
        _ssids.push_back(s);
        _pass.push_back(wprefs.getString(key("pass", i).c_str(), ""));
    }
    // Fast-reconnect cache: the AP that last worked, so boot connects directly (no scan).
    _bootSsid = wprefs.getString("last", "");
    _cacheChannel = wprefs.getInt("chan", 0);
    size_t got = wprefs.getBytes("bssid", _cacheBssid, sizeof(_cacheBssid));
    _haveCache = (got == sizeof(_cacheBssid) && _cacheChannel > 0 && _bootSsid.length() > 0);
    _lastSsid = _bootSsid;  // label the connecting screen with the expected SSID before we associate
}

void WifiManager::persist() {
    wprefs.putInt("count", (int)_ssids.size());
    for (size_t i = 0; i < _ssids.size(); ++i) {
        wprefs.putString(key("ssid", i).c_str(), _ssids[i]);
        wprefs.putString(key("pass", i).c_str(), _pass[i]);
    }
}

void WifiManager::factoryReset() {
    wprefs.clear();  // wipe the "wifinet" NVS namespace (all saved SSIDs/passwords + fast-reconnect cache)
    _ssids.clear();
    _pass.clear();
    _bootSsid = "";
    _lastSsid = "";
    _cacheChannel = 0;
    _haveCache = false;
    memset(_cacheBssid, 0, sizeof(_cacheBssid));
}

void WifiManager::seedIfEmpty(const String &ssid, const String &pass) {
    if (!_ssids.empty()) return;
    if (ssid.isEmpty() || ssid == "your-wifi-ssid") return;
    addNetwork(ssid, pass);
}

bool WifiManager::addNetwork(const String &ssid, const String &pass) {
    if (ssid.isEmpty()) return false;
    for (size_t i = 0; i < _ssids.size(); ++i) {
        if (_ssids[i] == ssid) {
            _pass[i] = pass;
            persist();
            return true;
        }
    }
    if (_ssids.size() >= (size_t)kMaxNet) {
        _ssids.erase(_ssids.begin());
        _pass.erase(_pass.begin());
    }
    _ssids.push_back(ssid);
    _pass.push_back(pass);
    persist();
    return true;
}

// Manual join from the on-device keyboard: reuse the NON-BLOCKING boot FSM instead of a blocking
// scan+connect on the UI loop. Prefers the just-entered SSID, then falls through the saved-network
// ladder. loop() drives serviceConnect() and reacts (onConnected / captive portal).
void WifiManager::beginConnectTo(const String &preferSsid) {
    if (_mode == MODE_PORTAL) stopPortal();  // tear down the softAP -> back to plain STA
    _mode = MODE_IDLE;                        // stop diag reconnect/roam from racing the FSM
    _bootSsid = preferSsid;                   // try the just-entered network first
    _haveCache = false;                       // no cached channel/BSSID for a fresh join
    _reconnAttempts = 0;
    beginConnect();
}

// ---- non-blocking boot connect (UI-thread state machine) -------------------
// WiFi.begin() returns immediately; only connectBest()'s status busy-wait blocked.
// Here we kick an ASYNC scan, then WiFi.begin() each candidate and poll status —
// all from loop(), so the UI/touch/console never stall and no side task races the
// (not thread-safe) WiFi driver.
void WifiManager::beginConnect() {
    _cnCands.clear();
    _cnTry = 0;
    _cnScanned = false;
    _cnBootStart = millis();
    _reconnAttempts = 0;
    _consecCredFail = 0;
    if (_ssids.empty()) { _cn = CN_FAIL; return; }
    // Connect-FIRST, scan only on failure. Order: the last-good SSID first (persisted), then the
    // rest in saved order. No upfront scan — that was ~10.7s of dead time (and returned 0 networks).
    // (One-time radio config + event handlers were set in begin().)
    int lastIdx = -1;
    for (size_t i = 0; i < _ssids.size(); ++i)
        if (_ssids[i] == _bootSsid) { lastIdx = (int)i; break; }
    if (lastIdx >= 0) _cnCands.push_back(lastIdx);
    for (size_t i = 0; i < _ssids.size(); ++i)
        if ((int)i != lastIdx) _cnCands.push_back((int)i);
    startAttempt(0);
    _cn = CN_TRYING;
}

// Begin associating to candidate k. The last-good AP on the FIRST attempt uses its cached
// channel + BSSID (5-arg begin) which pins the connect to one channel and skips the internal
// AP search — the single biggest boot-connect accelerator on a stationary device.
void WifiManager::beginToAp(const String &ssid, const String &pass, bool directed) {
    if (directed) WiFi.begin(ssid.c_str(), pass.c_str(), _cacheChannel, nullptr, true);
    else WiFi.begin(ssid.c_str(), pass.c_str());
}

void WifiManager::startAttempt(size_t k) {
    _cnTry = k;
    // Clear the event edges so this attempt only reacts to its OWN GOT_IP/DISCONNECTED (the
    // self-induced disconnect between attempts also fires DISCONNECTED — ignore that one).
    _evGotIp = false;
    _evDisconnected = false;
    _online = false;
    int idx = _cnCands[k];
    const String &ssid = _ssids[idx];
    const String &pass = _pass[idx];
    _cnDirected = (!_cnForcePlain && k == 0 && !_cnScanned && _haveCache && ssid == _bootSsid);
    _cnForcePlain = false;
    if (_cnDirected) {
        // Channel-ONLY directed join: the cached channel restricts the internal scan to one channel
        // (the real accelerator, ~1s), while letting the supplicant pick the BSSID normally.
        Serial.printf("[wifi] try '%s' directed ch%d\n", ssid.c_str(), _cacheChannel);
        beginToAp(ssid, pass, true);
        _cnPerTry = 4000;
    } else {
        Serial.printf("[wifi] try '%s'\n", ssid.c_str());
        beginToAp(ssid, pass, false);
        _cnPerTry = 4500;
    }
    _cnStart = millis();
}

int WifiManager::serviceConnect() {
    switch (_cn) {
        case CN_OK: return 1;
        case CN_FAIL: return -1;
        case CN_IDLE: return 0;

        case CN_TRYING: {
            // Success is the GOT_IP edge (a real IP exists), not WL_CONNECTED (L2-only, races DHCP).
            if (_evGotIp) {
                rememberConnected();
                _reconnAttempts = 0;
                _consecCredFail = 0;
                _cn = CN_OK;
                return 1;
            }
            // React to the DISCONNECTED reason (arrives in ~1-2s), or a wall-clock backstop.
            bool disc = _evDisconnected;
            uint8_t reason = disc ? _evReason : 0;
            bool timeout = (millis() - _cnStart > _cnPerTry);
            if (!disc && !timeout) return 0;  // still associating

            ReasonClass rc = disc ? classifyReason(reason) : RC_TRANSIENT;
            if (disc) Serial.printf("[wifi] '%s' disconnected reason=%u (%s)\n",
                                    _ssids[_cnCands[_cnTry]].c_str(), reason,
                                    rc == RC_NO_AP ? "no-ap" : rc == RC_CREDENTIAL ? "cred" : "transient");
            if (rc == RC_CREDENTIAL) _consecCredFail++;
            WiFi.disconnect(false, true);  // clear the driver AP-blacklist before the next begin
            _cnStart = millis();

            if (_cnDirected) {
                // The channel-pinned fast path missed (moved channel / transient assoc / mesh
                // steering) -> retry the SAME SSID all-channel once; that is the robust path.
                if (rc == RC_NO_AP) _haveCache = false;
                _cnForcePlain = true;
                _cnNextIdx = (int)_cnTry;
            } else if (rc == RC_TRANSIENT && _cnRetries < 1) {
                _cnRetries++;              // one extra all-channel retry on a transient assoc blip
                _cnForcePlain = true;
                _cnNextIdx = (int)_cnTry;
            } else if (_cnTry + 1 < _cnCands.size()) {
                _cnRetries = 0;
                _cnNextIdx = (int)(_cnTry + 1);  // next saved network
            } else if (!_cnScanned) {
                _cnRetries = 0;
                _cnNextIdx = -1;           // one fallback all-channel scan
            } else if (_consecCredFail >= 3 || millis() - _cnBootStart > 45000UL) {
                _cn = CN_FAIL;             // genuine bad creds, or gave the router 45s -> portal
                return -1;
            } else {
                _cnRetries = 0;
                _cnNextIdx = -2;           // AP outage: self-heal, restart the ladder (no portal)
            }
            _cn = CN_SETTLE;
            return 0;
        }

        case CN_SETTLE: {  // let the just-issued disconnect propagate before the next begin()
            if (millis() - _cnStart < 300) return 0;
            if (_cnNextIdx == -1) {  // fallback scan
                _cnScanned = true;
                WiFi.scanDelete();
                WiFi.scanNetworks(true, false);  // async, no hidden directed probes (faster)
                _cn = CN_SCANNING;
                return 0;
            }
            if (_cnNextIdx == -2) {  // restart the whole ladder (AP-outage self-heal)
                _cnScanned = false;
                startAttempt(0);
                _cn = CN_TRYING;
                return 0;
            }
            startAttempt((size_t)_cnNextIdx);
            _cn = CN_TRYING;
            return 0;
        }

        case CN_SCANNING: {  // fallback only
            int n = WiFi.scanComplete();
            if (n == WIFI_SCAN_RUNNING) return 0;
            if (n < 0) n = 0;
            Serial.printf("[wifi] fallback scan=%d\n", n);
            struct C { int rssi, idx; };
            std::vector<C> cs;
            for (size_t s = 0; s < _ssids.size(); ++s) {
                int best = -1000;
                for (int i = 0; i < n; ++i)
                    if (WiFi.SSID(i) == _ssids[s] && WiFi.RSSI(i) > best) best = WiFi.RSSI(i);
                cs.push_back({best, (int)s});
            }
            WiFi.scanDelete();
            std::sort(cs.begin(), cs.end(), [](const C &a, const C &b) { return a.rssi > b.rssi; });
            _cnCands.clear();
            for (const C &c : cs)
                if (c.rssi > -1000) _cnCands.push_back(c.idx);
            if (_cnCands.empty()) { _cn = CN_FAIL; return -1; }
            startAttempt(0);
            _cn = CN_TRYING;
            return 0;
        }
    }
    return 0;
}

// Capture + persist the AP that just worked so the next boot connects directly. Prefer the
// BSSID/channel latched from the STA_CONNECTED event (atomic, exact moment); fall back to the
// live API for the blocking manual-join paths that don't run through the event FSM.
void WifiManager::rememberConnected() {
    _lastSsid = WiFi.SSID();  // keep the RAW SSID bytes — it's a join key/compare target; fold only at draw
    const uint8_t *b = WiFi.BSSID();  // pointer to a SHARED static buffer -> copy right away
    if (b) {
        memcpy(_cacheBssid, b, sizeof(_cacheBssid));
        _cacheChannel = WiFi.channel();
    }
    _haveCache = (_cacheChannel > 0);
    _bootSsid = _lastSsid;
    wprefs.putString("last", _lastSsid);
    if (_haveCache) {
        wprefs.putBytes("bssid", _cacheBssid, sizeof(_cacheBssid));
        wprefs.putInt("chan", _cacheChannel);
    }
    Serial.printf("[wifi] cache: %s ch%d %02x:%02x:%02x:%02x:%02x:%02x\n", _lastSsid.c_str(),
                  _cacheChannel, _cacheBssid[0], _cacheBssid[1], _cacheBssid[2], _cacheBssid[3],
                  _cacheBssid[4], _cacheBssid[5]);
}

bool WifiManager::connected() const { return WiFi.status() == WL_CONNECTED; }

String WifiManager::passFor(const String &ssid) const {
    for (size_t i = 0; i < _ssids.size(); ++i) {
        if (_ssids[i] == ssid) return _pass[i];
    }
    return String();
}

void WifiManager::ensureServer() {
    if (_serverStarted) return;
    server.on("/", HTTP_GET, []() { self->handleRoot(); });          // hub
    server.on("/wifi", HTTP_GET, []() { self->handleWifiPage(); });    // WiFi subpage
    server.on("/apikey", HTTP_GET, []() { self->handleApiKeyPage(); }); // API-key subpage
    server.on("/scan", HTTP_GET, []() { self->handleScan(); });
    server.on("/connect", HTTP_POST, []() { self->handleConnect(); });
    server.on("/apikey", HTTP_POST, []() { self->handleApiKey(); });   // save key
    server.on("/status", HTTP_GET, []() { self->handleStatus(); });
    // Captive-portal probe URLs so the page auto-opens on phones/PCs.
    server.on("/generate_204", []() { self->handleCaptive(); });
    server.on("/gen_204", []() { self->handleCaptive(); });
    server.on("/ncsi.txt", []() { self->handleCaptive(); });
    server.on("/hotspot-detect.html", []() { self->handleCaptive(); });
    server.on("/connecttest.txt", []() { self->handleCaptive(); });
    channels.registerRoutes(server);   // /channels admin + /api/channels REST
    timeKeeper.registerRoutes(server);  // /api/time, /api/time/zones, /api/time/tz
    server.onNotFound([]() { self->handleCaptive(); });
    server.begin();
    _serverStarted = true;
}

void WifiManager::startPortal(const String &apSsid) {
    _apSsid = apSsid;
    _mode = MODE_PORTAL;
    _portalConnected = false;
    WiFi.mode(WIFI_AP_STA);
    WiFi.setSleep(WIFI_PS_NONE);
    WiFi.setScanMethod(WIFI_ALL_CHANNEL_SCAN);
    WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);
    WiFi.softAP(apSsid.c_str(), kPortalPass);  // WPA2 — matches the password the setup screen + QR advertise
    delay(100);
    IPAddress ip = WiFi.softAPIP();
    dns.start(53, "*", ip);
    ensureServer();
    _lastScanKick = 0;  // scan immediately
    Serial.printf("[wifi] portal up: SSID='%s'  http://%s\n", apSsid.c_str(),
                  ip.toString().c_str());
}

void WifiManager::startDiagnostics() {
    _mode = MODE_DIAG;
    WiFi.setScanMethod(WIFI_ALL_CHANNEL_SCAN);
    WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);
    if (MDNS.begin("vulncast")) MDNS.addService("http", "tcp", 80);
    ensureServer();
    _lastScanKick = 0;
    Serial.printf("[wifi] diagnostics up: http://%s  (vulncast.local)\n",
                  WiFi.localIP().toString().c_str());
}

void WifiManager::stopPortal() {
    dns.stop();
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    _mode = MODE_IDLE;
}

void WifiManager::serviceScan() {
    int st = WiFi.scanComplete();
    if (_scanning) {
        if (st >= 0) {
            _scanJson = buildScanJson(st);
            WiFi.scanDelete();
            _scanning = false;
        } else if (st == WIFI_SCAN_FAILED) {
            _scanning = false;
        }
        return;
    }
    if (_lastScanKick == 0 || millis() - _lastScanKick > 10000) {
        _lastScanKick = millis();
        WiFi.scanNetworks(true, true);  // async, include hidden
        _scanning = true;
    }
}

String WifiManager::buildScanJson(int n) {
    struct E { String ssid; int rssi; bool lock; };
    std::vector<E> list;
    String cur = connected() ? WiFi.SSID() : String();
    int bestCur = -1000;
    for (int i = 0; i < n; ++i) {
        String s = WiFi.SSID(i);  // RAW bytes: this string is the join target + web value; fold only at panel draw
        if (s.isEmpty()) continue;
        int r = WiFi.RSSI(i);
        bool lock = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
        if (!cur.isEmpty() && s == cur && r > bestCur) bestCur = r;
        bool found = false;
        for (E &e : list) {
            if (e.ssid == s) {
                if (r > e.rssi) { e.rssi = r; e.lock = lock; }
                found = true;
                break;
            }
        }
        if (!found) list.push_back({s, r, lock});
    }
    _bestRssiCurrent = bestCur;
    std::sort(list.begin(), list.end(), [](const E &a, const E &b) { return a.rssi > b.rssi; });

    // Mirror the deduped list into the cache the on-device settings screen reads.
    _scanNets.clear();
    for (const E &e : list) {
        WifiNet w;
        w.ssid = e.ssid;
        w.rssi = e.rssi;
        w.secure = e.lock;
        _scanNets.push_back(w);
    }

    JsonDocument doc;
    JsonArray arr = doc.to<JsonArray>();
    for (const E &e : list) {
        JsonObject o = arr.add<JsonObject>();
        o["ssid"] = e.ssid;
        o["rssi"] = e.rssi;
        o["lock"] = e.lock;
    }
    String out;
    serializeJson(doc, out);
    return out;
}

void WifiManager::maybeRoam() {
    if (millis() - _lastRoam < 45000) return;
    _lastRoam = millis();
    if (!_online) return;
    int cur = WiFi.RSSI();
    // Roam to a stronger AP only when the link is weak and a clearly better AP of the same SSID is
    // visible (hysteresis avoids flapping). Just DROP the link (cache cleared so the reconnect picks
    // the strongest via sort-by-signal); the owned reconnect policy does the single re-associate —
    // never begin() here too, or it races that policy ("sta is connecting").
    if (cur < -70 && _bestRssiCurrent > cur + 12) {
        Serial.printf("[wifi] roam: cur=%d best=%d -> drop for a stronger AP\n", cur, _bestRssiCurrent);
        _haveCache = false;
        _reconnAttempts = 0;
        WiFi.disconnect(false, true);
    }
}

void WifiManager::loop() {
    if (_mode == MODE_IDLE) return;
    if (_mode == MODE_PORTAL) dns.processNextRequest();
    server.handleClient();
    serviceScan();

    if (_mode == MODE_PORTAL) {
        if (connected()) _portalConnected = true;
        return;
    }

    // Diagnostics (STA) mode — steady state. Link health tracks the GOT_IP-based _online flag.
    if (_online) {
        if (_evGotIp) {  // a fresh (re)connect landed -> reset the backoff ladder
            _evGotIp = false;
            _reconnAttempts = 0;
            _consecCredFail = 0;
            _linkDownSince = 0;  // link is back -> cancel the give-up timer
        }
        maybeRoam();
        return;
    }

    // Link is down. We OWN reconnect (setAutoReconnect is off): classify the drop reason and
    // re-associate on a reason-aware exponential backoff, directed from the cache for speed —
    // replacing the old blind 10s WiFi.reconnect() (which re-scanned every time).
    if (_evDisconnected) {
        _evDisconnected = false;
        if (classifyReason(_evReason) == RC_NO_AP) _haveCache = false;  // AP moved -> next begin all-channel
        _nextRetryAt = millis();  // attempt promptly; the block below applies/paces the backoff
    }
    if (_bootSsid.isEmpty()) return;
    if (_linkDownSince == 0) _linkDownSince = millis();  // start the give-up timer on the first down tick

    // Bootstrap fallback: after a sustained outage the saved network is effectively gone (moved, renamed,
    // powered off, out of range). Stop hammering it and raise the setup AP so the user can point the
    // device at a reachable network. A brief blip (router reboot) reconnects first and never reaches here.
    if (millis() - _linkDownSince > kReconnGiveUpMs) {
        Serial.printf("[wifi] reconnect gave up after %lus down -> raising setup portal\n",
                      (unsigned long)((millis() - _linkDownSince) / 1000));
        _linkDownSince = 0;
        _reconnAttempts = 0;
        startPortal(kPortalSsid);
        _reconnPortalEvent = true;  // tell the UI loop to show the setup screen
        return;
    }

    if (millis() < _nextRetryAt) return;
    uint32_t backoff = 750UL << (_reconnAttempts < 7 ? _reconnAttempts : 7);  // 0.75..96s, capped
    if (backoff > 60000UL) backoff = 60000UL;
    _nextRetryAt = millis() + backoff + (millis() & 0x7F);  // small jitter
    _reconnAttempts++;
    String pass = passFor(_bootSsid);
    WiFi.disconnect(false, true);  // clear the AP-blacklist to avoid a CONNECTION_FAIL(205) loop
    beginToAp(_bootSsid, pass, _haveCache);  // channel-only when cached (never pin BSSID: reason 203)
}

bool WifiManager::takeReconnectPortalEvent() {
    if (!_reconnPortalEvent) return false;
    _reconnPortalEvent = false;
    return true;
}

// Validate the Vulners key after the link is up. This makes a BLOCKING HTTPS call,
// so it must run on the network task (core 0), never on the UI loop. Retry on
// transient failures (an occasional Cloudflare challenge / network blip) instead of
// sticking on a false "invalid"; stop only once we get a definitive answer.
void WifiManager::serviceKeyCheck() {
    if (!connected() || !config.hasApiKey() || _apiKeyChecked) return;
    // A successful channel fetch uses the same key — that's authoritative proof it's valid, even when
    // the dedicated /apiKey/valid endpoint keeps failing on a weak link (HTTP -1). Trust it.
    if (channels.apiKeyProvenByFetch()) { _apiKeyValid = true; _apiKeyChecked = true; return; }
    if (_lastKeyCheck != 0 && millis() - _lastKeyCheck <= 15000) return;
    _lastKeyCheck = millis();
    String err;
    bool ok = VulnersClient::validateKey(config.apiKey(), err);
    if (ok) {
        _apiKeyValid = true;
        _apiKeyChecked = true;
    } else if (err == "invalid key") {
        _apiKeyValid = false;
        _apiKeyChecked = true;  // server definitively rejected the key
    }  // else: transient -> leave unchecked, retry in ~15 s
    Serial.printf("[vulners] key check: %s\n", ok ? "valid" : err.c_str());
}

void WifiManager::handleRoot() {
    vcSendHead(server, "VulnCast");
    server.sendContent_P(kHubBody);
    vcSendTail(server);
}
void WifiManager::handleWifiPage() {
    vcSendHead(server, "VulnCast \xC2\xB7 WiFi");
    server.sendContent_P(kWifiBody);
    vcSendTail(server);
}
void WifiManager::handleApiKeyPage() {
    vcSendHead(server, "VulnCast \xC2\xB7 API key");
    server.sendContent_P(kApiKeyBody);
    vcSendTail(server);
}

void WifiManager::handleScan() { server.send(200, "application/json", _scanJson); }

void WifiManager::handleStatus() {
    JsonDocument d;
    d["mode"] = _mode == MODE_PORTAL ? "portal" : (_mode == MODE_DIAG ? "connected" : "idle");
    bool conn = connected();
    d["connected"] = conn;
    d["ssid"] = conn ? WiFi.SSID() : String();
    d["rssi"] = conn ? WiFi.RSSI() : 0;
    d["ip"] = conn ? WiFi.localIP().toString() : String();
    d["saved"] = (int)_ssids.size();
    d["apiKeySet"] = config.hasApiKey();
    d["apiKeyValid"] = _apiKeyValid;
    d["apiKeyChecked"] = _apiKeyChecked;
    // Time folded in so the status bar needs one request, not two.
    d["synced"] = timeKeeper.synced();
    d["time"] = timeKeeper.localTime();
    d["tzLabel"] = timeKeeper.timezoneLabel();
    vcSendJson(server, 200, d);
}

void WifiManager::handleConnect() {
    String ssid = server.arg("ssid");
    String custom = server.arg("custom");
    if (!custom.isEmpty()) ssid = custom;
    String pass = server.arg("pass");

    JsonDocument d;
    if (ssid.isEmpty()) {
        d["ok"] = false;
        d["message"] = "SSID required";
        vcSendJson(server, 200, d);
        return;
    }
    addNetwork(ssid, pass);
    WiFi.begin(ssid.c_str(), pass.c_str());
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 12000) delay(150);

    bool ok = connected();
    if (ok) {
        rememberConnected();     // persist SSID + BSSID + channel for a fast next-boot connect
        _apiKeyChecked = false;  // re-validate the key on the new link
        _lastKeyCheck = 0;
        if (_mode == MODE_PORTAL) _portalConnected = true;
        d["ok"] = true;
        d["ip"] = WiFi.localIP().toString();
    } else {
        d["ok"] = false;
        d["message"] = "Failed to connect";
    }
    vcSendJson(server, 200, d);
}

void WifiManager::handleApiKey() {
    String k = server.arg("key");
    JsonDocument d;
    if (k.isEmpty()) {
        d["valid"] = false;
        d["message"] = "empty";
        vcSendJson(server, 200, d);
        return;
    }
    String err;
    bool valid = VulnersClient::validateKey(k, err);
    _apiKeyChecked = true;
    if (valid) {
        config.setApiKey(k);
        channels.resetApiKeyProof();  // new key -> the old fetch-proof is stale
        _apiKeyValid = true;
        d["valid"] = true;
    } else if (err == "invalid key") {
        _apiKeyValid = false;
        d["valid"] = false;
        d["message"] = "Invalid key";
    } else {
        // Could not verify (offline / transient): store but mark unverified.
        config.setApiKey(k);
        channels.resetApiKeyProof();  // new key -> don't let a prior key's fetch-proof mark it valid
        _apiKeyValid = false;
        _apiKeyChecked = false;
        d["valid"] = false;
        d["message"] = "Saved, but could not verify (" + err + ")";
    }
    vcSendJson(server, 200, d);
}

void WifiManager::handleCaptive() {
    if (_mode == MODE_PORTAL) {
        server.sendHeader("Location", apUrl());
        server.send(302, "text/plain", "");
        return;
    }
    handleRoot();
}
