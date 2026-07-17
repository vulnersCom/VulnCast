// VulnCast firmware entry point.
//
// Fully on-device ops-console: modern WiFi (WPA2/WPA3, multi-network NVS store,
// captive-portal provisioning), Vulners "channels" over HTTPS, and a 9-screen
// e-paper touch UI (see ui.{h,cpp}). ESP32-S3 + e-paper tuned: 240 MHz, WiFi
// power-save OFF, HTTPS on a core-0 FreeRTOS task so the UI/touch loop never
// blocks; flash-free 2-bit partial repaints via FastEPD (see gfx.{h,cpp}).
#include <Arduino.h>
#include <ArduinoOTA.h>
#include <Button2.h>
#include <WiFi.h>
#include <ctime>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <vector>

#include "board_pins.h"  // BUTTON_1 / BATT_PIN (was LilyGo-EPD47 utilities.h)
#include "channels.h"
#include "config.h"
#include "gfx.h"          // drawing toolkit (also pulls in the epdiy rasterizer headers)
#include "secrets.h"
#include "timekeeper.h"
#include "ui.h"
#include "updater.h"
#include "vulners.h"
#include "wifi_manager.h"

namespace {

VulnersClient vulners;
Button2 button(BUTTON_1);
TaskHandle_t g_fetchTask = nullptr;
bool g_otaReady = false;
uint32_t g_lastNav = 0;  // millis() of the last manual page/refresh or dashboard entry — suppresses
                         // the update-driven auto-switch for kNavGraceMs so the user can read
constexpr uint32_t kNavGraceMs = 20000UL;  // grace after a manual nav/entry before an auto-switch
volatile uint32_t g_loopN = 0;  // UI-loop heartbeat: advances every loop() iteration
                                // (frozen value here => the UI loop is blocked, not just noisy)
uint32_t g_lastDashUpd = 0;   // updatedMs the dashboard was last drawn from
uint32_t g_refreshBusyUntil = 0;  // manual-refresh "UPDATING" ack shown until data lands or this timeout
uint32_t g_lastStatusDraw = 0;
String g_updateShownVer;  // version whose update offer we've already surfaced (don't re-navigate to it)

// Boot AND manual-join Wi-Fi bring-up is NON-BLOCKING and driven from loop() (see wifiManager
// .beginConnect / beginConnectTo / serviceConnect). A blocking scan+connect on the UI loop froze
// the panel/touch ("board doesn't finish booting"); running it on a side task instead hard-froze
// the WiFi driver (not thread-safe). The state machine keeps every WiFi call on the UI thread
// without ever blocking. WB_DONE latches once loop() has reacted to the result.
enum WifiBoot : uint8_t { WB_CONNECTING = 0, WB_DONE };
WifiBoot g_wifiBoot = WB_CONNECTING;
volatile bool g_forceDash = false;  // console 'F': stop the boot-connect churn and show the
                                    // dashboard for UI testing regardless of Wi-Fi state
volatile bool g_uiReady = false;    // onConnected drew the dashboard -> fetch task may hit the net
bool g_needNetServices = false;     // bring up mDNS diagnostics + OTA off the connect draw path

// Network fetch task (core 0): keeps HTTPS off the UI path. Services channels.
// Gated on g_uiReady: its first burst (TLS key-check + JSON parsing in PSRAM) must NOT run while
// onConnected() is drawing — concurrent PSRAM/CPU contention starves the e-paper I2S DMA and wedges
// the panel. onConnected() draws the dashboard first, then opens the gate.
void fetchTask(void *) {
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
        if (!g_uiReady || WiFi.status() != WL_CONNECTED) continue;
        if (updater.installPending()) {  // dedicate this wake to the (blocking) download+install; reboots on success
            updater.serviceInstall();
            continue;
        }
        wifiManager.serviceKeyCheck();  // blocking HTTPS validation, off the UI loop
        channels.tick(vulners);
        if (wifiManager.apiKeyValid()) vulners.serviceCredits();  // refresh the credit balance (throttled)
        updater.tick();                 // self-throttled hourly update discovery, off the UI loop
    }
}

void triggerFetch() {
    if (g_fetchTask) xTaskNotifyGive(g_fetchTask);
}

// Force-refresh the active channel now and wake the network task. Shared by the console 'r'
// command, the hardware button, and the UI refresh event.
void requestActiveRefresh() {
    channels.refreshNow(ui.activeId());
    triggerFetch();
}

// ---- always-on debug console -----------------------------------------------
// Runs in its OWN FreeRTOS task on core 0, so UART commands keep working even if
// the UI loop (loopTask, core 1) blocks or hangs — you can always inspect state,
// dump the screen, or reboot. The task only does read-only work + reboot itself;
// anything that DRAWS is queued to the UI loop (two tasks writing the panel would
// corrupt it). Not subscribed to the Task Watchdog, and it yields every cycle.
TaskHandle_t g_debugTask = nullptr;

void consoleHelp() {
    Serial.print(F(
        "\n=== VulnCast UART console (always-on) ===\n"
        " INSPECT\n"
        "  h ?        this help\n"
        "  i          device state (screen/wifi/api/time/channels/heap/uptime)\n"
        "  s          current screen id + name\n"
        "  C          list channels (name/active/manual/interval)\n"
        "  D          dump framebuffer -> host PNG (tools/console.py dump)\n"
        " CONTROL\n"
        "  t <x> <y>  inject a touch, e.g.  t 903 100   (hit-box = drawn control)\n"
        "  M          toggle echo of REAL panel taps (verify touch hardware)\n"
        "  W          cycle repaint mode: SMART (clean partial) <-> FULL\n"
        "  G          cycle a gfx self-test pattern (white/black/checker/ramp/grid)\n"
        "  Q <0..7>   probe one driver op in isolation (pinpoints a hang; see gfx.h)\n"
        "  X          verify shadow==framebuffer (0 = compositor pushed every change)\n"
        "  F          force dashboard now (stop boot-connect churn; UI testing w/o wifi)\n"
        "  n / p      next / prev channel (dashboard)\n"
        "  r          refresh the active channel now\n"
        "  u          check for a firmware update now (forces the OTA check; + crypto self-test)\n"
        "  1-9 VKYUBLO preview a screen: 1 dashboard 2 document 3 settings 4 keyboard\n"
        "             5 interval 6 timezone 7 boot 8 connecting 9 setup V vuln-doc\n"
        "             K needkey Y reset-confirm U update B update-failed L chill O no-credits\n"
        "  R          reboot the device\n"
        " REFERENCE\n"
        "  screen ids (s/i): 0 boot 1 connecting 2 setup 3 dashboard 4 document\n"
        "             5 settings 6 keyboard 7 interval 8 timezone\n"
        "  panel 960x540, origin top-left. Own FreeRTOS task -> answers even when\n"
        "  the main app is stuck. Host CLI: python3 tools/console.py <cmd>\n"));
}

void consoleState() {
    const char *net = wifiManager.connected() ? "connected"
                      : wifiManager.inPortal() ? "portal(setup)" : "down";
    Serial.println(F("--- device state ---"));
    Serial.printf("uptime  : %lu s  loopN=%lu (UI-loop heartbeat)\n",
                  (unsigned long)(millis() / 1000), (unsigned long)g_loopN);
    Serial.printf("screen  : %d %s\n", (int)ui.screen(), ui.screenName());
    Serial.printf("wifi    : %s ssid=%s ip=%s rssi=%d\n", net, wifiManager.lastSsid().c_str(),
                  wifiManager.connected() ? WiFi.localIP().toString().c_str() : "-",
                  wifiManager.connected() ? WiFi.RSSI() : 0);
    Serial.printf("api key : %s\n", wifiManager.apiKeyValid()   ? "valid"
                                    : config.hasApiKey()        ? "set (unchecked)"
                                                                : "none");
    Serial.printf("time    : %s tz=%s synced=%d\n", timeKeeper.localTime().c_str(),
                  timeKeeper.timezone().c_str(), timeKeeper.synced());
    Serial.printf("channels: %d in rotation, showing %s (%d/%d)\n", ui.channelCount(),
                  ui.channelCount() ? ui.activeName().c_str() : "-",
                  ui.channelCount() ? ui.channelIndex() + 1 : 0, ui.channelCount());
    Serial.printf("heap    : %u free / %u largest block\n", ESP.getFreeHeap(), ESP.getMaxAllocHeap());
    Serial.printf("repaint : %s\n", gfx::repaintModeName());
    Serial.printf("last draw: %s\n", gfx::lastFlushInfo());
    Serial.printf("fetch   : %s\n",
                  g_fetchTask && eTaskGetState(g_fetchTask) != eDeleted ? "task alive" : "task dead");
    if (updater.available())
        Serial.printf("update  : fw %s -> %s AVAILABLE\n", updater.currentVersion().c_str(),
                      updater.availableVersion().c_str());
    else
        Serial.printf("update  : fw %s, %s\n", updater.currentVersion().c_str(),
                      updater.phase() == Updater::CHECKING    ? "checking\xE2\x80\xA6"
                      : updater.phase() == Updater::DOWNLOADING ? "downloading"
                      : updater.phase() == Updater::INSTALLING  ? "installing"
                      : updater.phase() == Updater::FAILED      ? "last attempt failed"
                                                                : "up to date");
}

void consoleDispatch(char c) {
    switch (c) {
        case 'h':
        case '?': consoleHelp(); break;
        case 'i': consoleState(); break;
        case 's': Serial.printf("[scr] %d %s\n", (int)ui.screen(), ui.screenName()); break;
        case 'C':
            for (const Channel &ch : channels.list())
                Serial.printf("CH %-14s active=%d manual=%d refreshSec=%u\n", ch.name.c_str(),
                              ch.active, ch.manual, ch.refreshSec);
            break;
        case 'D': {  // clean dump: let the UI loop do it between draws (no torn frame);
            ui.requestDump();                //  fall back to dumping here if the UI is hung.
            uint32_t t0 = millis();
            while (ui.dumpPending() && millis() - t0 < 1500) vTaskDelay(pdMS_TO_TICKS(20));
            if (ui.dumpPending()) gfx::dumpSerial();  // UI loop not responding -> best-effort
            break;
        }
        case 'R':
            Serial.println(F("[console] rebooting..."));
            delay(60);
            ESP.restart();
            break;
        case 't': {  // inject a synthetic touch: "t <x> <y>"
            int x = Serial.parseInt(), y = Serial.parseInt();
            ui.injectTouch(x, y);
            Serial.printf("[tap] %d,%d queued\n", x, y);
            break;
        }
        case 'M':  // toggle echoing of REAL panel taps (verify touch hardware)
            ui.setTouchMonitor(!ui.touchMonitor());
            Serial.printf("[touchmon] %s\n", ui.touchMonitor() ? "ON - tap the panel" : "off");
            break;
        case 'W':  // cycle repaint mode: SMART (diff, minimal flash) <-> FULL (flash always)
            gfx::setRepaintMode(gfx::repaintMode() == gfx::RP_SMART ? gfx::RP_FULL : gfx::RP_SMART);
            Serial.printf("[repaint] %s\n", gfx::repaintModeName());
            break;
        case 'G': {  // cycle a gfx self-test pattern on the panel (inspect contrast/grays/alignment)
            static int pat = 0;
            ui.requestTest(pat);
            Serial.printf("[gfx-test] %d %s\n", pat, gfx::testPatternName(pat));
            pat = (pat + 1) % gfx::kTestPatterns;
            break;
        }
        case 'Q': {  // probe one driver op in isolation: "Q <0..7>" (pinpoints a hang)
            int op = Serial.parseInt();
            if (op < 0 || op >= gfx::kProbes) op = 0;
            ui.requestProbe(op);
            Serial.printf("[probe] queued op %d\n", op);
            break;
        }
        case 'F':  // force the dashboard (stop boot-connect churn) — reliable UI testing
            g_forceDash = true;
            Serial.println(F("[force] dashboard requested (wifi-independent)"));
            break;
        case 'X': {  // correctness proof: shadow (pushed to panel) vs framebuffer (should show)
            int d = gfx::shadowMismatch();
            if (d < 0) Serial.println(F("[verify] no panel state yet (no present)"));
            else Serial.printf("[verify] shadow-vs-fb mismatch = %d bytes (0 = every change pushed)\n", d);
            break;
        }
        case 'r':  // refresh the active channel now
            requestActiveRefresh();
            Serial.println(F("[refresh] queued fetch for active channel"));
            break;
        case 'u':  // OTA: crypto self-test + force an update-discovery check now (off the UI loop)
            updater.selfTest();
            updater.requestCheck();
            triggerFetch();
            Serial.println(F("[ota] self-test done; forced discovery queued (watch for [ota] lines)"));
            break;
#ifdef VULNCAST_OTA_TEST
        case 'I': {  // TEST: install from a URL over insecure TLS — "I <url> <sha256hex> <size>"
            String line = Serial.readStringUntil('\n');
            line.trim();
            int a = line.indexOf(' '), b = line.indexOf(' ', a + 1);
            if (a > 0 && b > a) {
                updater.testInstall(line.substring(0, a), line.substring(a + 1, b),
                                    (uint32_t)line.substring(b + 1).toInt());
                triggerFetch();
            } else {
                Serial.println(F("[ota] usage: I <url> <sha256hex> <size>"));
            }
            break;
        }
        case 'O':  // TEST: force a rollback (simulate a failed health verification)
            updater.rollbackAndReboot();
            break;
#endif
        case 'n': ui.injectTouch(925, 174); Serial.println(F("[ch] next")); break;  // ▸ pager
        case 'p': ui.injectTouch(35, 174); Serial.println(F("[ch] prev")); break;   // ◂ pager
        case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
        case 'V': case 'K': case 'Y': case 'U': case 'B': case 'L': case 'O':
            ui.requestJump(c);  // drawing happens on the UI loop
            Serial.printf("[jump] %c queued\n", c);
            break;
        default: break;  // ignore whitespace/unknown
    }
}

void debugTask(void *) {
    for (;;) {
        while (Serial.available()) consoleDispatch((char)Serial.read());
        vTaskDelay(pdMS_TO_TICKS(15));
    }
}

// Battery volts via the /2 divider on BATT_PIN. Cached ~30 s: the voltage moves slowly but
// buildStatus() runs on every redraw (channel switch, back-nav, fresh fetch, 60 s tick), so a live
// read per redraw would stall the UI needlessly. (The old epd_poweron/off gating was a no-op under
// FastEPD — epdiy runs on a dummy board — and the divider rail is already powered in normal
// operation; if battery-only readings ever look wrong, assert the rail via FastEPD before the read.)
float readBattery() {
    static float cachedV = 0.0f;
    static uint32_t lastMs = 0;
    uint32_t now = millis();
    if (cachedV == 0.0f || now - lastMs >= 30000UL) {
        cachedV = (analogReadMilliVolts(BATT_PIN) * 2.0f) / 1000.0f;
        lastMs = now;
    }
    return cachedV;
}
int battPct(float v) {
    int p = (int)((v - 3.30f) / (4.20f - 3.30f) * 100.0f);
    return p < 0 ? 0 : p > 100 ? 100 : p;
}

void pushChannelsToUi() {
    std::vector<Channel> act = channels.active();
    std::vector<String> ids, names;
    for (const Channel &c : act) {
        ids.push_back(c.id);
        String n = c.name;
        n.toUpperCase();
        names.push_back(n);
    }
    ui.setChannels(ids, names);
}

UiStatus buildStatus() {
    UiStatus s;
    s.connected = (WiFi.status() == WL_CONNECTED);
    s.apMode = wifiManager.inPortal();
    if (s.connected) {
        s.ssid = WiFi.SSID();
        s.rssi = WiFi.RSSI();
        s.ip = WiFi.localIP().toString();
    }
    s.apiKeySet = config.hasApiKey();
    s.apiKeyValid = wifiManager.apiKeyValid();
    s.creditsKnown = vulners.creditsKnown();
    s.apiCredits = vulners.creditsRemaining();
    s.licenseType = vulners.licenseType();
    s.timeSynced = timeKeeper.synced();
    s.timeStr = timeKeeper.localTime();
    if (s.timeSynced) s.dateStr = timeKeeper.formatLocal("%a %d %b %Y", "", true);
    float bv = readBattery();
    s.battPct = battPct(bv);
    s.charging = bv > 4.15f;
    // sync age from the active channel's last successful fetch (cheap read, no full-result copy)
    uint32_t upd = channels.updatedMs(ui.activeId());
    if (upd) s.syncAgeMin = (int)((millis() - upd) / 60000UL);
    return s;
}

// Full clean redraw — entry, channel rotation, fresh data, or back-navigation.
// A full refresh fully clears the prior frame so new data never overlays old.
void redrawDashboard() {
    ui.showDashboard(buildStatus());
    ChannelResult r;
    if (channels.snapshot(ui.activeId(), r)) g_lastDashUpd = r.updatedMs;
    g_lastStatusDraw = millis();
}

// Enter the dashboard view: reset the read-grace window (suppresses auto-switch right after a manual
// action) and do a full clean redraw. Shared by connect, force-dash, back-nav, channel paging, and
// the update-driven auto-switch.
void enterDashboard() {
    g_lastNav = millis();
    redrawDashboard();
}

void setupOTA() {
    ArduinoOTA.setHostname("vulncast");
    ArduinoOTA.setPassword(OTA_PASSWORD);
    ArduinoOTA.begin();
    g_otaReady = true;
}

void onConnected() {
    Serial.print("[wifi] connected: ");
    Serial.println(WiFi.localIP());
    // Draw the dashboard FIRST and keep this path draw-only: the network-heavy steps (SNTP, mDNS
    // diagnostics, OTA, the first fetch) are deferred so nothing contends the e-paper I2S DMA during
    // the connect-time paint (concurrent PSRAM/TLS work wedges the panel).
    timeKeeper.onConnected();  // configTzTime: starts async SNTP, returns immediately (no net I/O)
    // No API key yet -> the dashboard can't fetch anything. Send the user to the web interface to add
    // it (the key is entered there, never on-device); loop() auto-advances once a key lands.
    if (!config.hasApiKey()) {
        ui.showNeedKey(WiFi.localIP().toString());
    } else {
        pushChannelsToUi();
        enterDashboard();
    }
    g_needNetServices = true;  // loop() brings up mDNS diagnostics + the web server (needed to enter the key!)
    g_uiReady = true;          // fetch task may now hit the network (a screen is already up)
    triggerFetch();
}

// Full factory wipe (from the Settings RESET -> confirm flow). Erases every persisted store, then
// reboots — on the next boot the compiled seeds apply (empty on a release build -> the setup AP),
// so the device comes up exactly like a new unit. Runs on the UI loop (poll -> EV_FACTORY_RESET).
void factoryReset() {
    Serial.println(F("[reset] factory reset requested — wiping all storage, rebooting into setup"));
    ui.showErasing();          // brief on-panel ack before the reboot
    config.factoryReset();     // NVS "vulncast"  (Vulners API key)
    wifiManager.factoryReset();// NVS "wifinet"   (saved networks + fast-reconnect cache)
    timeKeeper.factoryReset(); // NVS "clock"     (timezone)
    channels.factoryReset();   // LittleFS        (/channels.json + /feeds.json)
    updater.factoryReset();    // NVS "ota"       (snooze / skip / pending-version state)
    delay(600);                // let the ack render + NVS commits settle
    ESP.restart();
}

}  // namespace

void setup() {
    Serial.begin(115200);
    delay(200);
    setCpuFrequencyMhz(240);
    Serial.println("[vulncast] boot " VULNCAST_FW_VERSION);
    Serial.println("[uart] always-on debug console - send 'h' for commands");

    if (!ui.begin()) Serial.println("[vulncast] UI init failed");
    // Bring the always-on debug console up right after the framebuffer exists, so
    // it can report state / dump the screen even while the rest of setup() runs
    // (e.g. a slow or hanging Wi-Fi connect). Core 0, priority above loopTask.
    xTaskCreatePinnedToCore(debugTask, "debug", 4096, nullptr, 4, &g_debugTask, 0);
    ui.showBoot(1, "display \xC2\xB7 storage \xC2\xB7 radio");  // caption static; bar advances per stage

    config.begin();
    config.seedApiKeyIfEmpty(VULNERS_API_KEY);
    channels.begin();
    timeKeeper.begin();
    updater.begin();  // opens NVS "ota"; boot verify/rollback detection is wired in a later stage

    // Bring Wi-Fi up here (after the framebuffer/stores exist, before the last two boot paints) and
    // kick the NON-BLOCKING connect: WiFi.begin() returns immediately, so the ~2-3s association+DHCP
    // overlaps the showBoot(2/3)+connecting paints below. Starting it any earlier (before the first
    // paint) let a GOT_IP-triggered fetch-task HTTPS contend with e-paper init and wedged setup().
    wifiManager.begin();
    wifiManager.seedIfEmpty(WIFI_SSID, WIFI_PASSWORD);
    g_wifiBoot = WB_CONNECTING;
    wifiManager.beginConnect();

    ui.showBoot(2, "display \xC2\xB7 storage");
    xTaskCreatePinnedToCore(fetchTask, "fetch", 20480, nullptr, 1, &g_fetchTask, 0);
    // Pause the network task during each e-paper transfer so its TLS+PSRAM work can't wedge the
    // timing-sensitive I2S/RMT DMA (an intermittent hard hang under concurrent load).
    gfx::setContentionGuard(g_fetchTask);
    ui.showBoot(3, "display \xC2\xB7 storage \xC2\xB7 radio");
    // Show the connecting screen; loop() drives the connect state machine and reacts to the
    // result (onConnected or portal) while keeping the UI/touch/console fully live.
    ui.showConnecting(wifiManager.lastSsid().length() ? wifiManager.lastSsid() : String("Wi-Fi"), 0);

    button.setPressedHandler([](Button2 &) { requestActiveRefresh(); });
}

void loop() {
    g_loopN++;  // UI-loop heartbeat (see consoleState)
    // Console 'F': force the dashboard for UI testing (stops the boot-connect churn).
    if (g_forceDash) {
        g_forceDash = false;
        g_wifiBoot = WB_DONE;
        pushChannelsToUi();
        enterDashboard();  // fresh read-grace on force-dash entry
    }
    // Drive the non-blocking boot connect; the UI stays fully live while it runs.
    if (g_wifiBoot == WB_CONNECTING) {
        int r = wifiManager.serviceConnect();
        if (r == 1) {  // connected
            g_wifiBoot = WB_DONE;
            onConnected();
        } else if (r == -1) {  // no known network reachable -> captive portal
            g_wifiBoot = WB_DONE;
            wifiManager.startPortal(kPortalSsid);
            ui.showSetup(kPortalSsid, kPortalPass, wifiManager.apUrl(),
                         wifiManager.savedCount());
        }
    }

    // Bring up mDNS diagnostics + OTA once, AFTER the connect-time dashboard paint (kept off the
    // draw path so the mDNS/OTA setup never contends the e-paper DMA).
    if (g_needNetServices) {
        g_needNetServices = false;
        wifiManager.startDiagnostics();
        setupOTA();
    }

    wifiManager.loop();
    // Runtime bootstrap fallback: a sustained reconnect failure raised the setup AP — show the setup
    // screen so the user can re-provision (the inPortal() block below then drives the portal).
    if (wifiManager.takeReconnectPortalEvent()) {
        ui.showSetup(kPortalSsid, kPortalPass, wifiManager.apUrl(), wifiManager.savedCount());
    }
    ui.serviceJump();  // drain any screen-jump queued by the debug console task
    ui.serviceDump();  // perform a queued framebuffer dump between draws (no tearing)

    // Provisioning: run the captive portal until a network connects.
    if (wifiManager.inPortal()) {
        if (wifiManager.portalConnected()) {
            wifiManager.stopPortal();
            onConnected();
        }
        delay(2);
        return;
    }

    if (g_otaReady) ArduinoOTA.handle();
    button.loop();

    // Give a fresh read-grace whenever we ARRIVE on the dashboard (boot, Back, or a debug 'F'/'1'
    // jump) so an auto-switch doesn't yank the entry view. Manual page/refresh reset it at their own
    // sites; this covers every screen->dashboard transition centrally.
    static int s_prevScreen = -1;
    int curScreen = (int)ui.screen();
    if (curScreen == (int)SCR_DASHBOARD && s_prevScreen != (int)SCR_DASHBOARD) g_lastNav = millis();
    s_prevScreen = curScreen;

    // "Add your API key" screen: keep the live spinner moving, and the moment a key is entered via the
    // web interface, move on to the dashboard.
    if (ui.screen() == SCR_NEEDKEY) {
        if (config.hasApiKey()) {
            pushChannelsToUi();
            enterDashboard();
            triggerFetch();
        } else {
            static uint32_t s_needKeyAnim = 0;
            if (millis() - s_needKeyAnim > 1400) {
                s_needKeyAnim = millis();
                ui.animateNeedKey();
            }
        }
    }

    // Chill mode (lofi screensaver): keep the CVE feed scrolling and the sailboat drifting at a calm cadence.
    if (ui.screen() == SCR_CHILL) {
        static uint32_t s_chillAnim = 0;
        if (millis() - s_chillAnim > 1500) {
            s_chillAnim = millis();
            ui.animateChill();
        }
    }

    // Surface a discovered firmware update: navigate to the offer once per version, only when idle on
    // the dashboard and outside the read-grace window (never yank the screen mid-read).
    if (updater.available() && ui.screen() == SCR_DASHBOARD &&
        updater.availableVersion() != g_updateShownVer && millis() - g_lastNav > kNavGraceMs) {
        g_updateShownVer = updater.availableVersion();
        ui.showUpdate();
    }

    // Surface the out-of-credits screen once per exhaustion episode, only when idle on the dashboard and
    // outside the read-grace window. Re-arms when credits recover (a monthly reset or an upgrade).
    static bool s_creditsShown = false;
    if (!vulners.creditsExhausted()) {
        s_creditsShown = false;
    } else if (!s_creditsShown && ui.screen() == SCR_DASHBOARD && millis() - g_lastNav > kNavGraceMs) {
        s_creditsShown = true;
        ui.showNoCredits();
    }

    // Fresh-install health check (only ever true right after an OTA): mark the new image valid once it
    // boots through to a live UI without crashing. We do NOT require live Wi-Fi — a transient outage must
    // never roll back a good build, and reaching the setup-AP fallback still proves the image runs. A
    // crash/hang that never reaches a terminal screen fails the deadline -> rollback; a hard boot-loop is
    // caught by the RTC three-strikes guard in updater.begin().
    if (updater.verifyPending()) {
        bool ran = (ui.screen() == SCR_DASHBOARD || ui.screen() == SCR_NEEDKEY ||
                    ui.screen() == SCR_SETUP || ui.screen() == SCR_CHILL);
        if (ran) updater.markHealthyIfPending();
        else if (updater.verifyDeadlinePassed()) updater.rollbackAndReboot();  // does not return
    }

    // After a rollback, surface the failure screen once, when we reach a steady screen.
    static bool s_rollbackShown = false;
    if (!s_rollbackShown && updater.bootWasRollback() &&
        (ui.screen() == SCR_DASHBOARD || ui.screen() == SCR_NEEDKEY)) {
        s_rollbackShown = true;
        ui.showUpdateFailed();
    }

    // Repaint the update-progress slider as the install advances (throttled to integer-% changes, so
    // the periodic de-ghost stays rare over the ~1 min download).
    if (ui.screen() == SCR_UPDATE) {
        Updater::Phase ph = updater.phase();
        static Updater::Phase s_ph = Updater::IDLE;
        static uint8_t s_pct = 255;
        static uint32_t s_drawn = 0;
        if (ph >= Updater::DOWNLOADING &&
            (ph != s_ph || (updater.percent() != s_pct && millis() - s_drawn > 700))) {
            s_ph = ph;
            s_pct = updater.percent();
            s_drawn = millis();
            ui.showUpdate();
        }
    }

    if (ui.screen() == SCR_DASHBOARD) {
        // Update-driven feed switch (replaces the old 45s timer): the fetch task bumps an update
        // generation whenever a channel gets a NEW top item. Reading the counter is free (no snapshot
        // copy). On a bump, show that channel — unless it's already active, or we're within
        // kNavGraceMs of a manual page/refresh/entry (let the user read). Consuming the generation
        // even while in grace means boot-time first loads don't queue up a burst of switches.
        static uint32_t seenGen = 0;
        uint32_t gen = channels.updateGen();
        if (gen != seenGen) {
            seenGen = gen;
            if (ui.channelCount() > 1 && millis() - g_lastNav > kNavGraceMs &&
                ui.setActiveById(channels.lastUpdatedId())) {
                enterDashboard();
            }
        }
        // Full redraw when the active channel's data changed (fresh fetch landed) — this also
        // reverts the manual-refresh "UPDATING" ack.
        // Cheap change-check: read just the active channel's updatedMs (no full-result deep copy per
        // loop iteration); redrawDashboard() does the one real snapshot when the data actually changed.
        if (channels.updatedMs(ui.activeId()) != g_lastDashUpd) {
            g_refreshBusyUntil = 0;
            redrawDashboard();
        }
        // Manual refresh that returned no data change (or failed) — revert the busy ack on timeout.
        else if (g_refreshBusyUntil && millis() > g_refreshBusyUntil) {
            g_refreshBusyUntil = 0;
            redrawDashboard();
        }
        // Minute clock/sync tick — status-bar-only partial (no flash), when idle.
        else if (millis() - g_lastStatusDraw > 60000UL) {
            ui.refreshStatus(buildStatus());
            g_lastStatusDraw = millis();
        }
        // Live status changed (link up/down, IP via DHCP renew/reconnect, or the API key just verified) —
        // repaint the bar at once so "WEB INTERFACE <ip>" and the API ✓/? state are never stale, without
        // waiting for the 60 s tick. Compared as primitives (no per-iteration String allocation).
        else {
            static bool lastConn = false;
            static uint32_t lastIp = 0;
            static bool lastApi = false;
            bool conn = (WiFi.status() == WL_CONNECTED);
            uint32_t ip = conn ? (uint32_t)WiFi.localIP() : 0;
            bool api = wifiManager.apiKeyValid();
            if (conn != lastConn || ip != lastIp || api != lastApi) {
                lastConn = conn;
                lastIp = ip;
                lastApi = api;
                ui.refreshStatus(buildStatus());
                g_lastStatusDraw = millis();
            }
        }
    }

    // Document: re-render once when the async full record lands.
    if (ui.screen() == SCR_DOCUMENT && !ui.docDetailShown()) {
        VulnDoc d;
        if (channels.detailFor(ui.docId(), d)) ui.showDocument(ui.activeId(), ui.lastDocIndex());
    }

    switch (ui.poll()) {
        case EV_REFRESH:
            ui.showRefreshing();  // instant additive ack (no flash), decoupled from the round-trip
            requestActiveRefresh();
            g_lastNav = millis();
            g_refreshBusyUntil = millis() + 12000;  // clear the busy state on timeout if the fetch fails
            break;
        case EV_SETTINGS:
            ui.showSettings();
            break;
        case EV_OPEN_DOC: {
            ChannelResult r;
            String docId;
            if (channels.snapshot(ui.activeId(), r)) {
                int idx = ui.lastDocIndex();
                if (idx == 0) docId = r.champion.id;
                else if (idx - 1 < (int)r.candidates.size()) docId = r.candidates[idx - 1].id;
            }
            if (docId.length()) channels.requestDetail(docId);
            triggerFetch();  // wake the network task to serve the detail promptly
            ui.showDocument(ui.activeId(), ui.lastDocIndex());
            break;
        }
        case EV_BACK:
            // Returning from Settings: feed enable/disable may have changed the
            // rotation set — rebuild it so toggles take effect immediately.
            pushChannelsToUi();
            enterDashboard();
            break;
        case EV_NEXT_CH:
            ui.setChannelIndex(ui.channelIndex() + 1);
            enterDashboard();
            break;
        case EV_PREV_CH:
            ui.setChannelIndex(ui.channelIndex() - 1);
            enterDashboard();
            break;
        case EV_CONNECT: {  // on-device Wi-Fi join from the keyboard — NON-BLOCKING (boot FSM)
            String ssid = ui.kbSsid(), pass = ui.kbPass();
            wifiManager.addNetwork(ssid, pass);
            ui.showConnecting(ssid, 0);
            g_wifiBoot = WB_CONNECTING;        // loop() drives the connect; UI/touch stay live
            wifiManager.beginConnectTo(ssid);  // try the just-entered network first, no blocking scan
            break;
        }
        case EV_FACTORY_RESET:  // reset-confirm ERASE -> wipe everything + reboot into setup
            factoryReset();
            break;
        case EV_UPDATE_NOW:  // update offer accepted -> download + verify + install (shows progress)
            updater.startInstall();
            triggerFetch();  // wake the fetch task to begin the install now
            break;
        case EV_UPDATE_LATER:  // "Try again tomorrow" -> snooze ~24h and return to the dashboard
            updater.snoozeOneDay();
            g_updateShownVer = "";  // let the offer re-appear after the snooze expires (snoozed() blocks
            pushChannelsToUi();     // discovery meanwhile, so this can't immediately re-navigate)
            enterDashboard();
            break;
        default:
            break;
    }
    delay(2);
}
