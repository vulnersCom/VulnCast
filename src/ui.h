// VulnCast ops-console UI engine — 9 e-paper screens drawn directly with gfx.
//
// Screen state machine + GT911 touch hit-testing. Each screen matches the design
// handoff (960x540, JetBrains Mono, black/white with grayscale chrome) and obeys
// the e-paper refresh model (FULL on screen change, PART for in-place updates).
// Data-driven screens read the app globals (channels / wifiManager / timeKeeper).
#pragma once

#include <Arduino.h>
#include <vector>

enum UiScreen {
    SCR_BOOT = 0,
    SCR_CONNECTING,
    SCR_SETUP,
    SCR_DASHBOARD,
    SCR_DOCUMENT,
    SCR_SETTINGS,
    SCR_KEYBOARD,
    SCR_INTERVAL,
    SCR_TIMEZONE,
    SCR_NEEDKEY,   // connected but no Vulners API key yet -> "enter it via the web interface"
    SCR_RESET_CONFIRM,  // "Are you sure?" gate before a full factory wipe
    SCR_UPDATE,         // firmware update: offer (now/later) then download progress
    SCR_UPDATE_FAILED,  // shown at boot after a failed update was rolled back
};

// Events surfaced by poll() for main to act on.
enum UiEvent {
    EV_NONE = 0,
    EV_REFRESH,     // ⟳ refetch current channel
    EV_SETTINGS,    // ⚙ open settings
    EV_OPEN_DOC,    // tap featured/feed row -> document (index in lastDocIndex())
    EV_BACK,        // ◂ back
    EV_NEXT_CH,     // swipe/pager next channel
    EV_PREV_CH,     // prev channel
    EV_CONNECT,     // keyboard CONNECT — join kbSsid()/kbBuf()
    EV_FACTORY_RESET,  // reset-confirm ERASE tapped — main wipes all storage + reboots
    EV_UPDATE_NOW,     // update offer — "Update now": start download+install
    EV_UPDATE_LATER,   // update offer — "Try again tomorrow": snooze ~24h
};

// Live status pulled into the status bar / screens.
struct UiStatus {
    bool connected = false;
    bool apMode = false;
    String ssid;
    int rssi = 0;
    String ip;
    bool apiKeySet = false;
    bool apiKeyValid = false;
    int syncAgeMin = -1;   // minutes since last successful channel fetch (-1 = never)
    bool timeSynced = false;
    String dateStr;        // "FRI 10 JUL 2026"
    String timeStr;        // "14:07"
    int battPct = 82;
    bool charging = true;
};

class Ui {
public:
    bool begin();

    // Provisioning flow (static chrome; PART updates for progress/steps).
    void showBoot(int stage, const char *caption);   // stage 0..4 progress
    void showConnecting(const String &ssid, int step);  // step: 0..4 completed
    void showSetup(const String &apSsid, const String &apPass, const String &url, int saved);
    void showNeedKey(const String &ip);  // online but no API key: point the user at the web interface
    void animateNeedKey();               // advance the live "listening" spinner (called ~1.4 s from loop)

    // Data-driven screens.
    void showDashboard(const UiStatus &st);          // full clean redraw (entry / rotation / data)
    void refreshStatus(const UiStatus &st);          // status-bar-only partial (minute clock tick)
    void showRefreshing();                           // additive "updating" ack in the refresh button
    void showDocument(const String &channelId, int idx);
    void showSettings();
    void showResetConfirm();  // full-frame "Are you sure?" gate before a factory wipe
    void showErasing();       // brief "Erasing…" ack drawn just before the reboot
    void showUpdate();        // firmware-update screen (reads updater: offer, or download progress)
    void showUpdateFailed();  // post-rollback screen: the update didn't start, previous version restored
    void showInterval(const String &channelId);      // per-source update-interval picker
    void enterTimezone();                            // open the picker scrolled to the current zone
    void showTimezone();                             // timezone picker (renders at the current _tzScroll)
    void drawDocBody(const String &sum, int y0);     // scrollable CVE summary/description pane
    void showKeyboard(const String &ssid);           // Wi-Fi password on-screen keyboard

    String contextChannel() const { return _ctxCh; }  // channel whose pill opened interval

    // Channel navigation state (dashboard).
    void setChannels(const std::vector<String> &ids, const std::vector<String> &names);
    int channelIndex() const { return _chIdx; }
    int channelCount() const { return (int)_chIds.size(); }
    String activeId() const { return _chIds.empty() ? String() : _chIds[_chIdx]; }
    void setChannelIndex(int i);
    bool setActiveById(const String &id);  // point the dashboard at a channel by id (update-driven switch)

    // Non-blocking touch poll → event. Also drives swipe/auto-rotate hit-testing.
    UiEvent poll();
    int lastDocIndex() const { return _lastDocIdx; }  // 0=featured, 1..=feed row
    String docId() const { return _docId; }           // id shown on the Document screen
    bool docDetailShown() const { return _docDetailShown; }  // full record already rendered?
    String kbSsid() const { return _kbSsid; }          // network being joined (keyboard)
    String kbPass() const { return _kbBuf; }           // password entered (keyboard)

    // Debug-console hooks. Drawing must happen on the UI task, so the always-on
    // console task only *queues* jumps/taps; the UI loop drains them.
    void requestJump(char c);   // queue a dev screen-jump ('1'..'9','V') — console task
    void requestTest(int n);    // queue a gfx self-test pattern — console task
    void requestProbe(int n);   // queue a gfx driver-op probe — console task
    void serviceJump();         // execute a queued jump / test / probe (drawing) — UI loop
    void requestDump();         // ask the UI loop to dump the framebuffer (clean, no tear)
    void serviceDump();         // perform a requested dump between draws — UI loop
    bool dumpPending() const { return _dumpReq; }
    void injectTouch(int x, int y);  // queue a synthetic touch (host sends "t <x> <y>")
    void setTouchMonitor(bool on) { _touchMonitor = on; }  // echo real GT911 taps to UART
    bool touchMonitor() const { return _touchMonitor; }
    const char *screenName() const;
    String activeName() const { return _chNames.empty() ? String() : _chNames[_chIdx]; }

    UiScreen screen() const { return _scr; }
    bool touchOnline() const { return _touchOnline; }

private:
    UiScreen _scr = SCR_BOOT;
    bool _touchOnline = false;
    uint32_t _nextTouch = 0;
    bool _fingerDown = false;   // GT911 reports continuously while held; act on the press edge only
    int _lastDocIdx = 0;
    // What the last dashboard render actually drew, so a tap on an empty featured/feed slot is ignored
    // instead of opening a blank document.
    bool _dashHave = false;     // featured panel has a champion
    int _dashCand = 0;          // number of candidate feed rows drawn (0..2)

    // Channels for the dashboard tab strip.
    std::vector<String> _chIds, _chNames;
    int _chIdx = 0;

    // Sub-screen context.
    String _ctxCh;       // channel whose interval picker is open
    String _kbSsid;      // Wi-Fi network being entered
    String _kbBuf;       // password buffer
    bool _kbShow = false;
    bool _kbShift = false;
    bool _kbSym = false;  // ?123 symbol layer active (rows 2-4 show symbols)
    int _tzScroll = 0;   // first visible timezone row
    int _wifiScroll = 0; // first visible Wi-Fi network row (settings)
    int _feedScroll = 0; // first visible feed/channel row (settings)

    // "Add your API key" screen: live spinner state (animated via animateNeedKey).
    String _needKeyIp;
    uint8_t _needKeyPhase = 0;
    void drawNeedKeySpinner();  // the rotating "listening" comet (partial-update cell)

    // Document detail state.
    String _docId;
    bool _docDetailShown = false;
    int _docScroll = 0;       // scroll offset (lines) for the CVE summary/description pane
    int _docBodyY = 0;        // top y of that pane (for the scroll-rail hit-test)
    int _docScrollMax = 0;    // max scroll offset (0 = fits, no rail)
    int _docPage = 3;         // lines to advance per ▲/▼ tap

    UiStatus _lastStatus;  // last status passed to showDashboard (for dev re-render)

    // Synthetic touch injection + deferred screen-jump + touch monitor (dev/test).
    int _injX = 0, _injY = 0;
    bool _injPending = false;
    char _pendingJump = 0;
    int _pendingTest = -1;
    int _pendingProbe = -1;
    bool _touchMonitor = false;
    volatile bool _dumpReq = false;

    // Touch helpers + drawing.
    bool readTouch(int &x, int &y);
    void beginFrame();  // clear to paper + draw the 2px screen border (every screen opens with this)
    // Compact ▲/▼ scroll rail for an in-panel list (top half = up, bottom half = down).
    void drawScrollRail(int x, int y, int w, int h);
    void drawStatusBar(const UiStatus &st);
    void drawFooter(const char *left, const char *right);
    void drawHeaderBar(const char *back, const char *mid, const char *right);
    void drawChannelBar();
    // Worded state pill (JB_B17, +28px padding) at (x, y) height h; fill = solid/inverted, else outline.
    void drawPill(int x, int y, int h, const char *label, bool fill);
    String maskedPass() const;  // the Wi-Fi password shown as bullets (or plaintext when _kbShow)
    void renderDashboard(const UiStatus &st);  // draw into fb; no flush (BASE or partial decides)
    void presentScreen();  // present a whole screen (flash-free 2-bit partial of the changed rows)
    int chip(int x, int y, const char *label, bool filled, bool check, bool pencil);
    void renderKeyboard();  // draw the whole keyboard for the current _kbSym/_kbShow state (no reset)
    void drawKbField();  // repaint only the keyboard password field (partial, per keypress)
};

extern Ui ui;
