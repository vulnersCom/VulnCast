// Device clock: automatic NTP (SNTP) sync + timezone.
//
// The ESP32 keeps time across deep-sleep (internal RTC timer), and SNTP
// auto-resyncs periodically once WiFi is up. The timezone is a POSIX TZ string
// persisted in NVS and applied via setenv("TZ")/tzset(), so local time is
// correct on both the web page and the device UI. A curated zone list backs the
// web and on-device timezone pickers.
//
// Roadmap: also push synced time into the on-board PCF8563 RTC so the clock
// survives a full power-off (deep-sleep already preserves it).
#pragma once

#include <Arduino.h>
#include <time.h>
#include <vector>

class WebServer;  // Arduino sync web server (owned by wifi_manager)

// A selectable timezone: human label + POSIX TZ string (with DST rules).
struct TzOption {
    const char *label;  // IANA-style name, e.g. "Europe/Moscow"
    const char *posix;  // POSIX TZ string with DST rules
    const char *off;    // human UTC offset for the picker, e.g. "UTC+3"
};

class TimeKeeper {
public:
    void begin();        // load TZ from NVS and apply it (SNTP starts on connect)
    void onConnected();  // (re)start SNTP once WiFi is up
    bool synced() const; // SNTP has set a plausible wall-clock time

    time_t now() const;            // epoch (UTC)
    String localDateTime() const;  // "2026-07-11 14:30" in the configured TZ (or "--" if unsynced)
    String localTime() const;      // "14:30"
    String localDate() const;      // "2026-07-11"
    // Generic TZ-local strftime; returns `unsynced` if SNTP has not set the clock, uppercased if upper.
    String formatLocal(const char *fmt, const char *unsynced, bool upper = false) const;

    String timezone() const;       // current POSIX TZ string
    String timezoneLabel() const;  // human label if known, else the POSIX string
    bool setTimezone(const String &posix);  // persist + apply (used by web AND device UI)

    void registerRoutes(WebServer &s);  // GET /api/time, GET /api/time/zones, POST /api/time/tz
    static const std::vector<TzOption> &zones();  // curated list for the pickers

private:
    String _tz = "UTC0";
    void applyTz(const String &posix);  // setenv("TZ") + tzset()
    void handleTimePage();  // GET /time subpage
    void handleApiTime();
    void handleApiZones();
    void handleApiTz();
};

extern TimeKeeper timeKeeper;
