// Vulners "channels": named Lucene queries the device rotates through.
//
// A channel is just an alias + a Lucene filter (e.g. news =
// "(type:thn OR type:threatpost) order:published"). Channels are stored on
// LittleFS (/channels.json), CRUD'd over the web API, and each is fetched on its
// own cadence by the network task. Per channel we keep a "champion" (top hit)
// and a few "candidates" for the UI to render. The screens themselves live
// elsewhere; this module is the data/mechanics layer only.
#pragma once

#include <Arduino.h>
#include <time.h>
#include <vector>

#include "vulners.h"

class WebServer;  // Arduino sync web server (owned by wifi_manager)

// Refresh-interval presets — the SINGLE source of truth for the device UI (interval picker rows +
// settings pill), `snapInterval()`, and the interval hit-test. The last entry (sec 0, manual=true) is
// the Manual-only option. (The web admin's RF list mirrors these; keep it in sync.)
struct IntervalPreset {
    uint32_t sec;          // refresh cadence in seconds (ignored for the Manual entry)
    const char *shortLbl;  // compact pill label (settings feeds column): "1m", "5m", …
    const char *longLbl;   // full picker-row label: "1 minute", …
    bool manual;           // the Manual-only sentinel
};
extern const IntervalPreset kIntervals[];
extern const int kIntervalCount;

// A configured channel (persisted).
struct Channel {
    String id;                 // stable slug (key), derived from the name
    String name;               // display alias, e.g. "News"
    String query;              // Lucene query, e.g. "bulletinFamily:exploit order:published"
    bool active = true;        // included in the on-device rotation
    bool manual = false;       // true = refresh ONLY on an explicit button, never on the interval
    uint32_t refreshSec = 1800;  // auto-mode refresh cadence (>= kMinRefreshSec); ignored when manual
};

// The last fetch result for a channel. The document data + fetchedAt are
// persisted to LittleFS so the UI has content immediately after a reboot /
// deep-sleep wake; the millis()-based fields are runtime-only.
struct ChannelResult {
    bool haveData = false;
    bool forced = false;       // runtime: an explicit (manual/on-demand) refresh was requested
    String error;              // last error, empty if ok (runtime only)
    uint32_t updatedMs = 0;    // millis() of last fetch THIS session (0 = not yet this session)
    uint32_t attemptMs = 0;    // millis() of last attempt this session (success or fail)
    time_t fetchedAt = 0;      // wall-clock epoch of last successful fetch (0 = unknown); persisted
    long total = 0;            // total matches reported by the API; persisted
    VulnDoc champion;          // top hit; persisted
    std::vector<VulnDoc> candidates;  // next hits; persisted
};

class Channels {
public:
    static constexpr int kMaxChannels = 16;
    static constexpr uint32_t kMinRefreshSec = 60;
    static constexpr int kFetchLimit = 5;  // docs fetched per channel: 1 champion + up to 4 candidates

    void begin();                        // mount LittleFS, load or seed defaults
    void registerRoutes(WebServer &s);   // attach REST API + admin page to the shared server

    // Runs on the network task (core 0). Fetches at most one due active channel
    // per call (spreads load, keeps each call short). No-op if none are due.
    void tick(VulnersClient &client);

    // Request an immediate refetch of one channel (manual button, from web or device
    // UI). Works for both auto and manual channels. Returns false if id is unknown.
    bool refreshNow(const String &id);

    // Thread-safe reads for the UI / web.
    std::vector<Channel> list();          // all channels
    std::vector<Channel> active();        // active channels only, in rotation order
    bool snapshot(const String &id, ChannelResult &out);  // cached data for one channel

    // Update-driven dashboard switch: the fetch task bumps _updateGen whenever a channel gets a NEW
    // top item (championId change) and records which channel. The UI loop reads the counter cheaply
    // (no snapshot copy) and switches the dashboard to lastUpdatedId() on a bump.
    uint32_t updateGen() const { return _updateGen; }  // monotonic; 32-bit aligned read is atomic
    String lastUpdatedId();                            // id of the channel that last got a new headline

    // A channel fetch (same X-Api-Key) has succeeded since boot — authoritative proof the key is valid,
    // even when the flaky /apiKey/valid endpoint can't confirm it on a weak link.
    bool apiKeyProvenByFetch() const { return _fetchProvenKey; }
    void resetApiKeyProof() { _fetchProvenKey = false; }  // key changed -> the old proof no longer applies

    // Last successful-fetch timestamp for a channel (0 = none), WITHOUT deep-copying the whole result —
    // for the UI loop's cheap "did the active channel change?" check (see snapshot() for the full copy).
    uint32_t updatedMs(const String &id);

    // On-demand full-record fetch for the Document view. The UI requests a detail
    // by id (non-blocking); the network task fetches it via fetchById in tick();
    // the UI polls detailFor() and re-renders once it is ready.
    void requestDetail(const String &id);
    bool detailFor(const String &id, VulnDoc &out);

    // CRUD (thread-safe; persist to LittleFS). Return false + reason on invalid input.
    bool add(const String &name, const String &query, uint32_t refreshSec, bool active,
             bool manual, String &err);
    bool update(const String &id, const String &name, const String &query,
                uint32_t refreshSec, bool active, bool manual, String &err);
    bool remove(const String &id, String &err);

    // Factory reset: delete persisted channels + cached feed data. On the next boot begin() finds no
    // config file and re-seeds the default channels. Caller reboots afterwards.
    void factoryReset();

private:
    bool serveDetail(VulnersClient &client);  // top-priority on-demand detail fetch (tick helper)

    std::vector<Channel> _chans;
    std::vector<ChannelResult> _results;  // parallel to _chans by index
    uint32_t _dataHash = 0;               // hash of last-written /feeds.json (skip no-op writes)
    volatile uint32_t _updateGen = 0;     // bumped on each NEW-headline fetch (update-driven switch)
    volatile bool _fetchProvenKey = false;  // a searchChannel() has returned HTTP 200 -> the key works
    String _lastUpdatedId;                // channel id of the most recent new headline (under lock)

    // On-demand detail fetch (Document view). Written by the network task, read by UI.
    String _detailReq;      // requested id (empty = none pending)
    VulnDoc _detailDoc;     // last fetched full record
    bool _detailReady = false;
    bool _detailFailed = false;  // last fetch for _detailDoc.id failed -> re-request on the next open (no poison)

    void lock();
    void unlock();
    void load();        // channels config <- /channels.json
    void save();        // channels config -> /channels.json
    void loadData();    // cached feed data <- /feeds.json (into _results)
    void saveData();    // cached feed data -> /feeds.json
    void seedDefaults();
    int indexOf(const String &id) const;  // caller holds lock
    String makeSlug(const String &name) const;  // caller holds lock

    // Web handlers (registered via registerRoutes).
    void handleAdminPage();
    void handleApiList();
    void handleApiCreate();
    void handleApiUpdate();
    void handleApiDelete();
    void handleApiRefresh();
};

extern Channels channels;
