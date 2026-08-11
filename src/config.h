// Runtime configuration for VulnCast, backed by NVS (Preferences).
//
// Design rule (project): no hardcoding of secrets/tunables — they live in NVS with a compiled
// fallback default. This Config holds only the Vulners API key; channel queries/cadence live in
// channels.*, timezone in timekeeper.*. The fallback default lives in config.cpp.
#pragma once

#include <Arduino.h>

class Config {
public:
    void begin();

    // Vulners API key, stored in NVS. The portal never returns this value.
    String apiKey();
    bool hasApiKey();
    void setApiKey(const String &key);
    void seedApiKeyIfEmpty(const String &seed);

    // Data source: false = API mode (per-channel Lucene searches; consumes Vulners API credits),
    // true = zero-credit RSS mode (public firehose + credit-free search/id enrichment). Stored in
    // NVS; toggled from the device Settings screen.
    bool rssMode();
    void setRssMode(bool on);

    // Factory reset: wipe all persisted config (the Vulners API key). Caller reboots afterwards.
    void factoryReset();

private:
    bool _ready = false;
};

extern Config config;
