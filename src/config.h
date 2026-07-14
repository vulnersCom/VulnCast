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

private:
    bool _ready = false;
};

extern Config config;
