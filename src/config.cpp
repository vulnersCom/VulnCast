#include "config.h"

#include <Preferences.h>

// Runtime configuration backed by NVS. Currently the only persisted value here is
// the Vulners API key; channel definitions + cadence live in channels.{h,cpp} and
// the timezone in timekeeper. The key is write-only from the web portal's view
// (never disclosed) and seeded once from a compiled default if NVS is empty.
namespace {
Preferences prefs;
const char *kNamespace = "vulncast";
}  // namespace

Config config;

void Config::begin() {
    _ready = prefs.begin(kNamespace, false);  // read-write; created on first run
}

String Config::apiKey() {
    if (!_ready) return String();
    return prefs.getString("vulnersKey", "");
}

bool Config::hasApiKey() { return apiKey().length() > 0; }

void Config::setApiKey(const String &key) {
    if (_ready) prefs.putString("vulnersKey", key);
}

void Config::seedApiKeyIfEmpty(const String &seed) {
    if (!_ready) return;
    if (!prefs.getString("vulnersKey", "").isEmpty()) return;
    if (seed.isEmpty() || seed == "your-vulners-api-key") return;
    prefs.putString("vulnersKey", seed);
}

void Config::factoryReset() {
    if (_ready) prefs.clear();  // wipe the "vulncast" NVS namespace (the API key)
}
