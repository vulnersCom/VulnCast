#include "timekeeper.h"

#include <ArduinoJson.h>
#include <Preferences.h>
#include <WebServer.h>

#include "web_ui.h"

namespace {

Preferences prefs;
WebServer *g_server = nullptr;
TimeKeeper *self = nullptr;

// A plausible "time is real" threshold: 2020-09-13 (any earlier => not yet synced).
constexpr time_t kSyncedThreshold = 1600000000;

// /time subpage body (Back to hub). Shared chrome/status-bar come from web_ui.
const char kTimeBody[] PROGMEM = R"WEB(
<a class=back href="/">&larr; Back</a>
<div class=card><h2>Time &amp; timezone</h2>
<div id=tinfo class=mut style=margin:2px 0 4px>loading&hellip;</div>
<label>Timezone (clock auto-syncs via NTP)</label>
<select id=tz class=full onchange=savetz()></select></div>
<script>
function el(i){return document.getElementById(i)}
async function loadzones(){try{let z=await(await fetch('/api/time/zones')).json();let s=el('tz');s.innerHTML='';z.forEach(o=>{let e=document.createElement('option');e.value=o.posix;e.textContent=o.label;s.appendChild(e)})}catch(e){}}
async function ti(){try{let t=await(await fetch('/api/time')).json();let h=(t.synced?('<b>'+t.datetime+'</b>'):'<span class=mut>syncing&hellip;</span>')+' <span class=pill>'+(t.tzLabel||'')+'</span>';let e=el('tinfo');if(e.dataset.h!=h){e.dataset.h=h;e.innerHTML=h}if(document.activeElement!=el('tz')&&el('tz').value!=t.tz)el('tz').value=t.tz}catch(e){}}
async function savetz(){await fetch('/api/time/tz',{method:'POST',body:new URLSearchParams({tz:el('tz').value})});ti()}
loadzones().then(ti);setInterval(ti,10000);
</script>)WEB";

}  // namespace

TimeKeeper timeKeeper;

const std::vector<TzOption> &TimeKeeper::zones() {
    // Curated world set, sorted west -> east by STANDARD UTC offset (like an OS installer's picker).
    // POSIX TZ carries the DST rule; the "off" label is the standard-time offset for stable ordering.
    static const std::vector<TzOption> z = {
        {"Pacific/Honolulu", "HST10", "UTC-10"},
        {"America/Anchorage", "AKST9AKDT,M3.2.0,M11.1.0", "UTC-9"},
        {"America/Los_Angeles", "PST8PDT,M3.2.0,M11.1.0", "UTC-8"},
        {"America/Denver", "MST7MDT,M3.2.0,M11.1.0", "UTC-7"},
        {"America/Chicago", "CST6CDT,M3.2.0,M11.1.0", "UTC-6"},
        {"America/Mexico_City", "CST6", "UTC-6"},
        {"America/New_York", "EST5EDT,M3.2.0,M11.1.0", "UTC-5"},
        {"America/Bogota", "<-05>5", "UTC-5"},
        {"America/Sao_Paulo", "<-03>3", "UTC-3"},
        {"America/Argentina/Buenos_Aires", "<-03>3", "UTC-3"},
        {"Atlantic/Azores", "<-01>1<+00>,M3.5.0/0,M10.5.0/1", "UTC-1"},
        {"UTC", "UTC0", "UTC\xC2\xB1""0"},
        {"Europe/London", "GMT0BST,M3.5.0/1,M10.5.0", "UTC\xC2\xB1""0"},
        {"Europe/Berlin", "CET-1CEST,M3.5.0,M10.5.0/3", "UTC+1"},
        {"Europe/Paris", "CET-1CEST,M3.5.0,M10.5.0/3", "UTC+1"},
        {"Europe/Madrid", "CET-1CEST,M3.5.0,M10.5.0/3", "UTC+1"},
        {"Europe/Athens", "EET-2EEST,M3.5.0/3,M10.5.0/4", "UTC+2"},
        {"Africa/Cairo", "EET-2EEST,M4.5.5/0,M10.5.4/24", "UTC+2"},
        {"Europe/Moscow", "MSK-3", "UTC+3"},
        {"Europe/Istanbul", "<+03>-3", "UTC+3"},
        {"Asia/Dubai", "<+04>-4", "UTC+4"},
        {"Asia/Karachi", "PKT-5", "UTC+5"},
        {"Asia/Kolkata", "IST-5:30", "UTC+5:30"},
        {"Asia/Dhaka", "<+06>-6", "UTC+6"},
        {"Asia/Bangkok", "<+07>-7", "UTC+7"},
        {"Asia/Jakarta", "WIB-7", "UTC+7"},
        {"Asia/Singapore", "<+08>-8", "UTC+8"},
        {"Asia/Shanghai", "CST-8", "UTC+8"},
        {"Asia/Hong_Kong", "HKT-8", "UTC+8"},
        {"Asia/Tokyo", "JST-9", "UTC+9"},
        {"Asia/Seoul", "KST-9", "UTC+9"},
        {"Australia/Sydney", "AEST-10AEDT,M10.1.0,M4.1.0/3", "UTC+10"},
        {"Pacific/Auckland", "NZST-12NZDT,M9.5.0,M4.1.0/3", "UTC+12"},
    };
    return z;
}

void TimeKeeper::applyTz(const String &posix) {
    setenv("TZ", posix.c_str(), 1);
    tzset();
}

void TimeKeeper::begin() {
    self = this;
    prefs.begin("clock", false);
    _tz = prefs.getString("tz", "UTC0");
    applyTz(_tz);  // TZ correct even before the first NTP fix
}

void TimeKeeper::onConnected() {
    // Starts SNTP (auto-resyncs periodically by default) and re-applies the TZ.
    configTzTime(_tz.c_str(), "pool.ntp.org", "time.nist.gov");
}

bool TimeKeeper::synced() const { return now() > kSyncedThreshold; }

time_t TimeKeeper::now() const { return time(nullptr); }

String TimeKeeper::formatLocal(const char *fmt, const char *unsynced, bool upper) const {
    if (!synced()) return String(unsynced);
    time_t t = now();
    struct tm tmv;
    localtime_r(&t, &tmv);
    char buf[32];
    strftime(buf, sizeof(buf), fmt, &tmv);
    if (upper)
        for (char *p = buf; *p; ++p) *p = toupper((unsigned char)*p);
    return String(buf);
}

String TimeKeeper::localDateTime() const { return formatLocal("%Y-%m-%d %H:%M", "--"); }
String TimeKeeper::localTime() const { return formatLocal("%H:%M", "--:--"); }
String TimeKeeper::localDate() const { return formatLocal("%Y-%m-%d", "----"); }

String TimeKeeper::timezone() const { return _tz; }

String TimeKeeper::timezoneLabel() const {
    for (const TzOption &z : zones())
        if (_tz == z.posix) return String(z.label);
    return _tz;
}

bool TimeKeeper::setTimezone(const String &posix) {
    String tz = posix;
    tz.trim();
    if (tz.isEmpty() || tz.length() > 48) return false;
    _tz = tz;
    prefs.putString("tz", _tz);
    applyTz(_tz);  // SNTP keeps running (UTC); only the local conversion changes
    return true;
}

// ---- web API ---------------------------------------------------------------

void TimeKeeper::handleApiTime() {
    JsonDocument d;
    d["synced"] = synced();
    d["epoch"] = (long)now();
    d["datetime"] = localDateTime();
    d["time"] = localTime();
    d["date"] = localDate();
    d["tz"] = _tz;
    d["tzLabel"] = timezoneLabel();
    vcSendJson(*g_server, 200, d);
}

void TimeKeeper::handleApiZones() {
    JsonDocument d;
    JsonArray a = d.to<JsonArray>();
    for (const TzOption &z : zones()) {
        JsonObject o = a.add<JsonObject>();
        o["label"] = z.label;
        o["posix"] = z.posix;
    }
    vcSendJson(*g_server, 200, d);
}

void TimeKeeper::handleApiTz() {
    bool ok = setTimezone(g_server->arg("tz"));
    JsonDocument d;
    d["ok"] = ok;
    d["tz"] = _tz;
    d["datetime"] = localDateTime();
    if (!ok) d["error"] = "invalid tz";
    vcSendJson(*g_server, 200, d);
}

void TimeKeeper::handleTimePage() {
    vcSendHead(*g_server, "VulnCast \xC2\xB7 Time");
    g_server->sendContent_P(kTimeBody);
    vcSendTail(*g_server);
}

void TimeKeeper::registerRoutes(WebServer &s) {
    self = this;
    g_server = &s;
    s.on("/time", HTTP_GET, []() { self->handleTimePage(); });  // Setup Time subpage
    s.on("/api/time", HTTP_GET, []() { self->handleApiTime(); });
    s.on("/api/time/zones", HTTP_GET, []() { self->handleApiZones(); });
    s.on("/api/time/tz", HTTP_POST, []() { self->handleApiTz(); });
}
