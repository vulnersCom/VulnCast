#include "channels.h"

#include <ArduinoJson.h>
#include <LittleFS.h>
#include <WebServer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "gfx.h"
#include "web_ui.h"

// Single source of truth for the refresh-interval presets (declared extern in channels.h). Defined at
// global scope (NOT in the anonymous namespace below) so ui.cpp's picker/label code can link to it.
const IntervalPreset kIntervals[] = {
    {60,    "1m",  "1 minute",    false},
    {300,   "5m",  "5 minutes",   false},
    {900,   "15m", "15 minutes",  false},
    {3600,  "1h",  "1 hour",      false},
    {21600, "6h",  "6 hours",     false},
    {0,     "Man", "Manual only", true},
};
const int kIntervalCount = (int)(sizeof(kIntervals) / sizeof(kIntervals[0]));

namespace {

constexpr char kFile[] = "/channels.json";   // channel config (alias + query + settings)
constexpr char kDataFile[] = "/feeds.json";  // cached feed data (champion + candidates)

SemaphoreHandle_t g_mutex = nullptr;
WebServer *g_server = nullptr;
Channels *self = nullptr;

// Default channels seeded on first boot (all user-editable afterwards).
struct Seed {
    const char *name;
    const char *query;
    uint32_t refreshSec;
};
const Seed kSeeds[] = {
    {"News", "(type:thn OR type:threatpost) order:published", 900},      // 15m
    {"Exploits", "bulletinFamily:exploit order:published", 300},         // 5m
    {"Bugbounty", "type:hackerone bounty:[1 TO *] order:published", 3600},  // 1h — paid HackerOne reports (show the $ bounty)
    {"Vulnerabilities", "type:cve AND cvss.score:[7 TO 10] order:published", 300},  // 5m
};

// The device UI offers a fixed set of intervals; snap any other value (e.g. a legacy 30 min) to the
// nearest offered preset so the picker always has a match. Iterates the shared preset table.
uint32_t snapInterval(uint32_t s) {
    uint32_t best = kIntervals[0].sec, bestD = UINT32_MAX;
    for (int i = 0; i < kIntervalCount; ++i) {
        if (kIntervals[i].manual) continue;
        uint32_t p = kIntervals[i].sec, d = p > s ? p - s : s - p;
        if (d < bestD) { bestD = d; best = p; }
    }
    return best;
}

String trimmed(const String &s) {
    String out = s;
    out.trim();
    return out;
}

bool truthy(const String &v) {
    String s = v;
    s.toLowerCase();
    return s == "1" || s == "true" || s == "on" || s == "yes";
}

// (De)serialize a VulnDoc for the persistent feed-data cache (/feeds.json).
// Description is not cached (empty in list results; fetched on demand for detail).
void writeDoc(JsonObject o, const VulnDoc &d) {
    o["id"] = d.id;
    o["title"] = d.title;
    o["type"] = d.type;
    o["family"] = d.family;
    o["published"] = d.published;
    o["href"] = d.href;
    o["cvss"] = d.cvss;
    o["ec"] = d.exploitCount;            // exploit count (CVEs) — used by the EXPLOIT COUNT tile
    o["ai"] = d.aiScore;                 // AI score — used by the tiles/feed
    o["sd"] = d.shortDescription;        // AI short summary (fallback)
    o["ad"] = d.aiDescription;           // richer AI description — preferred for the champion summary
    o["de"] = d.description;             // raw description — last-resort summary (non-AI-enriched CVEs)
    o["bty"] = d.bounty;                 // bugbounty payout
    o["bst"] = d.bountyState;            // bugbounty state
    o["rep"] = d.reporter;               // human source
}

void readDoc(JsonObjectConst o, VulnDoc &d) {
    d.id = o["id"] | "";
    d.title = o["title"] | "";
    d.type = o["type"] | "";
    d.family = o["family"] | "";
    d.published = o["published"] | "";
    d.href = o["href"] | "";
    d.cvss = o["cvss"] | 0.0f;
    d.exploitCount = o["ec"] | 0;
    d.aiScore = o["ai"] | 0.0f;
    d.shortDescription = o["sd"] | "";
    d.aiDescription = o["ad"] | "";
    d.description = o["de"] | "";
    d.bounty = o["bty"] | 0.0f;
    d.bountyState = o["bst"] | "";
    d.reporter = o["rep"] | "";
}

}  // namespace

Channels channels;

void Channels::lock() {
    if (g_mutex) xSemaphoreTake(g_mutex, portMAX_DELAY);
}
void Channels::unlock() {
    if (g_mutex) xSemaphoreGive(g_mutex);
}

void Channels::begin() {
    if (g_mutex == nullptr) g_mutex = xSemaphoreCreateMutex();
    self = this;
    if (!LittleFS.begin(true)) {  // format on first use / corruption
        Serial.println("[chan] LittleFS mount failed");
    }
    lock();
    load();
    if (_chans.empty()) {
        seedDefaults();
        save();
    }
    _results.assign(_chans.size(), ChannelResult());
    loadData();  // restore last-session champion/candidates so the UI has content at boot
    unlock();
    Serial.printf("[chan] %d channels loaded\n", (int)_chans.size());
}

void Channels::seedDefaults() {
    for (const Seed &s : kSeeds) {
        if (_chans.size() >= (size_t)kMaxChannels) break;
        Channel c;
        c.name = s.name;
        c.query = s.query;
        c.refreshSec = s.refreshSec;
        c.active = true;
        c.id = makeSlug(c.name);
        _chans.push_back(c);
    }
}

// ---- persistence -----------------------------------------------------------

void Channels::load() {
    _chans.clear();
    File f = LittleFS.open(kFile, "r");
    if (!f) return;
    JsonDocument doc;
    DeserializationError e = deserializeJson(doc, f);
    f.close();
    if (e) {
        Serial.printf("[chan] parse %s failed: %s\n", kFile, e.c_str());
        return;
    }
    for (JsonObject o : doc["channels"].as<JsonArray>()) {
        if (_chans.size() >= (size_t)kMaxChannels) break;
        Channel c;
        c.id = o["id"] | "";
        c.name = o["name"] | "";
        c.query = o["query"] | "";
        c.active = o["active"] | true;
        c.manual = o["manual"] | false;
        c.refreshSec = o["refreshSec"] | 900;
        if (c.refreshSec < kMinRefreshSec) c.refreshSec = kMinRefreshSec;
        if (!c.manual) c.refreshSec = snapInterval(c.refreshSec);  // keep it a UI-offered preset
        if (c.id.isEmpty() || c.query.isEmpty()) continue;
        _chans.push_back(c);
    }
}

void Channels::save() {
    JsonDocument doc;
    JsonArray arr = doc["channels"].to<JsonArray>();
    for (const Channel &c : _chans) {
        JsonObject o = arr.add<JsonObject>();
        o["id"] = c.id;
        o["name"] = c.name;
        o["query"] = c.query;
        o["active"] = c.active;
        o["manual"] = c.manual;
        o["refreshSec"] = c.refreshSec;
    }
    File f = LittleFS.open(kFile, "w");
    if (!f) {
        Serial.println("[chan] save open failed");
        return;
    }
    serializeJson(doc, f);
    f.close();
}

// Persist the fetched feed data (champion + candidates + total + fetchedAt) so
// the UI has content immediately after a reboot / deep-sleep wake. Caller holds
// the lock. Keyed by channel id; only channels with data are written.
void Channels::saveData() {
    JsonDocument doc;
    JsonObject feeds = doc["feeds"].to<JsonObject>();
    for (size_t i = 0; i < _chans.size(); ++i) {
        const ChannelResult &r = _results[i];
        if (!r.haveData) continue;
        JsonObject o = feeds[_chans[i].id].to<JsonObject>();
        o["fetchedAt"] = (long)r.fetchedAt;
        o["total"] = r.total;
        writeDoc(o["champion"].to<JsonObject>(), r.champion);
        JsonArray cand = o["candidates"].to<JsonArray>();
        for (const VulnDoc &d : r.candidates) writeDoc(cand.add<JsonObject>(), d);
    }
    String out;
    serializeJson(doc, out);
    // Skip the flash rewrite when the payload is byte-identical (FNV-1a). Avoids
    // ~hundreds of no-op sector erases/day (real flash wear) on an awake device.
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < out.length(); ++i) {
        h ^= (uint8_t)out[i];
        h *= 16777619u;
    }
    if (h == _dataHash) return;
    File f = LittleFS.open(kDataFile, "w");
    if (!f) {
        Serial.println("[chan] feeds save failed");
        return;
    }
    f.print(out);
    f.close();
    _dataHash = h;
}

// Restore cached feed data into _results (matched to channels by id). Caller
// holds the lock. millis()-based fields stay 0 (this data is from a prior session).
void Channels::loadData() {
    File f = LittleFS.open(kDataFile, "r");
    if (!f) return;
    JsonDocument doc;
    DeserializationError e = deserializeJson(doc, f);
    f.close();
    if (e) {
        Serial.printf("[chan] parse %s failed: %s\n", kDataFile, e.c_str());
        return;
    }
    JsonObjectConst feeds = doc["feeds"];
    if (feeds.isNull()) return;
    int loaded = 0;
    for (size_t i = 0; i < _chans.size(); ++i) {
        JsonObjectConst o = feeds[_chans[i].id];
        if (o.isNull()) continue;
        ChannelResult &r = _results[i];
        r.fetchedAt = (time_t)(long)(o["fetchedAt"] | 0L);
        r.total = o["total"] | 0L;
        r.updatedMs = 0;  // from disk, not fetched this session
        readDoc(o["champion"].as<JsonObjectConst>(), r.champion);
        r.candidates.clear();
        for (JsonObjectConst c : o["candidates"].as<JsonArrayConst>()) {
            VulnDoc d;
            readDoc(c, d);
            r.candidates.push_back(d);
        }
        r.haveData = !r.champion.id.isEmpty();
        if (r.haveData) loaded++;
    }
    Serial.printf("[chan] restored cached data for %d feeds\n", loaded);
}

int Channels::indexOf(const String &id) const {
    for (size_t i = 0; i < _chans.size(); ++i)
        if (_chans[i].id == id) return (int)i;
    return -1;
}

String Channels::makeSlug(const String &name) const {
    String base;
    for (size_t i = 0; i < name.length(); ++i) {
        char c = name[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            base += c;
        } else if (!base.isEmpty() && base[base.length() - 1] != '-') {
            base += '-';
        }
    }
    while (base.endsWith("-")) base.remove(base.length() - 1);
    if (base.isEmpty()) base = "channel";
    if (base.length() > 24) base.remove(24);
    // Ensure uniqueness.
    String id = base;
    int n = 2;
    while (indexOf(id) >= 0) id = base + "-" + String(n++);
    return id;
}

// ---- CRUD ------------------------------------------------------------------

namespace {
// Validate + normalize channel input (trims in place, clamps refresh). Shared by add()/update().
bool validateChannelInput(String &name, String &query, uint32_t &refreshSec, String &err) {
    name = gfx::renderable(trimmed(name));  // display name reaches the panel — keep it renderable ASCII
    query = trimmed(query);
    if (name.isEmpty() || name.length() > 48) {
        err = "name required (<=48 chars)";
        return false;
    }
    if (query.isEmpty() || query.length() > 240) {
        err = "query required (<=240 chars)";
        return false;
    }
    if (refreshSec < Channels::kMinRefreshSec) refreshSec = Channels::kMinRefreshSec;
    refreshSec = snapInterval(refreshSec);  // snap to a UI preset; also bounds the upper end (no *1000 overflow)
    return true;
}
}  // namespace

bool Channels::add(const String &nameIn, const String &queryIn, uint32_t refreshSec,
                   bool active, bool manual, String &err) {
    String name = nameIn, query = queryIn;
    if (!validateChannelInput(name, query, refreshSec, err)) return false;
    lock();
    if (_chans.size() >= (size_t)kMaxChannels) {
        unlock();
        err = "channel limit reached";
        return false;
    }
    Channel c;
    c.name = name;
    c.query = query;
    c.refreshSec = refreshSec;
    c.active = active;
    c.manual = manual;
    c.id = makeSlug(name);
    _chans.push_back(c);
    _results.push_back(ChannelResult());
    save();
    unlock();
    return true;
}

bool Channels::update(const String &id, const String &nameIn, const String &queryIn,
                      uint32_t refreshSec, bool active, bool manual, String &err) {
    String name = nameIn, query = queryIn;
    if (!validateChannelInput(name, query, refreshSec, err)) return false;
    lock();
    int i = indexOf(id);
    if (i < 0) {
        unlock();
        err = "not found";
        return false;
    }
    bool queryChanged = _chans[i].query != query;
    _chans[i].name = name;
    _chans[i].query = query;
    _chans[i].refreshSec = refreshSec;
    _chans[i].active = active;
    _chans[i].manual = manual;
    if (queryChanged) _results[i] = ChannelResult();  // invalidate cached hits
    save();
    unlock();
    return true;
}

bool Channels::remove(const String &id, String &err) {
    lock();
    int i = indexOf(id);
    if (i < 0) {
        unlock();
        err = "not found";
        return false;
    }
    _chans.erase(_chans.begin() + i);
    _results.erase(_results.begin() + i);
    save();
    saveData();  // drop the removed feed's cached data too
    unlock();
    return true;
}

// ---- reads -----------------------------------------------------------------

std::vector<Channel> Channels::list() {
    lock();
    std::vector<Channel> out = _chans;
    unlock();
    return out;
}

std::vector<Channel> Channels::active() {
    lock();
    std::vector<Channel> out;
    for (const Channel &c : _chans)
        if (c.active) out.push_back(c);
    unlock();
    return out;
}

bool Channels::snapshot(const String &id, ChannelResult &out) {
    lock();
    int i = indexOf(id);
    if (i < 0) {
        unlock();
        return false;
    }
    out = _results[i];
    unlock();
    return true;
}

uint32_t Channels::updatedMs(const String &id) {
    lock();
    int i = indexOf(id);
    uint32_t ms = (i >= 0) ? _results[i].updatedMs : 0;
    unlock();
    return ms;
}

String Channels::lastUpdatedId() {
    lock();
    String id = _lastUpdatedId;  // copy under lock (written by the core-0 fetch task)
    unlock();
    return id;
}

bool Channels::refreshNow(const String &id) {
    lock();
    int i = indexOf(id);
    if (i >= 0) _results[i].forced = true;  // picked up by the next tick (within ~1 s)
    unlock();
    return i >= 0;
}

void Channels::requestDetail(const String &id) {
    lock();
    if (_detailDoc.id != id || _detailFailed) {  // not cached for this id, or the last attempt failed -> retry
        _detailReq = id;
        _detailReady = false;
        _detailFailed = false;
    }
    unlock();
}

bool Channels::detailFor(const String &id, VulnDoc &out) {
    lock();
    bool ok = _detailReady && _detailDoc.id == id;
    if (ok) out = _detailDoc;
    unlock();
    return ok;
}

// ---- scheduler (network task, core 0) --------------------------------------

// Serve a pending Document-detail request (short, on-demand, top priority). Returns true if it
// handled one — the caller then returns so the tick stays short and the scheduler runs next tick.
bool Channels::serveDetail(VulnersClient &client) {
    String detailId;
    lock();
    if (!_detailReady && _detailReq.length()) detailId = _detailReq;
    unlock();
    if (!detailId.length()) return false;
    VulnDoc d;
    String err;
    bool got = client.fetchById(detailId, d, err);
    lock();
    if (_detailReq == detailId) {  // still the current request
        _detailDoc = got ? d : VulnDoc();
        _detailDoc.id = detailId;   // keep id so detailFor() matches (empty doc -> graceful "scan QR" fallback)
        _detailReady = true;
        _detailFailed = !got;       // but mark failures so requestDetail() re-fetches on the next open (no poison)
        _detailReq = "";            // consumed — don't re-fetch until requestDetail() re-arms
    }
    unlock();
    return true;
}

void Channels::tick(VulnersClient &client) {
    if (serveDetail(client)) return;  // detail fetch is top priority; keep this tick short

    // Pick the single most-overdue active channel (never-fetched wins).
    String id, query;
    lock();
    uint32_t now = millis();
    int pick = -1;
    uint32_t bestOverdue = 0;
    for (size_t i = 0; i < _chans.size(); ++i) {
        const Channel &c = _chans[i];
        const ChannelResult &r = _results[i];
        if (r.forced) {          // explicit refresh (manual button / on-demand) — top priority
            pick = (int)i;
            break;
        }
        if (!c.active || c.manual) continue;  // manual feeds never auto-refresh on the interval
        uint32_t interval = c.refreshSec * 1000UL;
        if (r.attemptMs == 0) {
            pick = (int)i;
            break;  // auto feed never fetched this session — fetch now
        }
        uint32_t elapsed = now - r.attemptMs;
        if (elapsed >= interval && elapsed - interval >= bestOverdue) {
            bestOverdue = elapsed - interval;
            pick = (int)i;
        }
    }
    if (pick < 0) {
        unlock();
        return;
    }
    _results[pick].attemptMs = now;   // claim it now so we don't re-pick next tick
    _results[pick].forced = false;    // consume the on-demand request
    id = _chans[pick].id;
    query = _chans[pick].query;
    unlock();

    // Fetch outside the lock (network call must not block web/UI).
    // Limit to kFetchLimit (5) fresh docs per channel — champion + up to 4 candidates.
    std::vector<VulnDoc> docs;
    long total = 0;
    String err;
    bool ok = client.searchChannel(query, kFetchLimit, docs, &total, err);
    if (ok) _fetchProvenKey = true;  // HTTP 200 with this X-Api-Key -> the key is valid (authoritative)

    lock();
    int i = indexOf(id);  // channel may have been edited/removed meanwhile
    bool persist = false;
    if (i >= 0) {
        ChannelResult &r = _results[i];
        if (ok) {
            String oldChamp = r.champion.id;  // for the update-driven dashboard switch
            r.error = "";
            r.total = total;
            r.updatedMs = millis();
            time_t now_ts = time(nullptr);
            r.fetchedAt = (now_ts > 1600000000) ? now_ts : 0;  // real epoch only once SNTP-synced
            r.haveData = !docs.empty();
            if (!docs.empty()) {
                r.champion = docs.front();
                r.candidates.assign(docs.begin() + 1, docs.end());
            } else {
                r.champion = VulnDoc();
                r.candidates.clear();
            }
            // A NEW top item on this channel -> flag it so the dashboard can switch to show it.
            if (!r.champion.id.isEmpty() && r.champion.id != oldChamp) {
                _lastUpdatedId = _chans[i].id;
                _updateGen++;
            }
            persist = true;
        } else {
            r.error = err;
            // The attempt was claimed (attemptMs=now) + forced consumed before the network call, so a
            // failed fetch would otherwise wait a full interval. Re-arm it to retry in ~5s instead.
            uint32_t interval = _chans[i].refreshSec * 1000UL;
            r.attemptMs = now - (interval > 5000UL ? interval - 5000UL : 0);
        }
    }
    if (persist) saveData();  // durable cache for the UI (survives reboot / deep-sleep)
    unlock();

    if (ok) {
        Serial.printf("[chan] %s: champion=%s total=%ld (%d candidates)\n", id.c_str(),
                      docs.empty() ? "(none)" : docs.front().id.c_str(), total,
                      docs.empty() ? 0 : (int)docs.size() - 1);
    } else {
        Serial.printf("[chan] %s: fetch failed: %s\n", id.c_str(), err.c_str());
    }
}

// ---- web API + admin page --------------------------------------------------

namespace {

// Minimal functional admin UI. The polished device UI lives elsewhere; this is
// the system management surface for channel CRUD + active/refresh.
const char kAdminBody[] PROGMEM = R"WEB(
<a class=back href="/">&larr; Back</a>
<div class=card><h2>Add channel</h2>
<label>Name</label><input id=n placeholder="e.g. Ransomware">
<label>Lucene query</label><textarea id=q rows=2 placeholder="type:cve AND cvss.score:[9 TO 10] order:published"></textarea>
<a class=hint href="https://docs.vulners.com/docs/api/search/" target="_blank" rel="noopener"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15H6.5A2.5 2.5 0 0 0 4 20.5z"/><path d="M4 20.5A2.5 2.5 0 0 1 6.5 18H20"/></svg>New to the query language? We recommend the Vulners search syntax docs &rarr;</a>
<div class=row style=margin-top:10px>
<label class=chk><input type=checkbox id=a checked> active</label>
<span class=mut style=font-size:12px>refresh</span><select id=rf></select>
<span style=flex:1></span><button class=pri onclick=add()>Add</button></div>
<div id=amsg class=mut style=font-size:12px;margin-top:6px></div></div>
<div id=list></div>
<script>
/* Web admin refresh presets — mirror the device's kIntervals[] table (channels.h); keep in sync. */
const RF=[[60,'1 min'],[300,'5 min'],[900,'15 min'],[3600,'1 hour'],[21600,'6 hours'],['manual','Manual']];
function el(i){return document.getElementById(i)}
function esc(s){return (s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function opts(cur){return RF.map(([v,l])=>'<option value="'+v+'"'+(String(v)==String(cur)?' selected':'')+'>'+l+'</option>').join('')}
async function post(u,b){return (await(await fetch(u,{method:'POST',body:new URLSearchParams(b)})).json())}
async function get(){return await(await fetch('/api/channels')).json()}
function fmt(ep){try{return new Date(ep*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}catch(e){return ''}}
function stHtml(c){if(c.error)return '<span class=bad>err: '+esc(c.error)+'</span>';if(c.updated<0)return '<span class=mut>never</span>';var t=c.fetchedAt>0?(' '+fmt(c.fetchedAt)):'';return '<span class=ok>updated'+t+'</span> <span class=mut>total '+c.total+'</span>'}
function seth(e,h){if(e&&e.dataset.h!==h){e.dataset.h=h;e.innerHTML=h}}
function card(c){var vurl='https://vulners.com/search?query='+encodeURIComponent(c.query);return '<div class=card><div class=row><b style=font-size:15px>'+esc(c.name)+'</b><span class=pill>'+esc(c.id)+'</span>'+(c.active?'<span class="pill on">active</span>':'<span class=pill>off</span>')+(c.manual?'<span class=pill>manual</span>':'<span class="pill on">auto</span>')+'<span style=flex:1></span><span id="st-'+c.id+'">'+stHtml(c)+'</span></div>'
+'<div class=mono>'+esc(c.query)+'</div>'
+'<div class=row style=margin-top:10px>'
+'<label class=chk><input type=checkbox '+(c.active?'checked':'')+' onchange="tog(\''+c.id+'\',this.checked)"> active</label>'
+'<span class=mut style=font-size:12px>refresh</span><select onchange="setref(\''+c.id+'\',this.value)">'+opts(c.manual?'manual':c.refreshSec)+'</select>'
+'<button class=pri onclick="ref(\''+c.id+'\',this)">Refresh now</button>'
+'<a class=abtn href="'+vurl+'" target=_blank rel=noopener>Check on Vulners &#8599;</a>'
+'<span style=flex:1></span>'
+'<button class=del onclick="del(\''+c.id+'\')">Delete</button></div></div>'}
let _sig='';
async function load(){let a=await get();let sig=a.map(c=>c.id+c.active+c.manual+c.refreshSec).join('|');
if(sig!=_sig){_sig=sig;el('list').innerHTML=a.map(card).join('')}
a.forEach(c=>seth(el('st-'+c.id),stHtml(c)))}
async function add(){let rf=el('rf').value;let o={name:el('n').value,query:el('q').value,active:el('a').checked};
if(rf=='manual'){o.manual=true;o.refreshSec=1800}else{o.manual=false;o.refreshSec=rf}
let r=await post('/api/channels/create',o);el('amsg').textContent=r.ok?'added':(r.error||'failed');if(r.ok){el('n').value='';el('q').value=''}load()}
async function del(id){if(!confirm('Delete channel?'))return;await post('/api/channels/delete',{id});load()}
async function ref(id,btn){var o=btn.textContent;btn.textContent='Refreshing…';btn.disabled=true;
var b=(await get()).find(x=>x.id==id)||{},u0=b.updated,f0=b.fetchedAt,t0=b.total,e0=b.error||'';
await post('/api/channels/refresh',{id});var n=0;
var iv=setInterval(async()=>{n++;var c=(await get()).find(x=>x.id==id)||{};
if((c.fetchedAt!=f0)||(c.total!=t0)||((c.error||'')!=e0)||(u0>=0&&c.updated>=0&&c.updated<u0)||n>=15){clearInterval(iv);btn.disabled=false;btn.textContent=o;load()}},1000)}
async function upd(id,o){let c=(await get()).find(x=>x.id==id);if(!c)return;await post('/api/channels/update',Object.assign({id,name:c.name,query:c.query,refreshSec:c.refreshSec,active:c.active,manual:c.manual},o));load()}
async function tog(id,v){upd(id,{active:v})}
async function setref(id,v){if(v=='manual')upd(id,{manual:true});else upd(id,{manual:false,refreshSec:v})}
el('rf').innerHTML=opts(1800);load();setInterval(load,5000);
</script>)WEB";

void sendResult(bool ok, const String &err) {
    JsonDocument d;
    d["ok"] = ok;
    if (!ok) d["error"] = err;
    vcSendJson(*g_server, 200, d);
}

}  // namespace

void Channels::handleAdminPage() {
    vcSendHead(*g_server, "VulnCast \xC2\xB7 Channels");
    g_server->sendContent_P(kAdminBody);
    vcSendTail(*g_server);
}

void Channels::handleApiList() {
    JsonDocument d;
    JsonArray arr = d.to<JsonArray>();
    lock();
    uint32_t now = millis();
    for (size_t i = 0; i < _chans.size(); ++i) {
        const Channel &c = _chans[i];
        const ChannelResult &r = _results[i];
        JsonObject o = arr.add<JsonObject>();
        o["id"] = c.id;
        o["name"] = c.name;
        o["query"] = c.query;
        o["active"] = c.active;
        o["manual"] = c.manual;
        o["refreshSec"] = c.refreshSec;
        o["updated"] = r.updatedMs ? (long)((now - r.updatedMs) / 1000UL) : -1L;
        o["fetchedAt"] = (long)r.fetchedAt;  // wall-clock epoch (0 = unknown)
        o["total"] = r.total;
        o["error"] = r.error;
        JsonObject ch = o["champion"].to<JsonObject>();
        ch["id"] = r.champion.id;
        ch["title"] = r.champion.title;
        ch["cvss"] = r.champion.cvss;
    }
    unlock();
    vcSendJson(*g_server, 200, d);
}

void Channels::handleApiCreate() {
    String err;
    bool ok = add(g_server->arg("name"), g_server->arg("query"),
                  (uint32_t)g_server->arg("refreshSec").toInt(),
                  truthy(g_server->arg("active")), truthy(g_server->arg("manual")), err);
    sendResult(ok, err);
}

void Channels::handleApiUpdate() {
    String err;
    bool ok = update(g_server->arg("id"), g_server->arg("name"), g_server->arg("query"),
                     (uint32_t)g_server->arg("refreshSec").toInt(),
                     truthy(g_server->arg("active")), truthy(g_server->arg("manual")), err);
    sendResult(ok, err);
}

void Channels::handleApiRefresh() {
    bool ok = refreshNow(g_server->arg("id"));
    sendResult(ok, ok ? "" : "not found");
}

void Channels::handleApiDelete() {
    String err;
    bool ok = remove(g_server->arg("id"), err);
    sendResult(ok, err);
}

void Channels::registerRoutes(WebServer &s) {
    g_server = &s;
    s.on("/channels", HTTP_GET, []() { self->handleAdminPage(); });
    s.on("/api/channels", HTTP_GET, []() { self->handleApiList(); });
    s.on("/api/channels/create", HTTP_POST, []() { self->handleApiCreate(); });
    s.on("/api/channels/update", HTTP_POST, []() { self->handleApiUpdate(); });
    s.on("/api/channels/delete", HTTP_POST, []() { self->handleApiDelete(); });
    s.on("/api/channels/refresh", HTTP_POST, []() { self->handleApiRefresh(); });
}
