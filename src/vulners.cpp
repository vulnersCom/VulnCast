#include "vulners.h"

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>

#include "config.h"
#include "gfx.h"

namespace {

constexpr char kUrlLucene[] = "https://vulners.com/api/v3/search/lucene/";
constexpr char kUrlById[] = "https://vulners.com/api/v3/search/id";

// Percent-encode a value for use in a URL query component.
String urlEncode(const String &s) {
    static const char *hex = "0123456789ABCDEF";
    String out;
    out.reserve(s.length() * 3);
    for (size_t i = 0; i < s.length(); ++i) {
        char c = s[i];
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                          c == '.' || c == '~';
        if (unreserved) {
            out += c;
        } else {
            out += '%';
            out += hex[(c >> 4) & 0x0F];
            out += hex[c & 0x0F];
        }
    }
    return out;
}

// Copy an untrusted C string, truncated so the result (incl. the "..." marker) never exceeds `max`.
String bounded(const char *s, size_t max) {
    if (s == nullptr) return String();
    String out = gfx::renderable(String(s));  // pure ASCII -> the byte-truncate below is codepoint-safe
    if (out.length() > max) {
        out.remove(max > 3 ? max - 3 : 0);
        out += "...";
    }
    return out;
}

// Turn a markdown/HTML advisory/news body into plain readable prose: drop markdown images
// ![alt](url), unwrap links [text](url) -> text, strip <html> tags, decode the common HTML
// entities, drop stray markdown marks, and collapse whitespace. Bounded to `max` chars + "…".
// (Vulners descriptions — esp. news — are the full article body and often start with an image.)
String sanitizeText(const char *raw, size_t max) {
    if (raw == nullptr) return String();
    // Bound the UNTRUSTED input up front (Vulners text can be a huge article body): copy at most
    // ~4x the target so neither the heap copy nor the O(n) bracket scan blows up on a big/crafted doc.
    size_t rawLen = strlen(raw);
    size_t cap = max * 4 + 256;
    String s;
    s.concat(raw, rawLen < cap ? rawLen : cap);
    String out;
    out.reserve(s.length() < 2048 ? (unsigned)s.length() : 2048);
    int i = 0, n = s.length();
    while (i < n && (int)out.length() < (int)max * 3 + 64) {
        char ch = s[i];
        if (ch == '!' && i + 1 < n && s[i + 1] == '[') {  // markdown image -> drop whole ![..](..)
            int close = s.indexOf(']', i + 2);
            int paren = (close >= 0 && close + 1 < n && s[close + 1] == '(') ? s.indexOf(')', close + 2) : -1;
            if (paren > 0) { i = paren + 1; continue; }
        }
        if (ch == '[') {  // markdown link [text](url) -> keep text
            int close = s.indexOf(']', i + 1);
            int paren = (close >= 0 && close + 1 < n && s[close + 1] == '(') ? s.indexOf(')', close + 2) : -1;
            if (paren > 0) { out += s.substring(i + 1, close); i = paren + 1; continue; }
        }
        if (ch == '<') {  // html tag -> drop
            int close = s.indexOf('>', i + 1);
            if (close > 0 && close - i < 200) { i = close + 1; continue; }
        }
        if (ch == '*' || ch == '`') { i++; continue; }  // markdown emphasis/code marks
        out += ch;
        i++;
    }
    out.replace("&amp;", "&"); out.replace("&lt;", "<"); out.replace("&gt;", ">");
    out.replace("&quot;", "\""); out.replace("&#39;", "'"); out.replace("&apos;", "'");
    out.replace("&nbsp;", " "); out.replace("&mdash;", "-"); out.replace("&ndash;", "-");
    out.replace("&hellip;", "..."); out.replace("&rsquo;", "'"); out.replace("&lsquo;", "'");
    out.replace("&ldquo;", "\""); out.replace("&rdquo;", "\"");
    out = gfx::renderable(out);  // fold to pure ASCII (drop CJK/emoji + any malformed UTF-8) — the
                                 // whitespace collapse + byte-truncation below are then codepoint-safe
    String col;  // collapse runs of whitespace/newlines into single spaces
    col.reserve(out.length());
    bool sp = false;
    for (size_t k = 0; k < out.length(); k++) {
        char c = out[k];
        if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
            if (!sp && col.length()) col += ' ';
            sp = true;
        } else {
            col += c;
            sp = false;
        }
    }
    col.trim();
    // Append an ASCII ellipsis (not U+2026) so the output stays PURE ASCII — the whole point of the
    // gfx::renderable() fold above; any later byte-index cut then can't split a codepoint.
    if (col.length() > max) { col.remove(max); col += "..."; }
    return col;
}

// Parse the fields common to a search hit's `_source` and a by-id document (identical shape +
// bounds), so a bound change or a new common field lands in ONE place. Caller-specific fields
// (id fallback, description, cvssVector, cwe, kev, ...) are filled by each site afterward.
void parseCommon(JsonObjectConst s, VulnDoc &d) {
    d.id = bounded(s["id"] | "", 64);
    d.title = bounded(s["title"] | "", 200);
    d.type = bounded(s["type"] | "", 32);
    d.family = bounded(s["bulletinFamily"] | "", 32);
    d.published = bounded(s["published"] | "", 32);
    d.href = bounded(s["href"] | "", 256);
    d.reporter = bounded(s["reporter"] | "", 48);
    d.bounty = s["bounty"] | 0.0f;
    d.bountyState = bounded(s["bountyState"] | "", 16);
    d.cvss = s["cvss"]["score"] | 0.0f;
    d.exploitCount = s["exploits"].as<JsonArrayConst>().size();  // 0 for non-CVEs / CVEs with no exploits
    d.aiScore = s["enchantments"]["score"]["value"] | 0.0f;
    d.shortDescription = bounded(s["enchantments"]["short_description"] | "", 240);
}

// Fields fetched for a channel document — used for BOTH the request `fields` and
// the response `_source` filter, so the two lists can never drift apart.
constexpr const char *kChannelFields[] = {
    "id", "title", "type", "bulletinFamily", "published", "href", "cvss",
    "reporter", "bounty", "bountyState", "aiDescription", "description"};

// Configure a one-shot HTTPS request: insecure TLS (v1 — roadmap: pin the Vulners
// cert), timeouts, redirect policy, begin(). The single place the setInsecure()
// decision lives; callers add their own headers/verb afterwards.
bool configureHttps(WiFiClientSecure &client, HTTPClient &https, const char *url,
                    int readTimeoutMs) {
    client.setInsecure();
    https.setConnectTimeout(8000);
    https.setTimeout(readTimeoutMs);
    https.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    https.setUserAgent("VulnCast/" VULNCAST_FW_VERSION);  // identify the device+firmware to the Vulners API
    return https.begin(client, url);
}

// Shared HTTPS POST + filtered JSON parse. Keeps TLS/HTTP boilerplate in one
// place so each query only builds its request body and result filter.
bool postJson(const char *url, const String &body, const JsonDocument &filter,
              JsonDocument &out, String &err) {
    WiFiClientSecure client;
    HTTPClient https;
    if (!configureHttps(client, https, url, 12000)) {
        err = "begin failed";
        return false;
    }
    https.addHeader("Content-Type", "application/json");
    https.addHeader("X-Api-Key", config.apiKey());

    const int code = https.POST(body);
    if (code != HTTP_CODE_OK) {
        err = "HTTP " + String(code);
        https.end();
        return false;
    }
    DeserializationError jsonErr = deserializeJson(
        out, https.getStream(), DeserializationOption::Filter(filter));
    https.end();
    if (jsonErr) {
        err = String("json: ") + jsonErr.c_str();
        return false;
    }
    return true;
}

}  // namespace

void VulnDoc::mergeDetail(const VulnDoc &full) {
    if (full.description.length()) description = full.description;
    if (full.shortDescription.length()) shortDescription = full.shortDescription;
    if (full.aiDescription.length()) aiDescription = full.aiDescription;
    if (full.cvssVector.length()) cvssVector = full.cvssVector;
    if (full.cwe.length()) cwe = full.cwe;
    if (full.related.length()) related = full.related;
    if (full.affected.length()) affected = full.affected;
    if (full.program.length()) program = full.program;
    if (full.reporter.length()) reporter = full.reporter;
    if (full.href.length()) href = full.href;
    if (full.aiScore > 0) aiScore = full.aiScore;
    if (full.exploitCount > 0) exploitCount = full.exploitCount;
    if (full.title.length()) title = full.title;
    kev = kev || full.kev;
    exploited = exploited || full.exploited;
}

bool VulnersClient::searchChannel(const String &query, uint16_t size,
                                  std::vector<VulnDoc> &out, long *total, String &err) {
    if (size > 100) size = 100;
    JsonDocument reqDoc;
    reqDoc["query"] = query;
    reqDoc["size"] = size;
    JsonArray fields = reqDoc["fields"].to<JsonArray>();
    for (const char *f : kChannelFields) fields.add(f);
    // Request ONLY the sub-fields we actually use. Vulners honors dot-notation, and the full
    // `enchantments` object is ~100 KB on a heavily-referenced CVE (Log4Shell) — enough to blow the
    // read (IncompleteInput). Dot-notation keeps the response tiny (Log4Shell drops from ~145 KB to ~12 KB).
    fields.add("enchantments.score.value");         // AI score on the featured tile
    fields.add("enchantments.short_description");    // AI human summary
    fields.add("exploits.type");                     // exploit COUNT: only .type/element -> a tiny array we count
    String body;
    serializeJson(reqDoc, body);

    JsonDocument filter;
    JsonObject src = filter["data"]["search"][0]["_source"].to<JsonObject>();
    for (const char *f : kChannelFields) src[f] = true;
    src["enchantments"]["score"]["value"] = true;      // AI score
    src["enchantments"]["short_description"] = true;   // AI human summary (all families)
    src["exploits"][0]["type"] = true;                 // keep only a tiny field/element — we just count them
    filter["data"]["total"] = true;
    filter["result"] = true;

    JsonDocument doc;
    if (!postJson(kUrlLucene, body, filter, doc, err)) return false;

    if (total != nullptr) *total = doc["data"]["total"] | 0L;
    for (JsonObject hit : doc["data"]["search"].as<JsonArray>()) {
        JsonObject s = hit["_source"];
        if (s.isNull()) continue;
        VulnDoc d;
        parseCommon(s, d);  // id/title/type/family/published/href/reporter/bounty/cvss/exploitCount/ai/short
        // Only the champion (first hit) shows a summary on the dashboard. Fetch the AI text AND the raw
        // description so summaryText (aiDescription > shortDescription > description) always has content
        // even for brand-new CVEs that aren't AI-enriched yet. Candidates re-fetch full detail on open.
        if (out.empty()) {
            d.aiDescription = sanitizeText(s["aiDescription"] | "", 400);
            d.description = sanitizeText(s["description"] | "", 400);
        }
        out.push_back(d);
    }
    return true;
}

bool VulnersClient::fetchById(const String &id, VulnDoc &out, String &err) {
    if (id.isEmpty()) {
        err = "empty id";
        return false;
    }
    JsonDocument reqDoc;
    JsonArray ids = reqDoc["id"].to<JsonArray>();
    ids.add(id);
    JsonArray fields = reqDoc["fields"].to<JsonArray>();
    // Dot-notation sub-fields ONLY (never the whole `enchantments`/`exploits`): a Vulners doc can be
    // multiple MB (Log4Shell's enchantments alone is ~100 KB) and a big body truncates the TLS read
    // (IncompleteInput). This keeps even the worst-case doc to ~12 KB.
    for (const char *f : {"id", "title", "type", "bulletinFamily", "published", "href",
                          "description", "aiDescription", "reporter", "bounty", "bountyState",
                          "cvss", "cvss3", "cvss2", "cvss4", "exploits.type", "cwe", "cvelist",
                          "cnaAffected", "h1team", "cisaExploitAdd",
                          "enchantments.score.value", "enchantments.short_description",
                          "enchantments.exploitation.wildExploited"})
        fields.add(f);
    String body;
    serializeJson(reqDoc, body);

    // Response nests the docs under data.documents.<id> (like search's data.search[]._source) —
    // NOT a top-level { "<id>": {...} }. The filter mirrors that path (and bounds `enchantments`,
    // potentially huge, to just the AI score value + the wild-exploited flag).
    JsonDocument filter;
    JsonObject f = filter["data"]["documents"][id].to<JsonObject>();
    for (const char *k : {"id", "title", "type", "bulletinFamily", "published", "href",
                         "description", "aiDescription", "reporter", "bounty", "bountyState",
                         "cvss", "cwe", "cisaExploitAdd"})
        f[k] = true;
    f["exploits"][0]["type"] = true;               // exploit COUNT (keep only a tiny field per element)
    f["cvss3"]["cvssV3"]["vectorString"] = true;  // NVD-nested vector fallback
    f["cvss2"]["cvssV2"]["vectorString"] = true;
    f["cvss4"]["vector"] = true;                   // CVSS 4.0 vector (newer CVEs)
    f["cvelist"] = true;                           // linked CVE(s): targets/detects/relations
    f["cnaAffected"][0]["vendor"] = true;          // affected product (bound to vendor+product)
    f["cnaAffected"][0]["product"] = true;
    f["h1team"]["handle"] = true;                  // bugbounty program
    f["enchantments"]["score"]["value"] = true;
    f["enchantments"]["short_description"] = true;  // AI human summary
    f["enchantments"]["exploitation"]["wildExploited"] = true;
    filter["result"] = true;

    JsonDocument doc;
    if (!postJson(kUrlById, body, filter, doc, err)) return false;

    JsonObject s = doc["data"]["documents"][id];
    if (s.isNull()) {
        err = "not found";
        return false;
    }
    parseCommon(s, out);  // shared fields (id defaults to "" — fall back to the requested id below)
    if (out.id.isEmpty()) out.id = bounded(id.c_str(), 64);
    out.description = sanitizeText(s["description"] | "", 600);  // markdown/HTML -> readable prose
    out.aiDescription = sanitizeText(s["aiDescription"] | "", 600);
    out.cvssVector = bounded(s["cvss"]["vector"] | "", 80);
    if (out.cvssVector.isEmpty())  // fall back to the NVD-nested vector strings
        out.cvssVector = bounded(s["cvss3"]["cvssV3"]["vectorString"] |
                                     (s["cvss2"]["cvssV2"]["vectorString"] | ""),
                                 80);
    JsonArrayConst cwes = s["cwe"].as<JsonArrayConst>();
    if (!cwes.isNull() && cwes.size() > 0) out.cwe = bounded(cwes[0] | "", 24);
    out.kev = !String(s["cisaExploitAdd"] | "").isEmpty();
    out.exploited = out.kev || (s["enchantments"]["exploitation"]["wildExploited"] | false) ||
                    out.family == "exploit";
    // Rich detail fields: linked CVE(s), affected product, bugbounty program.
    JsonArrayConst cl = s["cvelist"].as<JsonArrayConst>();
    if (!cl.isNull() && cl.size() > 0) {
        out.related = bounded(cl[0] | "", 24);
        if (cl.size() > 1) out.related += " +" + String((int)cl.size() - 1);
    }
    JsonObjectConst cna = s["cnaAffected"][0].as<JsonObjectConst>();
    if (!cna.isNull()) {
        String v = bounded(cna["vendor"] | "", 40), p = bounded(cna["product"] | "", 60);
        out.affected = v + " " + p;
        out.affected.trim();
    }
    out.program = bounded(s["h1team"]["handle"] | "", 40);
    return true;
}

// Validate a key via the dedicated endpoint. The X-Api-Key header is REQUIRED
// (it bypasses the Cloudflare bot challenge); the candidate key also goes in the
// apiKey query param. Valid -> HTTP 200 {"data":{"valid":true}}. An unknown key
// is rejected at auth (HTTP 401); a known header with a wrong candidate -> valid:false.
bool VulnersClient::validateKey(const String &key, String &err) {
    if (key.isEmpty()) {
        err = "empty";
        return false;
    }
    WiFiClientSecure client;
    HTTPClient https;
    String url = "https://vulners.com/api/v3/apiKey/valid/?apiKey=" + urlEncode(key);
    if (!configureHttps(client, https, url.c_str(), 10000)) {
        err = "begin failed";
        return false;
    }
    // The X-Api-Key header is REQUIRED: it bypasses the Cloudflare bot challenge
    // (without it this endpoint returns a 403 "Just a moment" HTML page, not JSON).
    https.addHeader("X-Api-Key", key);
    int code = https.GET();
    String body = https.getString();
    https.end();
    if (code == 200) {
        JsonDocument d;
        if (deserializeJson(d, body)) {
            err = "parse";  // transient (unexpected body) -> caller should retry
            return false;
        }
        if (d["data"]["valid"] | false) return true;
        err = "invalid key";  // definitive: server explicitly says not valid
        return false;
    }
    if (code == 401) {
        err = "invalid key";  // definitive
        return false;
    }
    err = "HTTP " + String(code);  // transient (e.g. Cloudflare 403/5xx) -> retry
    return false;
}
