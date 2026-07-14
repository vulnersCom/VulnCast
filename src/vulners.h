// On-device Vulners API client. Calls the Lucene search endpoint (and the
// by-id endpoint) over HTTPS and parses only the fields we need (ArduinoJson
// streaming + filter) to stay within device memory. All Vulners text is
// untrusted input and is treated as data only (never executed / interpreted).
#pragma once

#include <Arduino.h>
#include <vector>

// A Vulners document as surfaced by a channel: enough to render a champion /
// candidate row. Full text (description, cvelist, ...) is fetched on demand by
// fetchById() for a detail view. All strings are bounded when parsed.
struct VulnDoc {
    String id;           // e.g. "CVE-2024-1234", "EDB-ID:51000", "THN:abc..."
    String title;        // human-readable headline
    String type;         // collection: cve, thn, threatpost, exploitdb, openbugbounty, ...
    String family;       // bulletinFamily: NVD, exploit, news, bugbounty, ...
    String published;    // ISO-8601 timestamp string
    String href;         // source URL
    String description;  // full body (fetchById only) — markdown/HTML, sanitized on parse
    String shortDescription;  // enchantments.short_description — the AI human summary (ALL families)
    String aiDescription;     // top-level aiDescription (when present; often empty)
    String reporter;     // human source/author, e.g. "The Hacker News", "twcert"
    String cvssVector;   // cvss.vector, e.g. "CVSS:3.1/AV:N/..." (fetchById only)
    String cwe;          // first CWE id, e.g. "CWE-122" (fetchById only)
    String bountyState;  // bugbounty: "resolved"/"new"/... (bulletinFamily bugbounty)
    String related;      // linked CVE(s): "CVE-X" or "CVE-X +N" — targets(exploit)/detects(scanner)
    String affected;     // affected vendor + product, e.g. "Comfast CF-WR631AX V3" (cnaAffected[0])
    String program;      // bugbounty program handle, e.g. "teleport" (h1team.handle)
    float cvss = 0.0f;   // cvss.score (0 if absent — many families have none)
    int exploitCount = 0;  // number of known exploits for a CVE (length of the top-level exploits[])
    float aiScore = 0.0f;  // Vulners AI score, enchantments.score.value
    float bounty = 0.0f;   // bugbounty payout in USD (0 if none/unknown)
    bool kev = false;      // on CISA KEV list (cisaExploitAdd present; fetchById only)
    bool exploited = false;  // exploit-family / known-exploited (fetchById only)

    // Enrich this (search-result) doc with the richer fetchById record: copy each non-empty field
    // and OR the kev/exploited flags. Fields the detail fetch doesn't carry are left untouched.
    void mergeDetail(const VulnDoc &full);
};

class VulnersClient {
public:
    VulnersClient() = default;

    // Channel query: runs a Lucene query and fills `out` with VulnDoc (id, title,
    // type, family, published, href, cvss, exploitCount). `total` (optional) receives
    // the API's total match count. Returns false on network/parse failure.
    bool searchChannel(const String &query, uint16_t size,
                       std::vector<VulnDoc> &out, long *total, String &err);

    // Detail fetch: POST /api/v3/search/id for a single id. Fills `out` with the
    // full document (including description + cvelist). Returns false on failure.
    bool fetchById(const String &id, VulnDoc &out, String &err);

    // Validate an API key against Vulners (does not store it). Sets err on failure.
    static bool validateKey(const String &key, String &err);
};
