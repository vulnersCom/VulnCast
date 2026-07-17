// VulnCast ops-console UI engine — 9 e-paper screens drawn directly with gfx.
//
// v2 "legibility build": 58 px bars, big type (JetBrains Mono 15..52), metric
// tiles, worded CVSS block, on-device Wi-Fi list. Every screen just draws the whole
// frame and calls gfx::present(); the damage-tracking compositor repaints only the
// changed bounding box, so the panel flashes as rarely as possible. Geometry
// follows docs/design_v2/.../PIXEL_SPEC.md exactly.
#include "ui.h"

#include <WiFi.h>
#include <Wire.h>

#include "TouchDrvGT911.hpp"
#include "assets/assets.h"
#include "board_pins.h"  // BOARD_SDA / BOARD_SCL for touch (was LilyGo-EPD47 utilities.h)
#include "channels.h"
#include "config.h"
#include "fonts/jbfonts.h"
#include "gfx.h"
#include "timekeeper.h"
#include "updater.h"
#include "wifi_manager.h"

using namespace gfx;

Ui ui;

namespace {

TouchDrvGT911 touch;

// Severity name + "is critical" from a CVSS base score.
const char *sevName(float s) {
    if (s <= 0.0f) return "NONE";
    if (s < 4.0f) return "LOW";
    if (s < 7.0f) return "MEDIUM";
    if (s < 9.0f) return "HIGH";
    return "CRITICAL";
}

String f1(float v) { char b[8]; snprintf(b, sizeof(b), "%.1f", v); return String(b); }

// ---- content archetype classifier + human labels ------------------------------------------
// Vulners groups 226 collection "types" into ~18 bulletinFamilies. We map them to 5 display
// ARCHETYPES that decide the lead line, the state pill, and the metric tiles. Computed once/render.
enum Kind { K_VULN, K_EXPLOIT, K_BUGBOUNTY, K_NEWS, K_GENERIC };
Kind kindOf(const VulnDoc &d) {
    const String &f = d.family;  // bulletinFamily
    if (d.bounty > 0 || f == "bugbounty" || f == "crypto") return K_BUGBOUNTY;
    if (f == "exploit" || f == "tools" || d.exploited || d.type.indexOf("exploit") >= 0)
        return K_EXPLOIT;
    if (f == "info" || f == "blog")  // advisories vs news: a real CVSS means it's a vuln advisory
        return d.cvss > 0.0f ? K_VULN : K_NEWS;
    if (f == "cve" || f == "NVD" || f == "euvd" || f == "cnnvd" || f == "cnvd" || f == "unix" ||
        f == "library" || f == "software" || f == "scanner" || f == "microsoft" || f == "jvn" ||
        f == "ncsc" || f == "nozomi" || d.type == "cve" || d.cvss > 0.0f)
        return K_VULN;
    return K_GENERIC;  // any unknown/future family degrades gracefully (AI summary + source + score)
}

// Human source label — never the raw hash id. Uppercased for the kicker.
String sourceName(const VulnDoc &d) {
    String t = d.type; t.toLowerCase();
    if (t == "thn") return "THE HACKER NEWS";
    if (t == "threatpost") return "THREATPOST";
    if (t == "cve" || t == "nvd" || d.family == "NVD" || d.family == "cve") return "NVD";
    if (t == "euvd") return "EU VULN DB";
    if (t == "exploitdb") return "EXPLOIT-DB";
    if (t == "githubexploit") return "GITHUB";
    if (t == "metasploit") return "METASPLOIT";
    if (t == "packetstorm" || t == "packetstormnews") return "PACKET STORM";
    if (t == "hackerone") return "HACKERONE";
    if (t == "openbugbounty") return "OPEN BUGBOUNTY";
    if (t == "huntr") return "HUNTR";
    if (t == "nuclei") return "NUCLEI";
    if (t == "nessus") return "NESSUS";
    if (t == "ossf") return "OSSF";
    if (t == "snyk") return "SNYK";
    if (t == "osv") return "OSV";
    if (t == "wired") return "WIRED";
    if (t == "schneier") return "SCHNEIER";
    if (t.length()) { t.toUpperCase(); return t; }
    String f = d.family; f.toUpperCase();
    return f.length() ? f : String("VULNERS");
}

// Best human-readable summary available, in priority order (AI first). Empty on the dashboard for
// items whose only body is the (not-searched) full description.
String summaryText(const VulnDoc &d) {
    if (d.aiDescription.length()) return d.aiDescription;
    if (d.shortDescription.length()) return d.shortDescription;
    return d.description;  // already sanitized in fetchById; empty in search results
}

// Bare host from a URL ("https://github.com/x/y" -> "github.com").
String hostOf(const String &url) {
    int p = url.indexOf("://");
    if (p < 0) return "";
    int s = p + 3;
    int e = url.indexOf('/', s);
    String h = (e < 0) ? url.substring(s) : url.substring(s, e);
    if (h.startsWith("www.")) h.remove(0, 4);
    return h;
}

String fmtBounty(float b) {  // compact for a metric tile: "$10K" / "$500"
    char x[16];
    if (b >= 1000.0f) snprintf(x, sizeof(x), "$%dK", (int)(b / 1000.0f));
    else snprintf(x, sizeof(x), "$%d", (int)(b + 0.5f));
    return String(x);
}

// Fill up to 3 metric tiles for a doc per archetype (real values only — never a fabricated 0.0).
// Returns the count. Shared by the dashboard and document so both stay consistent.
int metricTiles(const VulnDoc &d, Kind k, const char *lbl[3], String val[3]) {
    int n = 0;
    auto add = [&](const char *l, const String &v) {
        if (n < 3 && v.length()) { lbl[n] = l; val[n] = v; n++; }
    };
    if (k == K_BUGBOUNTY) {  // the bounty $ + AI score (state goes in the kicker — text won't fit a big tile)
        if (d.bounty > 0) add("BOUNTY", fmtBounty(d.bounty));
        if (d.aiScore > 0) add("AI SCORE", f1(d.aiScore));
    } else if (k == K_VULN) {
        if (d.cvss > 0) add("CVSS", f1(d.cvss));
        if (d.exploitCount > 0) add("EXPLOIT COUNT", String(d.exploitCount));  // known exploits for this CVE
        if (d.aiScore > 0) add("AI SCORE", f1(d.aiScore));
    } else {  // exploit / news / generic
        if (d.aiScore > 0) add(k == K_NEWS ? "AI RELEVANCE" : "AI SCORE", f1(d.aiScore));
        if (d.cvss > 0) add("CVSS", f1(d.cvss));
    }
    return n;
}

// State pill — only a MEANINGFUL state signal, never a restatement of the archetype (the channel
// tab + kicker already say "exploit"/"bugbounty"/"news"). So: severity or exploit-status for a
// VULN/CVE, KEV for anything actively exploited, and NO pill for the exploit/bugbounty/news/generic
// archetypes. Never a fabricated "NONE".
const char *statePill(const VulnDoc &d, Kind k, bool &fill) {
    fill = true;
    if (d.kev) return "ACTIVELY EXPLOITED";
    if (k == K_VULN) {
        if (d.exploited) return "EXPLOIT AVAILABLE";  // a CVE/vuln with a known exploit — the CVE case
        if (d.cvss > 0.0f) { fill = false; return sevName(d.cvss); }
    }
    fill = false;
    return nullptr;
}

// Correct UTC epoch for a civil date (Howard Hinnant's algorithm) — avoids the timezone error
// mktime() would introduce (published is UTC; the device TZ is user-set).
long daysFromCivil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    long era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097L + (long)doe - 719468;
}

// Coarse relative age "3d"/"5h"/"12m"/"now" from ISO-8601; empty when the clock isn't synced or
// the date can't be parsed (callers fall back to the plain date).
String relAge(const String &iso) {
    if (iso.length() < 10) return "";
    time_t now = time(nullptr);
    if (now < 1700000000L) return "";  // clock not synced yet
    int Y, Mo, D, h = 0, mi = 0, s = 0;
    if (sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d", &Y, &Mo, &D, &h, &mi, &s) < 3) return "";
    time_t pub = daysFromCivil(Y, Mo, D) * 86400LL + h * 3600LL + mi * 60LL + s;  // 64-bit (>2038 safe)
    long diff = (long)(now - pub);
    if (diff < 60) return "now";
    if (diff < 3600) return String(diff / 60) + "m";
    if (diff < 86400) return String(diff / 3600) + "h";
    return String(diff / 86400) + "d";
}

// "SOURCE · id · age". News drops the hash id; bugbounty shows the state instead of the id.
String kickerLine(const VulnDoc &d, Kind k) {
    String age = relAge(d.published);
    String when = age.length() ? age : d.published.substring(0, 10);
    String s = sourceName(d);
    if (k == K_BUGBOUNTY && d.bountyState.length()) {
        String st = d.bountyState; st.toUpperCase();
        s += " \xC2\xB7 " + st;
    } else if (k != K_NEWS && d.id.length()) {
        s += " \xC2\xB7 " + d.id;
    }
    if (when.length()) s += " \xC2\xB7 " + when;
    return s;
}

String intervalLabel(const Channel &c) {
    for (int i = 0; i < kIntervalCount; ++i) {
        if (c.manual && kIntervals[i].manual) return kIntervals[i].shortLbl;
        if (!c.manual && !kIntervals[i].manual && kIntervals[i].sec == c.refreshSec)
            return kIntervals[i].shortLbl;
    }
    return c.manual ? "Man" : String(c.refreshSec / 60) + "m";  // non-preset fallback
}

// Advance from byte index i to the start of the next UTF-8 codepoint (skip 10xxxxxx continuation
// bytes). drawWrap/wrapLines/textFit measure substrings while hunting the wrap point; a substring()
// that truncates a multi-byte char mid-sequence feeds epdiy's text-bounds decoder a lone lead byte
// and it hangs the UI loop (Vulners exploit "descriptions" are raw code carrying high bytes — the
// char at the hard-cut boundary was mid-codepoint). Cutting only on codepoint boundaries avoids it.
int utf8Next(const String &s, int i) {
    int n = s.length(), j = i + 1;
    while (j < n && ((uint8_t)s[j] & 0xC0) == 0x80) j++;
    return j;
}

// Word-wrap `s` in `font` within maxW; draw up to maxLines from baseline y0.
int drawWrap(const GFXfont &font, int x, int y0, int maxW, int lineH, int maxLines,
             const String &s, uint8_t fg) {
    int y = y0, lines = 0, start = 0, n = s.length();
    while (start < n && lines < maxLines) {
        int end = start, last = -1;
        while (end < n) {
            if (s[end] == ' ') last = end;
            int nx = utf8Next(s, end);  // whole codepoints only (truncated lead byte hangs epdiy)
            if (textW(font, s.substring(start, nx).c_str()) > maxW) break;
            end = nx;
        }
        int cut = (end >= n) ? n : (last > start ? last : end);
        if (cut <= start) cut = utf8Next(s, start);  // no-space overflow: hard cut (whole codepoint)
        String lineStr = s.substring(start, cut);
        int next = (cut < n && s[cut] == ' ') ? cut + 1 : cut;
        // Last permitted line but text remains → append an ellipsis (trim to fit) so the
        // reader sees the content was truncated instead of an abrupt mid-word stop.
        if (lines == maxLines - 1 && next < n) {
            while (lineStr.length() && textW(font, (lineStr + "\xE2\x80\xA6").c_str()) > maxW) {
                int i = lineStr.length() - 1;
                while (i > 0 && ((uint8_t)lineStr[i] & 0xC0) == 0x80) i--;  // whole trailing codepoint
                lineStr.remove(i);
            }
            lineStr += "\xE2\x80\xA6";
        }
        text(font, x, y, lineStr.c_str(), fg);
        start = next;
        y += lineH;
        lines++;
    }
    return y;
}

// Wrap the whole string to `maxW` and return every line (no ellipsis, no line cap) — for a scrollable
// text pane where the caller draws a window of lines and knows the total.
std::vector<String> wrapLines(const GFXfont &font, int maxW, const String &s) {
    std::vector<String> out;
    int start = 0, n = s.length();
    while (start < n) {
        int end = start, last = -1;
        while (end < n) {
            if (s[end] == ' ') last = end;
            int nx = utf8Next(s, end);  // measure whole codepoints — never a truncated lead byte
            if (textW(font, s.substring(start, nx).c_str()) > maxW) break;
            end = nx;
        }
        int cut = (end >= n) ? n : (last > start ? last : end);
        if (cut <= start) cut = utf8Next(s, start);  // force progress by >=1 whole codepoint
        out.push_back(s.substring(start, cut));
        start = (cut < n && s[cut] == ' ') ? cut + 1 : cut;
    }
    return out;
}

// Pull a "KEY:" metric out of a CVSS v3 vector string.
String cvssMetric(const String &vec, const char *key) {
    int p = vec.indexOf(key);
    if (p < 0) return "";
    p += strlen(key);
    int e = vec.indexOf('/', p);
    return (e < 0 ? vec.substring(p) : vec.substring(p, e));
}


// A 3-segment severity bar: `lvl` segments filled (High=3, Low=1, None=0).
void drawSegBar(int x, int y, int w, int h, int lvl) {
    const int seg = 3, gap = 5;
    int sw = (w - (seg - 1) * gap) / seg;
    for (int i = 0; i < seg; ++i) {
        int sx = x + i * (sw + gap);
        if (i < lvl) fillRect(sx, y, sw, h, INK);
        else rect(sx, y, sw, h, 2, GRAY4);
    }
}

// Visualize a CVSS v3 vector: exploitability pictograms (globe/gauge/lock/cursor = AV/AC/PR/UI) on the
// top row, then C/I/A impact as segmented bars. Draws from `y`; returns the y just below it. If the doc
// carries no vector (e.g. detail not fetched yet), returns `y` unchanged so the caller draws nothing.
int drawCvssVector(const VulnDoc &d, int y) {
    const String &vec = d.cvssVector;
    if (vec.indexOf("AV:") < 0) return y;
    String av = cvssMetric(vec, "AV:"), ac = cvssMetric(vec, "AC:"),
           pr = cvssMetric(vec, "PR:"), uiv = cvssMetric(vec, "UI:");
    const int cw = 148;
    int cx = 26;                                   // cell 0 — Attack Vector (globe)
    gGlobe(cx + 13, y + 15, 10, INK);
    text(JB_R15, cx + 32, y + 12, "VECTOR", GRAY3);
    text(JB_B16, cx + 32, y + 33,
         av == "N" ? "Network" : av == "A" ? "Adjacent" : av == "L" ? "Local"
                                                                     : av == "P" ? "Physical" : "\xE2\x80\x94",
         INK);
    cx += cw;                                      // cell 1 — Attack Complexity (gauge)
    gGauge(cx + 13, y + 24, 10, INK);
    text(JB_R15, cx + 32, y + 12, "COMPLEXITY", GRAY3);
    text(JB_B16, cx + 32, y + 33, ac == "L" ? "Low" : ac == "H" ? "High" : "\xE2\x80\x94", INK);
    cx += cw;                                      // cell 2 — Privileges Required (lock)
    gLock(cx + 4, y + 6, 18, INK);
    text(JB_R15, cx + 32, y + 12, "PRIVILEGES", GRAY3);
    text(JB_B16, cx + 32, y + 33, pr == "N" ? "None" : pr == "L" ? "Low" : pr == "H" ? "High" : "\xE2\x80\x94", INK);
    cx += cw;                                      // cell 3 — User Interaction (cursor)
    gCursor(cx + 5, y + 5, 18, INK);
    text(JB_R15, cx + 32, y + 12, "USER", GRAY3);
    text(JB_B16, cx + 32, y + 33, uiv == "N" ? "None" : uiv == "R" ? "Required" : "\xE2\x80\x94", INK);
    // C/I/A impact as segmented bars
    int by = y + 54;
    const char *cia[3] = {"Confidentiality", "Integrity", "Availability"};
    const char *keys[3] = {"C:", "I:", "A:"};
    for (int i = 0; i < 3; ++i) {
        int ry = by + i * 26;
        String v = cvssMetric(vec, keys[i]);
        int lvl = v == "H" ? 3 : v == "L" ? 1 : 0;
        text(JB_R16, 26, ry + 14, cia[i], GRAY3);
        drawSegBar(250, ry + 3, 176, 14, lvl);
        text(JB_B16, 442, ry + 14, lvl == 3 ? "High" : lvl == 1 ? "Low" : "None", INK);
    }
    return by + 3 * 26;
}

// Archetype facts with pictograms (non-CVE documents) — the middle section that mirrors the CVE's
// CVSS visualization. icon: 0 globe (source), 1 target (exploit targets), 2 shield (program), 3 user
// (author/researcher). Draws icon+label+value rows from y; returns the y below.
int drawDocFacts(const VulnDoc &d, Kind k, int y) {
    struct F { int icon; const char *lbl; String val; };
    F fx[3];
    int nf = 0;
    auto add = [&](int ic, const char *l, const String &v) {
        if (nf < 3 && v.length()) { fx[nf] = {ic, l, v}; nf++; }
    };
    if (k == K_EXPLOIT) {
        add(1, "TARGETS", d.related);
        add(0, "SOURCE", hostOf(d.href));
    } else if (k == K_BUGBOUNTY) {
        add(2, "PROGRAM", d.program);
        add(3, "RESEARCHER", d.reporter);
    } else if (k == K_NEWS) {
        add(3, "AUTHOR", d.reporter);
        add(0, "SOURCE", hostOf(d.href));
    } else {
        add(0, "SOURCE", d.reporter.length() ? d.reporter : sourceName(d));
    }
    for (int i = 0; i < nf; i++) {
        int ry = y + i * 32;
        switch (fx[i].icon) {
            case 0: gGlobe(40, ry + 14, 10, INK); break;
            case 1: gTarget(40, ry + 14, 10, INK); break;
            case 2: gShield(30, ry + 4, 20, INK); break;
            case 3: gUser(40, ry + 14, 20, INK); break;
        }
        text(JB_B15, 62, ry + 20, fx[i].lbl, GRAY3);
        textFit(JB_R17, 176, ry + 20, 436, fx[i].val.c_str(), INK2);
    }
    return y + nf * 32;
}

}  // namespace

// ---- lifecycle -------------------------------------------------------------

bool Ui::begin() {
    if (!gfx::begin()) return false;
    Wire.begin(BOARD_SDA, BOARD_SCL);
    touch.setPins(-1, -1);
    _touchOnline = touch.begin(Wire, GT911_SLAVE_ADDRESS_L, BOARD_SDA, BOARD_SCL) ||
                   touch.begin(Wire, GT911_SLAVE_ADDRESS_H, BOARD_SDA, BOARD_SCL);  // 0x14: GT911 latches either addr from INT at power-on
    if (_touchOnline) {
        touch.setMaxCoordinates(960, 540);
        touch.setSwapXY(true);
        touch.setMirrorXY(false, true);
        Serial.println("[ui] touch online");
    } else {
        Serial.println("[ui] touch NOT found");
    }
    return true;
}

void Ui::injectTouch(int x, int y) {
    _injX = x;
    _injY = y;
    _injPending = true;
    _nextTouch = 0;  // let poll() act on it immediately
}

bool Ui::readTouch(int &x, int &y) {
    if (_injPending) {  // synthetic tap takes priority (dev/test)
        x = _injX;
        y = _injY;
        _injPending = false;
        return true;
    }
    if (!_touchOnline) return false;
    int16_t xs[2], ys[2];
    if (touch.getPoint(xs, ys, 1) < 1) return false;
    x = xs[0];
    y = ys[0];
    if (_touchMonitor) Serial.printf("[touch] %d,%d on %s\n", x, y, screenName());
    return true;
}

namespace {
const char *kScrNames[] = {"boot",     "connecting", "setup",    "dashboard", "document",  "settings",
                           "keyboard", "interval",   "timezone", "needkey",   "reset?",    "update",
                           "updfail",  "chill",      "nocredits"};
}  // namespace

const char *Ui::screenName() const { return _scr <= SCR_NOCREDITS ? kScrNames[_scr] : "?"; }

void Ui::requestJump(char c) { _pendingJump = c; }  // queued by the console task
void Ui::requestTest(int n) { _pendingTest = n; }
void Ui::requestProbe(int n) { _pendingProbe = n; }

// A whole-screen present. Navigation vs in-place re-render no longer needs distinguishing:
// FastEPD's flash-free 2-bit partial diffs old->new and drives only the changed rows either way
// (see gfx::present). Kept as the named entry point the 9 full screens call.
void Ui::presentScreen() { gfx::present(); }

// Every screen opens by clearing to paper and drawing the 2px frame border.
void Ui::beginFrame() {
    // Every screen opens here, so this is the choke point that restores the normal periodic de-ghost:
    // chill mode disables it (setAutoDeghost(false)) AFTER its own beginFrame(), and leaving chill by
    // ANY path (tap, Wi-Fi reconnect-portal, debug jump) re-enters some show*() -> beginFrame() -> on.
    gfx::setAutoDeghost(true);
    clear(PAPER);
    rect(0, 0, W, H, 2, INK);
}

// Compact ▲/▼ scroll rail for an in-panel list: top half pages up, bottom half pages down. Both
// arrows are always drawn solid INK — on the 2-bit panel a greyed-out "disabled" arrow renders nearly
// invisible (looks like nothing is there), so instead both stay crisp and an end-tap is a harmless
// no-op. The visible list content (and, for timezone, the thumb + "X-Y of N") conveys the position.
void Ui::drawScrollRail(int x, int y, int w, int h) {
    int half = h / 2;
    rect(x, y, w, half - 3, 2, INK);
    gTriUp(x + w / 2 - 8, y + half / 2 - 5, 16, INK);
    rect(x, y + half + 3, w, half - 3, 2, INK);
    gTriDown(x + w / 2 - 8, y + half + half / 2 - 5, 16, INK);
}

// Worded state pill: a JB_B17 label in a rounded box (pw = text + 28px padding). fill = solid box with
// inverted text, else a 2px outline. Shared by the dashboard featured panel and the document header.
void Ui::drawPill(int x, int y, int h, const char *label, bool fill) {
    int pw = textW(JB_B17, label) + 28;
    if (fill) {
        fillRect(x, y, pw, h, INK);
        textAlign(JB_B17, x, y + 24, pw, C, label, PAPER, INK);
    } else {
        rect(x, y, pw, h, 2, INK);
        textAlign(JB_B17, x, y + 24, pw, C, label, INK);
    }
}

// Framebuffer dump coordination: the console task asks (requestDump); the UI loop
// performs it (serviceDump) BETWEEN its own draws, so the dump never reads a
// half-drawn frame. Clearing the flag before dumping means the console task sees
// it handled and won't also dump (which would garble the serial stream).
void Ui::requestDump() { _dumpReq = true; }
void Ui::serviceDump() {
    if (!_dumpReq) return;
    _dumpReq = false;
    gfx::dumpSerial();
}

// Executed on the UI task (drawing is single-threaded). A dev screen-jump previews
// a screen without changing navigation state; a self-test paints a panel pattern.
void Ui::serviceJump() {
    if (_pendingProbe >= 0) {
        gfx::probe(_pendingProbe);
        _pendingProbe = -1;
        return;
    }
    if (_pendingTest >= 0) {
        gfx::testPattern(_pendingTest);
        _pendingTest = -1;
        return;
    }
    char c = _pendingJump;
    if (!c) return;
    _pendingJump = 0;
    switch (c) {
        case '1': showDashboard(_lastStatus); break;
        case '2':
        case 'V': {
            if (c == 'V')
                for (int i = 0; i < (int)_chNames.size(); ++i)
                    if (_chNames[i].indexOf("VULN") >= 0) { _chIdx = i; break; }
            ChannelResult r;
            if (channels.snapshot(activeId(), r) && r.champion.id.length())
                channels.requestDetail(r.champion.id);
            showDocument(activeId(), 0);
            break;
        }
        case '3': showSettings(); break;
        case '4': showKeyboard("OFFICE-2.4G"); break;
        case '5': showInterval(activeId()); break;
        case '6': showTimezone(); break;
        case '7': showBoot(3, "display \xC2\xB7 storage \xC2\xB7 radio"); break;
        case '8': showConnecting("OFFICE-2.4G", 2); break;
        case '9': showSetup("VulnCast-Setup", "vulncast-setup", "192.168.4.1", 0); break;
        case 'K': showNeedKey("192.168.1.42"); break;  // preview the "add your API key" screen
        case 'Y': showResetConfirm(); break;           // preview the factory-reset confirm gate
        case 'U': updater.devPreviewAvailable(); showUpdate(); break;  // preview the update offer
        case 'B': updater.devPreviewRollback(); showUpdateFailed(); break;  // preview the rollback screen
        case 'L': showChill(); break;                  // preview the lofi chill-mode screensaver
        case 'O': showNoCredits(); break;              // preview the out-of-credits screen
    }
}

// ---- shared chrome ---------------------------------------------------------

// Compact remaining-credit count for the status bar: exact under 10k, then k / M / B with one decimal
// (a free key shows e.g. "2847", an OEM key "10.0B"). Buffer >= 8 bytes.
static void formatCredits(long long c, char *out, size_t n) {
    if (c < 0) { strlcpy(out, "\xE2\x80\x94", n); return; }  // em-dash = unknown
    if (c < 10000) { snprintf(out, n, "%lld", c); return; }
    double v = (double)c;
    if (c < 1000000LL) snprintf(out, n, "%.0fk", v / 1000.0);
    else if (c < 1000000000LL) snprintf(out, n, "%.1fM", v / 1e6);
    else snprintf(out, n, "%.1fB", v / 1e9);
}

void Ui::drawStatusBar(const UiStatus &st) {
    fillRect(0, 0, W, 58, INK);
    const int by = 37;  // 22px text baseline in a 58px bar
    int x = 22;
    gDot(x, 27, 5, WHITE);
    x += 16;
    char buf[48];
    snprintf(buf, sizeof(buf), "SYNC %s", st.syncAgeMin < 0 ? "\xE2\x80\x94" : (String(st.syncAgeMin) + "m").c_str());
    x += text(JB_B20, x, by, buf, WHITE, INK) + 26;
    // API status (the remaining-credit balance lives in the dashboard footer, not here).
    if (st.apiKeyValid) {
        x += text(JB_B20, x, by, "API", WHITE, INK) + 10;
        gCheck(x, 20, 16, WHITE);
    } else {
        text(JB_B20, x, by, st.apiKeySet ? "API ?" : "API OFF", GRAY6, INK);
    }
    // WEB INTERFACE <ip> — the live admin URL host, centered in the bar's middle gap (dashboard only).
    // st.ip is refreshed from WiFi.localIP() on every buildStatus() and the loop forces a repaint the
    // moment it changes (DHCP renew / reconnect), so it is always current.
    if (st.ip.length()) {
        static const int lw = textW(JB_B17, "WEB INTERFACE ");  // constant label width — measure once
        int hw = textW(JB_B17, st.ip.c_str());
        int wx = 330 + (375 - (lw + hw)) / 2;  // center within the [330,705] gap; never runs into either cluster
        if (wx < 330) wx = 330;
        wx += text(JB_B17, wx, by, "WEB INTERFACE ", GRAY6, INK);
        text(JB_B17, wx, by, st.ip.c_str(), WHITE, INK);
    }
    // right cluster: clock, signal, battery
    int rx = W - 22;
    snprintf(buf, sizeof(buf), "%d%%", st.battPct);
    int pw = textW(JB_B20, buf);
    text(JB_B20, rx - pw, by, buf, WHITE, INK);
    rx -= pw + 10;
    gBattery(rx - 34, 24, st.battPct, st.charging, WHITE);
    rx -= 34 + 16;
    // RSSI -> 0..4 bars. Keep these thresholds in sync with the web status bar (web_ui.cpp JS).
    int bars = !st.connected ? 0 : st.rssi > -55 ? 4 : st.rssi > -67 ? 3 : st.rssi > -78 ? 2 : 1;
    gSignal(rx - 18, 22, bars, WHITE);
    rx -= 18 + 18;
    String clk = st.timeStr.length() ? st.timeStr : String("--:--");
    int cw = textW(JB_B22, clk.c_str());
    text(JB_B22, rx - cw, by, clk.c_str(), WHITE, INK);
}

void Ui::drawFooter(const char *left, const char *right) {
    fillRect(0, H - 44, W, 44, INK);
    text(JB_R16, 22, H - 16, left, GRAY4, INK);
    if (right) {
        int rw = textW(JB_B16, right);
        text(JB_B16, W - 22 - rw, H - 16, right, WHITE, INK);
    }
}

void Ui::drawHeaderBar(const char *back, const char *mid, const char *right) {
    fillRect(0, 0, W, 58, INK);
    const int by = 37;
    int x = 22;
    if (back) {
        gTriLeft(x, 22, 14, WHITE);
        x += 22;
        x += text(JB_B22, x, by, back, WHITE, INK) + 22;
        vline(x - 11, 16, 26, GRAY1);
    }
    if (mid) text(JB_R19, x, by, mid, GRAY6, INK);
    if (right) {
        int rw = textW(JB_R17, right);
        text(JB_R17, W - 22 - rw, by, right, GRAY4, INK);
    }
}

// ---- provisioning screens --------------------------------------------------

// Every screen simply draws the whole frame into the framebuffer and calls
// present(); the compositor diffs against the shadow and repaints only what
// changed (so the boot bar / checklist advance without touching anything else,
// and no manual base/partial bookkeeping is needed).
void Ui::showBoot(int stage, const char *caption) {
    _scr = SCR_BOOT;
    beginFrame();
    text(JB_R17, W - 22 - textW(JB_R17, "v" VULNCAST_FW_VERSION), 40, "v" VULNCAST_FW_VERSION, GRAY4);
    blit((W - kLogo120W) / 2, 150, kLogo120W, kLogo120H, kLogo120);
    blit((W - kWord96W) / 2, 288, kWord96W, kWord96H, kWord96);
    rect(270, 446, 420, 12, 2, INK);
    int frac = stage < 0 ? 0 : stage > 4 ? 4 : stage;
    if (frac > 0) fillRect(273, 449, (414 * frac) / 4, 6, INK);
    if (caption) {
        String c = String("STARTING \xC2\xB7 ") + caption;
        textAlign(JB_R17, 0, 484, W, C, c.c_str(), GRAY3);
    }
    presentScreen();  // 1st stage flashes once; later stages -> only the bar redraws
}

void Ui::showConnecting(const String &ssid, int step) {
    _scr = SCR_CONNECTING;
    beginFrame();
    blit((W - kLogo50W) / 2, 40, kLogo50W, kLogo50H, kLogo50);
    textAlign(JB_X52, 0, 128, W, C, "Connecting\xE2\x80\xA6", INK);
    String disp = gfx::renderable(ssid);  // fold the raw SSID to safe ASCII only for on-panel drawing
    int lw = textW(JB_R19, "joining");
    int pillW = textW(JB_B22, disp.c_str()) + 40;
    int sx = (W - (lw + 14 + pillW)) / 2;
    text(JB_R19, sx, 178, "joining", GRAY3);
    rect(sx + lw + 14, 149, pillW, 45, 2, INK);
    textAlign(JB_B22, sx + lw + 14, 180, pillW, C, disp.c_str(), INK);
    rect(200, 222, 560, 243, 2, GRAY4);
    const char *steps[4] = {"Wi-Fi radio ready", "Associating & getting IP\xE2\x80\xA6",
                            "Sync time over NTP", "Validate Vulners API key"};
    for (int i = 0; i < 4; ++i) {
        int ry = 222 + i * 60;
        bool done = i < step, active = i == step;
        if (active) fillRect(201, ry + 1, 558, 59, INK);
        uint8_t fg = active ? PAPER : done ? INK : GRAY4;
        if (done) {
            fillRect(216, ry + 18, 24, 24, INK);
            gCheck(220, ry + 24, 15, PAPER);
        } else if (active) {
            gTriRight(220, ry + 20, 18, PAPER);
        } else {
            rect(216, ry + 18, 24, 24, 2, GRAY4);
        }
        text(JB_B20, 258, ry + 38, steps[i], fg, active ? INK : PAPER);
        if (i < 3) hline(201, ry + 60, 558, GRAY5);
    }
    presentScreen();  // later steps -> only the changed checklist rows redraw
}

void Ui::showSetup(const String &apSsid, const String &apPass, const String &url, int saved) {
    _scr = SCR_SETUP;
    beginFrame();
    fillRect(0, 0, W, 58, INK);
    text(JB_B22, 22, 37, "SETUP", WHITE, INK);
    // draw "Wi-Fi" + ✗ + "offline" manually (avoid a missing glyph for ✗)
    int rx = W - 22;
    int ow = textW(JB_R19, "offline");
    text(JB_R19, rx - ow, 37, "offline", GRAY4, INK);
    rx -= ow + 10;
    text(JB_R19, rx - textW(JB_R19, "Wi-Fi"), 37, "Wi-Fi", GRAY6, INK);
    line(rx - 22, 24, rx - 12, 34, GRAY4);
    line(rx - 22, 34, rx - 12, 24, GRAY4);
    // left column
    text(JB_X36, 28, 108, "Let\xE2\x80\x99s get you online", INK);
    struct { const char *a; const char *b; } steps[3] = {
        {"Join the Wi-Fi network", nullptr},
        {"The setup page opens automatically", "(else visit 192.168.4.1)"},
        {"Pick your network & add your", "Vulners API key"}};
    int sy = 141;
    for (int i = 0; i < 3; ++i) {
        rect(28, sy, 38, 38, 2, INK);
        char n[2] = {char('1' + i), 0};
        textAlign(JB_B22, 28, sy + 27, 38, C, n, INK);
        text(JB_M20, 80, sy + 20, steps[i].a, INK2);
        if (i == 0) text(JB_B20, 80, sy + 46, apSsid.c_str(), INK);
        else if (steps[i].b) text(JB_M20, 80, sy + 46, steps[i].b, INK2);
        sy += 74;
    }
    // right column (border-left)
    vline(578, 60, 480, INK, 2);
    rect(604, 137, 330, 124, 2, GRAY4);
    text(JB_R16, 622, 172, "JOIN THIS ACCESS POINT", GRAY3);
    text(JB_X34, 620, 210, apSsid.c_str(), INK);
    text(JB_R17, 622, 242, (String("pass: ") + apPass).c_str(), GRAY3);
    // real Wi-Fi join QR: scanning connects the phone to the setup AP -> captive portal
    String wifiQr = "WIFI:T:WPA;S:" + apSsid + ";P:" + apPass + ";;";
    qrCode(694, 281, 150, wifiQr.c_str(), INK);
    textAlign(JB_R16, 578, 462, 380, C, "Scan to join & open setup", GRAY3);
    presentScreen();
}

// Online, but no Vulners API key yet: the key is entered through the web interface (never on-device),
// so guide the user there with the device's live IP + a scannable link. main.cpp advances to the
// dashboard automatically once a key lands (config.hasApiKey()).
// Rotating "comet" cell (partial-update animated) so the screen feels alive while it waits for a key.
void Ui::drawNeedKeySpinner() {
    static const int8_t ox[8] = {14, 10, 0, -10, -14, -10, 0, 10};
    static const int8_t oy[8] = {0, 10, 14, 10, 0, -10, -14, -10};
    const int cx = 46, cy = 374;
    fillRect(cx - 17, cy - 17, 35, 35, PAPER);  // clear the cell (partial diff -> only this box repaints)
    for (int i = 0; i < 8; i++) {
        int d = (_needKeyPhase - i) & 7;                 // 0 = bright head, trailing dots fade -> motion
        int r = d == 0 ? 5 : d == 1 ? 4 : d == 2 ? 3 : 2;
        gDot(cx + ox[i], cy + oy[i], r, INK);
    }
}

void Ui::showNeedKey(const String &ip) {
    _scr = SCR_NEEDKEY;
    _needKeyIp = ip;
    _needKeyPhase = 0;
    beginFrame();
    // Header: a filled dot + "ONLINE" — deliberately NOT the offline "SETUP" bar, so the jump from the
    // provisioning screen reads as real progress, plus a "STEP 2 / 2" to signal we're nearly done.
    fillRect(0, 0, W, 58, INK);
    gDot(32, 27, 6, WHITE);
    text(JB_B22, 48, 37, "ONLINE", WHITE, INK);
    const char *step = "STEP 2 / 2";
    text(JB_B20, W - 22 - textW(JB_B20, step), 37, step, GRAY6, INK);

    // Left column — you're in, one thing left, and where to go.
    text(JB_X36, 28, 118, "You\xE2\x80\x99re online.", INK);
    text(JB_M20, 28, 160, "One step left \xE2\x80\x94 add your", INK2);
    text(JB_M20, 28, 188, "Vulners API key.", INK2);
    text(JB_R16, 28, 250, "OPEN IN YOUR BROWSER", GRAY3);
    textFit(JB_X34, 28, 292, 522, ("http://" + ip).c_str(), INK);
    text(JB_R17, 28, 324, "or  http://vulncast.local", GRAY3);
    // Live "listening" indicator (animated via animateNeedKey()).
    drawNeedKeySpinner();
    text(JB_M20, 78, 382, "Listening for your key\xE2\x80\xA6", INK2);
    text(JB_R16, 28, 456, "Need a key? Get one at docs.vulners.com", GRAY3);

    // Right column — the hero: a big QR straight to the on-device key page.
    vline(578, 60, 480, INK, 2);
    textAlign(JB_B20, 578, 120, 380, C, "SCAN TO ADD YOUR KEY", INK);
    String url = "http://" + ip + "/apikey";
    qrCode(651, 152, 214, url.c_str(), INK);
    textAlign(JB_R17, 578, 410, 380, C, "opens the key page on your phone", GRAY3);
    presentScreen();
}

// Advance the live spinner (partial update only — no full flash). Called ~1.4 s from loop() while the
// device waits on this screen.
void Ui::animateNeedKey() {
    if (_scr != SCR_NEEDKEY) return;
    _needKeyPhase++;
    drawNeedKeySpinner();
    presentScreen();
}

// ---- dashboard -------------------------------------------------------------

void Ui::drawChannelBar() {
    // Slim channel bar (y136..182, 46px — was 64px): hairline rules, a compact centered active
    // chip + clipped neighbors, and ◂ ▸ pagers at the edges (hit-tests unchanged).
    hline(0, 136, W, GRAY5, 1);
    hline(0, 182, W, GRAY5, 1);
    gTriLeft(26, 151, 16, INK);
    gTriRight(918, 151, 16, INK);
    int n = channelCount();
    if (n == 0) return;
    String cur = _chNames[_chIdx];
    int chipW = 240;
    int nameW = textW(JB_B20, cur.c_str());
    if (nameW + 36 > chipW) chipW = nameW + 36;
    int chipX = (W - chipW) / 2;
    fillRect(chipX, 143, chipW, 32, INK);
    textAlign(JB_B20, chipX, 166, chipW, C, cur.c_str(), PAPER, INK);
    if (n > 1) {
        String prev = _chNames[(_chIdx - 1 + n) % n];
        String next = _chNames[(_chIdx + 1) % n];
        textFit(JB_B16, 60, 166, chipX - 60 - 14, prev.c_str(), GRAY4);
        textFit(JB_B16, chipX + chipW + 14, 166, 900 - (chipX + chipW + 14), next.c_str(), GRAY4);
    }
}

void Ui::renderDashboard(const UiStatus &st) {
    _lastStatus = st;
    beginFrame();
    drawStatusBar(st);
    // brand row 0,60,960,82
    blit(22, 78, kLogo50W, kLogo50H, kLogo50);
    vline(22 + kLogo50W + 14, 84, 34, GRAY4, 2);
    blit(22 + kLogo50W + 32, 87, kWord38W, kWord38H, kWord38);
    rect(790, 67, 66, 66, 2, INK);
    gRefresh(823, 100, 17, INK);
    rect(870, 67, 66, 66, 2, INK);
    gGear(903, 100, 15, INK);
    drawChannelBar();

    // fetch active channel data
    ChannelResult r;
    bool have = channels.snapshot(activeId(), r) && r.haveData;
    VulnDoc champ = r.champion;
    _dashHave = have;  // record what we actually draw so poll() ignores taps on empty slots
    _dashCand = have ? min(2, (int)r.candidates.size()) : 0;

    // FEATURED PANEL — human-first, archetype-driven (x22..566, content y190..486).
    if (have) {
        Kind k = kindOf(champ);
        // STATE pill (right-aligned to x566) — worded, archetype-driven, never a fake "NONE".
        bool pillFill = false;
        const char *pill = statePill(champ, k, pillFill);
        int pillX = 566;
        if (pill) {
            pillX = 566 - (textW(JB_B17, pill) + 28);  // right-anchored to x566
            drawPill(pillX, 198, 33, pill, pillFill);
        }
        // KICKER: SOURCE · id · age (bounded so it never runs under the pill; long ids truncate).
        textFit(JB_R16, 22, 214, (pill ? pillX - 22 - 14 : 400), kickerLine(champ, k).c_str(), GRAY3);
        // HERO TITLE — the one dominant glance element. y270 (was 264) so line 1 clears the pill band
        // (y198-231) by a comfortable margin even where its right end runs under the CRITICAL pill.
        drawWrap(JB_X34, 22, 270, 544, 36, 2, champ.title.length() ? champ.title : champ.id, INK);
        // AI SUMMARY — the human "so what", one/two lines (the AI short_description).
        String sum = summaryText(champ);
        if (sum.length()) drawWrap(JB_R17, 22, 330, 544, 22, 2, sum, INK2);
        // METRIC TILES — real numbers only, per archetype (no fabricated 0.0).
        const char *lbl[3];
        String val[3];
        int nt = metricTiles(champ, k, lbl, val);
        const int tx[3] = {23, 198, 373}, tw[3] = {174, 174, 173};
        for (int i = 0; i < nt; i++) {
            rect(tx[i], 372, tw[i], 74, 2, GRAY4);
            text(JB_R15, tx[i] + 16, 392, lbl[i], GRAY3);  // label up: clear the big X42 value below
            text(JB_X42, tx[i] + 14, 440, val[i].c_str(), INK);
        }
        text(JB_R15, 22, 476, "TAP FOR FULL DETAILS", GRAY3);
    } else {
        textAlign(JB_M20, 2, 340, 566, C, "Fetching\xE2\x80\xA6", GRAY3);
    }

    // FEED PANEL — candidates, title-first (x568..960, y190..486).
    vline(568, 190, 296, GRAY5, 2);
    text(JB_B16, 586, 214, "MORE", GRAY3);
    hline(568, 230, 391, GRAY5);
    for (int i = 0; i < 2; ++i) {
        int ry = 230 + i * 128;
        if (i + 1 <= (int)r.candidates.size() && have) {
            const VulnDoc &d = r.candidates[i];
            bool scored = d.cvss > 0 || d.aiScore > 0;
            float score = d.cvss > 0 ? d.cvss : d.aiScore;
            if (scored) {  // real score, top-right + a bar
                String sc = f1(score);
                int sw = textW(JB_X24, sc.c_str());
                text(JB_X24, 941 - sw, ry + 30, sc.c_str(), INK);
            }
            // TITLE FIRST (2-line wrap), then a small source·age kicker.
            drawWrap(JB_R17, 586, ry + 24, scored ? 280 : 355, 22, 2,
                     d.title.length() ? d.title : d.id, INK2);
            String age = relAge(d.published);
            String kick = sourceName(d);
            if (age.length()) kick += " \xC2\xB7 " + age;
            textFit(JB_R15, 586, ry + 74, 355, kick.c_str(), GRAY3);
            if (scored) progressBar(586, ry + 92, 355, 10, score / 10.0f, INK);
        }
        if (i == 0) hline(568, ry + 128, 391, GRAY5);
    }

    // FOOTER — the tab bar conveys position, so just a hint + the champion's published date.
    // Reuse the champion already snapshotted above (`champ`/`have`) — no second deep copy.
    String pub = have ? champ.published.substring(0, 10) : String();
    drawFooter("", pub.length() ? (String("Published ") + pub).c_str() : nullptr);
    text(JB_B20, 22, H - 14, "v" VULNCAST_FW_VERSION, WHITE, INK);  // firmware version, bold/bright
    // Remaining Vulners API credits, centered in the footer. Both parts are bold and light (GRAY4
    // collapses to a near-invisible dark grey on the 2-bit panel's black footer, so the label is GRAY6).
    if (st.creditsKnown) {
        char cr[24];
        formatCredits(st.apiCredits, cr, sizeof(cr));
        int tw = textW(JB_B16, "API CREDITS ") + textW(JB_B16, cr);
        int fx = (W - tw) / 2;
        fx += text(JB_B16, fx, H - 15, "API CREDITS ", GRAY6, INK);
        text(JB_B16, fx, H - 15, cr, WHITE, INK);
    }
}

// Content changes (screen entry, channel rotation, fresh data) do a full 16-gray
// redraw. On e-paper this is the only update that fully clears the previous frame,
// so new data never ghosts on / overlays old data. (Project rule: full refresh on
// page/data change; partial only for tiny in-place values.)
void Ui::showDashboard(const UiStatus &st) {
    _scr = SCR_DASHBOARD;
    renderDashboard(st);
    presentScreen();
}

// Minute clock / sync-age tick: redraw the status bar into the existing dashboard
// framebuffer and present() — the compositor diffs and pushes only the changed
// digits (the rest of the frame is unchanged), so no flash.
void Ui::refreshStatus(const UiStatus &st) {
    if (_scr != SCR_DASHBOARD) return;
    _lastStatus = st;
    drawStatusBar(st);
    present();
}

// Immediate additive acknowledgement of a manual refresh: darken the refresh button interior and
// add an "UPDATING…" caption. Only ADDS ink in one small region, so the compositor emits no flash
// (~0.34 s). The button reverts when the next content redraw lands (fresh data or the busy timeout).
void Ui::showRefreshing() {
    if (_scr != SCR_DASHBOARD) return;
    // "Updating…" right BESIDE the refresh button (right-aligned, ending just left of its x790 edge).
    // Pure additive ink, NO button fill — a mid-gray box ghosts on e-paper when reverted (that was the
    // artifact by the button). Flash-free; it clears on the next content redraw (fresh data bumps
    // updatedMs, or the busy timeout).
    const char *msg = "Updating\xE2\x80\xA6";
    text(JB_B16, 778 - textW(JB_B16, msg), 106, msg, INK2);
    present();
}

// ---- document --------------------------------------------------------------

int Ui::chip(int x, int y, const char *label, bool filled, bool check, bool pencil) {
    int extra = (check || pencil) ? 24 : 0;
    int w = textW(JB_B17, label) + 28 + extra;
    if (filled) fillRect(x, y, w, 37, INK);
    else rect(x, y, w, 37, 2, INK);
    uint8_t fg = filled ? PAPER : INK;
    int tx = x + 14;
    text(JB_B17, tx, y + 25, label, fg, filled ? INK : PAPER);
    if (check) gCheck(x + w - 26, y + 10, 16, fg);
    if (pencil) gPencil(x + w - 26, y + 9, 16, fg);
    return x + w;
}

void Ui::showDocument(const String &channelId, int idx) {
    _scr = SCR_DOCUMENT;
    ChannelResult r;
    VulnDoc d;
    if (channels.snapshot(channelId, r)) {
        if (idx == 0) d = r.champion;
        else if (idx - 1 < (int)r.candidates.size()) d = r.candidates[idx - 1];
    }
    // enrich with the async detail record if it's ready for this id (the detail fetch has fields
    // the search results don't: description, cvssVector, cwe, related/affected/program, kev, ...).
    VulnDoc full;
    bool haveDetail = channels.detailFor(d.id, full);
    if (haveDetail) d.mergeDetail(full);
    if (d.id != _docId) _docScroll = 0;  // opening a different document -> back to the top
    _docId = d.id;
    _docDetailShown = haveDetail;

    Kind k = kindOf(d);

    beginFrame();
    drawHeaderBar("BACK", "DOCUMENT", nullptr);

    // === Unified card layout (every archetype): kicker + state pill, big title, metric tiles raised
    // right under it with CWE/KEV/EXPLOIT chips beside them, an archetype middle (CVE = CVSS vector
    // icons + C/I/A bars; others = pictogram facts), then a scrollable summary/description. ===
    String age = relAge(d.published);
    String kick = sourceName(d);
    if (k == K_BUGBOUNTY && d.bountyState.length()) {
        String st = d.bountyState;
        st.toUpperCase();
        kick += " \xC2\xB7 " + st;
    }
    kick += " \xC2\xB7 " + (age.length() ? age : d.published.substring(0, 10));
    textFit(JB_R16, 26, 90, 430, kick.c_str(), GRAY3);
    int titleMaxW = 585;
    {
        bool fill = false;
        const char *pill = statePill(d, k, fill);
        if (pill) {
            int pw = textW(JB_B17, pill) + 28;
            drawPill(612 - pw, 74, 32, pill, fill);
            titleMaxW = (612 - pw) - 26 - 16;  // keep the title clear of the right-anchored state pill
        }
    }
    // Title: CVE shows its id (1 line); others the headline (up to 2 lines). Tiles hug its bottom.
    int tb = drawWrap(JB_X34, 26, 128, titleMaxW, 38, k == K_VULN ? 1 : 2,
                      d.title.length() ? d.title : d.id, INK);
    const char *lbl[3];
    String val[3];
    int nt = metricTiles(d, k, lbl, val);
    const int tw = 150, tp = 158, th = 70, ty = tb - 14;
    for (int i = 0; i < nt; i++) {
        int tx = 26 + i * tp;
        rect(tx, ty, tw, th, 2, GRAY4);
        text(JB_R15, tx + 12, ty + 22, lbl[i], GRAY3);
        text(JB_X34, tx + 10, ty + 60, val[i].c_str(), INK);
    }
    int cx = 26 + nt * tp + 6;  // CWE / KEV / EXPLOIT chips beside the tiles
    if (d.cwe.length() && cx < 590) cx = chip(cx, ty + 18, d.cwe.c_str(), false, false, false) + 12;
    if (d.kev && cx < 590) cx = chip(cx, ty + 18, "CISA KEV", true, true, false) + 12;
    if ((d.exploited || d.family == "exploit" || d.type.indexOf("exploit") >= 0) && cx < 590)
        cx = chip(cx, ty + 18, "EXPLOIT", true, false, true) + 12;
    // Middle: CVE -> CVSS vector visualization; others -> pictogram facts.
    int vy = (k == K_VULN) ? drawCvssVector(d, ty + th + 18) : drawDocFacts(d, k, ty + th + 14);
    // Scrollable summary / description.
    int sy = vy + 16;
    String sum = summaryText(d);
    sum.trim();  // whitespace-only descriptions (some exploits) -> treat as empty, show the QR fallback
    const char *slabel = k == K_BUGBOUNTY ? "REPORT" : k == K_NEWS ? "ARTICLE" : "SUMMARY";
    if (sum.length()) {
        text(JB_B16, 26, sy, slabel, GRAY3);
        drawDocBody(sum, sy + 26);
    } else if (!_docDetailShown) {
        _docScrollMax = 0;
        text(JB_R19, 26, sy + 26, "Loading full record\xE2\x80\xA6", GRAY3);
    } else {
        _docScrollMax = 0;
        text(JB_R19, 26, sy + 26, "Scan the QR for the full record.", GRAY3);
    }
    // RIGHT column: real QR deep-link + captions (promoted to readable INK/INK2).
    vline(638, 60, 478, INK, 2);
    String qurl = "https://vulners.com/" + (d.type.length() ? d.type : String("cve")) + "/" + d.id;
    qrCode(687, 119, 224, qurl.c_str(), INK);
    textAlign(JB_B20, 638, 372, 320, C, "Scan to read", INK);
    textAlign(JB_B20, 638, 396, 320, C, "the full advisory", INK);
    textAlign(JB_R17, 638, 424, 320, C, "vulners.com", INK2);
    char meta[64];
    snprintf(meta, sizeof(meta), "Published %s", d.published.substring(0, 10).c_str());
    textAlign(JB_R16, 638, 452, 320, C, meta, INK2);
    presentScreen();
}

// Scrollable summary/description pane (CVE document). Wraps the full text and draws a window of lines
// from _docScroll; a ▲/▼ rail appears (and poll() drives it) when the text overflows the pane.
void Ui::drawDocBody(const String &sum, int y0) {
    const int lineH = 26, bottom = 532, x = 26, paneW = 558;
    _docBodyY = y0 - 16;
    std::vector<String> lines = wrapLines(JB_R19, paneW, sum);
    const int total = (int)lines.size();
    const int visible = max(1, (bottom - y0) / lineH + 1);
    _docScrollMax = max(0, total - visible);
    if (_docScroll > _docScrollMax) _docScroll = _docScrollMax;
    if (_docScroll < 0) _docScroll = 0;
    int yy = y0;
    for (int i = _docScroll; i < total && i < _docScroll + visible; ++i) {
        text(JB_R19, x, yy, lines[i].c_str(), INK2);
        yy += lineH;
    }
    if (_docScrollMax > 0) drawScrollRail(596, _docBodyY, 24, bottom - _docBodyY);
}

// ---- settings --------------------------------------------------------------

// Settings Wi-Fi list geometry — shared by showSettings() draw + poll() hit-test (keep in lockstep).
static constexpr int WIFI_VIS = 3, WIFI_Y = 116, WIFI_RH = 58;

void Ui::showSettings() {
    _scr = SCR_SETTINGS;
    beginFrame();
    drawHeaderBar("BACK", "SETTINGS", nullptr);
    vline(488, 60, 372, INK, 2);
    // Wi-Fi column
    text(JB_B22, 22, 92, "WI-FI", INK);
    if (wifiManager.connected()) {
        String ss = wifiManager.lastSsid();
        while (ss.length() > 4 && textW(JB_R17, ss.c_str()) > 300) ss.remove(ss.length() - 1);
        int sw = textW(JB_R17, ss.c_str());
        text(JB_R17, 464 - sw - 20, 92, ss.c_str(), INK2);
        gCheck(464 - 16, 82, 12, INK);
    }
    // network list — WIFI_VIS rows from _wifiScroll; a ▲/▼ rail appears when more networks are in range
    std::vector<WifiNet> nets = wifiManager.networks();
    const int wtotal = (int)nets.size(), wmax = max(0, wtotal - WIFI_VIS);
    if (_wifiScroll > wmax) _wifiScroll = wmax;
    const bool wscroll = wtotal > WIFI_VIS;
    const int wrowW = wscroll ? 420 : 444;      // narrow the rows to make room for the rail
    const int wlockX = 22 + wrowW - 36;
    for (int i = 0; i < WIFI_VIS; ++i) {
        int idx = _wifiScroll + i, ry = WIFI_Y + i * WIFI_RH;
        bool sel = (idx < wtotal) && wifiManager.connected() && nets[idx].ssid == wifiManager.lastSsid();
        if (sel) fillRect(22, ry, wrowW, WIFI_RH, INK);
        gRadio(45, ry + 29, 11, sel, sel ? PAPER : INK);
        if (idx < wtotal) {
            textFit(JB_B20, 72, ry + 37, wrowW - 130, gfx::renderable(nets[idx].ssid).c_str(),
                    sel ? PAPER : INK, sel ? INK : PAPER);  // fold to ASCII for draw; clamp before the lock icon
            if (nets[idx].secure) gLock(wlockX, ry + 20, 16, sel ? PAPER : GRAY4);
            else text(JB_R16, wlockX - 20, ry + 37, "open", sel ? GRAY6 : GRAY4, sel ? INK : PAPER);
        } else if (i == 0 && wtotal == 0) {
            text(JB_R17, 72, ry + 37, "Scanning\xE2\x80\xA6", GRAY4);
        }
        if (i < WIFI_VIS - 1) hline(22, ry + WIFI_RH, wrowW, GRAY5);
    }
    if (wscroll) drawScrollRail(446, WIFI_Y, 38, WIFI_VIS * WIFI_RH);
    // password field + CONNECT
    rect(22, 305, 295, 58, 2, INK);
    text(JB_M22, 40, 342, "\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2", GRAY4);
    fillRect(330, 305, 136, 58, INK);
    textAlign(JB_B22, 330, 342, 136, C, "CONNECT", PAPER, INK);
    text(JB_R16, 22, 396, "Saved automatically", GRAY3);
    // Feeds column — 4 rows from _feedScroll; a ▲/▼ rail appears when there are more than 4 channels
    text(JB_B22, 508, 92, "FEEDS", INK);
    std::vector<Channel> chs = channels.list();
    const int ftotal = (int)chs.size(), fmax = max(0, ftotal - 4);
    if (_feedScroll > fmax) _feedScroll = fmax;
    const bool fscroll = ftotal > 4;
    const int frightX = fscroll ? 886 : 920;   // interval-pill right anchor (leave room for the rail)
    for (int i = 0; i < 4 && _feedScroll + i < ftotal; ++i) {
        const Channel &c = chs[_feedScroll + i];
        int ry = 116 + i * 64;
        gToggle(525, ry + 16, c.active, INK);
        uint8_t nc = c.active ? INK : GRAY4;
        String nm = c.name;
        nm.toUpperCase();
        String pill = intervalLabel(c);
        int pw = textW(JB_B17, pill.c_str()) + 40;  // +40 leaves room for the dropdown arrow
        // Clamp the name to the gap before the interval pill so a long name never overprints it. Name
        // starts at 592 (tight to the toggle); with the slim rail even "VULNERABILITIES" fits.
        textFit(JB_B22, 592, ry + 42, (frightX - pw - 10) - 592, nm.c_str(), nc);
        rect(frightX - pw, ry + 12, pw, 40, 2, nc);
        text(JB_B17, frightX - pw + 14, ry + 38, pill.c_str(), nc);
        gTriDown(frightX - 22, ry + 27, 9, nc);
        if (i < 3 && _feedScroll + i + 1 < ftotal) hline(508, ry + 64, fscroll ? 378 : 431, GRAY5);
    }
    if (fscroll) drawScrollRail(898, 116, 38, 256);
    text(JB_R16, 508, 400, "Toggle & interval save automatically", GRAY3);
    // timezone strip 2,432,960,64
    hline(2, 432, 956, INK, 2);
    text(JB_B22, 22, 470, "TIME ZONE", INK);
    String tzl = timeKeeper.timezoneLabel(), tzo;
    for (const TzOption &z : TimeKeeper::zones())
        if (timeKeeper.timezone() == z.posix) { tzl = z.label; tzo = z.off; }
    if (tzo.length()) tzl += " \xC2\xB7 " + tzo;
    text(JB_R19, 210, 470, tzl.c_str(), INK2);
    rect(824, 443, 112, 43, 2, INK);
    text(JB_B17, 838, 470, "CHANGE", INK);
    gTriRight(915, 458, 12, INK);
    // Footer: RESET DEVICE deliberately parked in the far bottom-left — isolated from every other
    // control (nearest tappable is ~130px above) so it can't be fat-fingered; the confirm gate is the
    // real safety, this is the belt.
    fillRect(0, H - 44, W, 44, INK);
    rect(22, H - 36, 176, 28, 2, WHITE);
    textAlign(JB_B16, 22, H - 15, 176, C, "RESET DEVICE", WHITE, INK);
    int snw = textW(JB_R16, "Saved to device storage (NVS)");
    text(JB_R16, W - 22 - snw, H - 16, "Saved to device storage (NVS)", GRAY4, INK);
    presentScreen();
}

// ---- factory-reset confirm -------------------------------------------------

// Full-frame "Are you sure?" gate before wiping the device. Reached from the Settings RESET button
// (or dev-jump 'Y'). BACK/Cancel returns to Settings; ERASE emits EV_FACTORY_RESET to main.
void Ui::showResetConfirm() {
    _scr = SCR_RESET_CONFIRM;
    beginFrame();
    drawHeaderBar("BACK", "RESET DEVICE", nullptr);
    text(JB_X36, 28, 138, "Reset this device?", INK);
    text(JB_M20, 28, 186, "This erases everything and returns the device to", INK2);
    text(JB_M20, 28, 214, "its out-of-box state:", INK2);
    // Spell out exactly what gets wiped, so the cost is clear before the tap.
    const char *items[] = {"Saved Wi-Fi networks", "Vulners API key", "Feeds & channels",
                           "Time zone & cached data"};
    int ly = 258;
    for (const char *it : items) {
        gDot(42, ly - 6, 3, INK);
        text(JB_R19, 60, ly, it, INK);
        ly += 34;
    }
    text(JB_R17, 28, ly + 10, "You'll set it up again from scratch, like a new device.", GRAY3);

    // Buttons: Cancel (outline, safe default, left) · ERASE EVERYTHING (solid/destructive, right).
    rect(120, 440, 300, 66, 2, INK);
    textAlign(JB_B22, 120, 483, 300, C, "Cancel", INK);
    fillRect(540, 440, 300, 66, INK);
    textAlign(JB_B20, 540, 483, 300, C, "ERASE EVERYTHING", PAPER, INK);
    presentScreen();
}

// Brief ack drawn by main just before ESP.restart(), so the wipe isn't a silent black screen.
void Ui::showErasing() {
    beginFrame();
    textAlign(JB_X36, 0, 280, W, C, "Erasing\xE2\x80\xA6", INK);
    textAlign(JB_R19, 0, 330, W, C, "Restarting into setup", GRAY3);
    presentScreen();
}

// ---- firmware update -------------------------------------------------------

// Reads `updater`. AVAILABLE draws the offer (Update now / Try again tomorrow); the working phases
// draw a label + progress slider (driven by a throttled loop() block in main reading updater.percent()).
void Ui::showUpdate() {
    _scr = SCR_UPDATE;
    beginFrame();
    fillRect(0, 0, W, 58, INK);  // distinct "FIRMWARE UPDATE" header (not the settings BACK bar)
    gTriDown(30, 20, 16, WHITE);
    text(JB_B22, 54, 37, "FIRMWARE UPDATE", WHITE, INK);

    Updater::Phase ph = updater.phase();
    if (ph == Updater::AVAILABLE) {
        text(JB_X36, 28, 138, "Update available", INK);
        String vers = "v" + updater.currentVersion() + "   ->   v" + updater.availableVersion();
        text(JB_X34, 28, 204, vers.c_str(), INK);
        char sub[72];
        snprintf(sub, sizeof(sub), "~%.1f MB  \xC2\xB7  restarts once  \xC2\xB7  about a minute",
                 updater.availableSize() / 1048576.0);
        text(JB_R19, 28, 246, sub, GRAY3);
        text(JB_M20, 28, 300, "Your Wi-Fi, key and settings are kept. If the new", INK2);
        text(JB_M20, 28, 328, "version won\x27t start, it rolls back automatically.", INK2);
        // Update now (solid/primary) · Try again tomorrow (outline).
        fillRect(60, 402, 380, 82, INK);
        textAlign(JB_B24, 60, 454, 380, C, "Update now", PAPER, INK);
        rect(520, 402, 380, 82, 2, INK);
        textAlign(JB_B20, 520, 454, 380, C, "Try again tomorrow", INK);
    } else if (ph == Updater::FAILED) {
        text(JB_X36, 28, 170, "Update failed", INK);
        text(JB_R19, 28, 214, updater.error(), GRAY3);
        rect(28, 262, 300, 70, 2, INK);
        textAlign(JB_B20, 28, 305, 300, C, "Back", INK);
    } else {  // DOWNLOADING / VERIFYING / INSTALLING / DONE — progress slider, no touch actions
        const char *label = ph == Updater::DOWNLOADING ? "Downloading update\xE2\x80\xA6"
                            : ph == Updater::VERIFYING  ? "Verifying signature\xE2\x80\xA6"
                            : ph == Updater::INSTALLING ? "Installing\xE2\x80\xA6"
                            : ph == Updater::DONE       ? "Done \xE2\x80\x94 restarting\xE2\x80\xA6"
                                                        : "Working\xE2\x80\xA6";
        text(JB_X36, 28, 170, label, INK);
        progressBar(28, 240, 904, 44, updater.percent() / 100.0f, INK);
        char pct[48];
        snprintf(pct, sizeof(pct), "%u%%   \xC2\xB7   do not unplug", updater.percent());
        text(JB_R19, 28, 320, pct, GRAY3);
        String foot = "v" + updater.currentVersion() + " -> v" + updater.availableVersion();
        text(JB_R17, 28, 470, foot.c_str(), GRAY4);
    }
    presentScreen();
}

// Post-rollback screen (shown at boot after a failed update was reverted). Reassuring: nothing lost.
void Ui::showUpdateFailed() {
    _scr = SCR_UPDATE_FAILED;
    beginFrame();
    fillRect(0, 0, W, 58, INK);
    text(JB_B22, 30, 37, "UPDATE FAILED", WHITE, INK);
    text(JB_X36, 28, 148, "Update didn\x27t take", INK);
    String pv = updater.pendingVersion();
    String l1 = (pv.length() ? ("v" + pv) : String("The new version")) + " wouldn\x27t start, so the";
    text(JB_M20, 28, 200, l1.c_str(), INK2);
    text(JB_M20, 28, 228, "device restored your previous version. Nothing was lost.", INK2);
    String run = "Now running v" + updater.currentVersion();
    text(JB_X34, 28, 302, run.c_str(), INK);
    text(JB_R19, 28, 346, "It won\x27t retry this version automatically.", GRAY3);
    fillRect(60, 420, 300, 76, INK);
    textAlign(JB_B22, 60, 468, 300, C, "OK", PAPER, INK);
    presentScreen();
}

// Vulners API credits exhausted (a credit-consuming call returned 429, or apiKey/info reported credit
// 0). Cached vulnerabilities keep showing; this screen explains the two ways forward — wait for the
// monthly reset, or upgrade — with a QR straight to the pricing page. Any tap dismisses to the dashboard.
void Ui::showNoCredits() {
    _scr = SCR_NOCREDITS;
    beginFrame();
    fillRect(0, 0, W, 58, INK);
    text(JB_B22, 30, 37, "OUT OF API CREDITS", WHITE, INK);
    // license_type is API text -> fold to safe ASCII (never let a malformed byte reach epdiy's decoder).
    String plan = gfx::renderable(_lastStatus.licenseType);  // "free"/"basic"/"pro"/... ("" if never fetched)
    if (plan.length()) {
        plan.toUpperCase();
        String r = plan + " PLAN";
        text(JB_B20, W - 22 - textW(JB_B20, r.c_str()), 37, r.c_str(), GRAY6, INK);
    }

    // Left column — what happened and the two ways forward.
    text(JB_X36, 28, 126, "Out of API credits", INK);
    text(JB_M20, 28, 174, "Your Vulners API credits for this month", INK2);
    text(JB_M20, 28, 202, "are used up, so new feeds can\x27t be", INK2);
    text(JB_M20, 28, 230, "fetched right now.", INK2);
    text(JB_R16, 28, 288, "WHAT YOU CAN DO", GRAY3);
    gDot(36, 320, 3, INK);
    text(JB_M20, 52, 328, "Wait \xE2\x80\x94 credits refresh next month.", INK2);
    gDot(36, 356, 3, INK);
    text(JB_M20, 52, 364, "Upgrade to a commercial plan for", INK2);
    text(JB_M20, 52, 392, "more monthly credits.", INK2);
    text(JB_R16, 28, 470, "Cached items stay on screen. Tap anywhere to dismiss.", GRAY3);

    // Right column — the hero: a QR straight to the pricing / upgrade page.
    vline(578, 60, 480, INK, 2);
    textAlign(JB_B20, 578, 120, 380, C, "UPGRADE YOUR PLAN", INK);
    qrCode(651, 152, 214, "https://vulners.com/pricing", INK);
    textAlign(JB_R17, 578, 410, 380, C, "vulners.com/pricing", GRAY3);
    presentScreen();
}

// ---- interval / timezone pickers -------------------------------------------

void Ui::showInterval(const String &channelId) {
    _scr = SCR_INTERVAL;
    _ctxCh = channelId;
    Channel cur;
    bool found = false;
    for (const Channel &c : channels.list())
        if (c.id == channelId) { cur = c; found = true; }
    beginFrame();
    String nm = found ? cur.name : String();
    nm.toUpperCase();
    drawHeaderBar("BACK", nm.length() ? nm.c_str() : "UPDATE EVERY", nullptr);
    text(JB_R17, 24, 96, "Applies to this source only", GRAY3);
    int ry = 112, rh = 56;
    rect(24, 112, 913, kIntervalCount * rh + 3, 2, INK);
    for (int i = 0; i < kIntervalCount; ++i) {
        const IntervalPreset &p = kIntervals[i];
        bool sel = found && (p.manual ? cur.manual : (!cur.manual && cur.refreshSec == p.sec));
        if (sel) fillRect(25, ry + 1, 911, rh - 2, INK);
        gRadio(52, ry + rh / 2, 12, sel, sel ? PAPER : INK);
        text(JB_B22, 82, ry + rh / 2 + 7, p.longLbl, sel ? PAPER : INK, sel ? INK : PAPER);
        if (!p.manual && p.sec == 300)  // the recommended default
            textAlign(JB_R17, 400, ry + rh / 2 + 5, 510, R, "recommended", sel ? GRAY6 : GRAY3,
                      sel ? INK : PAPER);
        if (p.manual)
            textAlign(JB_R17, 320, ry + rh / 2 + 5, 590, R, "tap refresh on the home screen",
                      sel ? GRAY6 : GRAY3, sel ? INK : PAPER);
        if (i < kIntervalCount - 1) hline(25, ry + rh, 911, GRAY5);
        ry += rh;
    }
    drawFooter("Tap an option to apply", nullptr);
    presentScreen();
}

// Geometry shared by showTimezone() + its poll() hit-test (keep them in lockstep).
static constexpr int TZ_VIS = 6, TZ_RH = 54, TZ_Y = 112;      // 6 rows of 54px from y112
static constexpr int TZ_LX = 24, TZ_LW = 864;                 // list box x24..888
static constexpr int TZ_RAILX = 894, TZ_RAILW = 43;           // scroll rail x894..937
static constexpr int TZ_UPBOT = 214, TZ_DNTOP = 334;          // rail: [112,214]▲  [218,330]track  [334,436]▼
static constexpr int TZ_TRKY = 218, TZ_TRKH = 112;

// Open the timezone picker scrolled so the currently-selected zone is visible (centered). Called on
// ENTRY only — showTimezone() itself must not re-center, or scroll taps (which re-call it) would snap
// back to the selection.
void Ui::enterTimezone() {
    const std::vector<TzOption> &zs = TimeKeeper::zones();
    const int total = (int)zs.size(), maxScroll = max(0, total - TZ_VIS);
    String cur = timeKeeper.timezone();
    for (int i = 0; i < total; ++i)
        if (cur == zs[i].posix) { _tzScroll = min(maxScroll, max(0, i - TZ_VIS / 2)); break; }
    showTimezone();
}

void Ui::showTimezone() {
    _scr = SCR_TIMEZONE;
    beginFrame();
    drawHeaderBar("BACK", "TIME ZONE", (String("NTP ") + (timeKeeper.synced() ? "synced" : "syncing")).c_str());
    text(JB_R17, 24, 96, "Time syncs over NTP \xE2\x80\x94 scroll and pick your zone.", GRAY3);
    const std::vector<TzOption> &zones = TimeKeeper::zones();
    const int total = (int)zones.size(), maxScroll = max(0, total - TZ_VIS);
    if (_tzScroll > maxScroll) _tzScroll = maxScroll;
    if (_tzScroll < 0) _tzScroll = 0;
    // list box + rows
    rect(TZ_LX, TZ_Y, TZ_LW, TZ_VIS * TZ_RH, 2, INK);
    String curTz = timeKeeper.timezone();
    int ry = TZ_Y;
    for (int i = 0; i < TZ_VIS && _tzScroll + i < total; ++i) {
        const TzOption &z = zones[_tzScroll + i];
        bool sel = curTz == z.posix;
        if (sel) fillRect(TZ_LX + 1, ry + 1, TZ_LW - 2, TZ_RH - 2, INK);
        gRadio(52, ry + TZ_RH / 2, 12, sel, sel ? PAPER : INK);
        textFit(JB_B22, 82, ry + TZ_RH / 2 + 7, 664, z.label, sel ? PAPER : INK, sel ? INK : PAPER);
        textAlign(JB_R17, 758, ry + TZ_RH / 2 + 5, 114, R, z.off, sel ? GRAY6 : GRAY3, sel ? INK : PAPER);
        if (i < TZ_VIS - 1) hline(TZ_LX + 1, ry + TZ_RH, TZ_LW - 2, GRAY5);
        ry += TZ_RH;
    }
    // scroll rail: ▲ page-up button, position track+thumb, ▼ page-down button. Arrows are always solid
    // INK (grey renders near-invisible on the 2-bit panel); the thumb + "X-Y of N" convey position.
    rect(TZ_RAILX, TZ_Y, TZ_RAILW, TZ_UPBOT - TZ_Y, 2, INK);
    gTriUp(TZ_RAILX + TZ_RAILW / 2 - 9, TZ_Y + 34, 18, INK);
    rect(TZ_RAILX, TZ_DNTOP, TZ_RAILW, (TZ_Y + TZ_VIS * TZ_RH) - TZ_DNTOP, 2, INK);
    gTriDown(TZ_RAILX + TZ_RAILW / 2 - 9, TZ_DNTOP + 30, 18, INK);
    fillRect(TZ_RAILX + TZ_RAILW / 2 - 3, TZ_TRKY, 6, TZ_TRKH, GRAY5);  // track
    int thumbH = max(20, TZ_TRKH * TZ_VIS / max(TZ_VIS, total));
    int thumbY = TZ_TRKY + (maxScroll ? (TZ_TRKH - thumbH) * _tzScroll / maxScroll : 0);
    fillRect(TZ_RAILX + TZ_RAILW / 2 - 5, thumbY, 10, thumbH, INK);  // position thumb
    char pos[24];
    snprintf(pos, sizeof(pos), "%d\xE2\x80\x93%d of %d", _tzScroll + 1, min(_tzScroll + TZ_VIS, total), total);
    drawFooter("Zone saves to NVS \xC2\xB7 clock updates on NTP tick", pos);
    presentScreen();
}

// ---- keyboard --------------------------------------------------------------

// Keyboard keysets — rows 2-4 swap between letters and the ?123 symbol layer (row lengths 10/9/7).
// Row 1 is always the number row. Kept in one place so the draw (renderKeyboard) and the hit-test
// (poll) map identical characters.
static const char *kKbRow2(bool sym) { return sym ? "!@#$%^&*()" : "QWERTYUIOP"; }
static const char *kKbRow3(bool sym) { return sym ? "-_=+/\\:;'" : "ASDFGHJKL"; }
static const char *kKbRow4(bool sym) { return sym ? "?.,[]{}" : "ZXCVBNM"; }

void Ui::showKeyboard(const String &ssid) {
    _kbSsid = ssid;
    _kbBuf = "";       // fresh entry
    _kbShift = false;
    _kbSym = false;
    renderKeyboard();
}

// Draw the whole keyboard for the current state — no buffer reset, so the ?123/ABC toggle can
// re-render in place without losing what the user has typed.
void Ui::renderKeyboard() {
    _scr = SCR_KEYBOARD;
    beginFrame();
    fillRect(0, 0, W, 58, INK);
    int x = 22;
    gTriLeft(x, 22, 14, WHITE);
    x += 22;
    x += text(JB_B22, x, 37, "BACK", WHITE, INK) + 22;
    vline(x - 11, 16, 26, GRAY1);
    x += text(JB_R19, x, 37, gfx::renderable(_kbSsid).c_str(), GRAY6, INK) + 12;  // raw _kbSsid is the join target; fold only to draw
    gLock(x, 22, 18, GRAY4);
    // password field 22,76,917,66
    rect(22, 76, 917, 66, 2, INK);
    textFit(JB_M22, 42, 118, 793, maskedPass().c_str(), INK);  // clamp before the SHOW chip (x845)
    rect(845, 87, 74, 43, 2, INK);
    text(JB_B17, 861, 116, "SHOW", INK);
    // keys
    auto key = [&](int kx, int ky, int kw, const char *lbl, bool fill) {
        if (fill) fillRect(kx, ky, kw, 60, INK);
        else rect(kx, ky, kw, 60, 2, INK);
        textAlign(fill ? JB_B22 : JB_M22, kx, ky + 40, kw, C, lbl, fill ? PAPER : INK, fill ? INK : PAPER);
    };
    auto keyC = [&](int kx, int ky, int kw, char ch) {  // single-character key
        char lbl[2] = {ch, 0};
        key(kx, ky, kw, lbl, false);
    };
    const char *r1 = "1234567890", *r2 = kKbRow2(_kbSym), *r3 = kKbRow3(_kbSym), *r4 = kKbRow4(_kbSym);
    for (int i = 0; i < 10; ++i) keyC(18 + i * 93, 156, 85, r1[i]);
    for (int i = 0; i < 10; ++i) keyC(18 + i * 93, 224, 85, r2[i]);
    for (int i = 0; i < 9; ++i) keyC(60 + i * 94, 292, 86, r3[i]);
    key(18, 360, 134, "shift", false);
    for (int i = 0; i < 7; ++i) keyC(158 + i * 93, 360, 85, r4[i]);
    key(809, 360, 134, "del", false);
    key(18, 428, 168, _kbSym ? "ABC" : "?123", false);
    key(193, 428, 486, "space", false);
    key(688, 428, 255, "CONNECT", true);
    drawFooter("Only the field repaints per keypress", "WI-FI");
    presentScreen();
}

String Ui::maskedPass() const {
    if (_kbShow) return _kbBuf;
    String out;
    for (int i = 0; i < (int)_kbBuf.length(); ++i) out += "\xE2\x80\xA2";
    return out;
}

// Redraw the password field into the framebuffer + present() — the compositor
// pushes only the field (the keyboard chrome is identical, so it isn't touched),
// so typing never flashes the keyboard (PIXEL_SPEC screen 4).
void Ui::drawKbField() {
    fillRect(24, 78, 819, 62, PAPER);  // clear the field interior up to the SHOW chip (x845)
    int cw = textFit(JB_M22, 42, 118, 793, maskedPass().c_str(), INK);  // clamp before the SHOW chip
    fillRect(46 + cw, 92, 3, 34, INK);  // caret
    present();
}

// ---- channel nav state -----------------------------------------------------

void Ui::setChannels(const std::vector<String> &ids, const std::vector<String> &names) {
    _chIds = ids;
    _chNames = names;
    if (_chIdx >= (int)_chIds.size()) _chIdx = 0;
}

void Ui::setChannelIndex(int i) {
    int n = (int)_chIds.size();
    if (n == 0) return;
    _chIdx = ((i % n) + n) % n;
}

// Point the dashboard at a channel by id (used by the update-driven feed switch). No-op if unknown
// or already active; returns true only when the active channel actually changed.
bool Ui::setActiveById(const String &id) {
    for (int i = 0; i < (int)_chIds.size(); ++i)
        if (_chIds[i] == id) {
            if (i == _chIdx) return false;
            _chIdx = i;
            return true;
        }
    return false;
}

// ---- touch poll ------------------------------------------------------------

UiEvent Ui::poll() {
    int x, y;
    if (!readTouch(x, y)) {  // no contact -> finger released; re-arm the press edge
        _fingerDown = false;
        return EV_NONE;
    }
    if (_fingerDown) return EV_NONE;         // still the same press (GT911 streams while held)
    if (millis() < _nextTouch) return EV_NONE;  // debounce contact bounce after a release
    _fingerDown = true;
    _nextTouch = millis() + 120;

    if (_scr == SCR_CHILL) {  // any tap wakes it: clean full repaint + restore the normal de-ghost
        gfx::requestFullNext();
        gfx::setAutoDeghost(true);
        return EV_BACK;
    }

    if (_scr == SCR_DASHBOARD) {
        // Easter egg: tap the Vulners logo 5 times in quick succession -> lofi chill-mode screensaver.
        if (x >= 8 && x <= 320 && y >= 62 && y <= 138) {
            if (millis() - _logoTapMs > 1500) _logoTaps = 0;  // the run must be quick taps
            _logoTapMs = millis();
            if (++_logoTaps >= 5) { _logoTaps = 0; showChill(); }
            return EV_NONE;
        }
        if (x >= 790 && x <= 856 && y >= 67 && y <= 133) return EV_REFRESH;
        if (x >= 870 && x <= 936 && y >= 67 && y <= 133) return EV_SETTINGS;
        if (x >= 2 && x <= 68 && y >= 142 && y <= 206) return EV_PREV_CH;
        if (x >= 892 && x <= 958 && y >= 142 && y <= 206) return EV_NEXT_CH;
        if (x >= 2 && x <= 568 && y >= 208 && y <= 486) {
            if (!_dashHave) return EV_NONE;  // no champion drawn -> don't open a blank document
            _lastDocIdx = 0;
            return EV_OPEN_DOC;
        }
        if (x >= 568 && y >= 255 && y <= 486) {
            int idx = (y < 358) ? 1 : 2;  // split at the drawn row separator (ry0+128=358)
            if (idx > _dashCand) return EV_NONE;  // that feed row wasn't drawn
            _lastDocIdx = idx;
            return EV_OPEN_DOC;
        }
        return EV_NONE;
    }

    bool backHit = (x <= 150 && y <= 58);

    if (_scr == SCR_DOCUMENT) {
        if (backHit) return EV_BACK;
        // scrollable summary rail (CVE docs): top half pages up, bottom half pages down
        if (_docScrollMax > 0 && x >= 594 && x <= 632 && y >= _docBodyY && y <= 532) {  // rail is x596..620
            if (y < (_docBodyY + 532) / 2) _docScroll = max(0, _docScroll - _docPage);
            else _docScroll = min(_docScrollMax, _docScroll + _docPage);
            showDocument(activeId(), _lastDocIdx);
        }
        return EV_NONE;
    }

    if (_scr == SCR_SETTINGS) {
        if (backHit) return EV_BACK;
        if (x >= 824 && y >= 432 && y <= 496) { enterTimezone(); return EV_NONE; }
        if (x >= 12 && x <= 210 && y >= 496 && y <= 540) { showResetConfirm(); return EV_NONE; }  // RESET DEVICE (footer, isolated)
        // Wi-Fi list: ▲/▼ rail (when >3), then the 3 visible rows -> open that network's password
        std::vector<WifiNet> nets = wifiManager.networks();
        const int wtotal = (int)nets.size(), wmax = max(0, wtotal - WIFI_VIS);
        const bool wscroll = wtotal > WIFI_VIS;
        if (wscroll && x >= 446 && x <= 484 && y >= WIFI_Y && y < WIFI_Y + WIFI_VIS * WIFI_RH) {
            if (y < WIFI_Y + WIFI_VIS * WIFI_RH / 2) _wifiScroll = max(0, _wifiScroll - WIFI_VIS);
            else _wifiScroll = min(wmax, _wifiScroll + WIFI_VIS);
            showSettings();
            return EV_NONE;
        }
        const int wrowW = wscroll ? 420 : 444;
        if (x >= 22 && x <= 22 + wrowW && y >= WIFI_Y && y < WIFI_Y + WIFI_VIS * WIFI_RH) {
            int idx = _wifiScroll + (y - WIFI_Y) / WIFI_RH;
            if (idx < wtotal) { showKeyboard(nets[idx].ssid); return EV_NONE; }
        }
        // password field OR the CONNECT button -> open the keyboard for the last SSID
        if (x >= 22 && x <= 466 && y >= 305 && y <= 363) { showKeyboard(wifiManager.lastSsid()); return EV_NONE; }
        // Feeds list: ▲/▼ rail (when >4), then the 4 visible rows -> toggle active / open interval
        std::vector<Channel> chs = channels.list();
        const int ftotal = (int)chs.size(), fmax = max(0, ftotal - 4);
        const bool fscroll = ftotal > 4;
        if (fscroll && x >= 898 && x <= 936 && y >= 116 && y < 372) {
            if (y < 244) _feedScroll = max(0, _feedScroll - 4);
            else _feedScroll = min(fmax, _feedScroll + 4);
            showSettings();
            return EV_NONE;
        }
        const int frightX = fscroll ? 886 : 920;  // MUST match the draw anchor (showSettings line ~991)
        for (int i = 0; i < 4 && _feedScroll + i < ftotal; ++i) {
            int ry = 116 + i * 64;
            if (x >= 508 && x <= frightX + 4 && y >= ry && y < ry + 64) {
                const Channel &c = chs[_feedScroll + i];
                if (x >= frightX - 100) { showInterval(c.id); return EV_NONE; }  // interval pill
                String e;
                channels.update(c.id, c.name, c.query, c.refreshSec, !c.active, c.manual, e);
                showSettings();
                return EV_NONE;
            }
        }
        return EV_NONE;
    }

    if (_scr == SCR_RESET_CONFIRM) {
        if (backHit) { showSettings(); return EV_NONE; }                                    // BACK = cancel
        if (x >= 120 && x <= 420 && y >= 440 && y <= 506) { showSettings(); return EV_NONE; }  // Cancel
        if (x >= 540 && x <= 840 && y >= 440 && y <= 506) return EV_FACTORY_RESET;             // ERASE
        return EV_NONE;
    }

    if (_scr == SCR_UPDATE) {
        Updater::Phase ph = updater.phase();
        if (ph == Updater::AVAILABLE) {
            if (x >= 60 && x <= 440 && y >= 402 && y <= 484) return EV_UPDATE_NOW;    // Update now
            if (x >= 520 && x <= 900 && y >= 402 && y <= 484) return EV_UPDATE_LATER;  // Try again tomorrow
        } else if (ph == Updater::FAILED) {
            if (x >= 28 && x <= 328 && y >= 262 && y <= 332) return EV_BACK;  // Back (next tick re-discovers)
        }
        return EV_NONE;  // during download/install: no touch actions (a flash write can't be safely cancelled)
    }

    if (_scr == SCR_UPDATE_FAILED) {
        if (backHit) return EV_BACK;
        if (x >= 60 && x <= 360 && y >= 420 && y <= 496) return EV_BACK;  // OK -> dashboard
        return EV_NONE;
    }

    if (_scr == SCR_NOCREDITS) return EV_BACK;  // any tap dismisses -> dashboard (cached data stays)

    if (_scr == SCR_INTERVAL) {
        if (backHit) { showSettings(); return EV_NONE; }
        if (x >= 24 && x <= 937 && y >= 112 && y < 112 + kIntervalCount * 56) {
            int i = (y - 112) / 56;
            if (i < kIntervalCount) {
                const IntervalPreset &p = kIntervals[i];
                for (const Channel &c : channels.list())
                    if (c.id == _ctxCh) {
                        String e;
                        uint32_t sec = p.manual ? c.refreshSec : p.sec;  // manual keeps the prior cadence
                        channels.update(c.id, c.name, c.query, sec, c.active, p.manual, e);
                        break;
                    }
                showSettings();
            }
        }
        return EV_NONE;
    }

    if (_scr == SCR_TIMEZONE) {
        if (backHit) { showSettings(); return EV_NONE; }
        const std::vector<TzOption> &zs = TimeKeeper::zones();
        const int total = (int)zs.size(), maxScroll = max(0, total - TZ_VIS);
        if (x >= TZ_RAILX && y >= TZ_Y && y < TZ_Y + TZ_VIS * TZ_RH) {  // rail is y112..436 only
            if (y < TZ_UPBOT) _tzScroll = max(0, _tzScroll - TZ_VIS);
            else if (y >= TZ_DNTOP) _tzScroll = min(maxScroll, _tzScroll + TZ_VIS);
            else _tzScroll = max(0, min(maxScroll, (y - TZ_TRKY) * maxScroll / max(1, TZ_TRKH)));
            showTimezone();
            return EV_NONE;
        }
        if (x >= TZ_LX && x <= TZ_LX + TZ_LW && y >= TZ_Y && y < TZ_Y + TZ_VIS * TZ_RH) {
            int i = _tzScroll + (y - TZ_Y) / TZ_RH;
            if (i < total) { timeKeeper.setTimezone(zs[i].posix); showSettings(); }
            return EV_NONE;
        }
        return EV_NONE;
    }

    if (_scr == SCR_KEYBOARD) {
        if (backHit) { showSettings(); return EV_NONE; }
        if (x >= 845 && x <= 919 && y >= 87 && y <= 130) {  // SHOW
            _kbShow = !_kbShow;
            drawKbField();
            return EV_NONE;
        }
        char c = 0;
        bool del = false;
        if (y >= 156 && y < 216 && x >= 18) { int i = (x - 18) / 93; if (i < 10) c = "1234567890"[i]; }
        else if (y >= 224 && y < 284 && x >= 18) { int i = (x - 18) / 93; if (i < 10) c = kKbRow2(_kbSym)[i]; }
        else if (y >= 292 && y < 352 && x >= 60) { int i = (x - 60) / 94; if (i < 9) c = kKbRow3(_kbSym)[i]; }
        else if (y >= 360 && y < 420) {
            if (x < 152) { _kbShift = !_kbShift; return EV_NONE; }   // shift
            else if (x >= 809) del = true;                          // backspace
            else if (x >= 158) { int i = (x - 158) / 93; if (i < 7) c = kKbRow4(_kbSym)[i]; }
        } else if (y >= 428 && y < 488) {
            if (x >= 688) return EV_CONNECT;                        // CONNECT
            else if (x >= 193 && x < 679) c = ' ';                  // space
            else if (x < 186) { _kbSym = !_kbSym; renderKeyboard(); return EV_NONE; }  // ?123 / ABC toggle
        }
        if (del) { if (_kbBuf.length()) { _kbBuf.remove(_kbBuf.length() - 1); drawKbField(); } }
        else if (c) {
            if (c >= 'A' && c <= 'Z' && !_kbShift) c += 32;         // lowercase unless shift
            if (_kbBuf.length() < 63) { _kbBuf += c; drawKbField(); }
        }
        return EV_NONE;
    }
    return EV_NONE;
}
