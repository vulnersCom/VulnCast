// VulnCast "chill mode" — the lofi grayscale idle screensaver (SCR_CHILL): a detailed Bengal cat at a
// desk reading the live CVE feed, a window onto the sea (sun, gulls, a drifting sailboat), a cozy brick
// room. Split out of ui.cpp so the large scene + its animation live in their own module. Everything
// here is a Ui member (state lives in ui.h); the cat is a masked image sprite (assets/cat_sprite.h,
// built by tools/img2sprite.py). Animated cells repaint via the per-pixel present() (see gfx.{h,cpp}).
#include "ui.h"

#include <math.h>
#include <time.h>

#include "assets/cat_sprite.h"
#include "channels.h"
#include "fonts/jbfonts.h"
#include "gfx.h"
#include "timekeeper.h"

using namespace gfx;

namespace {
// Current wall-clock hour/minute in the configured timezone (tzset() is applied globally by the
// TimeKeeper). Returns false and leaves the outputs untouched until SNTP has set a plausible clock.
bool localHourMin(int &hh, int &mm) {
    if (!timeKeeper.synced()) return false;
    time_t t = timeKeeper.now();
    struct tm lt;
    localtime_r(&t, &lt);
    hh = lt.tm_hour;
    mm = lt.tm_min;
    return true;
}

// Demo fallback so the monitor is never empty before the first real fetch (buildChillFeed pads to 6).
const char *kChillFeed[] = {"CVE-2026-58644", "CVE-2026-41991", "CVE-2026-33127",
                            "CVE-2026-50219", "CVE-2026-29008", "CVE-2026-11732"};
const char *kChillScore[] = {"9.8", "7.5", "8.1", "6.4", "9.1", "5.3"};
constexpr int kChillFeedN = 6;
constexpr int kCatX = 174;  // cat sprite left edge (paws land on the desk at y432, left of the monitor)
// Window geometry (shared by showChill + drawChillWindow).
constexpr int WX = 600, WY = 64, WW = 330, WH = 300, WIX = WX + 12, WIY = WY + 12, WIW = WW - 24,
              WIH = WH - 24, WHORIZON = WIY + 120;
}  // namespace

// Two-hump seagull silhouette, tiny; `lift` = wingtip height (animate it to flap the wings).
static void drawGull(int x, int y, uint8_t c, int lift) {
    line(x - 7, y, x - 3, y - lift, c);
    line(x - 3, y - lift, x, y, c);
    line(x, y, x + 3, y - lift, c);
    line(x + 3, y - lift, x + 7, y, c);
}

// The window: a fully dithered seascape with sun, glimmer path, gulls, a hazy far shore and a drifting
// sailboat — the atmospheric heart of the scene. Frame + mullions go on top (they clip it).
void Ui::drawChillWindow() {
    const int sunX = WIX + WIW - 74, sunY = WIY + 40;
    int skyH = WHORIZON - WIY, seaH = WIY + WIH - WHORIZON;
    // Sky: soft haze, grayest up top and lightest at the horizon (atmospheric perspective).
    vGradient(WIX, WIY, WIW, skyH, GRAY6, PAPER);
    gDot(sunX, sunY, 20, GRAY6);           // sun: faint halo + bright disc
    gDot(sunX, sunY, 13, PAPER);
    gDot(WIX + 54, WIY + 34, 15, PAPER);   // soft white clouds against the hazy upper sky
    gDot(WIX + 78, WIY + 29, 21, PAPER);
    gDot(WIX + 102, WIY + 36, 14, PAPER);
    gDot(WIX + 150, WIY + 22, 11, PAPER);
    drawGull(WIX + 128, WIY + 54, INK, _gullUp ? 5 : 1);   // distant gulls, wings out of phase
    drawGull(WIX + 150, WIY + 62, INK, _gullUp ? 1 : 5);
    drawGull(WIX + 168, WIY + 50, INK, _gullUp ? 5 : 1);
    // Hazy far shoreline: low light hills sitting on the horizon (distant = light, low-contrast).
    for (int hx = WIX + 8; hx < WIX + WIW - 10; hx += 46)
        gDot(hx, WHORIZON + 2, 16, GRAY6);
    ditherRect(WIX, WHORIZON - 6, WIW, 10, PAPER, GRAY6, 8);  // haze band over the shore
    int lx = WIX + 44, ly = WHORIZON - 1;                     // a little lighthouse on the far shore
    fillRect(lx - 4, ly - 22, 9, 22, PAPER);
    rect(lx - 4, ly - 22, 9, 22, 1, INK);
    hline(lx - 4, ly - 15, 9, INK);
    hline(lx - 4, ly - 8, 9, INK);
    fillRect(lx - 5, ly - 28, 11, 6, INK);   // lantern room
    gDot(lx, ly - 30, 2, INK);               // finial
    // Sea: lighter at the horizon, deepening toward the foreground.
    vGradient(WIX, WHORIZON, WIW, seaH, GRAY6, GRAY4);
    for (int r = 0; r < 7; r++) {  // wave glints — brighter near the horizon
        int yy = WHORIZON + 8 + r * 17;
        uint8_t tone = (r < 3) ? PAPER : GRAY6;
        for (int xx = WIX + 8 + ((r * 17) % 30); xx < WIX + WIW - 10; xx += 44) hline(xx, yy, 9, tone);
    }
    for (int r = 0; r < 7; r++) {  // sun-glimmer path: a broadening bright column under the sun
        int yy = WHORIZON + 6 + r * 17, hw = 6 + r * 3;
        ditherRect(sunX - hw, yy, hw * 2, 4, GRAY5, PAPER, 9);
    }
    int bx = _boatX, by = WHORIZON - 3;  // Bermuda sloop; every stroke clipped to the pane, never spills
    auto chl = [&](int x, int y, int w, uint8_t col) {
        int x0 = x < WIX ? WIX : x, x1 = (x + w > WIX + WIW) ? WIX + WIW : x + w;
        if (x1 > x0) hline(x0, y, x1 - x0, col);
    };
    // Hull + tall mast + big triangular mainsail (aft of the mast) + jib (fore) — stamped at an offset
    // so we can lay a white wake, then the ink.
    auto boat = [&](uint8_t col, int ox, int oy) {
        int mx = bx + 22 + ox, mtop = by - 54 + oy, deck = by + oy, boom = deck - 4;
        for (int i = 0; i <= 11; i++) chl(bx - 2 + ox + i * 2, deck + i, 52 - i * 4, col);  // hull
        if (mx >= WIX && mx + 1 < WIX + WIW) vline(mx, mtop, deck - mtop, col, 2);           // mast
        int mh = boom - mtop;                                                                // mainsail (aft)
        for (int y = mtop; y <= boom; y++) {
            int w = (y - mtop) * (mx - (bx - 10 + ox)) / mh;
            if (w > 0) chl(mx - w, y, w, col);
        }
        int jt = mtop + 16, jb = deck - 2, jh = jb - jt;                                      // jib (fore)
        for (int y = jt; y <= jb; y++) {
            int w = (y - jt) * ((bx + 48 + ox) - (mx + 2)) / jh;
            if (w > 0) chl(mx + 2, y, w, col);
        }
    };
    if (bx + 48 > WIX && bx - 12 < WIX + WIW) {  // any part visible
        // White "wake": stamp the silhouette offset in 8 directions so every moving edge is INK<->PAPER
        // (the panel LUT's crisp 5-pass case) instead of INK->dark-sea (a 1-push ghost trail).
        const int off[8][2] = {{-2, 0}, {2, 0}, {0, -2}, {0, 2}, {-2, -2}, {2, -2}, {-2, 2}, {2, 2}};
        for (auto &o : off) boat(PAPER, o[0], o[1]);
        boat(INK, 0, 0);
    }
    rect(WX, WY, WW, WH, 6, INK);  // panoramic frame only — no mullions
}

// Snapshot real CVEs from the channels for the monitor feed (called once on chill entry); the demo
// list is the fallback so the screen is never empty before the first fetch.
void Ui::buildChillFeed() {
    _chillIds.clear();
    _chillScores.clear();
    for (auto &ch : channels.list()) {
        ChannelResult r;
        if (!channels.snapshot(ch.id, r)) continue;
        VulnDoc pool[1 + 8];
        int np = 0;
        if (r.champion.id.length()) pool[np++] = r.champion;
        for (auto &c : r.candidates) {
            if (np >= (int)(sizeof(pool) / sizeof(pool[0]))) break;
            pool[np++] = c;
        }
        for (int i = 0; i < np && (int)_chillIds.size() < 12; i++) {
            const VulnDoc &d = pool[i];
            if (!d.id.startsWith("CVE-")) continue;  // keep the monitor a clean CVE feed
            bool dup = false;
            for (auto &e : _chillIds)
                if (e == d.id) { dup = true; break; }
            if (dup) continue;
            char sc[8];
            if (d.cvss > 0) snprintf(sc, sizeof(sc), "%.1f", d.cvss);
            else snprintf(sc, sizeof(sc), "--");
            _chillIds.push_back(d.id);
            _chillScores.push_back(String(sc));
        }
    }
    for (int i = 0; i < kChillFeedN && (int)_chillIds.size() < 6; i++) {  // pad if the feed is sparse
        _chillIds.push_back(kChillFeed[i]);
        _chillScores.push_back(kChillScore[i]);
    }
}

// The monitor's screen interior: a scrolling CVE list with one highlighted "current" row.
void Ui::drawChillMonitor() {
    const int sx = 372, sy = 208, sw = 201, sh = 176;
    int n = (int)_chillIds.size();
    if (n == 0) return;
    fillRect(sx, sy, sw, sh, PAPER);
    fillRect(sx, sy, sw, 22, INK);
    text(JB_B14, sx + 8, sy + 16, "VULNERS \xC2\xB7 CVE FEED", WHITE, INK);
    int ry = sy + 42, rh = 26;
    for (int i = 0; i < 5; i++) {
        int idx = (_feedTop + i) % n;
        bool sel = (i == 1);  // the row the cat is "reading"
        if (sel) fillRect(sx + 4, ry - 17, sw - 8, rh - 3, INK);
        uint8_t fg = sel ? WHITE : INK;
        int bg = sel ? INK : -1;
        text(JB_R14, sx + 10, ry, _chillIds[idx].c_str(), fg, bg);
        int scw = textW(JB_B14, _chillScores[idx].c_str());
        text(JB_B14, sx + sw - 12 - scw, ry, _chillScores[idx].c_str(), fg, bg);
        ry += rh;
    }
}

// The room wall: brick with soft dark-gray mortar over a gentle top-down light gradient (a touch of
// shadow up by the ceiling, warming toward the desk) — depth without busy-ness. Running-bond courses,
// with ~1 in 4 bricks nudged a hair darker for texture.
void Ui::drawBrickWall(int x, int y, int w, int h) {
    vGradient(x, y, w, h, GRAY6, PAPER);  // ambient: dimmer ceiling -> lighter toward the desk
    const int bh = 22, bw = 44;
    for (int ry = y, row = 0; ry < y + h; ry += bh, row++) {
        int off = (row & 1) ? bw / 2 : 0;                // running bond
        for (int bx = x + off, k = 0; bx < x + w; bx += bw, k++)
            if (((row * 3 + k) % 6) == 0)                // sparse, subtle per-brick shading
                ditherRect(bx + 2, ry + 2, bw - 3, bh - 3, PAPER, GRAY6, 3);
        hline(x, ry, w, GRAY5);                          // mortar course
        for (int bx = x + off; bx <= x + w; bx += bw) vline(bx, ry, bh, GRAY5);
    }
}

// Fairy lights draped across the top of the room. On a light wall the bulbs read as dark beads with a
// glass glint (a lit white core would vanish on white), which still says "cozy string lights".
void Ui::drawStringLights() {
    const int spans[][2] = {{160, 430}, {430, 700}, {700, 946}};
    const int y0 = 20, sag = 30;
    for (auto &s : spans) {
        int px = s[0], py = y0;
        for (int i = 1; i <= 26; i++) {
            float t = i / 26.0f;
            int xx = s[0] + (int)((s[1] - s[0]) * t);
            int yy = y0 + (int)(sag * 4 * t * (1 - t));  // parabolic droop
            line(px, py, xx, yy, INK);
            px = xx;
            py = yy;
        }
        for (int i = 1; i < 6; i++) {
            float t = i / 6.0f;
            int xx = s[0] + (int)((s[1] - s[0]) * t);
            int yy = y0 + (int)(sag * 4 * t * (1 - t));
            vline(xx, yy, 5, INK);          // hanger
            gDot(xx, yy + 8, 4, INK);       // bulb bead
            gDot(xx, yy + 8, 2, GRAY6);     // glass
            setPx(xx - 1, yy + 6, PAPER);   // glint
        }
    }
}

// A small framed landscape on the wall — a tiny dithered sky + distant mountains, tilted-free (cozy).
void Ui::drawFramedArt(int x, int y) {
    const int w = 118, h = 92;
    fillRect(x - 3, y - 3, w + 6, h + 6, INK);   // frame
    fillRect(x, y, w, h, PAPER);                 // matte
    int ix = x + 8, iy = y + 8, iw = w - 16, ih = h - 16, gh = iy + ih * 3 / 5;
    vGradient(ix, iy, iw, gh - iy, GRAY6, PAPER);          // sky (haze at horizon)
    gDot(ix + iw - 18, iy + 13, 7, GRAY6);                 // sun
    gTriUp(ix + 6, gh - 22, 37, GRAY4);                    // distant mountains (soft)
    gTriUp(ix + 32, gh - 30, 50, GRAY4);
    gTriUp(ix + 62, gh - 20, 34, GRAY4);
    ditherRect(ix, gh, iw, ih - (gh - iy), GRAY5, GRAY4, 7);  // foreground land
    hline(ix, gh, iw, INK);                                // horizon
    gDot(x + w / 2, y - 8, 2, INK);                        // hanging nail
}

// Coffee mug + two wispy steam columns (steam = faint stipple, never a solid shape).
void Ui::drawMugSteam(int x, int baseY) {
    const int w = 30, h = 30;
    int mx = x, my = baseY - h;
    fillRect(mx, my, w, h, GRAY6);                         // body (light)
    ditherRect(mx + w * 2 / 3, my + 3, w / 3, h - 4, GRAY6, GRAY4, 8);  // shaded side
    fillRect(mx, my, w, 4, INK);                           // coffee surface / rim
    vline(mx, my, h, INK);
    vline(mx + w - 1, my, h, INK);
    hline(mx, my + h - 1, w, INK);
    rect(mx + w - 1, my + 9, 12, 14, 3, INK);              // handle
    for (int s = 0; s < 2; s++) {                          // steam wisps
        int sx = mx + 10 + s * 11;
        for (int k = 0; k < 6; k++) {
            int wob = ((k + s) & 1) ? 2 : -2;
            gDot(sx + wob, my - 4 - k * 5, 1, GRAY6);
        }
    }
}

// A small potted plant sitting on the desk (silhouette leaves + a light pot).
void Ui::drawDeskPlant(int x, int baseY) {
    const int pw = 26, ph = 20;
    int px = x, py = baseY - ph;
    for (int i = 0; i < ph; i++) {                         // pot: trapezoid, dark rim + light body
        int inset = i * 3 / ph;
        hline(px + inset, py + i, pw - 2 * inset, i < 4 ? INK : GRAY6);
    }
    rect(px, py, pw, ph, 1, INK);
    int cx = px + pw / 2, base = py + 1;
    const int blades[][2] = {{-15, -28}, {-8, -40}, {0, -47}, {8, -40}, {15, -28}};
    for (auto &b : blades) {
        line(cx, base, cx + b[0], base + b[1], INK);
        line(cx + 1, base, cx + b[0] + 1, base + b[1], INK);  // thicken
        gDot(cx + b[0], base + b[1], 2, INK);                 // leaf tip
    }
}

// A round wall clock showing a real time. 12 o'clock is up; angles run clockwise. The opaque face
// (rim + PAPER fill) fully overwrites the previous hands, so re-drawing in place each minute is clean.
void Ui::drawWallClock(int cx, int cy, int r, int hour, int minute) {
    gDot(cx, cy, r + 2, INK);        // rim
    gDot(cx, cy, r, PAPER);          // face
    gDot(cx, cy - r + 3, 1, INK);    // 12/3/6/9 ticks
    gDot(cx, cy + r - 3, 1, INK);
    gDot(cx - r + 3, cy, 1, INK);
    gDot(cx + r - 3, cy, 1, INK);
    constexpr float kPi = 3.14159265f;
    float ma = minute * (kPi / 30.0f);                        // minute hand: 6 deg/min
    float ha = ((hour % 12) + minute / 60.0f) * (kPi / 6.0f);  // hour hand: 30 deg/hr + minute creep
    int ml = r - 5, hl = r / 2;                                // minute long, hour short
    line(cx, cy, cx + (int)roundf(ml * sinf(ma)), cy - (int)roundf(ml * cosf(ma)), INK);
    line(cx, cy, cx + (int)roundf(hl * sinf(ha)), cy - (int)roundf(hl * cosf(ha)), INK);
    gDot(cx, cy, 2, INK);            // hub
}

// A floating shelf lined with a few books (varied heights + tones) and a small trinket.
void Ui::drawShelf(int x, int y, int w) {
    fillRect(x, y, w, 5, INK);                    // plank
    fillRect(x + 8, y + 5, 3, 5, GRAY1);          // brackets
    fillRect(x + w - 11, y + 5, 3, 5, GRAY1);
    const int hs[] = {32, 26, 34, 24, 30, 22};
    const uint8_t tone[] = {INK, GRAY5, GRAY4, INK, GRAY5, GRAY4};
    int bx = x + 7;
    for (int i = 0; i < 6 && bx < x + w - 24; i++) {
        int bw = 10 + (i % 2) * 3, bh = hs[i];
        fillRect(bx, y - bh, bw, bh, tone[i]);
        rect(bx, y - bh, bw, bh, 1, INK);         // spine outline
        hline(bx + 2, y - bh + 4, bw - 4, INK);   // a title band
        bx += bw + 2;
    }
    gDot(x + w - 13, y - 7, 6, GRAY4);            // a little pot/trinket at the end
    rect(x + w - 19, y - 7, 12, 7, 1, INK);
}

// A hanging planter: ceiling hook, macrame strings, a leafy mound spilling over the pot, trailing vines.
void Ui::drawHangingPlant(int x, int topY, int dropH) {
    gDot(x, topY, 2, INK);                        // ceiling hook
    line(x, topY, x - 12, topY + 20, GRAY1);      // strings from hook to the pot corners
    line(x, topY, x + 12, topY + 20, GRAY1);
    fillRect(x - 13, topY + 20, 26, 14, GRAY5);   // pot
    rect(x - 13, topY + 20, 26, 14, 1, INK);
    gDot(x, topY + 16, 9, INK);                   // foliage mound spilling over the rim
    gDot(x - 9, topY + 19, 7, INK);
    gDot(x + 9, topY + 19, 7, INK);
    gTriUp(x - 5, topY + 4, 12, INK);             // leaf tips poking up
    gTriUp(x - 15, topY + 11, 10, INK);
    gTriUp(x + 6, topY + 5, 11, INK);
    gTriUp(x + 13, topY + 12, 9, INK);
    for (int v = -1; v <= 1; v++) {               // trailing vines with leaf dots
        int vx = x + v * 9;
        for (int k = 0; k < dropH; k += 7) {
            int wob = (((k / 7) + v) & 1) ? 3 : -3;
            gDot(vx + wob, topY + 36 + k, 2, INK);
        }
    }
}

// A soft dithered contact shadow grounding an object on the desk (darkest under its centre).
void Ui::drawContactShadow(int cx, int baseY, int rw) {
    for (int i = 0; i < 5; i++) {
        int ww = rw * (5 - i) / 5;
        int mix = 12 - i * 3;
        if (ww > 2) ditherRect(cx - ww, baseY + i * 2, 2 * ww, 2, GRAY6, INK, mix < 2 ? 2 : mix);
    }
}

// The cat is a masked, dithered image SPRITE (tools/img2sprite.py from a reference photo) — a real
// detailed sitting kitten, not geometry. blitMask cuts its background out so it sits on the brick
// behind a thin white halo; placed with its paws on the desk, just left of the monitor.
// The cat is ONE complete frame per (head, tail) combo — no layered parts, so no seams/holes/doubling.
// Head and tail still animate independently: they index the same table on their own timers.
void Ui::drawCatAtDesk() {
    int hp = _headPose < 0 ? 0 : (_headPose >= kCatHeadFrames ? kCatHeadFrames - 1 : _headPose);
    int tp = _tailPose < 0 ? 0 : (_tailPose >= kCatTailFrames ? kCatTailFrames - 1 : _tailPose);
    blitMask(kCatX, 432 - kCatH, kCatW, kCatH, kCatSprite[hp * kCatTailFrames + tp]);
}

// "now watching" banner under the scene — tracks the CVE the cat is currently reading.
void Ui::drawChillCaption() {
    int n = (int)_chillIds.size();
    if (n == 0) return;
    int idx = (_feedTop + 1) % n;  // the highlighted row on the monitor
    // Big enough that the id (bounded to 64) + "\xC2\xB7" separators + score NEVER truncate — a
    // boundary-truncated "\xC2\xB7" would leave a lone lead byte that hangs epdiy's decoder. The id is
    // already folded to ASCII at parse, so with no truncation the whole string is well-formed.
    char buf[128];
    snprintf(buf, sizeof(buf), "now watching \xC2\xB7 %s \xC2\xB7 score %s", _chillIds[idx].c_str(),
             _chillScores[idx].c_str());
    fillRect(0, 488, W, 26, PAPER);
    textAlign(JB_R16, 0, 506, W, C, buf, GRAY3);
}

void Ui::showChill() {
    _scr = SCR_CHILL;
    _chillTick = 0;
    _feedTop = 0;
    _boatX = WIX;  // start at the window's left edge: visible on entry, then drifts out (gap, repeat)
    buildChillFeed();          // snapshot real CVEs for the monitor
    gfx::requestFullNext();    // seat the whole scene with one clean full paint (no dashboard ghost under it)
    beginFrame();              // (re-enables the normal de-ghost) ...
    gfx::setAutoDeghost(false);  // ... then disable it: no periodic whole-screen flash while idling here
    drawBrickWall(6, 6, W - 12, 424);
    drawStringLights();
    drawFramedArt(70, 96);
    int hh = 10, mm = 10;                 // decorative 10:10 until SNTP has synced
    bool haveTime = localHourMin(hh, mm);
    drawWallClock(258, 128, 24, hh, mm);
    drawShelf(58, 250, 112);
    drawHangingPlant(444, 66, 74);
    drawChillWindow();
    fillRect(WX - 6, WY + WH, WW + 12, 11, GRAY6);   // windowsill
    hline(WX - 6, WY + WH, WW + 12, INK);
    hline(WX - 6, WY + WH + 10, WW + 12, INK);
    fillRect(6, 430, W - 12, 6, INK);                // desk edge
    ditherRect(6, 436, W - 12, 36, GRAY6, GRAY5, 5);  // desk surface (subtle grain)
    drawContactShadow(472, 432, 132);                // shadows first, objects on top (cat uses a halo)
    drawContactShadow(624, 432, 30);
    drawContactShadow(52, 432, 26);
    fillRect(460, 402, 26, 22, INK);                 // monitor stand + foot
    fillRect(435, 424, 76, 8, INK);
    fillRect(354, 190, 237, 212, INK);               // monitor block (black bezel)
    gDot(472, 200, 2, WHITE);                        // webcam
    drawChillMonitor();
    rect(276, 416, 84, 12, 2, INK);                  // keyboard
    for (int kx = 284; kx < 356; kx += 10) vline(kx, 418, 8, GRAY5);
    drawMugSteam(610, 430);
    drawDeskPlant(40, 430);
    gfx::savePlate();     // snapshot the room WITHOUT the cat; the tail-flick restores this under the cat
    drawCatAtDesk();
    text(JB_B22, 28, 50, timeKeeper.localTime().c_str(), INK);  // real HH:MM (or "--:--" until synced)
    _lastClockMin = haveTime ? mm : -1;                         // seed the whole-minute update tracker
    drawChillCaption();
    presentScreen();
}

// Advance the looping cells at a calm cadence, then ONE per-pixel partial for whatever changed. In
// 2BPP FastEPD's partialUpdate drives only the pixels that differ from the panel (statics = 0 V,
// untouched) with no flash; the periodic whole-screen de-ghost is off in chill, and every moving
// sprite carries a white edge so its transitions are the panel's crisp INK<->PAPER case (no trail).
// Called ~every 1.5 s from loop(); most ticks redraw nothing.
void Ui::animateChill() {
    if (_scr != SCR_CHILL) return;
    _chillTick++;
    bool boatTick = (_chillTick % 3 == 0);  // drift the sailboat every ~4.5 s
    bool gullTick = (_chillTick % 2 == 0);  // flap the gulls' wings every ~3 s
    bool dirty = false;

    if (boatTick) {
        _boatX += 16;
        if (_boatX - 12 > WIX + WIW) _boatX = WIX - 52;  // whole sloop exited right -> re-enter from left
    }
    if (gullTick) _gullUp = !_gullUp;
    if (boatTick || gullTick) {
        drawChillWindow();  // redraws the window deterministically (its own restore); boat + gulls move
        dirty = true;
    }

    // Clocks: on its OWN timer, refresh on the whole-minute boundary (independent of the other cells).
    // The digital HH:MM is erased back to clean brick from the plate; the analog's opaque face overwrites
    // its old hands. This fires on the first tick after the minute rolls over (within one ~1.5 s tick).
    int hh, mm;
    if (localHourMin(hh, mm) && mm != _lastClockMin) {
        _lastClockMin = mm;
        gfx::restoreRect(20, 24, 120, 38);  // clean brick+lights under the digital time (no cat/clock here)
        char clk[8];
        snprintf(clk, sizeof(clk), "%02d:%02d", hh, mm);
        text(JB_B22, 28, 50, clk, INK);
        drawWallClock(258, 128, 24, hh, mm);
        dirty = true;
    }

    // Cat: tail and head animate on INDEPENDENT timers. When either advances, restore the room under
    // the cat from the plate and re-composite; present() then drives only the pixels that changed.
    bool catDirty = false;
    if (_chillTick % 2 == 0 && kCatTailFrames > 1) {  // tail flick every ~3 s
        static const int tseq[4] = {1, 0, 1, 2};      // rest, sway left, rest, sway right
        _tailPose = tseq[(_chillTick / 2) % 4];
        catDirty = true;
    }
    if (_chillTick % 5 == 0 && kCatHeadFrames > 1) {  // head turn to the monitor + back every ~7.5 s
        static const int hseq[4] = {0, 1, 2, 1};      // neutral -> partial -> at the monitor -> back
        _headPose = hseq[(_chillTick / 5) % 4];
        catDirty = true;
    }
    if (catDirty) {
        gfx::restoreRect(kCatX, 432 - kCatH, kCatW, kCatH);
        drawCatAtDesk();
        dirty = true;
    }

    // Feed: re-snapshot live CVEs every ~60 s (rotate the data), scroll a row every ~9 s.
    if (_chillTick % 40 == 0) {
        buildChillFeed();
        if (!_chillIds.empty()) _feedTop %= (int)_chillIds.size();
    }
    if (_chillTick % 6 == 0 && !_chillIds.empty()) _feedTop = (_feedTop + 1) % (int)_chillIds.size();
    if ((_chillTick % 6 == 0 || _chillTick % 40 == 0) && !_chillIds.empty()) {
        drawChillMonitor();
        drawChillCaption();
        dirty = true;
    }

    if (dirty) presentScreen();  // per-pixel partial: only the changed sprite pixels are driven
}
