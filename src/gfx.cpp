#include "gfx.h"

#include <FastEPD.h>
#include <qrcode.h>
#include <string.h>

#include "board_v24.h"

namespace gfx {

namespace {
uint8_t *_fb = nullptr;
uint8_t *_shadow = nullptr;  // last state pushed to the panel (for damage diffing)
uint32_t _lastGc = 0;
bool _hasShadow = false;
RepaintMode _rmode = RP_SMART;
uint32_t _lastMs = 0;         // duration of the last panel update
char _lastKind[96] = "none";  // description of the last panel update + flash profile (for debug)
bool _forceFullNext = false;  // de-ghost due -> next present() does a full clean paint
int _ghostBudget = 0;         // weighted residue since the last full clear
TaskHandle_t _guardTask = nullptr;  // suspended for the duration of each panel transfer
int _postMismatch = -1;       // shadow-vs-fb bytes measured on the UI thread right after
                              // the last present (authoritative; MUST be 0 if the
                              // compositor pushed every change). A live cross-core scan
                              // races the UI redraw and is meaningless.
constexpr int kBytesPerRow = W / 2;
constexpr int kFbBytes = (W / 2) * H;

// ---- de-ghost cadence ------------------------------------------------------
// FastEPD flash-free partials leave a little residue each time; sweep it with a periodic full
// de-ghost after this many partials, or this long since the last full clear (whichever comes first).
constexpr int GHOST_MAX = 18;
constexpr uint32_t GC_MS = 600000UL;
}  // namespace

// Panel driver = FastEPD (drives our V2.4 shift-register board on S3). epdiy is used only as a
// software rasterizer for fonts + framebuffer primitives (see begin()); it never touches hardware.
static inline void guardSuspend();  // defined below — suspend the fetch task around a panel transfer
static inline void guardResume();
namespace {
V24Epaper epaper;

// A no-op epdiy board: epd_init() with it sets epd_width()/epd_height() = 960/540 (needed by the
// epdiy font/primitive helpers) WITHOUT initializing any panel hardware. FastEPD owns the panel.
void dummyInit(uint32_t, const EpdInitConfig*) {}
void dummyDeinit() {}
void dummyCtrl(epd_ctrl_state_t*, const epd_ctrl_state_t* const) {}
void dummyPower(epd_ctrl_state_t*) {}
float dummyTemp() { return 20; }
void dummyVcom(int) {}
EpdBoardDefinition dummy_board = {};  // filled in begin() (field order varies; set imperatively)

// STAGE 2: render in FastEPD 2-bit mode (4 levels) so same-screen updates use the FLASH-FREE
// partialUpdate. Map our epdiy 4bpp design tokens (nibbles 1..15) to 2-bit levels: 0=black,
// 1=dark gray, 2=light gray, 3=white. INK/INK2 -> black; muted labels -> dark gray; hairlines /
// off-state -> light gray; PAPER -> white.
// FastEPD's 2-bit grays get only ~1 black push (levels 1/2 render very faint), so push information
// content to black: INK/INK2 + muted labels (GRAY1..3) -> BLACK (crisp), off-state/hairlines
// (GRAY4/5) -> dark gray, GRAY6 (light text on black bars) -> light gray, PAPER -> white.
static const uint8_t kTo2bpp[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 3 };

// Convert _fb (epdiy 4bpp: 2px/byte, even-x = LOW nibble) into FastEPD's currentBuffer (2bpp:
// 4px/byte, MSB-first — pixel0 -> bits 6-7 .. pixel3 -> bits 0-1). Only rows [y0,y1] are converted:
// a partial repaint changes just those rows, and unchanged rows still hold the correct 2bpp bits
// from the paint that last touched them (the diff always finds every changed row), so converting the
// whole 130 KB buffer for a small update is wasted work.
void convert2bpp(int y0 = 0, int y1 = H - 1) {
    uint8_t *dst = epaper.currentBuffer();
    if (!dst) return;
    const int obpr = W / 4;  // 240 output bytes per row
    for (int y = y0; y <= y1; ++y) {
        const uint8_t *src = _fb + y * kBytesPerRow;  // 480 input bytes/row (4bpp)
        uint8_t *o = dst + y * obpr;
        for (int ox = 0; ox < obpr; ++ox) {
            uint8_t a = src[ox * 2], b = src[ox * 2 + 1];  // a: px0(low),px1(high); b: px2,px3
            o[ox] = (uint8_t)((kTo2bpp[a & 0x0F] << 6) | (kTo2bpp[a >> 4] << 4) |
                              (kTo2bpp[b & 0x0F] << 2) | kTo2bpp[b >> 4]);
        }
    }
}
}  // namespace

bool begin() {
    _fb = (uint8_t *)ps_calloc(sizeof(uint8_t), kFbBytes);
    _shadow = (uint8_t *)ps_calloc(sizeof(uint8_t), kFbBytes);
    if (_fb == nullptr || _shadow == nullptr) return false;
    memset(_fb, PAPER, kFbBytes);
    memset(_shadow, PAPER, kFbBytes);
    // epdiy as a SOFTWARE RASTERIZER only: the no-op dummy board makes epd_width()/epd_height()
    // return 960/540 for the font + primitive helpers, with ZERO panel-hardware access. Only .init is
    // ever invoked (during epd_init -> renderer_init); the rest fire only on epd_draw_base, never called.
    dummy_board.init = dummyInit;
    dummy_board.deinit = dummyDeinit;
    dummy_board.set_ctrl = dummyCtrl;
    dummy_board.poweron = dummyPower;
    dummy_board.measure_vcom = dummyPower;
    dummy_board.poweroff = dummyPower;
    dummy_board.get_temperature = dummyTemp;
    dummy_board.set_vcom = dummyVcom;
    epd_init(&dummy_board, &ED047TC1, EPD_LUT_1K);
    // FastEPD drives the actual panel via our custom V2.4 shift-register definition.
    if (!v24InitPanel(epaper)) return false;
    epaper.setMode(BB_MODE_2BPP);   // 4-level grayscale -> flash-free partialUpdate (STAGE 2)
    epaper.setPasses(6, 6);         // more partial passes -> less residual ghost per flash-free update
    // (no clearWhite here — the first fullUpdate's own clear seats the panel; saves one boot flash)
    _lastGc = millis();
    return true;
}

uint8_t *fb() { return _fb; }

void clear(uint8_t color) { memset(_fb, color, kFbBytes); }

// ---- primitives ------------------------------------------------------------

void fillRect(int x, int y, int w, int h, uint8_t color) {
    if (w <= 0 || h <= 0) return;
    epd_fill_rect({x, y, w, h}, color, _fb);
}

// Two-radius stroked circle (r and r-1) = a ~2px outline; shared by the vector glyphs.
static inline void strokeCircle(int cx, int cy, int r, uint8_t c, uint8_t *fb) {
    epd_draw_circle(cx, cy, r, c, fb);
    epd_draw_circle(cx, cy, r - 1, c, fb);
}

void blit(int x, int y, int w, int h, const uint8_t *data) {
    if (x & 1) x--;  // nibble alignment
    Rect_t a = {x, y, w, h};
    epd_copy_to_framebuffer(a, (uint8_t *)data, _fb);
}

void rect(int x, int y, int w, int h, int thick, uint8_t color) {
    for (int i = 0; i < thick; ++i) epd_draw_rect({x + i, y + i, w - 2 * i, h - 2 * i}, color, _fb);
}

void hline(int x, int y, int w, uint8_t color, int thick) {
    for (int i = 0; i < thick; ++i) epd_draw_hline(x, y + i, w, color, _fb);
}

void vline(int x, int y, int h, uint8_t color, int thick) { epd_fill_rect({x, y, thick, h}, color, _fb); }

void line(int x0, int y0, int x1, int y1, uint8_t color) {
    epd_draw_line(x0, y0, x1, y1, color, _fb);
}

// ---- text ------------------------------------------------------------------

// Fold untrusted text down to what the panel fonts can actually render — PURE ASCII. The JB_*
// fonts cover only 0x20-0x7E plus a few typographic marks (see src/fonts/*.h intervals); more
// importantly, epdiy's next_cp() (font.c) does NOT advance its pointer on a lone continuation byte
// (10xxxxxx), so ANY malformed/truncated UTF-8 handed to text()/textW() spins its measure/draw loop
// forever and wedges the UI. Emitting pure ASCII means every downstream byte-index cut
// (substring/remove/length-bound) is codepoint-safe by construction. CJK/emoji/etc. are dropped;
// the handful of in-font typographic glyphs are folded to ASCII; every invalid sequence is skipped.
String renderable(const String &in) {
    String out;
    out.reserve(in.length());
    const uint8_t *p = (const uint8_t *)in.c_str();
    const uint8_t *end = p + in.length();
    while (p < end) {
        uint8_t b = *p;
        uint32_t cp;
        int len;
        if (b < 0x80) { cp = b; len = 1; }
        else if ((b & 0xE0) == 0xC0) { cp = b & 0x1F; len = 2; }
        else if ((b & 0xF0) == 0xE0) { cp = b & 0x0F; len = 3; }
        else if ((b & 0xF8) == 0xF0) { cp = b & 0x07; len = 4; }
        else { p++; continue; }              // stray continuation / 0xF8-0xFF -> drop, resync
        if (p + len > end) break;            // truncated tail -> stop (never over-read)
        bool ok = true;
        for (int k = 1; k < len; k++) {
            if ((p[k] & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (p[k] & 0x3F);
        }
        if (!ok) { p++; continue; }          // missing continuation -> drop lead, resync
        p += len;
        if (len == 2 && cp < 0x80) continue;         // reject overlong encodings
        if (len == 3 && cp < 0x800) continue;
        if (len == 4 && cp < 0x10000) continue;
        if (cp >= 0xD800 && cp <= 0xDFFF) continue;  // reject UTF-16 surrogates
        if (cp >= 0x20 && cp <= 0x7E) { out += (char)cp; continue; }  // ASCII printable
        switch (cp) {
            case 0x09: case 0x0A: case 0x0D: case 0x00A0: out += ' '; break;  // tab/nl/cr/nbsp
            case 0x2013: case 0x2014: case 0x00B7: out += '-'; break;   // en/em dash, middle dot
            case 0x2018: case 0x2019: out += '\''; break;               // curly single quotes
            case 0x201C: case 0x201D: out += '"'; break;                // curly double quotes
            case 0x2026: out += "..."; break;                           // ellipsis
            case 0x00B1: out += "+/-"; break;                           // plus-minus
            default: break;                                             // CJK/emoji/other -> drop
        }
    }
    return out;
}

int text(const GFXfont &font, int x, int yBaseline, const char *s, uint8_t fg, int bg) {
    if (s == nullptr || *s == 0) return 0;
    EpdFontProperties props = {};
    props.fg_color = nib(fg);
    props.bg_color = nib(bg >= 0 ? (uint8_t)bg : PAPER);
    props.fallback_glyph = 0;
    props.flags = EPD_DRAW_BACKGROUND;
    int cx = x, cy = yBaseline;
    epd_write_string(&font, s, &cx, &cy, _fb, &props);
    return cx - x;
}

int textW(const GFXfont &font, const char *s) {
    if (s == nullptr || *s == 0) return 0;
    int x = 0, y = 0, x1 = 0, y1 = 0, w = 0, h = 0;
    EpdFontProperties props = epd_font_properties_default();  // epdiy 2.0 asserts props != NULL
    epd_get_text_bounds(&font, s, &x, &y, &x1, &y1, &w, &h, &props);
    return w;
}

int textFit(const GFXfont &font, int x, int yBaseline, int maxW, const char *s, uint8_t fg, int bg) {
    if (textW(font, s) <= maxW) return text(font, x, yBaseline, s, fg, bg);
    String t(s);
    // Trim whole trailing UTF-8 codepoints (not lone bytes): a substring truncated mid-codepoint
    // feeds epdiy's text-bounds decoder a lone lead byte and hangs it (see wrapLines in ui.cpp).
    while (t.length() > 1 && textW(font, (t + "\xE2\x80\xA6").c_str()) > maxW) {
        int i = t.length() - 1;
        while (i > 0 && ((uint8_t)t[i] & 0xC0) == 0x80) i--;  // back over continuation bytes
        t.remove(i);
    }
    return text(font, x, yBaseline, (t + "\xE2\x80\xA6").c_str(), fg, bg);
}

int textAlign(const GFXfont &font, int x, int yBaseline, int boxW, Align a, const char *s,
              uint8_t fg, int bg) {
    int tw = textW(font, s);
    int px = x;
    if (a == C) px = x + (boxW - tw) / 2;
    else if (a == R) px = x + boxW - tw;
    return text(font, px, yBaseline, s, fg, bg);
}

// ---- design glyphs (vector) ------------------------------------------------

void gTriRight(int x, int y, int s, uint8_t c) {
    epd_fill_triangle(x, y, x, y + s, x + s * 3 / 5, y + s / 2, c, _fb);
}
void gTriLeft(int x, int y, int s, uint8_t c) {
    epd_fill_triangle(x + s * 3 / 5, y, x + s * 3 / 5, y + s, x, y + s / 2, c, _fb);
}
void gTriDown(int x, int y, int s, uint8_t c) {
    epd_fill_triangle(x, y, x + s, y, x + s / 2, y + s * 3 / 5, c, _fb);
}
void gTriUp(int x, int y, int s, uint8_t c) {
    epd_fill_triangle(x, y + s * 3 / 5, x + s, y + s * 3 / 5, x + s / 2, y, c, _fb);
}

void gRefresh(int cx, int cy, int r, uint8_t c) {
    // open circular arrow: ~300° arc + arrowhead.
    for (int a = 40; a <= 320; a += 6) {
        float r0 = a * 3.14159f / 180.0f, r1 = (a + 6) * 3.14159f / 180.0f;
        epd_draw_line(cx + (int)(r * cosf(r0)), cy + (int)(r * sinf(r0)),
                      cx + (int)(r * cosf(r1)), cy + (int)(r * sinf(r1)), c, _fb);
        epd_draw_line(cx + (int)((r - 1) * cosf(r0)), cy + (int)((r - 1) * sinf(r0)),
                      cx + (int)((r - 1) * cosf(r1)), cy + (int)((r - 1) * sinf(r1)), c, _fb);
    }
    int hx = cx + (int)(r * cosf(40 * 3.14159f / 180.0f));
    int hy = cy + (int)(r * sinf(40 * 3.14159f / 180.0f));
    epd_fill_triangle(hx - 4, hy - 1, hx + 4, hy - 3, hx + 1, hy + 5, c, _fb);
}

void gGear(int cx, int cy, int r, uint8_t c) {
    for (int a = 0; a < 360; a += 45) {
        float rad = a * 3.14159f / 180.0f;
        int x0 = cx + (int)((r) * cosf(rad)), y0 = cy + (int)((r) * sinf(rad));
        int x1 = cx + (int)((r + 4) * cosf(rad)), y1 = cy + (int)((r + 4) * sinf(rad));
        epd_draw_line(x0, y0, x1, y1, c, _fb);
        epd_draw_line(x0 + 1, y0, x1 + 1, y1, c, _fb);
    }
    strokeCircle(cx, cy, r, c, _fb);
    epd_draw_circle(cx, cy, r / 3, c, _fb);
}

// CVSS pictograms (small, ~r=11): globe = Attack Vector, gauge = Attack Complexity, cursor = User
// Interaction. Privileges Required reuses gLock.
void gGlobe(int cx, int cy, int r, uint8_t c) {
    strokeCircle(cx, cy, r, c, _fb);
    epd_draw_line(cx, cy - r, cx, cy + r, c, _fb);              // meridian
    epd_draw_line(cx - r, cy, cx + r, cy, c, _fb);              // equator
    int lw = r * 3 / 4, lh = r * 3 / 5;                         // latitude lines
    epd_draw_line(cx - lw, cy - lh, cx + lw, cy - lh, c, _fb);
    epd_draw_line(cx - lw, cy + lh, cx + lw, cy + lh, c, _fb);
}
void gGauge(int cx, int cy, int r, uint8_t c) {                 // cy = dial baseline; arc opens up (∩)
    for (int a = 180; a <= 360; a += 15) {
        float r0 = a * 3.14159f / 180.0f, r1 = (a + 15) * 3.14159f / 180.0f;
        epd_draw_line(cx + (int)(r * cosf(r0)), cy + (int)(r * sinf(r0)),
                      cx + (int)(r * cosf(r1)), cy + (int)(r * sinf(r1)), c, _fb);
    }
    float na = 305.0f * 3.14159f / 180.0f;                      // needle up-right
    epd_draw_line(cx, cy, cx + (int)(r * 0.8f * cosf(na)), cy + (int)(r * 0.8f * sinf(na)), c, _fb);
    epd_fill_circle(cx, cy, 2, c, _fb);                         // hub
}
void gCursor(int x, int y, int s, uint8_t c) {                 // classic pointer, apex at (x,y)
    epd_fill_triangle(x, y, x, y + s, x + s * 7 / 10, y + s * 7 / 10, c, _fb);  // arrowhead
    for (int i = 0; i < 3; ++i)                                                 // tail
        epd_draw_line(x + s * 9 / 20 + i, y + s * 11 / 20, x + s * 8 / 10 + i, y + s, c, _fb);
}

// Document-facts pictograms: target = exploit targets, shield = bugbounty program, person = author/researcher.
void gTarget(int cx, int cy, int r, uint8_t c) {
    strokeCircle(cx, cy, r, c, _fb);
    epd_draw_circle(cx, cy, r * 3 / 5, c, _fb);
    epd_fill_circle(cx, cy, 2, c, _fb);
    epd_draw_line(cx - r - 2, cy, cx - r + 2, cy, c, _fb);   // crosshair ticks
    epd_draw_line(cx + r - 2, cy, cx + r + 2, cy, c, _fb);
    epd_draw_line(cx, cy - r - 2, cx, cy - r + 2, c, _fb);
    epd_draw_line(cx, cy + r - 2, cx, cy + r + 2, c, _fb);
}
void gShield(int x, int y, int s, uint8_t c) {                // x,y = top-left of the s x s box
    int mid = y + s * 55 / 100;
    epd_draw_line(x, y, x + s, y, c, _fb);                    // top
    epd_draw_line(x + s, y, x + s, mid, c, _fb);             // right
    epd_draw_line(x + s, mid, x + s / 2, y + s, c, _fb);     // right -> point
    epd_draw_line(x + s / 2, y + s, x, mid, c, _fb);         // point -> left
    epd_draw_line(x, mid, x, y, c, _fb);                     // left
}
void gUser(int cx, int cy, int s, uint8_t c) {                // head + shoulders silhouette
    epd_fill_circle(cx, cy - s * 3 / 10, s * 28 / 100, c, _fb);                       // head
    epd_fill_triangle(cx - s / 2, cy + s / 2, cx + s / 2, cy + s / 2, cx, cy - s / 20, c, _fb);  // shoulders
}

void gCheck(int x, int y, int s, uint8_t c) {
    epd_draw_line(x, y + s / 2, x + s * 2 / 5, y + s, c, _fb);
    epd_draw_line(x + 1, y + s / 2, x + s * 2 / 5 + 1, y + s, c, _fb);
    epd_draw_line(x + s * 2 / 5, y + s, x + s, y, c, _fb);
    epd_draw_line(x + s * 2 / 5 + 1, y + s, x + s + 1, y, c, _fb);
}

void gPencil(int x, int y, int s, uint8_t c) {
    // Diagonal pencil: shaft + nib, drawn from bottom-left up to top-right.
    for (int i = 0; i < 3; ++i) {
        epd_draw_line(x + i, y + s, x + s - 3 + i, y + 3, c, _fb);  // shaft edge
    }
    epd_fill_triangle(x, y + s, x + 4, y + s, x, y + s - 4, c, _fb);  // nib
    epd_draw_line(x + s - 5, y + 1, x + s, y + 4, c, _fb);            // eraser cap
    epd_draw_line(x + s - 6, y + 2, x + s - 1, y + 5, c, _fb);
}

void gDot(int cx, int cy, int r, uint8_t c) { epd_fill_circle(cx, cy, r, c, _fb); }

void gLock(int x, int y, int s, uint8_t c) {
    int bw = s, bh = s * 3 / 5;
    epd_fill_rect({x, y + s - bh, bw, bh}, c, _fb);   // body
    strokeCircle(x + bw / 2, y + s - bh, s / 3, c, _fb);  // shackle
}

void gSignal(int x, int y, int bars, uint8_t c) {
    for (int i = 0; i < 4; ++i) {
        int bh = 3 + i * 3, bx = x + i * 4;
        if (i < bars)
            epd_fill_rect({bx, y + (12 - bh), 3, bh}, c, _fb);
        else
            epd_draw_rect({bx, y + (12 - bh), 3, bh}, c, _fb);
    }
}

void gBattery(int x, int y, int pct, bool charging, uint8_t c) {
    epd_draw_rect({x, y, 20, 11}, c, _fb);
    epd_fill_rect({x + 20, y + 3, 2, 5}, c, _fb);  // nub
    int fillw = (16 * (pct < 0 ? 0 : pct > 100 ? 100 : pct)) / 100;
    epd_fill_rect({x + 2, y + 2, fillw, 7}, c, _fb);
    if (charging) {
        epd_draw_line(x + 11, y + 1, x + 7, y + 6, c, _fb);
        epd_draw_line(x + 7, y + 6, x + 12, y + 6, c, _fb);
        epd_draw_line(x + 12, y + 6, x + 8, y + 10, c, _fb);
    }
}

void gRadio(int cx, int cy, int r, bool filled, uint8_t c) {
    strokeCircle(cx, cy, r, c, _fb);
    if (filled) epd_fill_circle(cx, cy, r - 3, c, _fb);
}

void gToggle(int x, int y, bool on, uint8_t c) {
    const int tw = 56, th = 32, r = th / 2;  // rounded pill (v2)
    int cy = y + r;
    if (on) {
        fillRect(x + r, y, tw - 2 * r, th, c);              // black track
        epd_fill_circle(x + r, cy, r, c, _fb);
        epd_fill_circle(x + tw - r, cy, r, c, _fb);
        epd_fill_circle(x + tw - r, cy, r - 4, PAPER, _fb); // white knob, right
    } else {
        fillRect(x + r, y, tw - 2 * r, th, GRAY5);          // light track
        epd_fill_circle(x + r, cy, r, GRAY5, _fb);
        epd_fill_circle(x + tw - r, cy, r, GRAY5, _fb);
        epd_fill_circle(x + r, cy, r - 4, GRAY3, _fb);      // grey knob, left
    }
}

void progressBar(int x, int y, int w, int h, float frac, uint8_t c) {
    rect(x, y, w, h, 2, c);
    if (frac < 0) frac = 0;
    if (frac > 1) frac = 1;
    int iw = (int)((w - 6) * frac);
    if (iw > 0) fillRect(x + 3, y + 3, iw, h - 6, c);
}

void qrCode(int x, int y, int box, const char *text, uint8_t c) {
    int len = (int)strlen(text);
    // smallest QR version whose byte-mode / ECC_MEDIUM capacity fits the text
    int version = len <= 14 ? 1 : len <= 26 ? 2 : len <= 42 ? 3 : len <= 62 ? 4 : len <= 84 ? 5
                : len <= 106 ? 6 : len <= 122 ? 7 : len <= 152 ? 8 : len <= 180 ? 9 : 10;
    static uint8_t buf[512];  // >= qrcode_getBufferSize(11) (467); UI task only -> static ok
    QRCode qr;
    if (qrcode_initText(&qr, buf, version, ECC_MEDIUM, text) != 0) {  // could not fit
        rect(x, y, box, box, 2, c);
        return;
    }
    int modules = qr.size;
    int quiet = 4;  // modules of white margin (QR spec)
    int scale = box / (modules + 2 * quiet);
    if (scale < 1) { quiet = 2; scale = box / (modules + 2 * quiet); }
    if (scale < 1) scale = 1;
    int total = (modules + 2 * quiet) * scale;
    int px0 = x + (box - total) / 2, py0 = y + (box - total) / 2;
    fillRect(px0, py0, total, total, PAPER);  // white field incl. quiet zone
    int ox = px0 + quiet * scale, oy = py0 + quiet * scale;
    for (int my = 0; my < modules; ++my)
        for (int mx = 0; mx < modules; ++mx)
            if (qrcode_getModule(&qr, mx, my)) fillRect(ox + mx * scale, oy + my * scale, scale, scale, c);
}

// ---- refresh model ---------------------------------------------------------

const char *lastFlushInfo() { return _lastKind; }

int shadowMismatch() {
    // Return the value captured on the UI thread at the end of the last present (atomic
    // w.r.t. the single fb writer). Scanning here from the console task would race an
    // in-flight UI redraw and report meaningless transient deltas.
    return _postMismatch;  // MUST be 0 after any present(): every changed pixel was tracked
}

const char *testPatternName(int n) {
    static const char *names[kTestPatterns] = {"white", "black", "checker", "16-gray ramp", "8px grid"};
    return names[((n % kTestPatterns) + kTestPatterns) % kTestPatterns];
}

// Panel self-test: draw a pattern and do a full clean paint. Lets us eyeball the
// panel's contrast/grays/alignment and confirm a clean full clear over the console.
void testPattern(int n) {
    n = ((n % kTestPatterns) + kTestPatterns) % kTestPatterns;
    switch (n) {
        case 0: clear(PAPER); break;  // full white
        case 1: clear(INK); break;    // full black
        case 2:                       // 40px checkerboard
            clear(PAPER);
            for (int y = 0; y < H; y += 40)
                for (int x = 0; x < W; x += 40)
                    if (((x / 40) + (y / 40)) & 1) fillRect(x, y, 40, 40, INK);
            break;
        case 3:                       // 16-step gray ramp (white -> black)
            for (int i = 0; i < 16; ++i) {
                uint8_t g = (uint8_t)((15 - i) * 17);  // 255,238,...,17,0
                fillRect(i * W / 16, 0, W / 16 + 1, H, g);
            }
            break;
        case 4:                       // 8px alignment grid (partial-update boundary check)
            clear(PAPER);
            for (int x = 0; x <= W; x += 8) vline(x, 0, H, (x % 40 == 0) ? GRAY3 : GRAY5);
            for (int y = 0; y <= H; y += 8) hline(0, y, W, (y % 40 == 0) ? GRAY3 : GRAY5);
            break;
    }
    commitFull();
}

// Run one driver op on a fixed 8px-aligned sub-region, with start/done markers so a
// hang is pinpointed over UART. Stages a black block in _fb first so erase paths are
// exercised. This is the empirical panel debugger (the glass can't be read back).
void probe(int op) {
    const int PX = 96, PY = 200, PW = 256, PH = 120;
    fillRect(PX, PY, PW, PH, INK);  // stage a black block in the framebuffer
    // op parity: even -> FastEPD full update (flash), odd -> flash-free partial of the block rows.
    Serial.printf("[probe %d start] %s\n", op, (op & 1) ? "FastEPD partial (flash-free)" : "FastEPD full");
    Serial.flush();
    uint32_t t = millis();
    convert2bpp();
    guardSuspend();
    if (op & 1) epaper.partialUpdate(false, PY, PY + PH - 1);
    else epaper.fullUpdate(CLEAR_FAST, false, NULL);
    guardResume();
    Serial.printf("[probe %d] done %lums\n", op, (unsigned long)(millis() - t));
    Serial.flush();
    _hasShadow = false;  // panel state now unknown -> next present() does a full paint
}

void setRepaintMode(RepaintMode m) { _rmode = m; }
RepaintMode repaintMode() { return _rmode; }
const char *repaintModeName() { return _rmode == RP_FULL ? "FULL (flashy full update every change)" : "SMART (flash-free 2-bit partial of the changed rows)"; }

void setContentionGuard(void *taskHandle) { _guardTask = (TaskHandle_t)taskHandle; }

// Suspend/resume the registered network task around a panel transfer so its TLS+PSRAM work can't
// starve the e-paper DMA. No-op if none registered. The transfer holds no channel/TLS locks, so
// suspending the fetch task here cannot deadlock the UI.
static inline void guardSuspend() { if (_guardTask) vTaskSuspend(_guardTask); }
static inline void guardResume() { if (_guardTask) vTaskResume(_guardTask); }

// A clean full refresh (FastEPD 4-level fullUpdate): flashes black/white then repaints. Used for the
// first paint, navigation, big changes, and de-ghost. Also seeds FastEPD's "previous" plane so the
// subsequent flash-free partialUpdates diff correctly.
void commitFull() {
    uint32_t t = millis();
    convert2bpp();
    guardSuspend();
    epaper.fullUpdate(CLEAR_SLOW, false, NULL);  // thorough de-ghost (rare event) sweeps residue
    guardResume();
    _lastMs = millis() - t;
    snprintf(_lastKind, sizeof(_lastKind), "full %ux%u 2bpp %lums", W, H, (unsigned long)_lastMs);
    memcpy(_shadow, _fb, kFbBytes);
    _hasShadow = true;
    _ghostBudget = 0;
    _forceFullNext = false;
    _lastGc = millis();
    _postMismatch = 0;  // whole shadow copied from fb -> panel state is exactly the fb
}

// Show the framebuffer with minimal flash. Diff against the shadow to find the changed row range and
// drive just those rows with FastEPD's FLASH-FREE 2-bit partialUpdate (diffs current vs previous, no
// black/white pulse — even a whole-screen change renders without a flash). The flashy full paint
// (commitFull) is reserved for the first paint (seat + seed the previous plane), an explicit RP_FULL,
// and the periodic de-ghost (GHOST_MAX).
void present() {
    // Nav no longer forces a flashy full refresh: FastEPD's 2-bit partialUpdate is flash-free and its
    // diff renders old->new correctly even for a whole-screen change. Only the FIRST paint (seat +
    // seed the previous plane) and the periodic de-ghost use the (flashy) fullUpdate. This is what
    // kills the boot flicker (boot/connecting/dashboard were 3 full clears = ~12 flashes -> now 1).
    if (_rmode == RP_FULL || !_hasShadow || _forceFullNext) {
        _forceFullNext = false;
        commitFull();
        return;
    }
    // Union bounding box of every changed pixel (minB/maxB are byte columns).
    int minY = H, maxY = -1, minB = kBytesPerRow, maxB = -1;
    for (int y = 0; y < H; ++y) {
        const uint8_t *f = _fb + y * kBytesPerRow;
        const uint8_t *s = _shadow + y * kBytesPerRow;
        if (memcmp(f, s, kBytesPerRow) == 0) continue;
        if (y < minY) minY = y;
        maxY = y;
        int b0 = 0;
        while (f[b0] == s[b0]) ++b0;
        int b1 = kBytesPerRow - 1;
        while (f[b1] == s[b1]) --b1;
        if (b0 < minB) minB = b0;
        if (b1 > maxB) maxB = b1;
    }
    if (maxY < 0) return;  // nothing changed -> no power-on, no blink
    int x = (minB * 2) & ~7;             // byte -> pixel, align down to 8px
    int xr = ((maxB + 1) * 2 + 7) & ~7;  // align up to 8px
    if (xr > W) xr = W;
    int y0 = minY, w = xr - x, h = maxY - minY + 1;
    // FastEPD's FLASH-FREE 2-bit partialUpdate on the changed row range — diffs current vs previous
    // and drives only changed pixels (no black/white pulse), even for a full-screen change. Ghosting
    // accumulates over many partials and is swept by the periodic de-ghost (GHOST_MAX).
    uint32_t t = millis();
    convert2bpp(y0, y0 + h - 1);  // only the changed rows partialUpdate will drive
    guardSuspend();
    epaper.partialUpdate(false, y0, y0 + h - 1);
    guardResume();
    _lastMs = millis() - t;
    for (int yy = y0; yy < y0 + h; ++yy)  // sync shadow for the region we pushed
        memcpy(_shadow + yy * kBytesPerRow + x / 2, _fb + yy * kBytesPerRow + x / 2, w / 2);
    snprintf(_lastKind, sizeof(_lastKind), "partial rows %d-%d 2bpp %lums", y0, y0 + h - 1,
             (unsigned long)_lastMs);
    _ghostBudget += 1;
    if (_ghostBudget >= GHOST_MAX || (millis() - _lastGc) > GC_MS) _forceFullNext = true;

    // Self-check on the UI thread (single fb writer -> atomic): every changed byte must now be
    // mirrored into the shadow. The normal (in-sync) case is a single memcmp; only on a real desync
    // (a compositor sync bug = ghosting) do we walk the buffer to count bytes for the WARN. 'X' reports it.
    if (memcmp(_shadow, _fb, kFbBytes) == 0) {
        _postMismatch = 0;
    } else {
        _postMismatch = 0;
        for (int i = 0; i < kFbBytes; ++i)
            if (_shadow[i] != _fb[i]) _postMismatch++;
        Serial.printf("[gfx] WARN shadow desync after partial: %d bytes (%s)\n", _postMismatch,
                      _lastKind);
    }
}

// ---- serial framebuffer dump (host reconstructs the 4bpp rasterizer _fb) ---

void dumpSerial() {
    Serial.printf("\nFBDUMP %d %d 4\n", W, H);
    Serial.flush();
    Serial.write(_fb, kFbBytes);
    Serial.flush();
    Serial.print("\nFBEND\n");
    Serial.flush();
}

}  // namespace gfx
