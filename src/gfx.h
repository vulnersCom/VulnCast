// gfx — direct e-paper drawing toolkit for the VulnCast ops-console UI.
//
// Owns the 960x540 4bpp framebuffer (in PSRAM) and wraps epdiy primitives with
// the design's grayscale tokens, JetBrains Mono fonts, colored text (via
// FontProperties), the glyph shapes the design needs (arrows, gear, check,
// battery, signal, lock, radio, toggle, meter, progress, QR hatch), and the
// refresh model (FULL flush, PART window, ghosting GC). A serial framebuffer
// dump lets the host reconstruct exactly what the panel shows (for verification).
#pragma once

#include <Arduino.h>

#include "epd_compat.h"  // epdiy 2.0 + GFXfont/Rect_t compatibility typedefs

namespace gfx {

// Panel geometry (ED047TC1). epdiy 2.0 exposes these only at runtime (epd_width()/epd_height()),
// so we keep them as compile-time literals for the framebuffer sizing.
constexpr int W = 960;
constexpr int H = 540;

// Design grayscale tokens as epd byte colors (nibble = value>>4).
// paper=white(15) ... ink≈near-black(1). Intermediate grays map to distinct nibbles.
constexpr uint8_t PAPER = 0xFF;   // background (nibble 15)
constexpr uint8_t INK = 0x11;     // primary text/borders/fills (nibble 1)
constexpr uint8_t INK2 = 0x2A;    // body copy on paper (nibble 2)
constexpr uint8_t GRAY1 = 0x46;   // secondary / dark divider on black bars
constexpr uint8_t GRAY3 = 0x78;   // muted labels / captions
constexpr uint8_t GRAY4 = 0xA8;   // disabled / inactive / off-state
constexpr uint8_t GRAY5 = 0xD4;   // hairline dividers
constexpr uint8_t GRAY6 = 0xE9;   // light text on black bars
constexpr uint8_t WHITE = 0xFF;   // brightest status text on black

// value>>4 nibble helpers for text fg/bg (write_mode takes 4-bit).
inline uint8_t nib(uint8_t c) { return c >> 4; }

enum Align { L = 0, C = 1, R = 2 };

bool begin();                 // epd_init + framebuffer alloc + touch
uint8_t *fb();                // raw 4bpp framebuffer
void clear(uint8_t color = PAPER);

// Primitives (draw into the framebuffer).
void fillRect(int x, int y, int w, int h, uint8_t color);
void blit(int x, int y, int w, int h, const uint8_t *data);  // 4bpp image into fb (x even)
void blitMask(int x, int y, int w, int h, const uint8_t *data);  // 4bpp sprite; nibble 0x0 = transparent
void rect(int x, int y, int w, int h, int thick, uint8_t color);  // border, inset inward
void hline(int x, int y, int w, uint8_t color, int thick = 1);
void vline(int x, int y, int h, uint8_t color, int thick = 1);
void line(int x0, int y0, int x1, int y1, uint8_t color);
void setPx(int x, int y, uint8_t color);  // plot one pixel (nibble write), bounds-checked

// Ordered (Bayer 4x4) dithering — mix two tokens per pixel to fake the midtones the 2-bit panel
// can't render directly (the real display collapses our 16 tokens to 4 levels). `mix` = 0..16 =
// how many of every 16 pixels take colB (0 = all colA .. 16 = all colB). Deterministic, so a
// redrawn-identical region diffs clean against the shadow (no spurious partial-update).
void ditherRect(int x, int y, int w, int h, uint8_t colA, uint8_t colB, int mix);
// Vertical dithered gradient from colTop (at y) to colBottom (at y+h-1) — sky/fog/sea atmosphere.
void vGradient(int x, int y, int w, int h, uint8_t colTop, uint8_t colBottom);

// Text. y is the BASELINE. Returns the advance width. `bg` <0 = transparent.
int text(const GFXfont &font, int x, int yBaseline, const char *s, uint8_t fg = INK,
         int bg = -1);
int textAlign(const GFXfont &font, int x, int yBaseline, int boxW, Align a,
              const char *s, uint8_t fg = INK, int bg = -1);
int textW(const GFXfont &font, const char *s);
// Fold untrusted feed text to PURE ASCII (what the JB_* panel fonts render). Drops CJK/emoji and,
// critically, every malformed/truncated UTF-8 sequence — a lone continuation byte hangs epdiy's
// text decoder. Route all untrusted strings through this before they reach any text()/textW().
String renderable(const String &in);
// Draw text truncated with a trailing "…" so it fits within maxW. Returns width.
int textFit(const GFXfont &font, int x, int yBaseline, int maxW, const char *s, uint8_t fg = INK,
            int bg = -1);

// Design glyphs (drawn as vector primitives; size ~s px box unless noted).
void gTriRight(int x, int y, int s, uint8_t c);
void gTriLeft(int x, int y, int s, uint8_t c);
void gTriDown(int x, int y, int s, uint8_t c);   // ▾
void gTriUp(int x, int y, int s, uint8_t c);     // ▴
void gRefresh(int cx, int cy, int r, uint8_t c);  // ⟳
void gGear(int cx, int cy, int r, uint8_t c);     // ⚙
void gCheck(int x, int y, int s, uint8_t c);      // ✓
void gGlobe(int cx, int cy, int r, uint8_t c);    // CVSS Attack Vector
void gGauge(int cx, int cy, int r, uint8_t c);    // CVSS Attack Complexity (cy = dial baseline)
void gCursor(int x, int y, int s, uint8_t c);     // CVSS User Interaction
void gTarget(int cx, int cy, int r, uint8_t c);   // exploit targets
void gShield(int x, int y, int s, uint8_t c);     // bugbounty program
void gUser(int cx, int cy, int s, uint8_t c);     // author / researcher
void gPencil(int x, int y, int s, uint8_t c);     // ✎ (exploit tag)
void gDot(int cx, int cy, int r, uint8_t c);      // ● filled dot
void gLock(int x, int y, int s, uint8_t c);       // 🔒
void gSignal(int x, int y, int bars, uint8_t c);  // 4-bar wifi signal (bars 0..4)
void gBattery(int x, int y, int pct, bool charging, uint8_t c);
void gRadio(int cx, int cy, int r, bool filled, uint8_t c);
void gToggle(int x, int y, bool on, uint8_t c);   // 46x26 slide toggle
void progressBar(int x, int y, int w, int h, float frac, uint8_t c);  // 1-bit fill in border
// Render a real, scannable QR of `text`, centered in the box (x,y,box,box) with a
// white quiet zone. Auto-picks the smallest version that fits. Black modules in `c`.
void qrCode(int x, int y, int box, const char *text, uint8_t c);

// ---- damage-tracking compositor --------------------------------------------
// We keep a SHADOW copy of what is currently on the panel. present() diffs the
// working framebuffer against the shadow and drives ONLY the changed rows with a
// FastEPD flash-free 2-bit partial update (no black<->white pulse). The flashy
// full update is reserved for the very first paint and a periodic de-ghost, so
// the panel "blinks" as rarely as possible while we always know the exact state.
enum RepaintMode {
    RP_SMART = 0,  // diff -> partial; flash only on 1st paint + de-ghost (default)
    RP_FULL,       // flashy full update on every present (cleanest, but blinks a lot)
};
void present();                 // show the framebuffer (flash-free 2-bit partial of the changed rows)
void commitFull();              // FastEPD full update + reset shadow (the one flash)
void requestFullNext();         // make the NEXT present() a clean full refresh (e.g. leaving a scene)
// --- smart-animation engine (research-verified: 2BPP partialUpdate is per-pixel + flash-free, so a
//     stable background + white-edged sprites gives ghost-free, neighbour-safe motion) ---------------
void setAutoDeghost(bool on);   // chill mode: suppress the periodic whole-screen de-ghost (no flash)
void savePlate();               // snapshot the framebuffer as the static "plate" backdrop (PSRAM)
void restoreRect(int x, int y, int w, int h);  // memcpy the plate back over a box (erase a sprite cleanly)
// Register a FreeRTOS task (TaskHandle_t as void*) that is SUSPENDED for the duration of each
// e-paper panel transfer and resumed after. The FastEPD i80 LCD transfer is timing-sensitive;
// heavy concurrent work on the network task (TLS + JSON parsing in PSRAM) can starve its DMA and
// wedge the panel. Pass nullptr to disable. Safe: the transfer holds no channel/TLS locks.
void setContentionGuard(void *taskHandle);
void setRepaintMode(RepaintMode m);
RepaintMode repaintMode();
const char *repaintModeName();

// ---- GFX debug harness -----------------------------------------------------
// Panel self-test patterns (draw into fb + full clean paint) so the physical
// panel can be inspected/calibrated over the debug console.
void testPattern(int n);        // 0 white · 1 black · 2 checker · 3 16-gray ramp · 4 8px grid
constexpr int kTestPatterns = 5;
const char *testPatternName(int n);
// Isolate a single driver op on a fixed sub-region (prints start/done over UART so a hang is
// pinpointed). Even op -> FastEPD full update (flash); odd op -> flash-free 2-bit partial.
void probe(int op);
constexpr int kProbes = 8;
// Timing + kind of the last panel update ("full 480ms" / "partial 320x88 90ms").
const char *lastFlushInfo();
// Correctness proof: bytes where the shadow (what we told the panel) differs from the
// framebuffer (what should be shown). After any present() this MUST be 0 — a non-zero
// count means the compositor left a changed region un-pushed (the source of ghosting).
int shadowMismatch();

// Serial framebuffer dump: host reconstructs the 4bpp rasterizer framebuffer (verification;
// this is the drawn _fb, not the 2-bit panel image — see gfx.cpp / CLAUDE.md).
void dumpSerial();

}  // namespace gfx
