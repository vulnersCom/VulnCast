// Compatibility shim: lets the existing gfx code and the generated JetBrains-Mono font headers
// (both forked from epdiy 1.x / LilyGo-EPD47) build against modern epdiy 2.0 unchanged.
//
// epdiy 2.0 renamed the font/rect types but kept their field layout byte-for-byte:
//   GFXglyph        -> EpdGlyph            (width,height,advance_x,left,top,compressed_size,data_offset)
//   UnicodeInterval -> EpdUnicodeInterval  (first,last,offset)
//   GFXfont         -> EpdFont             (bitmap,glyph,intervals,interval_count,compressed,advance_y,ascender,descender)
//   Rect_t          -> EpdRect             ({int x,y,width,height})
// so a set of typedefs is enough — no font regeneration needed. Text rendering / panel push moved to
// the new mode-based API (epd_write_string / epd_draw_base) and is ported directly in gfx.cpp.
#pragma once

#include "epdiy.h"

typedef EpdRect Rect_t;
typedef EpdFont GFXfont;
typedef EpdGlyph GFXglyph;
typedef EpdUnicodeInterval UnicodeInterval;
