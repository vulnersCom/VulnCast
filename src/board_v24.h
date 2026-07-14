// Custom FastEPD panel definition for the LilyGo T5 4.7" E-Paper S3 V2.4 (ED047TC1, 960x540).
//
// This exact board isn't in FastEPD's built-in panel table (its LilyGo entry is the newer "Pro"
// pinout), but our V2.4 uses the SAME 74HC595 config-shift-register control mechanism + bit order as
// FastEPD's tested `LilyGo*` procs — only the pins differ. So we build a custom BBPANELDEF with our
// pins and reuse those procs. epdiy 2.0 can't drive this board on S3 (its esp_lcd backend needs LE/STV
// as direct pins; ours are behind the shift register), so FastEPD is the modern driver we use.
#pragma once

#include <FastEPD.h>

// FastEPD 2.2.0's initCustomPanel() sets the panel def + runs the board's pfnIOInit, but SKIPS
// bbepIOInit() — the ESP32-S3 LCD i80-bus setup that creates the io_handle. So we subclass to reach
// the protected _state and run bbepIOInit ourselves.
class V24Epaper : public FASTEPD {
  public:
    int initLCD();  // run FastEPD's bbepIOInit(&_state) to create the S3 LCD bus
    // Tune the update pass counts (bbepIOInit defaults: partial=4, full=5). More partial passes move
    // the particles more completely -> less residual ghost per flash-free update.
    void setPasses(int partial, int full) { _state.iPartialPasses = partial; _state.iFullPasses = full; }
};

// Init the V2.4 panel: custom def + LCD bus + buffer allocation. Returns true on success.
bool v24InitPanel(V24Epaper &epaper);
