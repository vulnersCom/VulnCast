#include "board_v24.h"

// FastEPD internal (external linkage): full IO init = pfnIOInit + ESP32-S3 LCD i80-bus setup.
extern int bbepIOInit(FASTEPDSTATE *pState);

int V24Epaper::initLCD() { return bbepIOInit(&_state); }

// FastEPD's LilyGo shift-register control procs (external linkage in FastEPD.inl). Our V2.4 board
// uses the identical 74HC595 config-register mechanism + bit order (0x80=OE, 0x40=mode,
// 0x20=scan_dir, 0x10=stv, 0x08=neg_pwr, 0x04=pos_pwr, 0x02=pwr_disable, 0x01=latch), so we reuse
// these tested callbacks with our own pin map.
extern int LilyGoEinkPower(void *pBBEP, int bOn);
extern int LilyGoIOInit(void *pBBEP);
extern void LilyGoRowControl(void *pBBEP, int iMode);

// 16-gray waveform matrix (each row = the black/white/neutral passes for one gray level). Copied from
// FastEPD's u8M5Matrix — that symbol is `const` (internal linkage), so we keep our own copy.
static const uint8_t v24Matrix[] = {
    1, 1, 1, 1, 1, 1, 1, 1,  2, 2, 1, 1, 2, 1, 1, 1,  2, 2, 1, 1, 1, 1, 2, 1,  2, 2, 1, 1, 2, 2, 1, 1,
    2, 2, 2, 2, 1, 1, 2, 1,  2, 2, 1, 1, 1, 2, 2, 1,  2, 2, 1, 1, 2, 1, 1, 2,  2, 2, 2, 1, 2, 1, 1, 2,
    2, 2, 2, 2, 2, 1, 2, 1,  1, 1, 1, 1, 1, 1, 2, 2,  2, 2, 1, 1, 1, 1, 2, 2,  1, 1, 1, 1, 2, 1, 2, 2,
    2, 2, 1, 1, 2, 1, 2, 2,  2, 1, 1, 2, 2, 1, 2, 2,  2, 2, 1, 2, 2, 1, 2, 2,  2, 2, 2, 2, 2, 2, 2, 2,
};

// LilyGo T5 4.7" S3 V2.4 pins (from the board's ed047tc1.h): data D0..D7 = {8,1,2,3,4,5,6,7};
// CKV=38, STH(SPH)=40, CKH(CL)=41; config shift register CFG_DATA(SDA)=13, CFG_CLK(SCL)=12,
// CFG_STR=0. OE/MODE/STV/LE/power are all driven through the shift register by the LilyGo procs, so
// their direct-pin fields are BB_NOT_USED.
static BBPANELDEF v24Def = {
    .width = 960,
    .height = 540,
    .bus_speed = 20000000,
    .flags = BB_PANEL_FLAG_SLOW_SPH,
    .data = { 8, 1, 2, 3, 4, 5, 6, 7, BB_NOT_USED, BB_NOT_USED, BB_NOT_USED, BB_NOT_USED, BB_NOT_USED,
              BB_NOT_USED, BB_NOT_USED, BB_NOT_USED },
    .bus_width = 8,
    .ioPWR = BB_NOT_USED,
    .ioSPV = BB_NOT_USED,
    .ioCKV = 38,
    .ioSPH = 40,
    .ioOE = BB_NOT_USED,
    .ioLE = BB_NOT_USED,
    .ioCL = 41,
    .ioPWR_Good = BB_NOT_USED,
    .ioSDA = 13,          // CFG_DATA (shift register serial data)
    .ioSCL = 12,          // CFG_CLK  (shift register clock)
    .ioShiftSTR = 0,      // CFG_STR  (shift register latch/store)
    .ioShiftMask = 0,
    .ioDCDummy = 46,      // spare GPIO the LCD peripheral toggles harmlessly
    .pGrayMatrix = v24Matrix,
    .iMatrixSize = sizeof(v24Matrix),
    .iLinePadding = 16,
    .iVCOM = -1600,
};

static BBPANELPROCS v24Procs = { LilyGoEinkPower, LilyGoIOInit, LilyGoRowControl, nullptr, nullptr };

bool v24InitPanel(V24Epaper &epaper) {
    if (epaper.initCustomPanel(&v24Def, &v24Procs) != BBEP_SUCCESS) return false;
    // initCustomPanel skips the LCD-bus setup -> do it (creates io_handle). Re-runs pfnIOInit
    // (harmless GPIO re-init) then esp_lcd_new_i80_bus / esp_lcd_new_panel_io_i80.
    if (epaper.initLCD() != BBEP_SUCCESS) return false;
    // Allocate the frame buffers.
    if (epaper.setPanelSize(960, 540, BB_PANEL_FLAG_SLOW_SPH, -1600) != BBEP_SUCCESS) return false;
    return true;
}
