// Board pin map for the LilyGo T5 4.7" E-Paper S3 V2.4 (ESP32-S3), replacing the pin macros the old
// LilyGo-EPD47 library provided via its utilities.h. The e-paper panel pins themselves are owned by
// the display driver's board definition (epdiy 2.0 / FastEPD); this header only carries the NON-EPD
// peripherals the firmware wires up directly: touch I2C (GT911), battery ADC, and the boot button.
//
// Values captured from LilyGo-EPD47 utilities.h, CONFIG_IDF_TARGET_ESP32S3 section.
#pragma once

#define BOARD_SCL  17  // GT911 touch I2C clock
#define BOARD_SDA  18  // GT911 touch I2C data
#define BATT_PIN   14  // battery voltage divider ADC
#define BUTTON_1   21  // on-board button (BOOT)
