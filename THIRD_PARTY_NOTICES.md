# Third-party notices

VulnCast bundles or builds on the following third-party works. Each remains under its own
license; the summaries below are for attribution — consult each upstream project for the full,
authoritative license text.

## Fonts

### JetBrains Mono
- Copyright 2020 The JetBrains Mono Project Authors.
- License: SIL Open Font License, Version 1.1 (`OFL-1.1`) — <https://openfontlicense.org/>
- Upstream (ships the full OFL text): <https://github.com/JetBrains/JetBrainsMono>
- Used as: the on-panel UI typeface. The TTFs in `tools/fonts/` are converted to the bitmap
  headers in `src/fonts/*.h` by `tools/fonts/fontconvert_px.py`.

### Poppins
- Copyright 2020 The Poppins Project Authors.
- License: SIL Open Font License, Version 1.1 (`OFL-1.1`) — <https://openfontlicense.org/>
- Upstream (ships the full OFL text): <https://github.com/itfoundry/Poppins>
- Used as: the "vulncast" wordmark, baked to a 4bpp asset in `src/assets/assets.h` by
  `tools/assets/bake.py`.

The OFL permits use, study, modification, embedding, and redistribution of these fonts (and of
derivatives such as the bitmap/wordmark assets generated here); the fonts may not be sold on their
own, and this notice satisfies the OFL's requirement that the copyright and license accompany the
redistributed font software.

## Libraries (pinned in `platformio.ini`)

| Library | Author | License | Upstream |
|---------|--------|---------|----------|
| FastEPD | bitbank2 (Larry Bank) | see repo | <https://github.com/bitbank2/FastEPD> |
| epdiy | Valentin Roland et al. | `LGPL-3.0` | <https://github.com/vroland/epdiy> |
| ArduinoJson | Benoît Blanchon | `MIT` | <https://github.com/bblanchon/ArduinoJson> |
| SensorLib | lewisxhe | see repo | <https://github.com/lewisxhe/SensorLib> |
| Button2 | Lennart Hennigs | `MIT` | <https://github.com/LennartHennigs/Button2> |
| QRCode | Richard Moore | `MIT` | <https://github.com/ricmoo/QRCode> |

`epdiy` is `LGPL-3.0`: it is used unmodified as a linked library (its source is fetched by
PlatformIO, not vendored), which the LGPL permits. `tools/fonts/fontconvert_px.py` is adapted from
epdiy's `scripts/fontconvert.py` and therefore remains under the `LGPL-3.0` (see its file header).

## Board definition

`boards/T5-ePaper-S3.json` is derived from LilyGo's board definition for the T5 4.7" E-Paper S3
V2.4 — <https://github.com/Xinyuan-LilyGO>.

## Data

Vulnerability data is provided by [Vulners](https://vulners.com/). VulnCast is a Vulners Inc.
project; it is not affiliated with or endorsed by LilyGo.
