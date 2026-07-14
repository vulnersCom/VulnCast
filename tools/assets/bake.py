#!/usr/bin/env python3
# Bake the Vulners logo (from the design handoff) and the Poppins "vulncast"
# wordmark into 4bpp epdiy image arrays (src/assets/assets.h). Format matches the
# framebuffer: 2 px/byte, low nibble = even x, value = gray>>4 (white=15=paper).
#
# NOTE: the generated output (src/assets/assets.h) IS committed, so a normal build never runs this.
# Regeneration is a maintainer task and needs the design handoff (docs/ — git-ignored, not shipped).
import os
from PIL import Image, ImageFont, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
LOGO = os.path.join(ROOT, "docs/design_v2/design_handoff_vulncast/assets/vulners-logo-trim.png")
POPX = os.path.join(ROOT, "tools/fonts/Poppins-ExtraBold.ttf")
POPB = os.path.join(ROOT, "tools/fonts/Poppins-Bold.ttf")
OUT = os.path.join(ROOT, "src/assets")
os.makedirs(OUT, exist_ok=True)


def pack4(img):
    img = img.convert("L")
    w, h = img.size
    px = img.load()
    wpad = w if w % 2 == 0 else w + 1
    out = bytearray()
    for y in range(h):
        for xb in range(0, wpad, 2):
            p0 = px[xb, y] if xb < w else 255
            p1 = px[xb + 1, y] if xb + 1 < w else 255
            out.append((p0 >> 4) | ((p1 >> 4) << 4))
    return bytes(out), wpad, h


def emit(f, name, data, w, h):
    f.write(f"const int {name}W = {w}, {name}H = {h};\n")
    f.write(f"const uint8_t {name}[{len(data)}] PROGMEM = {{")
    f.write(",".join(str(b) for b in data))
    f.write("};\n")


def logo(height):
    im = Image.open(LOGO)
    if im.mode == "RGBA":  # composite onto white so the transparent bg -> paper
        bg = Image.new("RGB", im.size, (255, 255, 255))
        bg.paste(im, mask=im.split()[3])
        im = bg
    im = im.convert("L")
    ratio = height / im.height
    im = im.resize((round(im.width * ratio), height), Image.LANCZOS)
    return pack4(im)


def word(ttf, px, text="vulncast"):
    font = ImageFont.truetype(ttf, px)
    tmp = ImageDraw.Draw(Image.new("L", (1, 1)))
    bb = tmp.textbbox((0, 0), text, font=font)
    w, h = bb[2] - bb[0], bb[3] - bb[1]
    im = Image.new("L", (w + 2, h + 2), 255)
    ImageDraw.Draw(im).text((1 - bb[0], 1 - bb[1]), text, font=font, fill=0)
    return pack4(im)


with open(os.path.join(OUT, "assets.h"), "w") as f:
    f.write("#pragma once\n#include <stdint.h>\n#include <pgmspace.h>\n")
    f.write("// AUTO-GENERATED (tools/assets/bake.py): Vulners logo + Poppins wordmark, 4bpp.\n")
    # logo-trim (mark + "vulners"): boot 120, dashboard/connecting ~50.
    for hgt, nm in [(120, "kLogo120"), (50, "kLogo50")]:
        d, w, h = logo(hgt)
        emit(f, nm, d, w, h)
        print(f"  {nm}: {w}x{h}  {len(d)} bytes")
    # "vulncast" wordmark (Poppins ExtraBold): boot ~76 tall (px96), dashboard ~30 (px38).
    for ttf, px, nm in [(POPX, 96, "kWord96"), (POPX, 38, "kWord38")]:
        d, w, h = word(ttf, px)
        emit(f, nm, d, w, h)
        print(f"  {nm}: {w}x{h}  {len(d)} bytes")
print("assets baked -> src/assets/assets.h")
