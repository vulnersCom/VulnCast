#!/usr/bin/env python3
"""Convert an image (a cat photo / halftone / pixel-art) into a MASKED Bayer-dithered epdiy-4bpp C
sprite the firmware gfx::blitMask()es onto the e-paper.

- Auto-trims white borders, scales to --height.
- Dithers to 2 (ink/white) or 4 panel levels with positional Bayer 4x4 (matches gfx.cpp).
- MASKS the background: flood-fills white connected to the border -> transparent (nibble 0x0, skipped
  at blit), so the cat sits on the brick with no white card. A --halo px white ring hugs the silhouette
  (separation on the busy wall + the panel's crisp INK<->PAPER edge for animation).

  python3 tools/img2sprite.py assets/cat.png --height 176 --name Cat --levels 4 -o src/assets/cat_sprite.h
"""
import argparse
import os
import numpy as np
from scipy import ndimage
from PIL import Image

ap = argparse.ArgumentParser()
ap.add_argument("img")
ap.add_argument("-o", "--out", default="src/assets/cat_sprite.h")
ap.add_argument("--name", default="Cat")
ap.add_argument("--height", type=int, default=176)
ap.add_argument("--levels", type=int, default=4, choices=[2, 4])
ap.add_argument("--halo", type=int, default=3)
ap.add_argument("--invert", action="store_true", help="source is a light subject on a dark ground")
ap.add_argument("--gamma", type=float, default=1.0, help=">1 lightens, <1 darkens before dithering")
ap.add_argument("--flip", action="store_true", help="mirror horizontally")
# Head/tail animation: the HEAD region (rotated about the neck) and the TAIL wedge (rotated about its
# base) are re-posed to produce headframes x tailframes COMPLETE frames (see the emit below) — the
# firmware indexes k<Name>Sprite[head*TailFrames + tail] and animates head and tail on separate timers.
ap.add_argument("--tailsplit", type=int, default=0, help="x below which is the tail (0 = no tail part)")
ap.add_argument("--tailbase", type=int, default=0, help="row the tail pivots around (default = height)")
ap.add_argument("--tailsway", type=float, default=6.0)
ap.add_argument("--tailframes", type=int, default=3)
ap.add_argument("--headframes", type=int, default=3)
ap.add_argument("--headbot", type=int, default=0, help="neck row: pixels above it are the head (rotated)")
ap.add_argument("--headcx", type=int, default=0, help="pivot x for the head turn (default = width/2)")
ap.add_argument("--headangle", type=float, default=0.0, help="deg the head turns/tilts toward the monitor")
a = ap.parse_args()

im = Image.open(a.img).convert("L")
if a.invert:
    im = Image.eval(im, lambda v: 255 - v)
if a.flip:
    im = im.transpose(Image.FLIP_LEFT_RIGHT)
bbox = im.point(lambda v: 0 if v > 244 else 255).getbbox()
if bbox:
    m = 6
    im = im.crop((max(0, bbox[0] - m), max(0, bbox[1] - m),
                  min(im.width, bbox[2] + m), min(im.height, bbox[3] + m)))
w = max(2, round(im.width * a.height / im.height))
w -= w % 2
im = im.resize((w, a.height), Image.LANCZOS)
if a.gamma > 0 and a.gamma != 1.0:  # gamma <= 0 is meaningless -> skip (don't divide by zero)
    im = Image.eval(im, lambda v: int(255 * (v / 255) ** (1.0 / a.gamma)))

g0 = np.asarray(im, dtype=np.float32)  # H x W, 0=black..255=white
H, W = g0.shape
bay = np.array([[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]])
bt = np.tile(bay, (H // 4 + 1, W // 4 + 1))[:H, :W]
tb = a.tailbase or H
headcx = a.headcx or W // 2
yy, xx = np.mgrid[0:H, 0:W]
head_mask = (yy < a.headbot) & (xx >= a.tailsplit) if a.headbot else None  # head region (excl. tail)
# tail wedge = upper-left, ABOVE the tail-body junction row `tb` (so the body haunch below is untouched)
tail_mask = (xx < a.tailsplit) & (yy < tb) if a.tailsplit > 0 else None


def to_nibbles(g, suppress=None):  # dither + cut white bg to transparent; drop halo where `suppress`
    if a.levels == 2:
        nib = np.where((g * 16 / 256) > bt, 0xF, 0x1).astype(np.uint8)
    else:
        f = g * 3.0 / 255.0
        b = np.floor(f).astype(int)
        lvl = np.clip(b + (bt < (f - b) * 16).astype(int), 0, 3)
        nib = np.array([0x1, 0xD, 0xE, 0xF], dtype=np.uint8)[lvl]
    lbl, _ = ndimage.label(g > 245)
    border = set(lbl[0, :]) | set(lbl[-1, :]) | set(lbl[:, 0]) | set(lbl[:, -1])
    border.discard(0)
    cat = ~np.isin(lbl, list(border))
    # NB: scipy treats iterations<1 as "dilate until stable" (would fill the whole frame and make the
    # background opaque), so --halo 0 must mean "no halo", not iterations=0.
    halo = (ndimage.binary_dilation(cat, iterations=a.halo) & ~cat) if a.halo > 0 else np.zeros_like(cat)
    if suppress is not None:
        halo &= ~suppress   # no halo along an internal cut (neck / tail-base) so parts meet seamlessly
    return np.where(cat, nib, np.where(halo, 0xF, 0x0)).astype(np.uint8)


def turn_tail(g, angle):  # rotate the tail wedge about its base (tb, tailsplit); mode='nearest' fills
    if tail_mask is None or not angle:  # the vacated pixels with fur (no hole)
        return g
    th = np.radians(angle)
    c, s = np.cos(th), np.sin(th)
    R = np.array([[c, -s], [s, c]])
    center = np.array([tb, a.tailsplit])
    rot = ndimage.affine_transform(g, R, offset=center - R @ center, order=1, mode="nearest")
    return np.where(tail_mask, rot, g)


def turn_head(g, angle):  # rotate the head+neck about the neck pivot; mode='nearest' fills w/ fur (no hole)
    if head_mask is None or not angle:
        return g
    th = np.radians(angle)
    c, s = np.cos(th), np.sin(th)
    R = np.array([[c, -s], [s, c]])
    center = np.array([a.headbot, headcx])
    rot = ndimage.affine_transform(g, R, offset=center - R @ center, order=1, mode="nearest")
    return np.where(head_mask, rot, g)


def keep_largest(g):  # drop detached fragments (a split tail-tip, a spilled island) — keep the one cat
    cat = g < 248
    lbl, num = ndimage.label(cat)
    if num <= 1:
        return g
    counts = np.bincount(lbl.ravel())
    counts[0] = 0
    out = g.copy()
    out[lbl != counts.argmax()] = 255.0
    return out


# ONE COMPLETE cat per (head, tail) combo: no cuts/layers -> no seams, holes or doubling. The head+neck
# and the tail ROTATE about their bases (mode='nearest' fills with fur, no gap), then keep_largest() cuts
# any fragment that detached/spilled past the body. The firmware picks kCatSprite[head*TailFrames + tail]
# on independent timers, so head and tail still animate separately.
tailN = max(1, a.tailframes)
headN = max(1, a.headframes)
frames = []
for hi in range(headN):
    for ti in range(tailN):
        hph = 0.0 if headN == 1 else hi / (headN - 1)           # 0..1  head turns toward the monitor
        tph = 0.0 if tailN == 1 else (ti / (tailN - 1)) * 2 - 1  # -1..1 tail sway
        g = turn_head(turn_tail(g0.copy(), a.tailsway * tph), a.headangle * hph)
        frames.append(to_nibbles(keep_largest(g)))


def pack(nib):
    lo = nib[:, 0::2].astype(np.uint16)
    hi = nib[:, 1::2].astype(np.uint16)
    return ((hi << 4) | lo).astype(np.uint8).flatten()


n = a.name
bpf = (w // 2) * a.height
L = [f"// Generated by tools/img2sprite.py from {os.path.basename(a.img)} ({w}x{a.height}, {a.levels}-level, masked,",
     f"// {headN}x{tailN} COMPLETE cat frames, index = head*{tailN}+tail, epdiy 4bpp. 0x0 = transparent.",
     "#pragma once", "#include <stdint.h>", "",
     f"constexpr int k{n}W = {w};", f"constexpr int k{n}H = {a.height};",
     f"constexpr int k{n}HeadFrames = {headN};", f"constexpr int k{n}TailFrames = {tailN};", "",
     f"const uint8_t k{n}Sprite[{len(frames)}][{bpf}] = {{"]
for nib in frames:
    p = pack(nib)
    L.append("  {")
    for i in range(0, len(p), 24):
        L.append("    " + ", ".join(str(int(b)) for b in p[i:i + 24]) + ",")
    L.append("  },")
L.append("};")
open(a.out, "w").write("\n".join(L) + "\n")
print(f"wrote {a.out}: {w}x{a.height}, {headN}x{tailN}={len(frames)} complete frames, {a.levels}-level")
