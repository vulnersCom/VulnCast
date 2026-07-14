#!/usr/bin/env python3
# Generate the JetBrains Mono epdiy font matrix for VulnCast into src/fonts/.
import subprocess, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
FC = os.path.join(HERE, "fontconvert_px.py")
OUT = os.path.abspath(os.path.join(HERE, "..", "..", "src", "fonts"))
os.makedirs(OUT, exist_ok=True)

TTF = {
    "R": "JetBrainsMono-Regular.ttf",
    "M": "JetBrainsMono-Medium.ttf",
    "B": "JetBrainsMono-Bold.ttf",
    "X": "JetBrainsMono-ExtraBold.ttf",
}
# weight-tag -> pixel sizes actually used across the 9 screens (v2 legibility build).
# R=Regular (body/captions, doubles for IBM Plex Mono small labels), M=Medium (titles),
# B=Bold 700 (labels/tabs/buttons), X=ExtraBold 800 (big ids + metric numbers).
MATRIX = {
    "R": [14, 15, 16, 17, 19],
    "M": [17, 19, 20, 22],
    "B": [14, 15, 16, 17, 19, 20, 22, 24],
    "X": [24, 34, 36, 42, 44, 52],
}

names = []
for tag, sizes in MATRIX.items():
    ttf = os.path.join(HERE, TTF[tag])
    for sz in sizes:
        name = f"JB_{tag}{sz}"
        r = subprocess.run(["python3", FC, name, str(sz), ttf, "--compress"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("FAIL", name, r.stderr[-400:], file=sys.stderr)
            sys.exit(1)
        with open(os.path.join(OUT, name + ".h"), "w") as f:
            f.write(r.stdout)
        names.append(name)
        print(f"  {name}: {len(r.stdout):>7} bytes header")

with open(os.path.join(OUT, "jbfonts.h"), "w") as f:
    f.write("#pragma once\n")
    f.write("// AUTO-GENERATED (tools/fonts/gen.py): JetBrains Mono epdiy fonts.\n")
    f.write("// Naming: JB_<weight><px> — R=Regular M=Medium B=Bold X=ExtraBold.\n")
    for n in names:
        f.write(f'#include "{n}.h"\n')

print(f"TOTAL {len(names)} fonts -> {OUT}")
