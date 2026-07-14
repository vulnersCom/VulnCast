#!/usr/bin/env python3
# Trigger the device to dump its 960x540 4bpp framebuffer over serial and save
# it as a PNG — an exact reconstruction of what the e-paper panel shows.
# Usage: python3 tools/fbdump.py [out.png]
import serial, sys, time
from serial.tools import list_ports
from PIL import Image


def find_port():
    for p in list_ports.comports():
        h = (p.hwid or "").upper()
        if "303A:1001" in h or "usbmodem" in (p.device or ""):
            return p.device
    return None


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "fb.png"
    port = find_port()
    if not port:
        print("no device port found"); sys.exit(2)
    screen = sys.argv[2] if len(sys.argv) > 2 else None
    ser = serial.Serial(port, 115200, timeout=3)
    time.sleep(0.3)
    ser.reset_input_buffer()
    if screen:
        ser.write(screen.encode()[:1])  # jump to a screen (7/8/9/2/3)
        time.sleep(3.5)                  # let the FULL refresh finish
        ser.reset_input_buffer()
    ser.write(b"D")  # trigger gfx::dumpSerial()

    # find the FBDUMP header line
    buf = b""
    deadline = time.time() + 20
    while b"FBDUMP " not in buf:
        c = ser.read(1)
        buf += c
        if time.time() > deadline:
            print("no FBDUMP header. tail:", buf[-160:]); sys.exit(3)
    # read to end of the header line
    while not buf.endswith(b"\n"):
        buf += ser.read(1)
    hdr = buf.split(b"FBDUMP ")[-1].strip().split()
    W, H, bpp = int(hdr[0]), int(hdr[1]), int(hdr[2])
    nbytes = (W // 2) * H

    data = bytearray()
    deadline = time.time() + 40
    while len(data) < nbytes:
        chunk = ser.read(nbytes - len(data))
        if chunk:
            data += chunk
        if time.time() > deadline:
            print("short read:", len(data), "/", nbytes); break
    ser.close()

    img = Image.new("L", (W, H))
    px = img.load()
    row_bytes = W // 2
    for row in range(H):
        base = row * row_bytes
        for col in range(row_bytes):
            b = data[base + col] if base + col < len(data) else 0xFF
            px[2 * col, row] = (b & 0x0F) * 17
            px[2 * col + 1, row] = ((b >> 4) & 0x0F) * 17
    img.save(out)
    print("saved", out, f"{W}x{H}  ({len(data)}/{nbytes} bytes)")


main()
