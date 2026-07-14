#!/usr/bin/env python3
"""VulnCast debug console — host side.

Talks to the device's always-on UART console (a dedicated FreeRTOS task that keeps
answering even if the main app hangs). Robust to the ESP32-S3 native-USB
"reset-on-open" re-enumeration: it reopens the port and waits until the device is
answering before running a command.

Examples:
  python3 tools/console.py info                 # device state
  python3 tools/console.py dump out.png         # screenshot the e-paper framebuffer
  python3 tools/console.py dump out.png -q       # screenshot + decode any QR codes
  python3 tools/console.py screen 3             # preview a screen (3=settings)
  python3 tools/console.py tap 903 100          # inject a touch (drive a control)
  python3 tools/console.py press gear           # named tap (see NAMED below: gear/back/...)
  python3 tools/console.py channels             # list channels
  python3 tools/console.py refresh              # fetch the active channel now
  python3 tools/console.py touchmon             # echo REAL panel taps (verify touch)
  python3 tools/console.py reboot
  python3 tools/console.py repl                 # interactive: type raw console chars
"""
import argparse, os, re, sys, time

os.environ.setdefault("DYLD_LIBRARY_PATH", "/opt/homebrew/lib:/usr/local/lib")
import serial
from serial.tools import list_ports

# Named hit-boxes for common controls (center of the drawn control) — makes taps
# self-documenting. Coordinates are panel pixels (960x540).
NAMED = {
    "gear": (903, 100), "settings": (903, 100), "refresh_btn": (823, 100),
    "next_ch": (925, 174), "prev_ch": (35, 174),
    "featured": (280, 350), "feed1": (760, 300), "feed2": (760, 415),
    "back": (50, 30),
}
SCREENS = {0: "boot", 1: "connecting", 2: "setup", 3: "dashboard", 4: "document",
           5: "settings", 6: "keyboard", 7: "interval", 8: "timezone"}


def find_port():
    for p in list_ports.comports():
        if "303A:1001" in (p.hwid or "").upper() or "usbmodem" in (p.device or ""):
            return p.device
    return None


class Console:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.s = None
        self._open()

    def _open(self):
        for _ in range(40):
            p = find_port()
            if p:
                try:
                    s = serial.Serial()
                    s.port, s.baudrate, s.timeout = p, 115200, 1
                    s.dtr = s.rts = False  # avoid asserting the reset lines
                    s.open()
                    self.s = s
                    return
                except Exception:
                    pass
            time.sleep(1)
        raise SystemExit("no device port (303A:1001 / usbmodem) found")

    def _reopen(self):
        try:
            self.s.close()
        except Exception:
            pass
        time.sleep(1.5)
        self._open()

    def send(self, data, settle=0.0):
        for _ in range(3):
            try:
                self.s.reset_input_buffer()
                self.s.write(data.encode() if isinstance(data, str) else data)
                if settle:
                    time.sleep(settle)
                return
            except Exception:
                self._reopen()

    def read(self, secs=1.0):
        end = time.time() + secs
        out = b""
        while time.time() < end:
            try:
                out += self.s.read(4000)
            except Exception:
                self._reopen()
        return out.decode("utf-8", "replace")

    def cmd(self, data, secs=1.2):
        """Send a command, return the text the device printed back."""
        self.send(data)
        return self.read(secs)

    def wait_ready(self, timeout=70, app=False):
        """Wait until the console task answers. If app=True, wait further until the
        main app has finished init (reached setup=2 or dashboard=3), so data-driven
        commands (dump/tap/screen) act on a live app rather than the boot screen."""
        t = time.time()
        seen = False
        while time.time() - t < timeout:
            sid = self.screen_id()
            if sid >= 0:
                seen = True
                if not app or sid >= 2:  # 2 setup, 3 dashboard, ... = app ready
                    return True
            time.sleep(1.0)
        return seen

    def screen_id(self):
        # Parse the exact "[scr] N" line — not any digit (log lines have stray digits).
        m = re.search(r"\[scr\] (\d+)", self.cmd("s", 0.8))
        return int(m.group(1)) if m else -1

    def dump(self, path):
        """Trigger 'D' and reconstruct the 4bpp framebuffer into a PNG."""
        from PIL import Image
        for _ in range(3):
            try:
                self.s.reset_input_buffer()
                self.s.write(b"D")
                buf = b""
                dl = time.time() + 12
                while b"FBDUMP " not in buf:
                    buf += self.s.read(1)
                    if time.time() > dl:
                        raise TimeoutError("no FBDUMP header")
                while not buf.endswith(b"\n"):
                    buf += self.s.read(1)
                h = buf.split(b"FBDUMP ")[-1].split()
                W, H = int(h[0]), int(h[1])
                n = (W // 2) * H
                d = bytearray()
                dl = time.time() + 30
                while len(d) < n:
                    c = self.s.read(n - len(d))
                    if c:
                        d += c
                    elif time.time() > dl:
                        break
                im = Image.new("L", (W, H))
                px = im.load()
                rb = W // 2
                for row in range(H):
                    base = row * rb
                    for col in range(rb):
                        b = d[base + col] if base + col < len(d) else 0xFF
                        px[2 * col, row] = (b & 0xF) * 17
                        px[2 * col + 1, row] = ((b >> 4) & 0xF) * 17
                im.save(path)
                return im
            except Exception:
                self._reopen()
        return None


def decode_qr(im):
    """Decode QR codes in the image. Uses OpenCV (pyzbar segfaults on macOS arm)."""
    try:
        import cv2, numpy as np
        g = np.array(im.convert("L"))
        det = cv2.QRCodeDetector()
        for scale in (1, 2, 3):  # e-paper QRs are small; upscaling helps detection
            img = g if scale == 1 else cv2.resize(g, None, fx=scale, fy=scale,
                                                  interpolation=cv2.INTER_NEAREST)
            ok, texts, pts, _ = det.detectAndDecodeMulti(img)
            hits = [t for t in (texts or []) if t]
            if hits:
                return hits
        t, _, _ = det.detectAndDecode(g)
        return [t] if t else ["(no QR detected)"]
    except Exception as e:
        return ["(decode error: %s)" % e]


def main():
    ap = argparse.ArgumentParser(description="VulnCast device debug console (host side)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info", help="device state (i)")
    sub.add_parser("channels", help="list channels (C)")
    sub.add_parser("refresh", help="fetch the active channel now (r)")
    sub.add_parser("reboot", help="reboot the device (R)")
    sub.add_parser("touchmon", help="echo real panel taps; Ctrl-C to stop (M)")
    sub.add_parser("repl", help="interactive: type raw console chars")
    sp = sub.add_parser("screen", help="preview a screen"); sp.add_argument("n")
    sp = sub.add_parser("tap", help="inject a touch"); sp.add_argument("x"); sp.add_argument("y")
    sp = sub.add_parser("press", help="tap a named control"); sp.add_argument("name")
    sp = sub.add_parser("dump", help="screenshot -> PNG")
    sp.add_argument("path", nargs="?", default="fb.png")
    sp.add_argument("-q", "--qr", action="store_true", help="also decode QR codes")
    sp.add_argument("-j", "--jump", help="jump to a screen first (e.g. 2, 9, V)")
    sp = sub.add_parser("raw", help="send raw console chars"); sp.add_argument("chars")
    args = ap.parse_args()

    c = Console()
    # Data-driven commands need the app fully up (connected, on a real screen). For
    # a boot hang, wait_ready(app) times out and still shows whatever state it reached.
    need_app = args.cmd in ("dump", "screen", "tap", "press", "refresh", "channels", "info")
    if not c.wait_ready(app=need_app):
        print("device not answering (still connecting?) — proceeding anyway", file=sys.stderr)

    if args.cmd == "info":
        print(c.cmd("i", 1.4).strip())
    elif args.cmd == "channels":
        print(c.cmd("C", 1.2).strip())
    elif args.cmd == "refresh":
        print(c.cmd("r", 1.0).strip())
    elif args.cmd == "reboot":
        print(c.cmd("R", 1.0).strip())
    elif args.cmd == "screen":
        print(c.cmd(args.n, 3.0).strip(), "->", SCREENS.get(c.screen_id(), "?"))
    elif args.cmd == "tap":
        print(c.cmd(f"t {args.x} {args.y}\n", 2.6).strip(), "-> screen", SCREENS.get(c.screen_id(), "?"))
    elif args.cmd == "press":
        if args.name not in NAMED:
            sys.exit("unknown control; known: " + ", ".join(NAMED))
        x, y = NAMED[args.name]
        print(c.cmd(f"t {x} {y}\n", 2.6).strip(), "-> screen", SCREENS.get(c.screen_id(), "?"))
    elif args.cmd == "dump":
        if args.jump:
            c.cmd(args.jump, 4.0)
        im = c.dump(args.path)
        if im is None:
            sys.exit("dump failed")
        print("saved", args.path, im.size)
        if args.qr:
            print("QR:", decode_qr(im))
    elif args.cmd == "raw":
        print(c.cmd(args.chars, 1.5).strip())
    elif args.cmd == "touchmon":
        c.cmd("M", 0.6)
        print("touch monitor ON — tap the panel (Ctrl-C to stop)")
        try:
            while True:
                sys.stdout.write(c.read(1.0))
                sys.stdout.flush()
        except KeyboardInterrupt:
            c.cmd("M", 0.4)
            print("\ntouch monitor off")
    elif args.cmd == "repl":
        print("REPL — type console chars (e.g. i, s, C, D not supported here). Ctrl-C to exit.")
        try:
            while True:
                line = input("> ")
                if line:
                    print(c.cmd(line + ("\n" if line[0] == "t" else ""), 1.5).strip())
        except (KeyboardInterrupt, EOFError):
            print()


if __name__ == "__main__":
    main()
