<div align="center">

# ⚡ VulnCast — screen gallery

The full on-device UI, captured from the live 960×540 e-paper framebuffer. Wi-Fi names shown are
placeholders.

**[← Back to README](../README.md)**

</div>

---

## Boot
![Boot](boot.png)
Splash with staged init progress (display · storage · radio) and the firmware version.

## Connecting
![Connecting](connecting.png)
Non-blocking join with live per-step progress (radio → IP → NTP → API key); the UI never blocks.

## Setup (captive portal)
![Setup](setup.png)
First boot with no known Wi-Fi (or after a sustained reconnect failure) raises the `VulnCast-Setup`
WPA2 hotspot with a Wi-Fi QR and a web provisioning page.

## Dashboard
![Dashboard](dashboard.png)
Rotating channels: a featured champion (severity, metrics, summary) plus a candidate feed. The status
bar shows sync age, Vulners API status, and the live web-interface IP.

## Document — CVE
![CVE document](document.png)
Full record for a vulnerability: CVSS + AI-score tiles, CWE chip, the CVSS vector decoded into
exploitability icons and C/I/A impact bars, a scrollable summary, and a QR deep-link to vulners.com.

## Document — exploit
![Exploit document](document-exploit.png)
The document view adapts to the record type: an exploit shows TARGETS / SOURCE facts and an EXPLOIT
tag instead of the CVSS vector — same layout engine, archetype-driven content.

## Settings
![Settings](settings.png)
On-device management: Wi-Fi networks, per-channel enable + refresh interval, and the time zone — all
saved to NVS. (Wi-Fi names redacted.)

## Wi-Fi keyboard
![Keyboard](keyboard.png)
On-screen keyboard for the Wi-Fi password, with a symbol layer and a show-password toggle; only the
field repaints per keypress (no flashing).

## Refresh-interval picker
![Interval](interval.png)
Per-channel update cadence, chosen from presets.

## Time-zone picker
![Time zone](timezone.png)
Linux-installer-style scrollable IANA zone list with UTC offsets; time syncs over NTP.
