# Security Policy

VulnCast processes vulnerability data and operates as a networked device, so we take
security seriously.

## Reporting a vulnerability

Please **do not open a public issue** for vulnerabilities. Instead, use the private
GitHub Security Advisories channel ("Report a vulnerability") in this repository, or email
**isox@vulners.com**. We aim to respond within a reasonable time and coordinate disclosure.

Include: a description, reproduction steps, potential impact, and the version/commit.

## Project security principles

- **Secrets** (`secrets.yaml`, `include/secrets.h`, `vulners_api_key`, Wi-Fi/OTA passwords) —
  outside the repository (`.gitignore`) or in device NVS only. Never logged. The provisioning
  portal never returns a stored key (write-only).
- **Untrusted input:** all Vulners response text (ids, titles, descriptions) is untrusted.
  It is rendered as data only — never interpreted or executed. Field/buffer lengths are bounded.
- **Supply chain:** dependencies are pinned in `platformio.ini` `lib_deps` (`@version`); pin new
  libraries to a released tag and review before bumping.
- **Boundaries:** validate at the network boundary (HTTP status + JSON shape); parse defensively
  with ArduinoJson filters — never trust reported totals/array sizes blindly.
- **Transport:** HTTPS to the Vulners API; OTA is password-protected. Roadmap: pin the Vulners
  certificate (v1 uses `WiFiClientSecure.setInsecure()`).

## Supported versions

The latest released version (currently **1.0.0**) and the `main` branch are supported.
