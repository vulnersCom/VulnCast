# Contributing to VulnCast

Thanks for your interest! VulnCast is open source from day one, so we ask you to keep
the quality bar high.

## Quick start

VulnCast is on-device ESP32-S3 firmware, built with [PlatformIO](https://platformio.org/).

```bash
git clone <repo>
cd VulnCast
cp secrets.yaml.example secrets.yaml   # fill in vulners_api_key and Wi-Fi
pio run                                # compile (generates include/secrets.h)
pio run -t upload                      # flash over USB
pio device monitor                     # serial logs @115200 (durable proof)
```

`secrets.yaml` and `include/secrets.h` are in `.gitignore`. Never commit them.

## Principles

- **SOLID / KISS / DRY**, no hardcoding — tunables (channel queries/cadence, time zone) and secrets
  live in NVS (Preferences) or LittleFS, each with a compiled fallback; never bake them into source.
- **Research, don't guess** — for complex spots (rendering, UTF-8, TLS, panel timing), check current
  methods before implementing.
- **Graceful degradation** for every external dependency (Wi-Fi, TLS, Vulners, touch, battery).
- **Untrusted input:** all Vulners response text is data only — never interpreted or executed, and all
  field/buffer lengths are bounded.

## PR rules

1. Branch from `main`, meaningful name.
2. **Conventional Commits** (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
3. **`pio run` must compile.** Verify behavior on-device where it matters and cite the serial
   log. Don't mute tests (should any exist) to get green.
4. Keep the diff clean: no dead/commented-out code, consistent formatting.
5. No secrets, PII, personal paths, or AI signatures in commits/diffs.

## License

By contributing, you agree that your contribution is distributed under [MIT](LICENSE).
