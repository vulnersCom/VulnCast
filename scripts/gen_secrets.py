"""PlatformIO pre-build hook: generate include/secrets.h from secrets.yaml.

secrets.yaml and include/secrets.h are git-ignored and must never be committed.
Parsing is intentionally dependency-free (no PyYAML): secrets.yaml is a flat
`key: "value"` map. Values are C-string escaped for the generated header.
"""

import os

Import("env")  # noqa: F821  (provided by PlatformIO SCons)

project_dir = env["PROJECT_DIR"]  # noqa: F821
secrets_yaml = os.path.join(project_dir, "secrets.yaml")
out_dir = os.path.join(project_dir, "include")
out_file = os.path.join(out_dir, "secrets.h")


def parse_flat_yaml(path):
    data = {}
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
                value = value[1:-1]
            data[key] = value
    return data


def c_escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def write_header(values):
    os.makedirs(out_dir, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as handle:
        handle.write("// AUTO-GENERATED from secrets.yaml by scripts/gen_secrets.py.\n")
        handle.write("// DO NOT COMMIT. Regenerated on every build.\n")
        handle.write("#pragma once\n")
        handle.write('#define WIFI_SSID "%s"\n' % c_escape(values.get("wifi_ssid", "")))
        handle.write('#define WIFI_PASSWORD "%s"\n' % c_escape(values.get("wifi_password", "")))
        handle.write('#define VULNERS_API_KEY "%s"\n' % c_escape(values.get("vulners_api_key", "")))
        ota = values.get("ota_password", values.get("wifi_password", "vulncast"))
        handle.write('#define OTA_PASSWORD "%s"\n' % c_escape(ota))


if os.path.isfile(secrets_yaml):
    write_header(parse_flat_yaml(secrets_yaml))
    print("gen_secrets: wrote include/secrets.h from secrets.yaml")
elif os.path.isfile(out_file):
    print("gen_secrets: secrets.yaml not found; keeping existing include/secrets.h")
else:
    raise SystemExit(
        "gen_secrets: secrets.yaml not found and include/secrets.h missing. "
        "Copy secrets.yaml.example to secrets.yaml and fill it in."
    )
