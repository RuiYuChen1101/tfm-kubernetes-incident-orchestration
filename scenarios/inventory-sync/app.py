import json
import sys
import time
from pathlib import Path

CONFIG_PATH = Path("/app/runtime-config.json")
SUPPORTED_SCHEMA_VERSION = 2

def main():
    print("inventory sync worker starting", flush=True)

    config = json.loads(CONFIG_PATH.read_text())

    configured_version = config.get("schema_version")

    if configured_version != SUPPORTED_SCHEMA_VERSION:
        print(
            f"ERROR incompatible runtime configuration schema: "
            f"received={configured_version}, supported={SUPPORTED_SCHEMA_VERSION}",
            flush=True,
        )
        sys.exit(1)

    print("inventory sync configuration loaded", flush=True)
    print("inventory sync worker ready", flush=True)

    while True:
        time.sleep(30)

if __name__ == "__main__":
    main()
