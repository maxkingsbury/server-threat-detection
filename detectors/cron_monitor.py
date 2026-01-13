#!/usr/bin/env python3

import os
import hashlib
import time
from datetime import datetime

CRON_FILES = ["/etc/crontab"]
CRON_DIR = "/etc/cron.d"
CHECK_INTERVAL = 30

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def snapshot():
    state = {}

    for path in CRON_FILES:
        state[path] = file_hash(path)

    for name in os.listdir(CRON_DIR):
        full = os.path.join(CRON_DIR, name)
        if os.path.isfile(full):
            state[full] = file_hash(full)

    return state

def main():
    print("[*] Starting cron persistence monitor\n")

    baseline = snapshot()

    while True:
        time.sleep(CHECK_INTERVAL)
        current = snapshot()

        if current != baseline:
            print(
                "\n[ALERT] Cron persistence change detected\n"
                f"Time: {datetime.now()}\n"
            )
            baseline = current

if __name__ == "__main__":
    main()
