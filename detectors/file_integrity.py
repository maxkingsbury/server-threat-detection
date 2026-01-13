#!/usr/bin/env python3

import hashlib
import time
from datetime import datetime

FILES_TO_MONITOR = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
]

CHECK_INTERVAL = 30  # seconds

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def main():
    print("[*] Starting file integrity monitor")
    print("[*] Monitoring critical system files\n")

    baseline = {}
    for path in FILES_TO_MONITOR:
        baseline[path] = file_hash(path)

    while True:
        time.sleep(CHECK_INTERVAL)

        for path in FILES_TO_MONITOR:
            current = file_hash(path)
            if current != baseline[path]:
                print(
                    "\n[ALERT] File integrity violation detected\n"
                    f"File: {path}\n"
                    f"Time: {datetime.now()}\n"
                )
                baseline[path] = current  # prevent alert spam

if __name__ == "__main__":
    main()
