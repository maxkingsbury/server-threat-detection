#!/usr/bin/env python3

import subprocess
import time
from datetime import datetime

CHECK_INTERVAL = 30

def get_listening_ports():
    result = subprocess.run(
        ["ss", "-tulpen"],
        capture_output=True,
        text=True
    )

    ports = set()

    for line in result.stdout.splitlines():
        if line.startswith("Netid") or not line.strip():
            continue

        parts = line.split()
        proto = parts[0]
        local_addr = parts[4]

        if ":" not in local_addr:
            continue

        ip, port = local_addr.rsplit(":", 1)
        process = parts[-1] if "users:" in line else "unknown"

        ports.add((proto, ip, port, process))

    return ports

def main():
    print("[*] Starting listening port monitor\n")

    baseline = get_listening_ports()

    while True:
        time.sleep(CHECK_INTERVAL)
        current = get_listening_ports()

        new_ports = current - baseline
        if new_ports:
            for proto, ip, port, process in new_ports:
                print(
                    "\n[ALERT] New listening port detected\n"
                    f"Protocol: {proto}\n"
                    f"Address: {ip}:{port}\n"
                    f"Process: {process}\n"
                    f"Time: {datetime.now()}\n"
                )

            baseline = current

if __name__ == "__main__":
    main()
