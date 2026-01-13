#!/usr/bin/env python3

import time
import re
import subprocess
from datetime import datetime

LOG_FILE = "/var/log/auth.log"
HONEYPOT_USER = "testadmin"

SSH_REGEX = re.compile(
    r"(Failed|Accepted) password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

def block_ip(ip):
    subprocess.run(
        ["ufw", "deny", "from", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line

def main():
    print("[*] Starting SSH honeypot detector")
    print(f"[*] Honeypot user: {HONEYPOT_USER}")
    print(f"[*] Log file: {LOG_FILE}\n")

    with open(LOG_FILE, "r") as log:
        for line in follow(log):
            match = SSH_REGEX.search(line)
            if not match:
                continue

            user = match.group("user")
            ip = match.group("ip")

            if user == HONEYPOT_USER:
                print(
                    "\n[ALERT] Honeypot SSH access attempt detected\n"
                    f"User: {HONEYPOT_USER}\n"
                    f"Source IP: {ip}\n"
                    f"Time: {datetime.now()}\n"
                )
                block_ip(ip)

if __name__ == "__main__":
    main()
