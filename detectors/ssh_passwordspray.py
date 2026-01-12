#!/usr/bin/env python3

import time
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

LOG_FILE = "/var/log/auth.log"
TIME_WINDOW_SECONDS = 300
MIN_DISTINCT_USERS = 5
MAX_FAILURES_PER_USER = 2
SSH_FAIL_REGEX = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Data structure
# ip_attempts[ip][username] -> deque[timestamps]
ip_attempts = defaultdict(lambda: defaultdict(deque))

# Helper functions
def prune_old_attempts(ip, now):
    """Remove attempts outside the time window."""
    cutoff = now - timedelta(seconds=TIME_WINDOW_SECONDS)

    for user in list(ip_attempts[ip].keys()):
        attempts = ip_attempts[ip][user]
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        if not attempts:
            del ip_attempts[ip][user]

    if not ip_attempts[ip]:
        del ip_attempts[ip]


def check_password_spray(ip):
    """Determine if password spray conditions are met."""
    users = ip_attempts[ip]

    distinct_users = len(users)
    if distinct_users < MIN_DISTINCT_USERS:
        return False

    for attempts in users.values():
        if len(attempts) > MAX_FAILURES_PER_USER:
            return False

    return True


def alert(ip):
    users = list(ip_attempts[ip].keys())
    print(
        "\n[ALERT] Password spray detected\n"
        f"Source IP: {ip}\n"
        f"Distinct usernames: {len(users)}\n"
        f"Usernames: {', '.join(users)}\n"
        f"Time window: {TIME_WINDOW_SECONDS // 60} minutes\n"
    )

# Main loop
def follow(file):
    """Generator to follow a log file (tail -f style)."""
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.2)
            continue
        yield line


def main():
    print("[*] Starting SSH password spray detector")
    print(f"[*] Log file: {LOG_FILE}")
    print(f"[*] Time window: {TIME_WINDOW_SECONDS}s")
    print(f"[*] Min distinct users: {MIN_DISTINCT_USERS}")
    print(f"[*] Max failures per user: {MAX_FAILURES_PER_USER}\n")

    with open(LOG_FILE, "r") as log:
        for line in follow(log):
            match = SSH_FAIL_REGEX.search(line)
            if not match:
                continue

            ip = match.group("ip")
            user = match.group("user")
            now = datetime.now()

            ip_attempts[ip][user].append(now)
            prune_old_attempts(ip, now)

            if check_password_spray(ip):
                alert(ip)
                # reset after alert to avoid spam
                del ip_attempts[ip]


if __name__ == "__main__":
    main()
