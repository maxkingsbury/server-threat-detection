#!/usr/bin/env python3

import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
import sys

FAILURE_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=2)

LOG_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

FAILED_PASSWORD_RE = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Failed password.*from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

INVALID_USER_RE = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def parse_time(ts: str) -> datetime:
    return datetime.strptime(ts, LOG_TIME_FORMAT)

def detect_bruteforce(logfile_path: str):
    failures_by_ip = defaultdict(deque)
    alerts = []

    with open(logfile_path, "r") as f:
        for line in f:
            match = FAILED_PASSWORD_RE.search(line) or INVALID_USER_RE.search(line)
            if not match:
                continue

            event_time = parse_time(match.group("time"))
            src_ip = match.group("ip")

            window = failures_by_ip[src_ip]
            window.append(event_time)

            # Remove events outside time window
            while window and event_time - window[0] > TIME_WINDOW:
                window.popleft()

            if len(window) == FAILURE_THRESHOLD:
                alerts.append({
                    "ip": src_ip,
                    "count": len(window),
                    "window_start": window[0],
                    "window_end": event_time
                })

    return alerts

def main():
    if len(sys.argv) != 2:
        print("Usage: python ssh_bruteforce.py <auth_log_file>")
        sys.exit(1)

    logfile = sys.argv[1]
    alerts = detect_bruteforce(logfile)

    if not alerts:
        print("No SSH brute-force activity detected.")
        return

    print("SSH BRUTE-FORCE ALERTS:")
    print("-" * 40)

    for alert in alerts:
        print(
            f"IP: {alert['ip']} | "
            f"Failures: {alert['count']} | "
            f"Window: {alert['window_start']} -> {alert['window_end']}"
        )

if __name__ == "__main__":
    main()
