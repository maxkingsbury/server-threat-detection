# Defensive Security Lab

A defensive security testing environment to detect attacks against a modern Linux server 

## Lab Overview
- OS: Ubuntu Server 22.04 LTS
- Services: OpenSSH
- Network: VM Host-Only Network

## Goals
- Understand how common attacks look in system logs
- Build detection tools to identify attacks
- Practice thinking from a defence perspective

## Repository Structure
- `detectors/` – Detection scripts
- `samples/` – Sanitized example logs
- `docs/` – Lab documentation and analysis

---

## Server Security Measures

### Honeypot Validation
A decoy ssh account named "testadmin" is deployed to mimic an entry point for malicious login attempts
Upon receiving a login attempt the ip address is blocked and an alert is sent

### File Integrity Monitoring
Any modification to critical system authentication or authorization files triggers an immediate alert
- Hash files at startup
- Periodically re-hash
- Alert if hash changes

### Cron Persistence Detection
Any creation or modification of system cron jobs indicates potential persistence and triggers an alert

## Disclaimer
This lab is for educational purposes only. All testing was performed
against systems I own or am authorized to test.
