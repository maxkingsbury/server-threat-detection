# Defensive Security Lab

A defensive security testing environment to detect attacks against a modern Linux server 

## Lab Overview
- OS: Ubuntu Server 22.04 LTS
- Services: OpenSSH
- Network: VM Host-Only Network

## Purpose

This lab environment is built to simulate how a production Linux server 
might detect intrusion attempts.

The goal is to:
- Monitor system level authentication files
- Detect persistence mechanisms
- Identify unauthorized exposure
- Log and alert on suspicious login attempts

This project shows:
- Linux system admin
- Log analysis
- File integrity monitoring
- Basic intrusion detection concepts

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

### Listening Port Detector
Any newly opened listening port on the host indicates potential unauthorized service exposure and triggers an alert

## Disclaimer
This lab is for educational purposes only. All testing was performed
against systems I own or am authorized to test.
