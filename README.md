# Linux SSH Security Monitor

<p align="center">
  <img src="https://img.icons8.com/color/96/linux--v1.png" alt="Linux" width="64"/>
  <img src="https://img.icons8.com/color/96/python--v1.png" alt="Python" width="64"/>
  <img src="https://img.icons8.com/color/96/ubuntu--v1.png" alt="Ubuntu" width="64"/>
  <img src="https://img.icons8.com/color/96/bash.png" alt="Bash" width="64"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Linux-Ubuntu-orange?logo=linux&logoColor=white" alt="Linux"/>
  <img src="https://img.shields.io/badge/Network-SSH-green?logo=openssh&logoColor=white" alt="SSH"/>
  <img src="https://img.shields.io/badge/Focus-Blue%20Team-red" alt="Blue Team"/>
</p>

## Overview

**Linux SSH Security Monitor** is a lightweight defensive cybersecurity tool written in Python. It analyzes Linux authentication logs, identifies repeated failed SSH authentication attempts, and generates alerts when activity matches a defined brute-force detection pattern. The project demonstrates practical Blue Team concepts including log analysis, SSH monitoring, event parsing, detection rules, and basic security alerting.

---

## Tools & Technologies

<div>
  <img width="48" height="48" src="https://img.icons8.com/color/48/python--v1.png" alt="Python" />
  <img width="48" height="48" src="https://img.icons8.com/color/48/linux--v1.png" alt="Linux" />
  <img width="48" height="48" src="https://img.icons8.com/color/48/ubuntu--v1.png" alt="Ubuntu" />
  <img width="48" height="48" src="https://img.icons8.com/color/48/bash.png" alt="Bash" />
  <img width="48" height="48" src="https://img.icons8.com/color/48/networking-manager.png" alt="Networking" />
  <img width="48" height="48" src="https://img.icons8.com/color/48/ssh.png" alt="SSH" />
</div>

* Python 3
* Linux / Ubuntu
* Bash
* OpenSSH
* Networking fundamentals
* JSON

---

## Architecture

```text
Linux System
     │
     ▼
OpenSSH
     │
     ▼
Authentication Logs
     │
     ▼
Python Log Parser
     │
     ▼
Detection Engine
     │
     ▼
Security Alert / JSON Report
```

---

## Features

* Parses Linux SSH authentication logs
* Detects repeated failed authentication attempts
* Supports IPv4 and IPv6 addresses
* Uses configurable time windows and thresholds
* Classifies alerts by severity
* Generates console alerts
* Exports JSON security reports
* Includes automated unit tests

---

## Detection Logic

The monitor groups failed SSH authentication attempts by source IP and evaluates them within a configurable time window.

**Default configuration:**

```text
5 failed attempts → MEDIUM
15 failed attempts → HIGH
Time window       → 5 minutes
```

Successful SSH authentications are not treated as brute-force attempts.

---

## Installation

### Linux

```bash
git clone https://github.com/YOUR_USERNAME/linux-ssh-security-monitor.git
cd linux-ssh-security-monitor
```

### Windows

```powershell
git clone https://github.com/YOUR_USERNAME/linux-ssh-security-monitor.git
cd linux-ssh-security-monitor
```

> Windows demonstrations use the included sample authentication log.

---

## Usage

### Linux

Analyze the system authentication log:

```bash
sudo python3 -m src.main --log /var/log/auth.log
```

Analyze the included sample log:

```bash
python3 -m src.main --log samples/auth.log
```

### Windows

Analyze the included sample log:

```powershell
py -m src.main --log samples\auth.log
```

---

## Testing

### Linux

```bash
python3 -m unittest -v tests.test_parser tests.test_detector
```

### Windows

```powershell
py -m unittest -v tests.test_parser tests.test_detector
```

---

## Project Structure

```text
linux-ssh-security-monitor/
├── src/
│   ├── main.py
│   ├── log_parser.py
│   ├── detector.py
│   └── alert_manager.py
├── config/
├── samples/
├── reports/
├── tests/
├── README.md
├── LICENSE
└── requirements.txt
```

## Scope

**Current version:** Linux SSH authentication monitoring and brute-force detection.

Designed as a small Blue Team / SOC-oriented security monitoring project.

---

## Author

**Ali Hasanli**
