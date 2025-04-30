# Multi-Service Honeypot System
A Python-based honeypot that simulates multiple network services to detect, log, and analyze malicious activity. Supports real-time Prometheus metrics and Discord alerts.

---

## 📚 Table of Contents

- [Features](#-features)
- [Services](#-services)
- [Getting Started](#-getting-started)
- [Prometheus Metrics](#-prometheus-metrics)
- [Discord Alerts](#-discord-alerts)
- [Simulated Activity](#-simulated-activity)
- [Security Notice](#-security-notice)
- [License](#-license)

---

## ✨ Features

✅ Simulates common services (SSH, FTP, HTTP, Telnet, Shell)  
✅ Logs all login attempts, inputs, and command histories  
✅ Sends real-time alerts via Discord Webhook  
✅ Tracks usage using Prometheus for metrics and monitoring  
✅ Identifies suspicious commands and attack patterns  
✅ Lightweight and easy to deploy

---

## 🧰 Services

| Protocol | Behavior |
|----------|----------|
| **Shell**  | Fake shell environment that logs commands (`ls`, `cat`, etc.) |
| **SSH**    | Simulates SSH banner and login; logs usernames and passwords |
| **FTP**    | Simulates standard FTP commands (`USER`, `PASS`, `LIST`, etc.) |
| **HTTP**   | Fakes HTTP server with suspicious path detection |
| **Telnet** | Simulated login shell; captures inputs and logs activity |

---

## 🚀 Getting Started

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/multi-service-honeypot.git
cd multi-service-honeypot

---

## 📚 Table of Contents

- [Features](#-features)
- [Services](#-services)
- [Getting Started](#-getting-started)
- [Prometheus Metrics](#-prometheus-metrics)
- [Discord Alerts](#-discord-alerts)
- [Simulated Activity](#-simulated-activity)
- [Security Notice](#-security-notice)
- [License](#-license)

---

## ✨ Features

✅ Simulates common services (SSH, FTP, HTTP, Telnet, Shell)  
✅ Logs all login attempts, inputs, and command histories  
✅ Sends real-time alerts via Discord Webhook  
✅ Tracks usage using Prometheus for metrics and monitoring  
✅ Identifies suspicious commands and attack patterns  
✅ Lightweight and easy to deploy

---

## 🧰 Services

| Protocol | Behavior |
|----------|----------|
| **Shell**  | Fake shell environment that logs commands (`ls`, `cat`, etc.) |
| **SSH**    | Simulates SSH banner and login; logs usernames and passwords |
| **FTP**    | Simulates standard FTP commands (`USER`, `PASS`, `LIST`, etc.) |
| **HTTP**   | Fakes HTTP server with suspicious path detection |
| **Telnet** | Simulated login shell; captures inputs and logs activity |

---

## 🚀 Getting Started

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/multi-service-honeypot.git
cd multi-service-honeypot
```

### 2️⃣ Install Dependencies

```bash
pip install prometheus_client requests
```

### 3️⃣ Configure Discord Webhook

Open `honeypot.py` and set your Discord webhook URL:

```python
WEBHOOK_URL = "https://discord.com/api/webhooks/your_webhook_here"
```

### 4️⃣ Run the Honeypot

```bash
python honeypot.py
```

All services will start, and logs will be saved in the `sessions/` folder.

---

## 📈 Prometheus Metrics

Metrics are exposed via an HTTP server (default: `:9091`). These include:

- `honeypot_commands{service="..."}`  
- `honeypot_login_attempts{service,username}`  
- `honeypot_alerts{service,type}`  
- `honeypot_active_connections{service}`

### 📌 Sample Prometheus Scrape Config

```yaml
- job_name: 'honeypot'
  static_configs:
    - targets: ['localhost:9091']
```

---

## 🔔 Discord Alerts

Each time an attacker interacts with a honeypot (login, command, HTTP request), an alert is sent to your configured Discord webhook.

Example Alert:
```
🚨 Honeypot Alert (SSH) from IP 192.168.1.5: SSH Login Attempt: root:toor
```

---

## 🧪 Simulated Activity (Optional)

Enable simulation mode to generate fake attacker traffic:

```python
simulation_enabled = True  # in honeypot.py
```

This is useful for testing metrics, logs, and alerts without exposing the system publicly.

---

## 🔒 Security Notice

- ⚠️ **Do NOT expose this honeypot to the internet without firewall and VM isolation.**
- ⚠️ Intended for educational, research, or internal monitoring use.
- ⚠️ Use at your own risk — logs may contain dangerous payloads.

---

## 📁 File Structure

```text
.
├── honeypot.py               # Main honeypot script
├── honeypot_log.txt          # Log of suspicious activity
├── honeypot_system.log       # System-level log
├── sessions/                 # Logs for each connection/session
├── README.md                 # You're here
```

---

## Contact

Contributions and suggestions welcome!

---

## Show Your Support

If you find this useful, please ⭐️ the repository on GitHub and share it with others in the cybersecurity community!
```
