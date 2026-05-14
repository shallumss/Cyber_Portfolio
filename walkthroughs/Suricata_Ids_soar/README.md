# SlowLoris Active Response Pipeline

Automated detection and mitigation of SlowLoris HTTP flood attacks using Suricata, Wazuh, and n8n.

## Overview

This project demonstrates a complete end-to-end security automation pipeline that:

- Detects SlowLoris attacks using custom Suricata IDS rules
- Ships alerts to Wazuh for centralized monitoring
- Queries alerts through Elasticsearch
- Automatically blocks attacker IPs using iptables over SSH
- Sends real-time email notifications
- Requires zero manual intervention once the attack begins

The goal of the project was to build a fully automated detection and response workflow instead of only generating alerts.

---

# Architecture

The lab environment consists of four systems running on the same subnet (`150.1.7.0/24`):

| Machine | Role | IP Address |
|---|---|---|
| Rocky Linux | Suricata IDS + Wazuh Agent | `150.1.7.140` |
| Wazuh Server | SIEM + Elasticsearch | `150.1.7.99` |
| Metasploitable 2 | Victim Web Server | `150.1.7.104` |
| Kali Linux | Attacker Machine | `150.1.7.101` |

## Workflow

1. Kali launches a SlowLoris attack against Metasploitable
2. Suricata detects abnormal SYN connection behavior
3. Wazuh ingests and indexes the alert
4. n8n polls Elasticsearch every 15 seconds
5. n8n extracts the attacker IP
6. An SSH command adds an iptables DROP rule
7. A structured email alert is sent

---

# Technologies Used

- Suricata
- Wazuh
- n8n
- Elasticsearch
- iptables
- pentmenu
- Rocky Linux
- Kali Linux
- Metasploitable 2

---

# Features

- Custom Suricata IDS signatures
- Real-time SlowLoris detection
- Wazuh SIEM integration
- Automated SOAR workflow using n8n
- Automatic attacker IP blocking
- Email-based alerting
- Duplicate alert suppression
- Alert age filtering and cooldown logic

---

# Suricata Detection Rules

## Ping of Death Test Rule

```rules
alert icmp any any -> any any (
    msg:"Ping of Death - Oversized ICMP";
    dsize:>1000;
    itype:8;
    sid:1000002;
    rev:1;
)
```

## SlowLoris Detection Rule

```rules
alert tcp any any -> $HOME_NET 80 (
    msg:"SLOWLORIS High Connection Rate to HTTP Port";
    flow:to_server;
    flags:S;
    threshold:type threshold, track by_src, count 20, seconds 10;
    sid:1000011;
    rev:2;
)
```

---

# Installation

## Install Suricata 8 on Rocky Linux

```bash
sudo dnf install 'dnf-command(copr)'
sudo dnf copr enable @oisf/suricata-8.0
sudo dnf install epel-release
sudo dnf install suricata
```

## Configure Suricata

Edit `/etc/suricata/suricata.yaml`

```yaml
HOME_NET: "[150.1.7.0/24]"
EXTERNAL_NET: "any"

default-rule-path: /etc/suricata/rules

rule-files:
  - "*.rules"

af-packet:
  - interface: ens192
```

Restart Suricata:

```bash
sudo systemctl daemon-reload
sudo systemctl restart suricata
sudo systemctl status suricata
```

---

# Wazuh Agent Setup

## Install Wazuh Agent

```bash
curl -o wazuh-agent-4.14.4-1.x86_64.rpm \
https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.4-1.x86_64.rpm

sudo WAZUH_MANAGER='150.1.7.99' \
WAZUH_AGENT_NAME='RockyLinux-Suricata2-9.3' \
rpm -ihv wazuh-agent-4.14.4-1.x86_64.rpm
```

---

# n8n SOAR Workflow

## Elasticsearch Query

```json
POST https://150.1.7.99:9200/wazuh-alerts-4.x-*/_search
{
  "size": 1,
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ],
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "data.alert.signature_id": "1000011"
          }
        }
      ],
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-30s"
            }
          }
        }
      ]
    }
  }
}
```

## SSH Auto-Mitigation

```bash
echo 'msfadmin' | sudo -S iptables -L INPUT -n | \
grep -q "{{ $('Extract, Filter & Cool-down').item.json.src_ip }}" || \
echo 'msfadmin' | sudo -S iptables -A INPUT \
-s {{ $('Extract, Filter & Cool-down').item.json.src_ip }} -j DROP
```

---

# Launching the Attack

## Install pentmenu on Kali

```bash
git clone https://github.com/GinjaChris/pentmenu.git

cd pentmenu
./pentmenu
```

Navigate to:

```text
2 -> Network
9 -> SlowLoris
```

Target IP:

```text
150.1.7.104
```

---

# Verification

## Verify DROP Rule

```bash
sudo iptables -L INPUT -n
```

Expected:

```text
DROP all -- 150.1.7.101 0.0.0.0/0
```

---

# Future Improvements

- Replace polling with webhook-based alerting
- Add firewall integration with pfSense or FortiGate
- Push alerts to Slack or Discord
- Add GeoIP enrichment
- Store blocked IPs in Redis
- Add automatic unblock timers
- Containerize the environment using Docker

---

# Disclaimer

This project was built in a controlled lab environment for educational and defensive security purposes only.

---

# Author

**Shallum Safdar**

Cybersecurity | SOC Automation | Detection Engineering | SIEM & SOAR Integration
