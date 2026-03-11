#  TryHackMe — Threat Hunting Walkthrough
### Detecting a Data Exfiltration Attempt via Firewall, VPN & IDS Log Analysis

---

##  Lab Objective

> Identify the external threat actor, trace their path through the network, and determine which internal host was used to exfiltrate data.

**Log files analysed:**
- `firewall.log`
- `vpn_auth.log`
- `ids_alerts.log`

---

##  Summary of Findings

| Finding | Value | Log Source |
|---|---|---|
| Attacker External IP | `203.0.113.45` | firewall.log (BLOCK analysis) |
| Primary Internal Target | `10.0.0.50` | firewall.log (dest IP analysis) |
| Brute-Forced Username | `svc_backup` | vpn_auth.log (FAIL analysis) |
| Attacker's VPN IP | `10.8.0.23` | vpn_auth.log (SUCCESS session) |
| Lateral Movement Port | `445 (SMB)` | ids_alerts.log (SMB alerts) |
| C2 Beaconing Host | `10.0.0.60` | ids_alerts.log (C2 alerts) |
| C2 Server IP | `198.51.100.77` | ids_alerts.log (C2 alerts) |
| Exfiltration Host | `10.0.0.51` | ids_alerts.log (Exfiltration alerts) |

---

##  Attack Chain

```
1. RECONNAISSANCE     → 203.0.113.45 fires 279 blocked probes at the perimeter firewall
2. BRUTE FORCE        → 118 failed VPN login attempts against svc_backup
3. INITIAL ACCESS     → Attacker authenticates via VPN, assigned internal IP 10.8.0.23
4. LATERAL MOVEMENT   → 10.8.0.23 attempts SMB exploitation across internal hosts on port 445
5. C2 ESTABLISHMENT   → 10.0.0.60 begins beaconing to 198.51.100.77:4444 every 6 hours
6. EXFILTRATION       → 10.0.0.51 sends large HTTP POST uploads to 198.51.100.77:8080/80
```

---

##  Step-by-Step Investigation

### Step 1 — Identify the External Attacker via Firewall Reconnaissance

**Question:** Which external IP performed the most reconnaissance?

The first task was to find which external IP was hammering the firewall hardest. Reconnaissance shows up as a high volume of blocked connection attempts from a single source.

**Count BLOCKED connections by source IP:**

```bash
grep "BLOCK" firewall.log | cut -d " " -f 5 | cut -d: -f1 | sort -nr | uniq -c
```

**How the pipeline works:**

| Command | Purpose |
|---|---|
| `grep "BLOCK"` | Filters only BLOCKED firewall events |
| `cut -d " " -f 5` | Extracts the 5th field (source IP:port) |
| `cut -d: -f1` | Strips the port, keeping only the IP |
| `sort -nr \| uniq -c` | Counts and sorts highest first |

**Result:**
```
279 203.0.113.45
 46 203.0.113.10
 26 10.8.0.23
```

A follow-up check against ALLOW entries confirmed `203.0.113.45` eventually got through (18 allowed entries), showing the attacker persisted until they succeeded.

```bash
grep "ALLOW" firewall.log | cut -d " " -f 5 | cut -d: -f1 | sort -nr | uniq -c
```

Tailing the log also revealed regular outbound beaconing — a sign something inside was already compromised:

```bash
cat firewall.log | tail
```

```
2025-09-28 19:00:00 ALLOW TCP 10.0.0.60:30071 -> 198.51.100.77:4444
2025-09-28 19:00:00 ALLOW TCP 10.0.0.51:40059 -> 198.51.100.77:8080
2025-09-29 01:00:00 ALLOW TCP 10.0.0.60:30072 -> 198.51.100.77:4444
...
```

> ✅ **Finding:** `203.0.113.45` is the primary threat actor — 279 blocked connection attempts, and eventually gained access.

---

### Step 2 — Identify the Primary Internal Target

**Question:** Which internal host was targeted by scans?

With the attacker's IP confirmed, the next step was finding which internal host they were most focused on.

**Filter firewall log for attacker's IP and count destination IPs:**

```bash
grep "203.0.113.45" firewall.log | cut -d " " -f 7 | cut -d: -f1 | sort -nr | uniq -c
```

Field 7 of the log holds the destination (internal) IP:port. Stripping the port and counting shows which machine attracted the most traffic.

**Result:**
```
140 10.0.0.50
127 10.0.0.20
 18 10.0.0.60
 12 10.0.0.51
```

> ✅ **Finding:** `10.0.0.50` was the primary internal host targeted — hit 140 times by the attacker.

---

### Step 3 — Analyse VPN Logs for Brute Force Activity

**Question:** Which username was targeted in VPN logs?

The VPN authentication logs were the next logical step — attackers commonly brute-force VPN credentials to get a legitimate foothold inside the network.

**Step 3a — Browse the VPN log to understand its format:**

```bash
cat vpn_auth.log | tail
```

Log format: `timestamp | source_ip | username | status | assigned_ip`

**Step 3b — Count FAILED logins by source IP:**

```bash
grep "FAIL" vpn_auth.log | cut -d " " -f3 | sort -nr | uniq -c
```

**Result:**
```
118 203.0.113.45
  1 203.0.113.100
  1 198.51.100.92
  1 198.51.100.45
```

`203.0.113.45` had **118 failed VPN logins** — confirming an automated brute-force attack.

**Step 3c — Identify the targeted username (field 4 in failed entries):**

```bash
grep "FAIL" vpn_auth.log | cut -d " " -f4 | sort -nr | uniq -c
```

**Result:**
```
118 svc_backup
  2 jsmith
  1 alice
```

The `svc_backup` account was the target of all 118 failed attempts. Service accounts with elevated backup privileges are high-value targets — they often have access to sensitive data across multiple systems.

> ✅ **Finding:** The attacker brute-forced `svc_backup` with 118 attempts from `203.0.113.45` — and eventually cracked it.

---

### Step 4 — Trace the Attacker's VPN Session

**Question:** What internal IP was assigned after successful VPN login?

Once an attacker successfully authenticates to a VPN, they receive an internal IP. That IP becomes their identity inside the network — finding it is critical to tracing all subsequent activity.

**Find successful sessions for the attacker using the compromised account:**

```bash
grep "SUCCESS" vpn_auth.log | grep "203.0.113.45" | grep "svc_backup" | cut -d " " -f6 | cut -d= -f2
```

This chains three `grep` filters to narrow to exactly the sessions needed, then extracts the `assigned_ip` value by stripping the `assigned_ip=` prefix with `cut -d= -f2`.

**Result:**
```
10.8.0.193
10.8.0.104
10.8.0.23
10.8.0.23
10.8.0.181
...
```

`10.8.0.23` appeared most frequently — confirming it as the attacker's primary internal VPN address.

> ✅ **Finding:** The threat actor operated inside the network under VPN-assigned IP `10.8.0.23`.

---

### Step 5 — Detect Lateral Movement via SMB

**Question:** Which port was used for lateral SMB attempts?

With the attacker's internal VPN IP confirmed, the IDS alerts log was checked for lateral movement originating from `10.8.0.23`. SMB is a common protocol abused for lateral movement in Windows environments.

**Search IDS alerts for SMB activity from the attacker's VPN IP:**

```bash
grep "SMB" ids_alerts.log | head | grep "10.8.0.23"
```

**Result (excerpt):**
```
2025-09-05 06:10:00 [**] ET EXPLOIT Possible MS-SMB Lateral Movement [**] [Classification: Attempted Unauthorized Access] {TCP} 10.8.0.23:2001 -> 10.0.0.51:445
2025-09-05 07:00:00 [**] ET EXPLOIT Possible MS-SMB Lateral Movement [**] [Classification: Attempted Unauthorized Access] {TCP} 10.8.0.23:2006 -> 10.0.0.20:445
2025-09-05 07:40:00 [**] ET EXPLOIT Possible MS-SMB Lateral Movement [**] [Classification: Attempted Unauthorized Access] {TCP} 10.8.0.23:2010 -> 10.0.0.60:445
```

The IDS flagged repeated SMB lateral movement events from `10.8.0.23` targeting `10.0.0.51`, `10.0.0.20`, and `10.0.0.60` — all on port **445** (standard Windows file sharing / SMB port).

> ✅ **Finding:** The attacker used port `445` (SMB) from VPN IP `10.8.0.23` to attempt lateral movement across multiple internal hosts.

---

### Step 6 — Confirm C2 Beaconing

**Questions:** Which host beaconed to C2? Which IP is the C2 server?

C2 beaconing is a tell-tale sign that a host has been fully compromised and is "calling home" to the attacker's infrastructure on a regular schedule.

**Filter IDS alerts for C2 beaconing events:**

```bash
grep "C2" ids_alerts.log | head
```

**Result (excerpt):**
```
2025-09-11 01:00:00 [**] ET TROJAN Possible C2 Beaconing [**] [Classification: A network Trojan was detected] {TCP} 10.0.0.60:30000 -> 198.51.100.77:4444
2025-09-11 07:00:00 [**] ET TROJAN Possible C2 Beaconing [**] [Classification: A network Trojan was detected] {TCP} 10.0.0.60:30001 -> 198.51.100.77:4444
2025-09-11 13:00:00 [**] ET TROJAN Possible C2 Beaconing [**] [Classification: A network Trojan was detected] {TCP} 10.0.0.60:30002 -> 198.51.100.77:4444
```

`10.0.0.60` was connecting to `198.51.100.77:4444` every **6 hours** — a textbook beacon interval. Port 4444 is classically associated with Metasploit reverse shells and other C2 frameworks.

> ✅ **Finding:** Host `10.0.0.60` was beaconing to C2 server `198.51.100.77:4444` on a regular 6-hour schedule.

---

### Step 7 — Identify the Exfiltration Host

**Question:** Which host showed exfiltration attempts?

The final step was identifying which internal host was actively exfiltrating data. Exfiltration over HTTP POST blends outbound data theft into normal web traffic.

**Search IDS alerts for exfiltration events:**

```bash
grep "Exfiltration" ids_alerts.log | head
```

**Result (excerpt):**
```
2025-09-18 23:00:00 [**] ET INFO Possible HTTP POST Large Upload [**] [Classification: Potential Data Exfiltration] {TCP} 10.0.0.51:40000 -> 198.51.100.77:8080
2025-09-19 03:00:00 [**] ET INFO Possible HTTP POST Large Upload [**] [Classification: Potential Data Exfiltration] {TCP} 10.0.0.51:40001 -> 198.51.100.77:8080
2025-09-19 07:00:00 [**] ET INFO Possible HTTP POST Large Upload [**] [Classification: Potential Data Exfiltration] {TCP} 10.0.0.51:40002 -> 198.51.100.77:8080
```

The IDS flagged repeated large HTTP POST uploads from `10.0.0.51` to `198.51.100.77` on ports **8080** and **80** — the same C2 infrastructure from Step 6. Alerts ran across multiple days starting September 18, 2025.

> ✅ **Finding:** Host `10.0.0.51` was exfiltrating data to the attacker's C2 at `198.51.100.77` via HTTP POST over ports 8080 and 80.

---

## 🛠️ Tools Used

| Tool | Purpose |
|---|---|
| `grep` | Filter log entries by keyword or IP |
| `cut` | Extract specific fields from log lines |
| `sort` | Sort output numerically |
| `uniq -c` | Count and deduplicate entries |
| `cat \| tail` | View the end of log files |
| `head` | Limit output to first N lines |

---

*TryHackMe — Examine the Firewall Logs Challenge*
