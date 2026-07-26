# Cyber Shield Threat Intelligence & Real-Time Alerting System

## Comprehensive Documentation

---

## 1. System Overview

**Cyber Shield** is an automated threat intelligence feed ingestion, network traffic correlation, and real-time security alerting system built on top of **n8n**, **MongoDB**, **Tshark (Wireshark)**, and **Discord**.

The system operates in two core operational loops:

1. **Threat Intelligence Ingestion Pipeline (24h Sync):** Fetches, cleans, and stores high-volume threat intelligence indicators (IP addresses and domains) from trusted threat feeds into a MongoDB database.


2. **Real-Time Detection & Correlation Engine:** Listens to real-time network traffic captured by an edge sensor (running Tshark/PowerShell), cross-references active connections against the local threat intelligence database, calculates risk severity, and posts actionable incident alerts to a Discord channel.



---

## 2. System Architecture & Component Workflow

```
[ Edge Network Sensor ]
     (Tshark / PS1)
           │
           │ HTTP POST (Header Auth)
           ▼
[ n8n: Cyber Shield Agent ] ◄─────── [ MongoDB Threat Intel DB ]
           │                                 ▲
           │ Risk Scoring & Correlation      │ 24h Scheduled Sync
           ▼                                 │
[ Discord Alert Channel ]            [ Threat Intel DB Workflow ]
                                             │
                                     ├── FeodoTracker Feed
                                     ├── Ipsum Feed
                                     └── EmergingThreats Feed

```

---

## 3. Workflow Specifications

### A. Real-Time Detection Engine: `Cyber Shield Agent`

* **Purpose:** Inspect incoming live connection streams against active threat feeds and trigger automated Discord alerts when high/medium-risk indicators are identified.


* **Ingress Method:** HTTP Webhook (`POST`) protected via Header Authentication.



```
Webhook ──► Mongo Query (Feodotracker) ──► Edit Fields ──┐
        ├──► Mongo Query (Ipsum)        ──► Edit Fields ──┼─► Merge ──► Correlation Code ──► IF (Hits > 0) ──► Discord Node
        └──► Mongo Query (EmergingThreats)─► Edit Fields ──┘

```

#### Node Breakdown & Logic:

1. **Webhook Node (`Listen to Tshark`):** Receives structured network traffic logs containing `src_ip`, `dst_ip`, `domain`, and `timestamp`.


2. **MongoDB Parallel Query Nodes (`feodotracker`, `ipsum`, `emergingthreat`):** Queries MongoDB collections concurrently using standard `$or` and `$in` query syntax to match incoming destination IPs and domains:


```json
{
  "$or": [
    { "type": "ip", "indicator": { "$in": ["dst_ip_1", "dst_ip_2"] } },
    { "type": "domain", "indicator": { "$in": ["domain_1", "domain_2"] } }
  ]
}

```


3. **Set / Edit Fields Nodes:** Appends an `intel_source` field (e.g., `"feodotracker"`, `"ipsum"`, or `"emergingthreats"`) to identify where a match was found.


4. **Merge Node:** Combines output streams from all three parallel database lookups.


5. **Correlate Malicious Connection (Code Node):** Ingests incoming network traffic, correlates indicators against database hits, and generates the alert payload:


* **Full Connection Object Preservation:** Grabs and attaches the **entire connection object** (`conn` containing `src_ip`, `dst_ip`, `domain`, and `timestamp`) directly from the Webhook node. This ensures full connection context—including the domain—is always passed to downstream alerts regardless of risk severity.


* **Indicator Correlation:** Evaluates the connection's `dst_ip` against IP threat hits (`ipHits`) and `domain` against domain threat hits (`domainHits`).


* **Risk Scoring:**
* **High Risk:** Both `dst_ip` and `domain` match malicious entries.


* **Medium Risk:** Only `domain` matches malicious entries (full connection object attached).


* **Medium Risk:** Only `dst_ip` matches malicious entries (full connection object attached, preserving domain).


6. **If Node:** Filters execution—proceeds only if matched alert objects are present (`notEmpty`).


7. **Discord Node:** Sends structured rich embeds to the target Discord webhook channel.



---

### B. Threat Intelligence Data Pipeline: `Threat Intel DB`

* **Purpose:** Scheduled daily synchronization of external threat intelligence feeds.
* **Execution Trigger:** Schedule Trigger (Every 24 Hours).

```
Schedule Trigger ──► HTTP Request (FeodoTracker)     ──► Clean Data 1 ──► IF ──► Sub-workflow (MongoDB_Intel_1)
                 ├──► HTTP Request (Ipsum)            ──► Clean Data 2 ──► IF ──► Sub-workflow (MongoDB_Intel_2)
                 └──► HTTP Request (EmergingThreats)  ──► Clean Data 3 ──► IF ──► Sub-workflow (MongoDB_Intel_3)

```

#### Why Sub-Workflows are Used:

* **Performance:** Direct MongoDB node batch updates in primary canvas can stall or drop under heavy loads.
* **Reliability:** Standard n8n MongoDB nodes experience issues with "Continue on error output". Delegating updates to dedicated sub-workflows allows for safer batch loops (5,000 records/iteration) and error isolates.



---

### C. Batch Insertion Sub-Workflows (`MongoDB_Intel_1`, `2`, `3`)

* **Purpose:** Wipes old threat intelligence records and performs batch inserts of fresh indicators.



```
Data Input ──► Delete Documents (Wipe Collection) ──► Loop Over Items (Batch Size: 5000) ──► Insert Documents ──► Success
                                                               ▲                                   │
                                                               └───────────────────────────────────┘

```

* **Batching Configuration:** `batchSize: 5000`.


* **Database Target Collections:**
* `intel_feodotracker`

* `intel_ipsum`

* `intel_emergingthreats`




---

## 4. Threat Scoring & Discord Alert Format

### Risk Scoring Matrix

| Incident Severity | Condition | Discord Embedded Color Code |
| --- | --- | --- |
| **High Risk** | Matched BOTH malicious IP and malicious Domain | **Red** (`16711680` / `#FF0000`) |
| **Medium Risk** | Matched malicious IP OR malicious Domain only | **Amber** (`16753920` / `#FF8C00`) |

### Discord Alert Preview Example

```text
🚨 Threat Intelligence Alert

Connection
Src IP: xxxxx
Dst IP: yyyyy
Domain: zzzzz
Time: 7/21/2026, 09:13:07

Threat IP Source
feodotracker

Threat Domain Source
feodotracker

Intel:
High Risk: Malicious IP (yyyyy) and domain (zzzzz) detected

```

---

## 5. Database Schema (MongoDB `threat_intel`)

The local database maintains three core indicator collections:

| Database Name | Collection Name | Sample Record Document Structure |
| --- | --- | --- |
| `threat_intel` | `intel_feodotracker`<br> | `{ "_id": ObjectId("..."), "indicator": "195.178.110.137", "type": "ip" }` |
| `threat_intel` | `intel_ipsum`<br> | `{ "_id": ObjectId("..."), "indicator": "94.154.43.50", "type": "ip" }` |
| `threat_intel` | `intel_emergingthreats`<br> | `{ "_id": ObjectId("..."), "indicator": "malicious-domain.com", "type": "domain" }` |

### Database Indexes

To optimize lookup performance, each collection uses a compound index on `indicator` and `type`.

#### Setup via MongoDB Compass GUI
1. On each collection -> Select **Indexes** tab -> Click **Create Index**.
2. Add Field 1: `indicator` -> Select `1 (asc)`.
3. Add Field 2: `type` -> Select `1 (asc)`.
4. Leave options unchecked and click **Create Index**.

#### Setup via MongoDB Shell / Code
```javascript
// Run on each collection: intel_feodotracker, intel_ipsum, intel_emergingthreats
db.collection.createIndex({ "indicator": 1, "type": 1 });
```
---
## 6. Sensor Deployment Script (Tshark PowerShell Agent)

Network traffic is captured via a dedicated PowerShell script (included in this repository) that acts as a continuous wrapper around `tshark`. It actively sniffs network interfaces for outbound connections and forwards the telemetry to the n8n agent.

### Configuration Variables

Before running the script, open it and define the following variables at the top of the file:

| Variable | Description |
| --- | --- |
| `$WebhookUrl` | The full HTTP endpoint of your n8n Cyber Shield Agent Webhook. |
| `$InterfaceNum` | The numeric ID of the network interface tshark should listen on (Run `tshark -D` to find your interface number). |
| `$SecretKey` | Your custom API Key / Password, sent via the `X-API-KEY` header to authenticate with n8n. |

### Running the Script & Execution Policies

By default, Windows restricts running custom or unsigned PowerShell scripts. To execute the sensor, you must modify the Execution Policy.

**Option A: Temporary Bypass (Recommended for testing)**

This modifies the policy *only* for the current active PowerShell window. Once you close the terminal, the security policy reverts to its safe default.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\sensor_v3_test.ps1
```

**Option B: Permanent Bypass (For permanent/production deployments)**

If you are setting this up to run automatically on startup or in the background and do not want to manually bypass the policy every time, you can set it permanently. **Open PowerShell as Administrator** and run:

```powershell
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
```

*(After doing this, you can execute `.\sensor_v3_test.ps1` or any other powershell script normally anytime).*

### Script Execution Flow & Payload Schema

The script runs in an infinite loop, capturing network data in batches and structuring it before transmission.

#### Internal Workflow Tree

```text
[Start Infinite Loop]
 │
 ├──► 1. Traffic Capture (30-second window)
 │       Target: TLS SNI handshakes (tls.handshake.type == 1)
 │
 ├──► 2. Data Extraction
 │       Fields mapped: timestamp, src_ip, dst_ip, domain
 │
 ├──► 3. Noise Filtering
 │       Drops empty lines.
 │       Drops local/broadcast destinations (127.*, 192.168.*, 10.*).
 │
 ├──► 4. Deduplication
 │       Groups identical connections (src, dst, domain) within the same window.
 │       Preserves only the timestamp of the first packet.
 │
 ├──► 5. Payload Transmission
 │       Action: HTTP POST to Webhook
 │       Headers: { "X-API-KEY": "$SecretKey", "Content-Type": "application/json" }
 │       Body: JSON Array of structured events (See Schema below)
 │
 └──► 6. Cooldown (5 seconds)
         Loops back to Start
```

#### Transmitted JSON Payload Schema

The webhook receives a deduplicated JSON array of connection objects matching this schema:

```json
[
  {
    "src_ip": "192.168.1.100",
    "dst_ip": "104.18.32.7",
    "domain": "malicious-example.com",
    "timestamp": "May 15, 2024 14:32:01.123456000"
  },
  {
    "src_ip": "192.168.1.100",
    "dst_ip": "93.184.216.34",
    "domain": "another-domain.org",
    "timestamp": "May 15, 2024 14:32:10.987654000"
  }
]
```
