# Key SPL Queries — BOTSv1 SIEM Homelab

> **Important:** All queries below must use `earliest=0 latest=now` (All Time) because BOTSv1 data is from August 2016.

---

## 1. Data Inventory

```spl
| eventcount summarize=false index=botsv1
```
*Returns total event count for the BOTSv1 index.*

```spl
index=botsv1 | stats count by sourcetype | sort -count
```
*Lists all 22 sourcetypes and their event counts.*

---

## 2. Network Threat Detection

### Top Source IPs (Firewall)
```spl
index=botsv1 sourcetype=fgt_traffic
| stats count by srcip
| sort -count | head 10
```

### Firewall Blocks by Country
```spl
index=botsv1 sourcetype=fgt_traffic action=deny srccountry!="Reserved" srccountry!=""
| stats count by srccountry
| sort -count | head 10
```

### Suricata IDS — Top Alert Signatures
```spl
index=botsv1 sourcetype=suricata event_type=alert
| stats count by alert.signature, alert.severity, alert.category
| sort -count | head 15
```

### Suricata IDS — Alerts by Category
```spl
index=botsv1 sourcetype=suricata event_type=alert
| stats count by alert.category
| sort -count
```

---

## 3. DNS Analysis (Potential C2)

### Top DNS Hostnames Queried
```spl
index=botsv1 sourcetype=stream:dns
| mvexpand hostname{}
| search hostname{}!=""
| stats count by hostname{}
| sort -count | head 15
| rename "hostname{}" as "DNS Hostname", count as "Query Count"
```

---

## 4. Windows Event Log Analysis

### Process Creation by Account (EventCode 4688)
```spl
index=botsv1 sourcetype="wineventlog:security" EventCode=4688 Account_Name!="-"
| stats count by Account_Name
| sort -count | head 10
```

### Privilege Escalation (EventCode 4672)
```spl
index=botsv1 sourcetype="wineventlog:security" EventCode=4672
| stats count by Account_Name, Privileges
| sort -count | head 15
```

### All Windows Security EventCodes
```spl
index=botsv1 sourcetype="wineventlog:security"
| stats count by EventCode
| sort -count
```

---

## 5. Sysmon Endpoint Monitoring

### Sysmon Events by Host
```spl
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"
| stats count by host
| sort -count | head 10
```

### Top Hosts by Sysmon Activity (Potential Malware)
```spl
index=botsv1 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"
| stats count by host
| sort -count
| rename host as "Host", count as "Sysmon Events"
```

---

## 6. Web Attack Analysis (IIS)

### HTTP Methods
```spl
index=botsv1 sourcetype=iis
| stats count by cs_method
| sort -count
```

### HTTP Status Codes
```spl
index=botsv1 sourcetype=iis
| stats count by sc_status
| sort -count | head 10
```

### HTTP URIs Requested
```spl
index=botsv1 sourcetype=iis
| stats count by cs_uri_stem
| sort -count | head 20
```

---

## 7. Lateral Movement Detection

### SMB Activity
```spl
index=botsv1 sourcetype="stream:smb"
| stats count by src_ip, dest_ip, command
| sort -count | head 15
| rename src_ip as "Source IP", dest_ip as "Dest IP", command as "SMB Command"
```

---

## 8. Registry Persistence

### Registry Changes by Host
```spl
index=botsv1 sourcetype=winregistry
| stats count by host, key_path, process_image
| sort -count | head 15
| rename host as "Host", key_path as "Registry Key Path", process_image as "Process"
```

---

## 9. Attack Timeline

### Events Over Time by Sourcetype
```spl
index=botsv1 sourcetype IN (suricata, fgt_traffic, fgt_utm, "wineventlog:security", stream:http, iis)
| timechart span=1h count by sourcetype limit=6
```

---

## MITRE ATT&CK Mapping

| Technique | ID | SPL Sourcetype |
|---|---|---|
| Initial Access — Web Exploit | T1190 | `suricata`, `iis` |
| Execution — Process Creation | T1059 | `wineventlog:security` EventCode=4688 |
| Persistence — Registry Run Keys | T1547 | `winregistry` |
| Privilege Escalation | T1068 | `wineventlog:security` EventCode=4672 |
| Defense Evasion | T1562 | `sysmon` |
| C2 — DNS | T1071.004 | `stream:dns` |
| Lateral Movement — SMB | T1021.002 | `stream:smb` |
| Exfiltration | T1041 | `stream:http`, `fgt_traffic` |
