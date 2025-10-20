# 🛡️ SOC HomeLab — End-to-End Detection & Analysis Project  
**Author:** Aman Sharma  
**Contact** aman825077@gmail.com
**Role:** SOC Analyst (HomeLab Simulation)  
**Report:** [SOC_Homelab_End_to_End_Project.pdf](./SOC_Homelab_End_to_End_Project.pdf)

-

## 📘 Overview  
This project demonstrates a complete **Security Operations Center (SOC)** workflow built in a home lab environment.  
It simulates a **phishing attack investigation** — from email analysis to Snort detection and Splunk visualization — replicating real-world SOC operations.

The goal was to replicate the day-to-day responsibilities of a SOC Analyst using open-source tools.

---

## 🧩 Project Phases

### **Phase 1 — Phishing Email & Attachment Analysis**
- Analyzed suspicious phishing email headers and attachments (`quotation.iso`, malicious PDF).  
- Verified spoofing via SPF, DKIM, and DMARC.  
- Extracted Indicators of Compromise (IOCs):  
  - **IPs:** `190.6.201.67`, `185.70.40.140`  
  - **Malicious URL:** `https://script.google.com/macros/s/AKfycbw.../exec`  
- Tools Used: *VirusTotal, Hybrid Analysis, URLScan.io, emlAnalyzer.*

**Outcome:** Identified a trojan dropper embedded in the PDF and isolated the phishing callback URL for further analysis.

---

### **Phase 2 — Network Traffic Capture (Wireshark & tcpdump)**
- Simulated the malicious URL callback safely using `curl` within an isolated VM.  
- Captured traffic using `tcpdump` and analyzed in **Wireshark**.  
- Applied HTTP filters and inspected full request/response streams.  
- Ensured all communication occurred locally to maintain a safe lab environment.

**Outcome:** Produced `pdf_simulate.pcap` for packet-level inspection of phishing callback behavior.

---

### **Phase 3 — Intrusion Detection with Snort**
- Configured **Snort 2.9.20** for HTTP callback detection.  
- Wrote custom detection rules targeting the phishing URL pattern:  

```bash
alert tcp any any -> any 9090 (msg:"PHISHING - Google Script macro URI detected"; content:"/macros/s/AKfycbw"; sid:3000001; rev:1;)
```

- Tested rule performance on captured PCAPs.  
- Verified decoded traffic and log entries within the Snort alert file.

**Outcome:** Demonstrated Snort rule creation, tuning, and alert validation.

---

### **Phase 4 — Splunk Dashboard & SIEM Visualization**
- Forwarded Snort alerts to **Splunk Universal Forwarder** for ingestion.  
- Used SPL (Search Processing Language) queries to parse alert logs:  

```spl
index=snort sourcetype="snort:alert"
| rex field=_raw "\[(?<gid>\d+):(?<sid>\d+):(?<rev>\d+)\] (?<rule_msg>.+?) \[\*\*\] \{(?<proto>\w+)\} (?<src_ip>\d+\.\d+\.\d+\.\d+):(?<src_port>\d+) -> (?<dest_ip>\d+\.\d+\.\d+\.\d+):(?<dest_port>\d+)"
| table _time gid sid rev rule_msg proto src_ip src_port dest_ip dest_port
```

- Built real-time dashboards:
  - 📊 Alerts by Rule Message  
  - 🧩 Alerts by Source IP  
  - 🔗 Alerts by Protocol  
- Exported the dashboard as a professional PDF report.  

**Outcome:** Achieved end-to-end visualization of Snort detections in Splunk.

---

## 🧰 Tools & Technologies
| Category | Tools Used |
|-----------|-------------|
| **Email Forensics** | emlAnalyzer, VirusTotal, Hybrid Analysis, URLScan.io |
| **Network Capture** | tcpdump, Wireshark |
| **IDS / Detection** | Snort (v2.9.20) |
| **SIEM / Visualization** | Splunk Enterprise |
| **Operating Systems** | Ubuntu 22.04, Kali Linux |
| **Scripting / Utilities** | curl, pcap replay, local HTTP server |

---

## 📈 Results Summary
| Phase | Focus | Result |
|-------|--------|--------|
| 1 | Email & IOC Analysis | Extracted phishing indicators |
| 2 | Network Capture | Safe simulation of malicious traffic |
| 3 | Snort Rules | Detected simulated phishing callback |
| 4 | Splunk Visualization | Created live dashboard from Snort alerts |

---

## 🧠 Key Takeaways
- Safely analyze phishing artifacts in isolated environments.  
- Capture, replay, and interpret network data effectively.  
- Write and validate custom IDS rules for detection logic.  
- Correlate detections in Splunk dashboards for situational awareness.  
- Build structured SOC-style documentation suitable for professional reporting.

---

## 📁 Repository Contents
```
📂 Aman-SOC-Homelab/
 ┣ 📄 Aman_Sharma_SOC_Homelab_End_to_End_Project.pdf
 ┣ 🧾 README.md
 ┣ 📁 screenshots

```

---

## 💬 Project Status
Completed

---

### ✅ Final Notes
This SOC HomeLab project showcases a **realistic, hands-on incident analysis** pipeline.  
It highlights core blue-team capabilities — **forensics, traffic analysis, intrusion detection, and SIEM correlation** — built entirely using open-source tools in a virtualized lab.  

Use this repository as a professional portfolio demonstration for SOC Analyst or Blue Team roles.
