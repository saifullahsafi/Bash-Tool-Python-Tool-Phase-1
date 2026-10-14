# Linux Security Checker (Scan + Real-Time Monitor)

## Objective
A read-only Bash tool with two modes. **Scan mode** audits common Linux security settings and reports
PASS / WARN / FAIL results, so an admin or student can quickly spot weak
configurations. **Watch mode (`-w`)** is a real-time monitor that keeps running and raises an ALERT the moment something changes. It does not change anything on the system.

## Features
- System information summary (host, kernel, OS, user)
- Permission checks on `/etc/passwd`, `/etc/shadow`, `/etc/group`, `sshd_config`
- Detects extra UID 0 accounts and empty-password accounts (root only)
- SSH hardening review (PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords)
- Listening-port summary and firewall status (ufw / firewalld / iptables)
- `NOPASSWD` sudo rule detection and SUID binary count
- World-writable file detection in `/etc`
- Failed-login analysis with top offending IPs
- Coloured output, quiet mode, optional report file, and meaningful exit codes (0 = OK, 1 = FAIL found, 2 = bad usage)

### Real-time monitor (watch mode)
Takes a baseline of the system, then re-checks every N seconds and alerts on differences:
- New listening network port opened (possible backdoor)
- Critical file modified (`/etc/passwd`, `/etc/shadow`, `/etc/hosts`, sudoers, sshd_config, crontab) via SHA-256 comparison
- New login session, and sessions ending
- New account with root privileges (UID 0)
- Programs running from `/tmp`, `/var/tmp` or `/dev/shm` (common malware behaviour)
- Brute-force detection: 5+ failed logins in one interval, with the attacking IPs
- Info events for successful logins and sudo activity

## Requirements
- Linux with Bash 4+
- Standard tools: `awk`, `grep`, `sed`, `find`, `stat`
- Optional: `ss`, `ufw`/`firewalld`/`iptables`
- Root (sudo) recommended for full results; the tool skips root-only checks otherwise

## How to Run
```bash
chmod +x tool.sh
./tool.sh -h          # help
./tool.sh             # run all checks
sudo ./tool.sh        # run with full checks
```

| Option | Description |
|--------|-------------|
| `-o FILE` | Save a plain-text report to FILE |
| `-w SEC` | **Real-time mode**: check every SEC seconds (Ctrl+C to stop) |
| `-c N` | With `-w`: stop after N checks |
| `-l FILE` | With `-w`: auth log to watch (auto-detects `/var/log/auth.log` or `/var/log/secure`) |
| `-q` | Quiet mode, show only WARN and FAIL |
| `-n` | Disable colours |
| `-h` | Show help |

## Example Usage
```bash
sudo ./tool.sh -o report.txt
./tool.sh -q -n
sudo ./tool.sh -w 5                 # real-time monitoring every 5 seconds
sudo ./tool.sh -w 5 -o live.log     # same, saving alerts to a file
./tool.sh -x        # invalid option -> error + usage, exit code 2
```

## Example Output
```
Linux Security Checker v1.0

== System Information ==
  [INFO] Host:   vm
  [INFO] Kernel: 6.18.44-fc-v114
  [INFO] OS:     Ubuntu 24.04.4 LTS

== Critical File Permissions ==
  [PASS] /etc/passwd permissions are 644 (max recommended 644)
  [PASS] /etc/shadow permissions are 640 (max recommended 640)

== User Accounts ==
  [PASS] Only 'root' has UID 0
  [PASS] No accounts with empty passwords

== World-Writable Files ==
  [PASS] No world-writable files in /etc

== Summary ==
  Checks run: 7 | PASS: 7 | WARN: 0 | FAIL: 0
```
### Real-time monitor output
```
Linux Security Checker v2.0: REAL-TIME MONITOR
Checking every 2s. Press Ctrl+C to stop.

16:10:44 [INFO ] Baseline captured: 2 listening ports, 4 files hashed, 0 active sessions
16:10:48 [ALERT] NEW listening port: tcp/8765
16:10:48 [ALERT] Critical file MODIFIED: /etc/hosts
16:10:48 [ALERT] Process running from temp directory: pid=486 /tmp/evil_sleep
16:10:48 [ALERT] Possible brute force: 6 failed logins in this interval. Sources: 203.0.113.9(6x)

== Monitoring stopped ==
  Alerts raised: 4
```
**How to demo it:** run `sudo ./tool.sh -w 3` in one terminal. In a second terminal run `python3 -m http.server 9999` (new port alert), `echo "# test" | sudo tee -a /etc/hosts` (file change alert; remove the line afterwards), or log in from another device (login alert).


## Challenges Faced
- Comparing file permissions correctly: they are octal, so Bash needs `8#` prefixes for numeric comparison.
- Making the tool behave sensibly when not run as root (skip rather than crash).
- Different distros use different log files and firewalls (`auth.log` vs `secure`, ufw vs firewalld).
- Watch mode compares snapshots between checks (polling), so it needs a baseline and is not instant.
- Reading only the *new* lines of the auth log each cycle, and handling log rotation.
- Stripping colour codes so the saved report is clean text.

## Future Improvements
- Add checks for pending security updates and password-ageing policy
- Export results as JSON/HTML
- Use `inotifywait`/`auditd` for instant file-change events instead of polling
- Send alerts by email, Telegram or Slack
- Compare against CIS Benchmark controls
- Add a `--fix` suggestions mode (advice only) for each finding
- Cron-friendly mode that emails the report