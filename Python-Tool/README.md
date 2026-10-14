# IOC Extractor (Scan + Real-Time Follow Mode)

## Objective
A Python command-line tool that extracts Indicators of Compromise (IOCs) from
logs, reports, phishing emails, or any text, saving analysts the work of
copying them out by hand. It works two ways: scan a file once, or **watch a log live (`--follow`)** and report each new IOC the moment it appears.

## Features
- Extracts IPv4 addresses, domains, URLs, emails, MD5/SHA1/SHA256 hashes, and CVE IDs
- Understands defanged input (`hxxp://evil[.]com`, `user[@]site[.]com`)
- De-duplicates results and counts how often each IOC appears
- `--exclude-private` removes private/loopback/reserved IPs
- Filters false-positive domains such as `notes.txt` using a TLD allow-list
- Output as text, JSON, or CSV; optional `--defang` for safe sharing
- **Real-time `--follow` mode**: works like `tail -f`, reports each IOC only the first time it is seen, handles log rotation, and can save alerts to a file
- Reads multiple files or stdin (`-`) and handles errors (missing file, permissions, bad type)

## Requirements
- Python 3.7+
- Standard library only (no `pip install` needed)

## How to Run
```bash
python3 tool.py -h
python3 tool.py sample.log
```

| Option | Description |
|--------|-------------|
| `files` | One or more input files, or `-` for stdin |
| `-t, --types` | `ip,domain,url,email,md5,sha1,sha256,cve` (default: all) |
| `-f, --format` | `text` (default), `json`, `csv` |
| `-o, --output` | Write results to a file |
| `--exclude-private` | Skip private/reserved IPs |
| `-F, --follow` | **Real-time mode**: watch one file and report new IOCs as lines arrive |
| `--interval` | With `--follow`: seconds between checks (default 1.0) |
| `--from-start` | With `--follow`: process existing content first |
| `--duration` | With `--follow`: auto-stop after N seconds |
| `--defang` | Defang output (`hxxp`, `[.]`) |

## Example Usage
```bash
python3 tool.py sample.log --exclude-private
python3 tool.py sample.log -t ip,cve -f csv
python3 tool.py a.log b.txt -f json -o iocs.json
cat alert.txt | python3 tool.py - --defang
sudo python3 tool.py /var/log/auth.log --follow --exclude-private
python3 tool.py app.log -F -t ip,domain -o live_iocs.txt
```

## Example Output
```
[URL] (2 unique)
  http://malware-host.ru/payload.exe  (seen 1x)
  https://secure-paypa1.com/login.php  (seen 1x)

[EMAIL] (1 unique)
  billing@secure-paypa1.com  (seen 1x)

[IP] (2 unique)
  185.220.101.4  (seen 2x)
  45.33.32.156  (seen 1x)

[CVE] (2 unique)
  CVE-2021-44228  (seen 1x)
  CVE-2024-3094  (seen 1x)

Total unique IOCs: 11
```
### Real-time (`--follow`) output
```
Following /tmp/live_test.log (checking every 0.5s). Press Ctrl+C to stop.

16:13:37 [NEW IP    ] 185.220.101.4
16:13:38 [NEW URL   ] http://evil-update.ru/a.exe
16:13:38 [NEW SHA256] 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
16:13:38 [NEW DOMAIN] evil-update.ru
16:13:38 [NEW CVE   ] CVE-2024-3094

== Monitoring stopped ==
  Total new IOCs: 5
```
**How to demo it:** run `python3 tool.py live.log -F` in one terminal (create the file first with `touch live.log`). 
In a second terminal append lines with `echo "attack from 8.8.4.4 via hxxp://bad[.]ru/x" >> live.log` and watch the alerts appear instantly.

## Challenges Faced
- Regex false positives: file names like `report.txt` look like domains, solved with a TLD allow-list.
- Avoiding double counts, since URLs and emails also contain domains.
- Real-time mode: reading only new lines, avoiding duplicate alerts, and detecting log rotation.
- Handling defanged indicators before matching.
- Reading messy or non-UTF-8 logs without crashing (`errors="replace"`).

## Future Improvements
- IPv6 support and a larger/updatable TLD list
- Alert on a watchlist of known-bad IOCs, plus email/Telegram notifications
- Optional enrichment (WHOIS, VirusTotal, AbuseIPDB lookups)
- Recursive directory scanning
- STIX/MISP export formats
- Unit tests with `pytest`
