
#!/usr/bin/env python3
"""
IOC Extractor - Terminal UI Edition
------------------------------------
Extracts IPv4 addresses, domains, URLs, emails, file hashes and CVE IDs.
Supports defanged IOCs, private-IP filtering, text/JSON/CSV exports,
multiple files, stdin, and real-time file monitoring with --follow.

Examples:
    python3 tool.py sample.log
    python3 tool.py report.txt -t ip,domain --exclude-private
    python3 tool.py a.log b.txt -f json -o iocs.json
    cat alert.txt | python3 tool.py -
    python3 tool.py /var/log/auth.log --follow
"""

import argparse
import csv
import io
import ipaddress
import json
import re
import os
import sys
import time
from datetime import datetime
from collections import OrderedDict


# ==========================================================================
# Terminal UI
# ==========================================================================

class UI:
    """Terminal presentation helpers. Does not change extraction logic."""

    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def setup(cls):
        if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
            for name in ("BLUE", "CYAN", "GREEN", "YELLOW",
                         "RED", "WHITE", "BOLD", "DIM", "RESET"):
                setattr(cls, name, "")

    @classmethod
    def banner(cls, mode="IOC ANALYSIS"):
        cls.setup()
        c, g, b, r = cls.CYAN, cls.GREEN, cls.BLUE, cls.RESET
        print()
        print(f"{b}╔══════════════════════════════════════════════════════════╗{r}")
        print(f"{b}║{r}  {g}██╗ ██████╗  ██████╗{r}                                   {b}║{r}")
        print(f"{b}║{r}  {g}██║██╔═══██╗██╔════╝{r}  {cls.BOLD}IOC EXTRACTOR{r}                    {b}║{r}")
        print(f"{b}║{r}  {g}██║██║   ██║██║      {r}  {c}Threat Intelligence Toolkit{r}       {b}║{r}")
        print(f"{b}║{r}  {g}██║██║   ██║██║      {r}  Version 1.0                       {b}║{r}")
        print(f"{b}╠══════════════════════════════════════════════════════════╣{r}")
        print(f"{b}║{r}  Mode: {cls.BOLD}{mode}{r}")
        print(f"{b}║{r}  Host: {os.uname().nodename if hasattr(os, 'uname') else 'Unknown'}")
        print(f"{b}║{r}  Time: {datetime.now():%Y-%m-%d %H:%M:%S}")
        print(f"{b}╚══════════════════════════════════════════════════════════╝{r}")
        print()

    @classmethod
    def section(cls, title):
        print(f"\n{cls.BLUE}{cls.BOLD}─── {title} {'─' * max(2, 42-len(title))}{cls.RESET}")

    @classmethod
    def status(cls, label, message):
        colors = {
            "INFO": cls.CYAN,
            "OK": cls.GREEN,
            "WARN": cls.YELLOW,
            "ERROR": cls.RED,
            "NEW": cls.GREEN,
        }
        color = colors.get(label, cls.WHITE)
        print(f"  {color}[{label}]{cls.RESET} {message}")


UI.setup()


# ==========================================================================
# IOC patterns and validation
# ==========================================================================

PATTERNS = OrderedDict([
    ("url", re.compile(r"\bhttps?://[^\s<>\"'\)\]]+", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ip", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("domain", re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)),
])

VALID_TLDS = {
    "com", "net", "org", "io", "co", "info", "biz", "xyz", "top", "ru", "cn",
    "de", "uk", "us", "in", "pk", "fr", "nl", "br", "jp", "kr", "tk", "cc",
    "me", "ly", "to", "site", "online", "club", "shop", "app", "dev", "edu",
    "gov", "mil", "live", "icu", "work", "click", "link", "pw", "su",
}


# ==========================================================================
# Helper functions
# ==========================================================================

def refang(text: str) -> str:
    """Convert defanged indicators back to normal form."""
    text = re.sub(r"hxxp", "http", text, flags=re.I)
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", text)
    text = re.sub(r"\[:\]", ":", text)
    text = re.sub(r"\[@\]|\[at\]|\(at\)", "@", text, flags=re.I)
    return text


def read_source(path: str) -> str:
    """Read a file or stdin when path is '-'."""
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return True


def valid_domain(value: str) -> bool:
    if re.fullmatch(r"[\d.]+", value):
        return False
    return value.rsplit(".", 1)[-1].lower() in VALID_TLDS


def extract_iocs(text: str, wanted: list, exclude_private: bool) -> dict:
    """Extract indicators and count occurrences."""
    results = {name: {} for name in wanted}
    consumed = text

    for name, pattern in PATTERNS.items():
        for match in pattern.findall(consumed):
            value = match.rstrip(".,;:")
            if name in ("md5", "sha1", "sha256", "domain", "email"):
                value = value.lower()
            if name == "cve":
                value = value.upper()
            if name == "ip" and exclude_private and is_private_ip(value):
                continue
            if name == "domain" and not valid_domain(value):
                continue
            if name in results:
                results[name][value] = results[name].get(value, 0) + 1

        if name in ("url", "email"):
            for match in pattern.findall(consumed):
                host = re.sub(r"^https?://", "", match, flags=re.I)
                host = host.split("/")[0].split(":")[0]
                host = host.split("@")[-1].lower()
                if ("domain" in results and valid_domain(host)
                        and not re.fullmatch(r"[\d.]+", host)):
                    results["domain"][host] = results["domain"].get(host, 0) + 1
            consumed = pattern.sub(" ", consumed)

    return results


# ==========================================================================
# Output formatters
# ==========================================================================

def format_text(results: dict) -> str:
    lines = []
    total = 0

    for name, items in results.items():
        if not items:
            continue
        lines.append(f"\n[{name.upper()}] ({len(items)} unique)")
        for value, count in sorted(items.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"  {value}  (seen {count}x)")
        total += len(items)

    lines.append(f"\nTotal unique IOCs: {total}")
    return "\n".join(lines).lstrip("\n")


def format_json(results: dict) -> str:
    return json.dumps({k: sorted(v) for k, v in results.items()}, indent=2)


def format_csv(results: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "count"])
    for name, items in results.items():
        for value, count in sorted(items.items()):
            writer.writerow([name, value, count])
    return buf.getvalue()


def defang_value(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")


def show_results(results):
    """Display a compact summary before the normal results."""
    unique = sum(len(items) for items in results.values())
    occurrences = sum(sum(items.values()) for items in results.values())

    UI.section("ANALYSIS SUMMARY")
    UI.status("OK", f"Unique indicators: {unique}")
    UI.status("INFO", f"Total occurrences: {occurrences}")

    for name, items in results.items():
        if items:
            UI.status("INFO", f"{name.upper():<7} {len(items)} unique indicator(s)")


# ==========================================================================
# Real-time mode (--follow)
# ==========================================================================

def follow_file(path, wanted, exclude_private, defang, out_path, interval,
                from_start, duration):
    """Watch a file and report each IOC the first time it is seen."""
    seen = set()
    totals = {name: 0 for name in wanted}
    started = time.time()
    out_fh = open(out_path, "a", encoding="utf-8") if out_path else None

    def report(line):
        found = extract_iocs(refang(line), wanted, exclude_private)
        for ioc_type, items in found.items():
            for value in items:
                if (ioc_type, value) in seen:
                    continue
                seen.add((ioc_type, value))
                totals[ioc_type] += 1
                shown = defang_value(value) if defang else value
                msg = f"{datetime.now():%H:%M:%S} [NEW {ioc_type.upper():<6}] {shown}"
                UI.status("NEW", msg)
                if out_fh:
                    out_fh.write(msg + "\n")
                    out_fh.flush()

    UI.section("LIVE IOC MONITOR")
    UI.status("INFO", f"File: {path}")
    UI.status("INFO", f"Interval: {interval}s")
    UI.status("INFO", "Press Ctrl+C to stop")

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            if not from_start:
                fh.seek(0, os.SEEK_END)
            while True:
                line = fh.readline()
                if line:
                    report(line)
                    continue

                try:
                    if os.path.getsize(path) < fh.tell():
                        UI.status("WARN", "Log rotated; restarting from the top")
                        fh.seek(0)
                        continue
                except OSError:
                    pass

                if duration and time.time() - started >= duration:
                    break
                time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        if out_fh:
            out_fh.close()

    UI.section("MONITORING STOPPED")
    for name, count in totals.items():
        if count:
            UI.status("INFO", f"{name}: {count} unique")
    UI.status("OK", f"Total new IOCs: {sum(totals.values())}")


# ==========================================================================
# CLI
# ==========================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Extract IOCs (IPs, domains, URLs, emails, hashes, CVEs) from files or stdin.",
        epilog="Example: python3 tool.py sample.log -t ip,domain --exclude-private -f json",
    )
    p.add_argument("files", nargs="+", help="input file(s); use '-' to read from stdin")
    p.add_argument("-t", "--types", default="all",
                   help="comma-separated types: ip,domain,url,email,md5,sha1,sha256,cve (default: all)")
    p.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text",
                   help="output format (default: text)")
    p.add_argument("-o", "--output", help="write results to this file instead of the screen")
    p.add_argument("--exclude-private", action="store_true",
                   help="skip private/loopback/reserved IP addresses")
    p.add_argument("-F", "--follow", action="store_true",
                   help="REAL-TIME mode: watch a single file and report new IOCs as lines arrive")
    p.add_argument("--interval", type=float, default=1.0,
                   help="with --follow: seconds between checks (default: 1.0)")
    p.add_argument("--from-start", action="store_true",
                   help="with --follow: also process the existing content first")
    p.add_argument("--duration", type=int, default=0,
                   help="with --follow: stop automatically after N seconds (default: run until Ctrl+C)")
    p.add_argument("--defang", action="store_true",
                   help="print results defanged (safe to share): http->hxxp, .->[.]")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.types.lower() == "all":
        wanted = list(PATTERNS.keys())
    else:
        wanted = [t.strip().lower() for t in args.types.split(",") if t.strip()]
        bad = [t for t in wanted if t not in PATTERNS]
        if bad:
            print(f"Error: unknown type(s): {', '.join(bad)}. "
                  f"Valid: {', '.join(PATTERNS)}", file=sys.stderr)
            return 2

    if args.follow:
        if len(args.files) != 1 or args.files[0] == "-":
            print("Error: --follow needs exactly one file (not stdin).", file=sys.stderr)
            return 2
        if not os.path.isfile(args.files[0]):
            print(f"Error: file not found: {args.files[0]}", file=sys.stderr)
            return 1
        if args.interval <= 0:
            print("Error: --interval must be greater than 0.", file=sys.stderr)
            return 2

        UI.banner("REAL-TIME IOC MONITOR")
        try:
            follow_file(args.files[0], wanted, args.exclude_private, args.defang,
                        args.output, args.interval, args.from_start, args.duration)
        except FileNotFoundError:
            UI.status("ERROR", f"File not found: {args.files[0]}")
            return 1
        except PermissionError:
            UI.status("ERROR", f"Permission denied: {args.files[0]} (try sudo)")
            return 1
        except OSError as exc:
            UI.status("ERROR", str(exc))
            return 1
        return 0

    UI.banner("IOC ANALYSIS")
    UI.section("INPUT")
    for path in args.files:
        UI.status("INFO", f"Source: {path}")
    UI.status("INFO", f"Format: {args.format.upper()}")
    UI.status("INFO", f"Types: {', '.join(wanted)}")
    if args.exclude_private:
        UI.status("INFO", "Private/reserved IP filtering: enabled")

    combined = ""
    for path in args.files:
        try:
            combined += read_source(path) + "\n"
        except FileNotFoundError:
            UI.status("ERROR", f"File not found: {path}")
            return 1
        except PermissionError:
            UI.status("ERROR", f"Permission denied: {path}")
            return 1
        except IsADirectoryError:
            UI.status("ERROR", f"'{path}' is a directory, not a file")
            return 1
        except OSError as exc:
            UI.status("ERROR", f"Error reading {path}: {exc}")
            return 1

    results = extract_iocs(refang(combined), wanted, args.exclude_private)

    if args.defang:
        results = {
            k: {defang_value(v): c for v, c in items.items()}
            for k, items in results.items()
        }

    output = {
        "text": format_text,
        "json": format_json,
        "csv": format_csv,
    }[args.format](results)

    show_results(results)
    UI.section("EXTRACTED INDICATORS")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output + "\n")
            UI.status("OK", f"Results written to {args.output}")
        except OSError as exc:
            UI.status("ERROR", f"Error writing output: {exc}")
            return 1
    else:
        print(output)

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
