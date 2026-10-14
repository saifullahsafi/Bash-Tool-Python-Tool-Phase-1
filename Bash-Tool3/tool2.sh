#!/usr/bin/env bash
# ============================================================================
# Linux Security Checker (tool.sh)
# Two modes (both READ-ONLY, nothing on the system is modified):
#   1) Scan mode (default): one-time audit with PASS / WARN / FAIL results.
#   2) Watch mode (-w): REAL-TIME monitor that raises ALERTs when ports,
#      logins, critical files, accounts, processes or failed-login activity change.
# UI enhancement: banner and boxed mode header; security checks/options preserved.
# ============================================================================

set -u
VERSION="1.0"

# ---- Defaults --------------------------------------------------------------
OUTPUT_FILE=""
QUIET=0
NO_COLOR=0
WATCH=0
MAX_CYCLES=0
AUTH_LOG=""
FAIL_THRESHOLD=5
ALERT_COUNT=0
PASS_COUNT=0; WARN_COUNT=0; FAIL_COUNT=0

# ---- Help / usage ----------------------------------------------------------
usage() {
cat << USAGE
Linux Security Checker v${VERSION}

Usage: $0 [options]

Options:
  -o FILE   Also save the report to FILE
  -w SEC    REAL-TIME mode: re-check every SEC seconds and alert on changes
  -c N      (with -w) stop after N checks instead of running forever
  -l FILE   (with -w) auth log to watch (default: auto-detect)
  -q        Quiet mode: show only WARN and FAIL results
  -n        Disable coloured output
  -h        Show this help message

Examples:
  $0                      Run all checks
  sudo $0 -o report.txt   Run as root (more checks) and save a report
  $0 -q -n                Compact, colourless output
  sudo $0 -w 5            Real-time monitoring every 5 seconds (Ctrl+C to stop)
  sudo $0 -w 5 -o live.log  Real-time monitoring, alerts saved to live.log

Note: some checks (e.g. /etc/shadow) need root. Without root they are skipped.
USAGE
}

# ---- Argument parsing ------------------------------------------------------
while getopts ":o:w:c:l:qnh" opt; do
  case "$opt" in
    o) OUTPUT_FILE="$OPTARG" ;;
    w) WATCH="$OPTARG" ;;
    c) MAX_CYCLES="$OPTARG" ;;
    l) AUTH_LOG="$OPTARG" ;;
    q) QUIET=1 ;;
    n) NO_COLOR=1 ;;
    h) usage; exit 0 ;;
    :) echo "Error: option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
    \?) echo "Error: unknown option -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

# ---- Basic sanity checks ---------------------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Error: this tool only supports Linux." >&2; exit 1
fi
if ! [[ "$WATCH" =~ ^[0-9]+$ && "$MAX_CYCLES" =~ ^[0-9]+$ ]]; then
  echo "Error: -w and -c need a positive whole number." >&2; exit 2
fi

if [[ -n "$OUTPUT_FILE" ]]; then
  if ! touch "$OUTPUT_FILE" 2>/dev/null; then
    echo "Error: cannot write to '$OUTPUT_FILE'." >&2; exit 1
  fi
  : > "$OUTPUT_FILE"
fi

# ---- Colours ---------------------------------------------------------------
if [[ $NO_COLOR -eq 0 && -t 1 ]]; then
  GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RED=$'\e[31m'; BLUE=$'\e[34m'; BOLD=$'\e[1m'; RESET=$'\e[0m'
else
  GREEN=""; YELLOW=""; RED=""; BLUE=""; BOLD=""; RESET=""
fi

# ---- Output helpers --------------------------------------------------------
emit() {
  echo -e "$1"
  if [[ -n "$OUTPUT_FILE" ]]; then
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
  fi
}

result() {
  local level="$1" msg="$2"
  case "$level" in
    PASS) PASS_COUNT=$((PASS_COUNT+1)); [[ $QUIET -eq 1 ]] && return
          emit "  [${GREEN}PASS${RESET}] $msg" ;;
    WARN) WARN_COUNT=$((WARN_COUNT+1)); emit "  [${YELLOW}WARN${RESET}] $msg" ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT+1)); emit "  [${RED}FAIL${RESET}] $msg" ;;
    INFO) [[ $QUIET -eq 1 ]] && return
          emit "  [${BLUE}INFO${RESET}] $msg" ;;
  esac
}

section() { [[ $QUIET -eq 1 ]] || emit "\n${BOLD}== $1 ==${RESET}"; }
is_root() { [[ $EUID -eq 0 ]]; }

# ---- Terminal UI: presentation only ----------------------------------------
banner() {
  local mode="$1"
  emit ""
  emit "${BLUE}╔══════════════════════════════════════════════════════════════╗${RESET}"
  emit "${BLUE}║${RESET}  ${GREEN}██╗     ███████╗ ██████╗${RESET}  ${BOLD}LINUX SECURITY CHECKER${RESET}       ${BLUE}║${RESET}"
  emit "${BLUE}║${RESET}  ${GREEN}██║     ██╔════╝██╔════╝${RESET}  ${BLUE}Host Security Toolkit${RESET}         ${BLUE}║${RESET}"
  emit "${BLUE}║${RESET}  ${GREEN}██║     ███████╗██║${RESET}      ${YELLOW}Version ${VERSION}${RESET}                   ${BLUE}║${RESET}"
  emit "${BLUE}╠══════════════════════════════════════════════════════════════╣${RESET}"
  emit "${BLUE}║${RESET}  Mode: ${BOLD}${mode}${RESET}"
  emit "${BLUE}║${RESET}  Host: $(hostname)"
  emit "${BLUE}║${RESET}  User: $(whoami)"
  emit "${BLUE}║${RESET}  Time: $(date '+%Y-%m-%d %H:%M:%S')"
  emit "${BLUE}╚══════════════════════════════════════════════════════════════╝${RESET}"
  emit ""
}

# ---- Individual checks -----------------------------------------------------
check_system_info() {
  section "System Information"
  result INFO "Host:   $(hostname)"
  result INFO "Kernel: $(uname -r)"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    result INFO "OS:     $(. /etc/os-release; echo "${PRETTY_NAME:-unknown}")"
  fi
  result INFO "Date:   $(date '+%Y-%m-%d %H:%M:%S')"
  result INFO "User:   $(whoami) (uid=$EUID)"
}

check_file_perms() {
  local file="$1" max="$2"
  if [[ ! -e "$file" ]]; then result INFO "$file not found (skipped)"; return; fi
  local mode; mode=$(stat -c '%a' "$file" 2>/dev/null) || { result WARN "Cannot stat $file"; return; }
  if (( 8#$mode <= 8#$max )); then
    result PASS "$file permissions are $mode (max recommended $max)"
  else
    result FAIL "$file permissions are $mode (should be $max or stricter)"
  fi
}

check_file_permissions() {
  section "Critical File Permissions"
  check_file_perms /etc/passwd 644
  check_file_perms /etc/shadow 640
  check_file_perms /etc/group 644
  check_file_perms /etc/ssh/sshd_config 644
}

check_accounts() {
  section "User Accounts"
  local extra
  extra=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
  if [[ -z "$extra" ]]; then result PASS "Only 'root' has UID 0"
  else result FAIL "Extra UID 0 account(s): $extra"; fi

  if is_root; then
    local empty
    empty=$(awk -F: '($2=="") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$empty" ]]; then result PASS "No accounts with empty passwords"
    else result FAIL "Accounts with EMPTY password: $empty"; fi
  else
    result INFO "Empty-password check skipped (run as root)"
  fi

  local count; count=$(awk -F: '$3>=1000 && $1!="nobody"' /etc/passwd | wc -l)
  result INFO "Regular user accounts: $count"
}

check_ssh() {
  section "SSH Configuration"
  local cfg=/etc/ssh/sshd_config
  if [[ ! -r $cfg ]]; then result INFO "No readable $cfg (SSH server not installed?)"; return; fi
  get_opt() { grep -iE "^[[:space:]]*$1[[:space:]]+" "$cfg" | tail -n1 | awk '{print tolower($2)}'; }

  local v
  v=$(get_opt PermitRootLogin)
  if [[ "$v" == "no" || "$v" == "prohibit-password" ]]; then result PASS "PermitRootLogin = $v"
  else result WARN "PermitRootLogin = ${v:-default (check your distro)}; recommend 'no'"; fi

  v=$(get_opt PasswordAuthentication)
  if [[ "$v" == "no" ]]; then result PASS "PasswordAuthentication = no (key-based only)"
  else result WARN "PasswordAuthentication = ${v:-default (yes)}; prefer SSH keys"; fi

  v=$(get_opt PermitEmptyPasswords)
  if [[ "$v" == "yes" ]]; then result FAIL "PermitEmptyPasswords = yes"
  else result PASS "PermitEmptyPasswords is not enabled"; fi

  v=$(get_opt Port)
  result INFO "SSH port: ${v:-22 (default)}"
}

check_network() {
  section "Network Exposure"
  if command -v ss >/dev/null 2>&1; then
    local ports
    ports=$(ss -tuln 2>/dev/null | awk 'NR>1 && /LISTEN|UNCONN/ {print $5}' | awk -F: '{print $NF}' | sort -un | tr '\n' ' ')
    result INFO "Listening ports: ${ports:-none}"
    local count; count=$(echo "$ports" | wc -w)
    if (( count > 10 )); then result WARN "$count listening ports; review unnecessary services"
    else result PASS "Listening port count is reasonable ($count)"; fi
  else
    result INFO "'ss' not available; skipping port check"
  fi

  if command -v ufw >/dev/null 2>&1 && is_root; then
    if ufw status 2>/dev/null | grep -qi "active"; then result PASS "UFW firewall is active"
    else result WARN "UFW installed but inactive"; fi
  elif command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state 2>/dev/null | grep -q running; then result PASS "firewalld is running"
    else result WARN "firewalld is not running"; fi
  elif command -v iptables >/dev/null 2>&1 && is_root; then
    local rules; rules=$(iptables -S 2>/dev/null | wc -l)
    if (( rules > 3 )); then result PASS "iptables has $rules rules"
    else result WARN "iptables has almost no rules"; fi
  else
    result INFO "Firewall status unknown (run as root or install ufw/firewalld)"
  fi
}

check_sudo() {
  section "Privilege Escalation"
  if is_root; then
    local nopw
    nopw=$(grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null)
    if [[ -z "$nopw" ]]; then result PASS "No NOPASSWD sudo rules found"
    else result WARN "NOPASSWD sudo rules present:"; echo "$nopw" | sed 's/^/           /'; fi
  else
    result INFO "sudoers check skipped (run as root)"
  fi
  local suid
  suid=$(find /usr/bin /usr/sbin /bin /sbin -perm -4000 -type f 2>/dev/null | wc -l)
  result INFO "SUID binaries in system dirs: $suid"
}

check_world_writable() {
  section "World-Writable Files"
  local ww
  ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 10)
  if [[ -z "$ww" ]]; then result PASS "No world-writable files in /etc"
  else result FAIL "World-writable files in /etc:"; echo "$ww" | sed 's/^/           /'; fi
}

check_failed_logins() {
  section "Authentication Logs"
  local log=""
  for f in /var/log/auth.log /var/log/secure; do [[ -r $f ]] && { log=$f; break; }; done
  if [[ -z "$log" ]]; then result INFO "No readable auth log (try running as root)"; return; fi
  local n; n=$(grep -ci "failed password" "$log" 2>/dev/null)
  if (( n > 20 )); then result WARN "$n failed password attempts in $log (possible brute force)"
  else result PASS "$n failed password attempts in $log"; fi
  if (( n > 0 )); then
    local top
    top=$(grep -i "failed password" "$log" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -3)
    [[ -n "$top" ]] && { result INFO "Top offending IPs:"; echo "$top" | sed 's/^/           /'; }
  fi
}

# ---- Real-time monitoring --------------------------------------------------
WATCH_FILES=(/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/hosts \
             /etc/ssh/sshd_config /etc/crontab)

clear_status() { [[ -t 1 ]] && printf '\r\033[2K'; }

alert() {
  clear_status
  emit "$(date '+%H:%M:%S') [${RED}ALERT${RESET}] $1"
  ALERT_COUNT=$((ALERT_COUNT+1))
}
note() { clear_status; emit "$(date '+%H:%M:%S') [${BLUE}INFO ${RESET}] $1"; }

added() { comm -13 <(printf '%s\n' "$1" | sort -u) <(printf '%s\n' "$2" | sort -u) | sed '/^$/d'; }
removed() { comm -23 <(printf '%s\n' "$1" | sort -u) <(printf '%s\n' "$2" | sort -u) | sed '/^$/d'; }

snap_ports() {
  if command -v ss >/dev/null 2>&1; then
    ss -tuln 2>/dev/null | awk 'NR>1 {n=split($5,a,":"); print $1"/"a[n]}' | sort -u
  else
    local f
    for f in /proc/net/tcp /proc/net/tcp6; do
      [[ -r $f ]] && awk 'NR>1 && $4=="0A" {split($2,a,":"); print a[2]}' "$f"
    done | while read -r hex; do echo "tcp/$((16#$hex))"; done | sort -u
  fi
}

snap_files() {
  local f
  for f in "${WATCH_FILES[@]}"; do
    [[ -r $f ]] && echo "$f $(sha256sum "$f" | cut -d' ' -f1)"
  done
}
snap_users() { who 2>/dev/null | sort; }
snap_uid0() { awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null | sort; }

snap_procs() {
  local p exe
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*) echo "pid=${p#/proc/} $exe" ;;
    esac
  done | sort
}

LOG_LINES=0
LOG_INODE=""
check_auth_log() {
  [[ -n "$AUTH_LOG" && -r "$AUTH_LOG" ]] || return
  local total new failed ips inode
  inode=$(stat -c %i "$AUTH_LOG" 2>/dev/null)
  [[ -n "$LOG_INODE" && "$inode" != "$LOG_INODE" ]] && LOG_LINES=0
  LOG_INODE=$inode
  total=$(wc -l < "$AUTH_LOG")
  (( total < LOG_LINES )) && LOG_LINES=0
  new=$(tail -n +$((LOG_LINES+1)) "$AUTH_LOG")
  LOG_LINES=$total
  [[ -z "$new" ]] && return

  failed=$(grep -ciE 'failed password|authentication failure|invalid user' <<< "$new")
  if (( failed >= FAIL_THRESHOLD )); then
    ips=$(grep -iE 'failed password|invalid user' <<< "$new" \
          | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -3 \
          | awk '{printf "%s(%sx) ", $2, $1}')
    alert "Possible brute force: $failed failed logins in this interval. Sources: ${ips:-unknown}"
  elif (( failed > 0 )); then
    note "$failed failed login attempt(s) in this interval"
  fi
  grep -iE 'accepted (password|publickey)' <<< "$new" | while read -r line; do
    note "Successful login: $(echo "$line" | grep -oE 'for [^ ]+ from [^ ]+' | head -1)"
  done
  grep -iE 'sudo:.*(COMMAND|incorrect password)' <<< "$new" | head -3 | while read -r line; do
    note "sudo activity: ${line##*sudo: }"
  done
}

stop_watch() {
  clear_status
  emit "\n${BOLD}== Monitoring stopped ==${RESET}"
  emit "  Alerts raised: ${ALERT_COUNT}"
  [[ -n "$OUTPUT_FILE" ]] && emit "  Log saved to: $OUTPUT_FILE"
  (( ALERT_COUNT > 0 )) && exit 1
  exit 0
}

monitor() {
  trap stop_watch INT TERM
  command -v sha256sum >/dev/null || { echo "Error: sha256sum is required." >&2; exit 1; }

  if [[ -z "$AUTH_LOG" ]]; then
    for f in /var/log/auth.log /var/log/secure; do [[ -r $f ]] && { AUTH_LOG=$f; break; }; done
  fi

  banner "REAL-TIME MONITOR"
  is_root || emit "${YELLOW}Not root: /etc/shadow and some logs cannot be watched.${RESET}"
  emit "Checking every ${WATCH}s. Press Ctrl+C to stop.\n"

  local b_ports b_files b_users b_uid0 b_procs
  b_ports=$(snap_ports); b_files=$(snap_files); b_users=$(snap_users)
  b_uid0=$(snap_uid0); b_procs=$(snap_procs)
  if [[ -n "$AUTH_LOG" && -r "$AUTH_LOG" ]]; then
    LOG_LINES=$(wc -l < "$AUTH_LOG"); LOG_INODE=$(stat -c %i "$AUTH_LOG")
  fi

  note "Baseline captured: $(echo "$b_ports" | sed '/^$/d' | wc -l) listening ports, $(echo "$b_files" | sed '/^$/d' | wc -l) files hashed, $(echo "$b_users" | sed '/^$/d' | wc -l) active sessions"
  if [[ -n "$AUTH_LOG" && -r "$AUTH_LOG" ]]; then note "Watching auth log: $AUTH_LOG"
  else note "No readable auth log: login-attack detection disabled"; fi

  local cycle=0 n_ports n_files n_users n_uid0 n_procs x
  while :; do
    [[ -t 1 ]] && printf '\r\033[2K  Monitoring... check #%d (Ctrl+C to stop)' "$cycle"
    sleep "$WATCH"
    cycle=$((cycle+1))

    n_ports=$(snap_ports)
    while read -r x; do [[ -n $x ]] && alert "NEW listening port: $x"; done < <(added "$b_ports" "$n_ports")
    while read -r x; do [[ -n $x ]] && note "Port closed: $x"; done < <(removed "$b_ports" "$n_ports")

    n_files=$(snap_files)
    while read -r x; do [[ -n $x ]] && alert "Critical file MODIFIED: ${x%% *}"; done \
      < <(added "$b_files" "$n_files" | awk '{print $1}' | sort -u | while read -r f; do
            grep -q "^$f " <<< "$b_files" && echo "$f x"; done)

    n_users=$(snap_users)
    while read -r x; do [[ -n $x ]] && alert "NEW login session: $x"; done < <(added "$b_users" "$n_users")
    while read -r x; do [[ -n $x ]] && note "Session ended: $x"; done < <(removed "$b_users" "$n_users")

    n_uid0=$(snap_uid0)
    while read -r x; do [[ -n $x ]] && alert "NEW account with root privileges (UID 0): $x"; done < <(added "$b_uid0" "$n_uid0")

    n_procs=$(snap_procs)
    while read -r x; do [[ -n $x ]] && alert "Process running from temp directory: $x"; done < <(added "$b_procs" "$n_procs")

    check_auth_log
    b_ports=$n_ports; b_files=$n_files; b_users=$n_users; b_uid0=$n_uid0; b_procs=$n_procs
    (( MAX_CYCLES > 0 && cycle >= MAX_CYCLES )) && break
  done
  stop_watch
}

# ---- Main (scan mode) ------------------------------------------------------
main() {
  banner "SCAN MODE"
  is_root || emit "${YELLOW}Running without root: some checks will be skipped.${RESET}"

  check_system_info
  check_file_permissions
  check_accounts
  check_ssh
  check_network
  check_sudo
  check_world_writable
  check_failed_logins

  local total=$((PASS_COUNT+WARN_COUNT+FAIL_COUNT))
  emit "\n${BOLD}== Summary ==${RESET}"
  emit "  Checks run: $total | ${GREEN}PASS: $PASS_COUNT${RESET} | ${YELLOW}WARN: $WARN_COUNT${RESET} | ${RED}FAIL: $FAIL_COUNT${RESET}"
  [[ -n "$OUTPUT_FILE" ]] && emit "  Report saved to: $OUTPUT_FILE"
  (( FAIL_COUNT > 0 )) && exit 1
  exit 0
}

if (( WATCH > 0 )); then monitor; else main; fi
