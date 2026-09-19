#!/bin/bash
# pathfinder-master.sh — PATHFINDER: hardening + baseline + live anomaly watch
# PSUCCSO Red v. Blue 2026 — Box: Pathfinder, Ubuntu 22.04, 10.x.2.12
# Scored services: SSH, FTP, HTTP, MySQL
#
# Run as root (sudo bash pathfinder-master.sh <mode>). TEST on the practice box first.
#
# Modes:
#   harden    cautious one-shot hardening/audit pass for SSH/FTP/HTTP/MySQL/UFW + persistence report.
#             Defaults are intentionally conservative because uptime is 50% of the competition score.
#   baseline  snapshot current "known good" state to diff against later — run this only after
#             confirming SSH, FTP, HTTP and MySQL all still pass their service checks.
#   watch     diff live state against the baseline, print ONLY what's new.
#   start     launch a background monitor daemon that survives SSH disconnects.
#   view      open the live read-only dashboard (a/u/p/i/q keys).
#   stop      stop the background collector.
#   status    show whether the collector is running.
#   install   register the collector as a systemd service so it starts on boot.
#   uninstall remove that systemd service; logs/snapshots remain.
#   monitor   interactive response console for accounts, privileges, cron, processes and sessions.
#
# Competition guardrails reflected here:
#   - do NOT remove or disable wazuh-agent
#   - no antivirus
#   - blocking individual hostile IPs is allowed; blanket subnet blocking is not
#   - this tool never auto-blocks or auto-kills anything; the defender decides
#
set -u
PATHFINDER_VERSION="2.1-pathfinder"
BASE_DIR="/root/pathfinder-baseline"
MON_DIR="/root/pathfinder-monitor"
SNAP_DIR="$MON_DIR/snapshots"
LIVE_VIEW="$MON_DIR/live.view"
LIVE_COL="$MON_DIR/live.collector"
PIDFILE="$MON_DIR/collector.pid"
LOGFILE="$MON_DIR/collector.log"
IP_SEEN="$MON_DIR/remote_ips.seen"
PROC_ALERTED="$MON_DIR/procs.alerted"
ACCT_LOGGED="$MON_DIR/accounts.logged"
MON_INTERVAL=5         # seconds between collector snapshots (background daemon)
VIEW_INTERVAL=1        # seconds between dashboard redraws
PROC_WINDOW=1800       # "new in the last 30 min" window, in seconds
RETENTION=2400         # keep 40 min of snapshots on disk
# Our own tooling shows up in ps while we sample — never report it as "new".
PROC_NOISE='^((ps|sort|comm|sed|awk|sleep|tput|who|last|grep|cat|ss|date|head|tail|clear|wc|diff|find|sha256sum|getent|stat)|pathfinder-master[^ ]*) '
SCRIPT_PATH="$(readlink -f "$0")"
SERVICE_NAME="pathfinder-monitor.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
MODE="${1:-}"
# Timezone for every timestamp Pathfinder prints or logs. The VM/box clock is UTC; Eastern matches
# the operator's wall clock. Override per run:  sudo PATHFINDER_TZ=UTC bash pathfinder-master.sh monitor
# (use `sudo -E` or put VAR=... after sudo as shown). Set PATHFINDER_TZ="" to use the system timezone.
PATHFINDER_TZ="${PATHFINDER_TZ-America/New_York}"
[ -n "$PATHFINDER_TZ" ] && export TZ="$PATHFINDER_TZ"

# ---------------------------------------------------------------------------
# LOOK & FEEL — colors only when talking to a real terminal (never in logs/systemd)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RST=$'\e[0m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_CYN=$'\e[36m'
else
  C_RST=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYN=""
fi

ok()   { printf '  %s✔%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '  %s▲%s %s\n' "$C_YEL" "$C_RST" "$*"; }
bad()  { printf '  %s✘%s %s\n' "$C_RED" "$C_RST" "$*"; }
info() { printf '  %s•%s %s\n' "$C_CYN" "$C_RST" "$*"; }
step() { printf '\n%s%s%s\n' "$C_BOLD$C_CYN" "$*" "$C_RST"; }

# ---- time formatting: one clean style everywhere -------------------------
#   fmt_ts <epoch>   -> "Sep 19, 9:12 AM"        (dashboards, tables)
#   now_stamp        -> "Sep 19 9:12:44 AM"      (log lines — seconds matter for the IR)
#   who_pretty       -> `who -u` with times in the same style
fmt_ts()    { date -d "@$1" '+%b %-d, %-I:%M %p' 2>/dev/null || echo "?"; }
now_stamp() { date '+%b %-d %-I:%M:%S %p'; }
who_pretty() {
  local u tty d t idle pid host
  who -u 2>/dev/null | while read -r u tty d t idle pid host; do
    printf '%-16s %-8s %-16s idle %-6s %s\n' "$u" "$tty" "$(date -d "$d $t" '+%b %-d, %-I:%M %p' 2>/dev/null || echo "$d $t")" "$idle" "${host:-local}"
  done
}

utf8_ok() {
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *UTF-8*|*utf8*|*UTF8*) return 0 ;; *) return 1 ;; esac
}

banner() {
  echo
  if utf8_ok && [ -n "$C_RST" ]; then
    printf '\e[38;5;39m%s\e[0m\n' '╔══════════════════════════════════════════════╗'
    printf '\e[38;5;45m%s\e[0m\n' '║              P A T H F I N D E R             ║'
    printf '\e[38;5;39m%s\e[0m\n' '╚══════════════════════════════════════════════╝'
  else
    printf '%s\n' "${C_CYN}${C_BOLD}=== P A T H F I N D E R ===${C_RST}"
  fi
  printf '  %sharden · baseline · monitor   v%s   PSUCCSO Red v. Blue 2026 · Ubuntu 22.04%s\n\n' \
    "$C_DIM" "$PATHFINDER_VERSION" "$C_RST"
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    bad "Run as root (sudo bash $0 $MODE)." >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# HARDEN
# ---------------------------------------------------------------------------
# Return 0 when a systemd unit exists (active or inactive).
unit_exists() {
  systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q "^${1}[[:space:]]"
}

# Print TCP listen ports whose ss line contains a process-name regex.
listen_ports_for() {
  local re="$1"
  ss -Hltpn 2>/dev/null | awk -v re="$re" '$0 ~ re {print $4}' \
    | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' | sort -nu
}

# Idempotently set KEY=VALUE in a simple key/value config file.
set_eq_kv() {
  local file="$1" key="$2" value="$3"
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key}=${value}|" "$file"
  else
    printf '\n%s=%s\n' "$key" "$value" >> "$file"
  fi
}

harden() {
  set -e
  local ts f key line ans keys_found bak ftp_impl web_impl mysql_impl
  local ftp_pasv_min="" ftp_pasv_max="" ufw_was_active=0
  ts=$(date +%s)
  step "Pathfinder cautious hardening pass"
  warn "UPTIME is 50% of the score. Verify each scored service before taking the baseline."
  info "Target from the packet: Ubuntu 22.04 · SSH · FTP · HTTP · MySQL."

  # ---- 1. SSH -----------------------------------------------------------
  step "[1/7] SSH"
  if [ ! -f /etc/ssh/sshd_config ]; then
    bad "/etc/ssh/sshd_config not found — skipping SSH edits."
  else
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$ts"
    keys_found=0
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
      [ -s "$f" ] && keys_found=$((keys_found + 1))
    done
    info "authorized_keys files with keys in them: $keys_found"

    local settings=("PubkeyAuthentication yes" "MaxAuthTries 3" "ClientAliveInterval 120" "ClientAliveCountMax 2")

    warn "PermitRootLogin/password auth may be required by the scoring engine. Safe default = leave them alone."
    read -r -p "  Block root SSH login? Only after confirming scorer does NOT use root [y/N] " ans || true
    case "${ans:-N}" in [Yy]*) settings+=("PermitRootLogin no") ;; *) info "PermitRootLogin left as-is." ;; esac

    read -r -p "  Disable SSH PASSWORD login? Only if keys AND scorer auth are confirmed [y/N] " ans || true
    case "${ans:-N}" in [Yy]*) settings+=("PasswordAuthentication no") ;; *) info "Password login left as-is." ;; esac

    # Ubuntu's OpenSSH also supports sshd_config.d drop-ins. Put explicit values before Include
    # and neutralise conflicting active directives in drop-ins, keeping timestamped backups.
    for line in "${settings[@]}"; do
      key=${line%% *}
      for f in /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f" ] || continue
        [ -f "$f.bak.$ts" ] || cp "$f" "$f.bak.$ts"
        sed -i -E "s/^([[:space:]]*${key}[[:space:]])/#\1/I" "$f"
      done
      sed -i -E "/^[[:space:]]*${key}[[:space:]]/Id" /etc/ssh/sshd_config
      sed -i "1i ${line}" /etc/ssh/sshd_config
    done

    if sshd -t; then
      systemctl restart ssh
      ok "SSH config validated and restarted. Effective settings:"
      sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries) ' | sed 's/^/      /' || true
      warn "Open a NEW SSH connection in a second terminal before closing this one."
    else
      bad "sshd -t failed — restoring backups and restarting original SSH config."
      cp "/etc/ssh/sshd_config.bak.$ts" /etc/ssh/sshd_config
      for f in /etc/ssh/sshd_config.d/*.conf; do
        [ -f "$f.bak.$ts" ] && cp "$f.bak.$ts" "$f"
      done
      systemctl restart ssh 2>/dev/null || true
    fi
  fi

  # ---- 2. FTP -----------------------------------------------------------
  step "[2/7] FTP — detect first, change only with confirmation"
  ftp_impl="unknown"
  if unit_exists vsftpd.service || pgrep -x vsftpd >/dev/null 2>&1; then ftp_impl="vsftpd"
  elif unit_exists proftpd.service || pgrep -x proftpd >/dev/null 2>&1; then ftp_impl="proftpd"
  elif unit_exists pure-ftpd.service || pgrep -x pure-ftpd >/dev/null 2>&1; then ftp_impl="pure-ftpd"
  fi
  info "Detected FTP implementation: $ftp_impl"
  ss -Hltpn 2>/dev/null | grep -E '(:21[[:space:]]|vsftpd|proftpd|pure-ftpd)' | sed 's/^/      /' || warn "No obvious FTP listener/process found."

  case "$ftp_impl" in
    vsftpd)
      f=/etc/vsftpd.conf
      if [ -f "$f" ]; then
        echo "  Current relevant vsftpd settings:"
        grep -Ei '^[[:space:]]*(anonymous_enable|local_enable|write_enable|chroot_local_user|allow_writeable_chroot|pasv_enable|pasv_min_port|pasv_max_port|listen|listen_ipv6)[[:space:]]*=' "$f" | sed 's/^/      /' || true
        ftp_pasv_min=$(grep -Ei '^[[:space:]]*pasv_min_port[[:space:]]*=' "$f" | tail -1 | cut -d= -f2 | tr -d '[:space:]')
        ftp_pasv_max=$(grep -Ei '^[[:space:]]*pasv_max_port[[:space:]]*=' "$f" | tail -1 | cut -d= -f2 | tr -d '[:space:]')
        warn "Do NOT disable local FTP users or alter passive ports until you know how the scorer logs in."
        read -r -p "  Disable anonymous FTP (anonymous_enable=NO)? [y/N] " ans || true
        if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
          bak="$f.bak.$ts"; cp "$f" "$bak"
          set_eq_kv "$f" anonymous_enable NO
          if systemctl restart vsftpd && systemctl is-active --quiet vsftpd; then
            ok "Anonymous FTP disabled; vsftpd is active. Test the scored FTP login now."
          else
            bad "vsftpd failed after edit — restoring $bak."
            cp "$bak" "$f"; systemctl restart vsftpd 2>/dev/null || true
          fi
        else
          info "FTP authentication settings left unchanged."
        fi
      else
        warn "vsftpd detected but /etc/vsftpd.conf was not found; skipped edits."
      fi
      ;;
    proftpd)
      info "ProFTPD detected. This script leaves authentication/chroot policy untouched to protect scoring."
      [ -x /usr/sbin/proftpd ] && /usr/sbin/proftpd -t 2>&1 | sed 's/^/      /' || true
      ;;
    pure-ftpd)
      info "Pure-FTPd detected. This script leaves authentication/passive-port policy untouched to protect scoring."
      ;;
    *)
      warn "Unknown FTP stack. Identify it with: ss -ltnp | grep ':21' ; ps aux | grep -Ei 'ftp|vsftpd|proftpd|pure-ftpd'"
      ;;
  esac

  # ---- 3. HTTP ----------------------------------------------------------
  step "[3/7] HTTP — detect web server and make only low-risk optional changes"
  web_impl="unknown"
  if unit_exists nginx.service || pgrep -x nginx >/dev/null 2>&1; then web_impl="nginx"
  elif unit_exists apache2.service || pgrep -x apache2 >/dev/null 2>&1; then web_impl="apache2"
  fi
  info "Detected HTTP implementation: $web_impl"
  ss -Hltpn 2>/dev/null | grep -E '(:80[[:space:]]|:443[[:space:]]|nginx|apache2|httpd)' | sed 's/^/      /' || warn "No obvious web listener/process found."

  case "$web_impl" in
    nginx)
      if nginx -t >/dev/null 2>&1; then ok "nginx config currently validates."; else bad "nginx -t already fails — do not edit until you inspect it."; fi
      read -r -p "  Hide nginx version tokens (server_tokens off)? [y/N] " ans || true
      if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
        f=/etc/nginx/conf.d/pathfinder-hardening.conf
        [ -f "$f" ] && cp "$f" "$f.bak.$ts"
        printf '# Added by pathfinder-master.sh %s\nserver_tokens off;\n' "$(now_stamp)" > "$f"
        if nginx -t >/dev/null 2>&1; then
          systemctl reload nginx
          ok "nginx version tokens disabled; config validated before reload."
        else
          bad "nginx validation failed — reverting Pathfinder drop-in."
          if [ -f "$f.bak.$ts" ]; then cp "$f.bak.$ts" "$f"; else rm -f "$f"; fi
        fi
      fi
      ;;
    apache2)
      if apache2ctl configtest 2>&1 | sed 's/^/      /'; then :; fi
      read -r -p "  Reduce Apache version/signature disclosure? [y/N] " ans || true
      if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
        f=/etc/apache2/conf-available/pathfinder-hardening.conf
        [ -f "$f" ] && cp "$f" "$f.bak.$ts"
        printf '# Added by pathfinder-master.sh %s\nServerTokens Prod\nServerSignature Off\n' "$(now_stamp)" > "$f"
        a2enconf pathfinder-hardening >/dev/null 2>&1 || true
        if apache2ctl configtest >/dev/null 2>&1; then
          systemctl reload apache2
          ok "Apache version/signature disclosure reduced; config validated before reload."
        else
          bad "Apache validation failed — disabling/reverting Pathfinder drop-in."
          a2disconf pathfinder-hardening >/dev/null 2>&1 || true
          if [ -f "$f.bak.$ts" ]; then cp "$f.bak.$ts" "$f"; else rm -f "$f"; fi
        fi
      fi
      ;;
    *) warn "Unknown HTTP stack. Identify it with: ss -ltnp | grep -E ':80|:443'" ;;
  esac

  # ---- 4. MySQL ---------------------------------------------------------
  step "[4/7] MySQL/MariaDB — audit first; no blind account/database deletion"
  mysql_impl="unknown"
  if unit_exists mysql.service || pgrep -x mysqld >/dev/null 2>&1; then mysql_impl="mysql"
  elif unit_exists mariadb.service || pgrep -x mariadbd >/dev/null 2>&1; then mysql_impl="mariadb"
  fi
  info "Detected database implementation: $mysql_impl"
  ss -Hltpn 2>/dev/null | grep -E '(:3306[[:space:]]|mysqld|mariadbd)' | sed 's/^/      /' || warn "No obvious MySQL listener/process found."
  if [ "$mysql_impl" != unknown ]; then
    if systemctl is-active --quiet "$mysql_impl" 2>/dev/null; then ok "$mysql_impl service is active."; else warn "$mysql_impl service is NOT active."; fi
    local dbline
    dbline=$(ss -Hltpn 2>/dev/null | grep -E 'mysqld|mariadbd|:3306[[:space:]]' | head -1 || true)
    if echo "$dbline" | grep -Eq '127\.0\.0\.1:3306|\[::1\]:3306'; then
      warn "MySQL appears loopback-only. If scoring connects remotely, that can fail — investigate before changing bind-address."
    fi
    if command -v mysql >/dev/null 2>&1 && mysql --protocol=socket -NBe 'SELECT 1' >/dev/null 2>&1; then
      ok "Local socket admin access works; current DB accounts:"
      mysql --protocol=socket -NBe "SELECT CONCAT(User,'@',Host) FROM mysql.user ORDER BY User,Host;" 2>/dev/null | sed 's/^/      /' || true
      local anon
      anon=$(mysql --protocol=socket -NBe "SELECT COUNT(*) FROM mysql.user WHERE User='';" 2>/dev/null || echo '?')
      [ "$anon" = "0" ] && ok "No anonymous MySQL accounts found." || warn "Anonymous MySQL account count: $anon — review manually before deleting anything."
    else
      info "No passwordless/socket MySQL admin access; skipped user-table audit."
    fi
    warn "Do NOT run mysql_secure_installation blindly: service-check credentials or application DB users may depend on existing accounts."
  fi

  # ---- 5. UFW -----------------------------------------------------------
  step "[5/7] Firewall (UFW) — preserve all four scored services"
  if ! command -v ufw >/dev/null 2>&1; then
    warn "ufw is not installed; skipped. Do not install new packages mid-event unless you have a reason."
  else
    ufw status | sed 's/^/      /'
    ufw status | grep -q '^Status: active' && ufw_was_active=1 || true
    info "Rules this script will ensure if you continue: SSH 22/tcp, FTP 21/tcp, HTTP 80/tcp, MySQL 3306/tcp, plus detected web/FTP passive ports."

    local extra_ports="" p
    extra_ports="$( { listen_ports_for 'nginx|apache2|httpd'; listen_ports_for 'vsftpd|proftpd|pure-ftpd'; listen_ports_for 'mysqld|mariadbd'; } | sort -nu | tr '\n' ' ' )"
    [ -n "$extra_ports" ] && info "Detected scored-service TCP listener ports: $extra_ports"

    if [ -n "$ftp_pasv_min" ] && [ -n "$ftp_pasv_max" ]; then
      info "Detected vsftpd passive range: ${ftp_pasv_min}:${ftp_pasv_max}/tcp"
    else
      warn "No fixed vsftpd passive range was detected. An inbound firewall can break passive FTP data connections."
    fi

    if [ "$ufw_was_active" -eq 1 ]; then
      ans=Y
      info "UFW is already active, so this will only add/confirm scored-service allows."
    else
      read -r -p "  UFW is inactive. Configure rules AND enable it now? [y/N] " ans || true
    fi

    if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
      if [ "$ufw_was_active" -eq 0 ] && [ "$ftp_impl" = vsftpd ] && { [ -z "$ftp_pasv_min" ] || [ -z "$ftp_pasv_max" ]; }; then
        warn "Passive FTP may break because no fixed passive range is configured."
        read -r -p "  Enable UFW anyway? [y/N] " ans || true
      fi
    fi

    if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
      ufw default deny incoming
      ufw default allow outgoing
      for p in 22 21 80 3306 $extra_ports; do
        case "$p" in ''|*[!0-9]*) continue ;; esac
        ufw allow "$p/tcp" >/dev/null
      done
      if [ -n "$ftp_pasv_min" ] && [ -n "$ftp_pasv_max" ]; then
        ufw allow "${ftp_pasv_min}:${ftp_pasv_max}/tcp" >/dev/null
      fi
      [ "$ufw_was_active" -eq 1 ] || ufw --force enable
      ok "UFW rules applied. This script did NOT add any blanket source-subnet blocks."
      ufw status numbered
    else
      info "UFW left unchanged."
    fi
  fi

  set +e
  # ---- 6. Accounts / persistence / Wazuh report -------------------------
  step "[6/7] Account / persistence / Wazuh report (READ-ONLY)"
  echo "  --- Accounts with UID >= 1000 ---"
  awk -F: '$3 >= 1000 && $3 < 65000 {print "   ", $1, "uid="$3, $7}' /etc/passwd
  echo "  --- UID 0 accounts (should normally be ONLY root) ---"
  awk -F: '$3 == 0 {print "   ", $1}' /etc/passwd
  echo "  --- sudo group members ---"
  getent group sudo | cut -d: -f4 | tr ',' '\n' | sed '/^$/d; s/^/    /'
  echo "  --- Accounts with NO password field set ---"
  awk -F: '($2 == "") {print "   ", $1}' /etc/shadow
  echo "  --- Cron (root + all users + /etc/cron.d) ---"
  for f in /var/spool/cron/crontabs/*; do
    [ -f "$f" ] && { echo "   == $f =="; sed 's/^/    /' "$f"; }
  done
  ls -la /etc/cron.d/ 2>/dev/null
  echo "  --- systemd timers (first 25) ---"
  systemctl list-timers --all --no-pager 2>/dev/null | head -25 | sed 's/^/    /'
  if systemctl list-unit-files wazuh-agent.service --no-legend 2>/dev/null | grep -q '^wazuh-agent.service'; then
    if systemctl is-active --quiet wazuh-agent; then ok "wazuh-agent is present and active — competition rules say DO NOT REMOVE IT."
    else warn "wazuh-agent is present but not active. Competition rules say do not remove it; verify with White Team before changing it."; fi
  else
    warn "wazuh-agent unit not found. The packet says not to remove it; if absent on the real box, ask White Team rather than installing/removing blindly."
  fi
  warn "Review accounts, cron and timers for persistence you do not recognize. This script does not auto-delete them."

  # ---- 7. SUID + final service sanity ----------------------------------
  step "[7/7] SUID/SGID count + scored-service sanity"
  printf '  SUID/SGID files on root filesystem: '
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l
  echo "  --- Relevant listeners now ---"
  ss -Hltpn 2>/dev/null | grep -E 'sshd|:22[[:space:]]|vsftpd|proftpd|pure-ftpd|:21[[:space:]]|nginx|apache2|httpd|:80[[:space:]]|mysqld|mariadbd|:3306[[:space:]]' | sed 's/^/    /'
  set -e

  echo
  ok "Hardening/audit pass complete."
  warn "BEFORE baseline: test SSH + FTP + HTTP + MySQL from the same path the scorer uses."
  info "Only after all four work: sudo bash $0 baseline"
}

# ---------------------------------------------------------------------------
# STATE COLLECTION — shared by baseline, watch, the daemon and the dashboard
# ---------------------------------------------------------------------------

# "comm user" per line, kernel threads dropped, our own tooling dropped. Whitespace is
# normalised (ps pads columns, which made identical processes compare as different).
procs_now() {
  ps -eo pid=,ppid=,user=,comm= 2>/dev/null \
    | awk '$1 != 2 && $2 != 2 { c = $4; for (i = 5; i <= NF; i++) c = c " " $i; print c, $3 }' \
    | grep -Ev "$PROC_NOISE" | sort -u
}

# Remote peer IPs of established connections. IPv6-safe: a naive trailing ":digits" strip
# would eat the last hextet of an IPv6 address.
# NOTE: `state established` makes ss drop the State column, so Peer is $4 (Local is $3).
ips_now() {
  ss -Hntp state established 2>/dev/null | awk '{print $4}' \
    | sed -E 's/^\[([0-9a-fA-F:.]+)\]:[0-9]+$/\1/; t; s/:[0-9]+$//' | sort -u
}

# Account-related state -> $1/<name>.$2. Split out so the dashboard/daemon can re-sample
# it live and diff against the baseline.
snap_accounts() {
  local d="$1" s="$2" f
  mkdir -p "$d"

  awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd | sort > "$d/accounts.$s"
  getent group sudo | sort > "$d/sudoers.$s"

  {
    for f in /root /home/*; do
      [ -f "$f/.ssh/authorized_keys" ] && { echo "== $f/.ssh/authorized_keys =="; cat "$f/.ssh/authorized_keys"; }
    done
  } > "$d/sshkeys.$s" 2>/dev/null

  # A UID-0 account, a changed password hash or a new sudoers drop-in all show up here.
  {
    sha256sum /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/sudoers.d/* 2>/dev/null
    awk -F: '$3 == 0 {print "uid0:" $1}' /etc/passwd
  } | sort > "$d/hashes.$s"
}

snapshot() {
  mkdir -p "$BASE_DIR"

  ss -Hntlup 2>/dev/null | awk '{print $1, $5, $7}' | sort -u > "$BASE_DIR/listeners.$1"
  ss -Hntp state established 2>/dev/null | awk '{print $3, $4, $5}' | sort -u > "$BASE_DIR/established.$1"
  ips_now   > "$BASE_DIR/remote_ips.$1"
  procs_now > "$BASE_DIR/procs.$1"
  snap_accounts "$BASE_DIR" "$1"

  {
    for f in /var/spool/cron/crontabs/*; do
      [ -f "$f" ] && { echo "== $f =="; cat "$f" 2>/dev/null; }
    done
    echo "== /etc/cron.d =="
    ls /etc/cron.d/ 2>/dev/null
  } > "$BASE_DIR/cron.$1"

  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$BASE_DIR/suid.$1"
}

# Everything account-related that differs from the baseline, one plain-text line each.
# "+" = appeared, "-" = disappeared. Prints nothing when there is no baseline or no change.
account_changes() {
  local d="$1" f line
  [ -f "$BASE_DIR/accounts.baseline" ] || return 0
  snap_accounts "$d" current
  for f in accounts sudoers sshkeys hashes; do
    [ -f "$BASE_DIR/$f.baseline" ] || continue
    diff "$BASE_DIR/$f.baseline" "$d/$f.current" 2>/dev/null | grep -E '^[<>]' | while IFS= read -r line; do
      case "$f" in
        hashes) printf '%s [critical file] %s\n' "${line:0:1}" "${line:2}" | sed -E 's/[0-9a-f]{64}  //' | cut -c1-90 ;;
        *)      printf '%s [%s] %s\n' "${line:0:1}" "$f" "${line:2}" | sed 's/^>/+/; s/^</-/' | cut -c1-90 ;;
      esac
    done
  done | sed 's/^>/+/; s/^</-/' | sort -u
}

baseline() {
  step "Snapshotting current state as baseline"
  snapshot baseline
  ok "Saved to $BASE_DIR/*.baseline — $(fmt_ts "$(date +%s)")"
  info "Re-run 'sudo bash $0 baseline' any time you want to reset the known-good point"
  info "(e.g. after legitimately adding a service account)."
}

# ---------------------------------------------------------------------------
# WATCH
# ---------------------------------------------------------------------------
diff_section() {
  local label="$1" file="$2" new_lines
  if [ ! -f "$BASE_DIR/${file}.baseline" ]; then
    echo "  (no baseline for $label yet — run 'baseline' mode first)"
    return
  fi
  new_lines=$(diff "$BASE_DIR/${file}.baseline" "$BASE_DIR/${file}.current" 2>/dev/null | grep '^>' | sed 's/^> /   /')
  if [ -n "$new_lines" ]; then
    printf '%s-- NEW %s --%s\n' "$C_YEL" "$label" "$C_RST"
    echo "$new_lines"
  fi
}

watch_once() {
  local new_ips
  snapshot current

  new_ips=$(diff "$BASE_DIR/remote_ips.baseline" "$BASE_DIR/remote_ips.current" 2>/dev/null | grep '^>' | sed 's/^> //')
  printf '%s=== %s ===%s\n' "$C_BOLD" "$(now_stamp)" "$C_RST"
  if [ -n "$new_ips" ]; then
    printf '%s>>> NEW REMOTE IP(S) NOT IN BASELINE — feed these into the block script:%s\n' "$C_RED$C_BOLD" "$C_RST"
    echo "$new_ips" | sed 's/^/    /'
  else
    ok "No new remote IPs since baseline."
  fi

  diff_section "listening ports"         listeners
  diff_section "established connections" established
  diff_section "processes (name,user)"   procs
  diff_section "accounts"                accounts
  diff_section "sudo group members"      sudoers
  diff_section "critical file hashes"    hashes
  diff_section "cron entries"            cron
  diff_section "SSH authorized_keys"     sshkeys
  diff_section "SUID/SGID binaries"      suid

  rm -f "$BASE_DIR"/*.current
  echo
}

watch_mode() {
  if [ ! -f "$BASE_DIR/remote_ips.baseline" ]; then
    bad "No baseline found. Run 'sudo bash $0 baseline' first (right after hardening)." >&2
    exit 1
  fi
  local interval=""
  if [ "${2:-}" = "-n" ] && [ -n "${3:-}" ]; then
    interval="$3"
  fi
  if [ -n "$interval" ]; then
    info "Watching every ${interval}s — Ctrl+C to stop."
    while true; do
      watch_once
      sleep "$interval"
    done
  else
    watch_once
  fi
}

# ---------------------------------------------------------------------------
# BACKGROUND COLLECTOR + LIVE DASHBOARD (start / view / stop / status)
# ---------------------------------------------------------------------------
# Deliberately no 'set -e' below — this runs unattended for hours, and one
# empty `ss` result (e.g. no established connections right now) must not be
# able to kill the whole daemon.

# Snapshot closest to (but not newer than) PROC_WINDOW seconds ago. If the
# daemon hasn't been running that long yet, falls back to the oldest snapshot
# on disk — i.e. "new since monitoring started" until 30 min of history exists.
baseline_30min_snapshot() {
  local now target best best_ts ts f
  now=$(date +%s)
  target=$((now - PROC_WINDOW))
  best=""; best_ts=0
  for f in "$SNAP_DIR"/*."$1"; do
    [ -e "$f" ] || continue
    ts=${f##*/}; ts=${ts%%.*}
    if [ "$ts" -le "$target" ] && [ "$ts" -gt "$best_ts" ]; then
      best="$f"; best_ts="$ts"
    fi
  done
  if [ -z "$best" ]; then
    best=$(ls -1 "$SNAP_DIR"/*."$1" 2>/dev/null | sort | head -1)
  fi
  echo "$best"
}

collector_loop() {
  local now new_ips base newp acct l ip p
  mkdir -p "$SNAP_DIR" "$LIVE_COL"
  touch "$IP_SEEN" "$PROC_ALERTED" "$ACCT_LOGGED"
  # IPs already in the baseline are known-good — don't shout about them.
  [ -f "$BASE_DIR/remote_ips.baseline" ] && sort -u "$BASE_DIR/remote_ips.baseline" "$IP_SEEN" -o "$IP_SEEN"

  while true; do
    now=$(date +%s)

    pwd_track
    procs_now > "$SNAP_DIR/$now.procs"
    ips_now   > "$SNAP_DIR/$now.ips"

    # -- new remote IPs
    new_ips=$(comm -23 "$SNAP_DIR/$now.ips" "$IP_SEEN" 2>/dev/null)
    if [ -n "$new_ips" ]; then
      while IFS= read -r ip; do
        [ -n "$ip" ] && echo "$(now_stamp)  NEW REMOTE IP: $ip" >> "$LOGFILE"
      done <<< "$new_ips"
      { cat "$IP_SEEN"; echo "$new_ips"; } | sort -u > "$IP_SEEN.tmp" && mv "$IP_SEEN.tmp" "$IP_SEEN"
    fi

    # -- new processes (logged once each, so short-lived ones are still on record)
    base=$(baseline_30min_snapshot procs)
    if [ -n "$base" ] && [ "$base" != "$SNAP_DIR/$now.procs" ]; then
      newp=$(comm -23 "$SNAP_DIR/$now.procs" "$base" 2>/dev/null | comm -23 - "$PROC_ALERTED" 2>/dev/null)
      if [ -n "$newp" ]; then
        while IFS= read -r p; do
          [ -n "$p" ] && echo "$(now_stamp)  NEW PROCESS: $p" >> "$LOGFILE"
        done <<< "$newp"
        { cat "$PROC_ALERTED"; echo "$newp"; } | sort -u > "$PROC_ALERTED.tmp" && mv "$PROC_ALERTED.tmp" "$PROC_ALERTED"
      fi
    fi

    # -- account / sudo / ssh-key / passwd changes vs baseline (logged once each)
    acct=$(account_changes "$LIVE_COL")
    if [ -n "$acct" ]; then
      while IFS= read -r l; do
        if ! grep -qxF -- "$l" "$ACCT_LOGGED" 2>/dev/null; then
          echo "$(now_stamp)  ACCOUNT CHANGE: $l" >> "$LOGFILE"
          echo "$l" >> "$ACCT_LOGGED"
        fi
      done <<< "$acct"
    fi

    find "$SNAP_DIR" -type f -mmin +"$((RETENTION / 60))" -delete 2>/dev/null

    sleep "$MON_INTERVAL"
  done
}

service_active() {
  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null
}

service_installed() {
  [ -f "$SERVICE_PATH" ]
}

collector_status_line() {
  if service_active; then
    echo "running via systemd (survives reboot/crash)"
  elif [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    echo "running (PID $(cat "$PIDFILE")) — manual, will NOT survive a reboot (run 'install' to fix that)"
  else
    echo "NOT RUNNING — start it with: sudo bash $SCRIPT_PATH start"
  fi
}

start_collector() {
  if service_active; then
    ok "Already running via the systemd service (survives reboot). Nothing to do."
    return
  fi
  mkdir -p "$MON_DIR" "$SNAP_DIR"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    ok "Already running (PID $(cat "$PIDFILE"))."
    return
  fi
  setsid nohup "$SCRIPT_PATH" __collector__ >>"$LOGFILE" 2>&1 < /dev/null &
  echo $! > "$PIDFILE"
  disown 2>/dev/null || true
  ok "Monitor daemon started — PID $(cat "$PIDFILE")."
  info "Keeps running after you close this terminal or SSH drops. Stop it with: sudo bash $0 stop"
  info "It will NOT survive a reboot this way — run 'sudo bash $0 install' for that."
  info "Open the live dashboard any time with: sudo bash $0 view"
  [ -f "$BASE_DIR/accounts.baseline" ] || warn "No baseline yet — account monitoring needs one. Run: sudo bash $0 baseline"
}

stop_collector() {
  if service_active; then
    systemctl stop "$SERVICE_NAME"
    ok "Stopped for now. It's still enabled — it WILL start again on the next boot."
    info "Run 'sudo bash $0 uninstall' if you want it gone for good."
    return
  fi
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    kill "$(cat "$PIDFILE")"
    rm -f "$PIDFILE"
    ok "Stopped."
  else
    info "Not running."
    rm -f "$PIDFILE"
  fi
}

install_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    bad "systemctl not found — this box doesn't appear to run systemd. Can't install as a boot service." >&2
    exit 1
  fi
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; then
    info "Stopping the manually-started collector first (systemd will take over)..."
    kill "$(cat "$PIDFILE")"
    rm -f "$PIDFILE"
  fi
  mkdir -p "$MON_DIR" "$SNAP_DIR"
  cat > "$SERVICE_PATH" <<UNIT
[Unit]
Description=Pathfinder live monitor collector (PSUCCSO RvB 2026)
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $SCRIPT_PATH __collector__
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
  ok "Installed. Pathfinder now starts monitoring on every boot; systemd restarts it if it crashes."
  info "Check status: sudo systemctl status $SERVICE_NAME"
  info "Dashboard:    sudo bash $0 view"
  info "Remove:       sudo bash $0 uninstall"
  warn "The unit runs $SCRIPT_PATH — don't move or delete that file."
}

uninstall_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SERVICE_NAME" 2>/dev/null
  fi
  rm -f "$SERVICE_PATH"
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
  ok "Removed — it will no longer start on boot. Snapshot/log data in $MON_DIR was left in place."
}

baseline_age() {
  local t
  t=$(stat -c %Y "$BASE_DIR/remote_ips.baseline" 2>/dev/null) || { echo "none — run 'baseline'"; return; }
  echo "$(( ($(date +%s) - t) / 60 ))m old (saved $(fmt_ts "$t"))"
}

snapshot_age_label() {
  [ -z "${1:-}" ] && { echo "n/a"; return; }
  local ts now
  ts=${1##*/}; ts=${ts%%.*}
  now=$(date +%s)
  echo "$(( (now - ts) / 60 ))m ago"
}

# Everything is sampled live on each redraw (cheap), so the view is a true 1-second view even
# though the background daemon only snapshots every MON_INTERVAL seconds for history/logging.
render_dashboard() {
  local mode="$1" out="" n_acct=0 n_proc=0 n_ip=0 n_all
  local base acct_txt proc_txt ip_now ip_new rows status

  add() { out+="$*"$'\n'; }
  head_() { add "${C_BOLD}${C_CYN}$*${C_RST}"; }

  # ---- sample
  if [ -f "$BASE_DIR/accounts.baseline" ]; then
    acct_txt=$(account_changes "$LIVE_VIEW")
    [ -n "$acct_txt" ] && n_acct=$(printf '%s\n' "$acct_txt" | grep -c .)
  else
    acct_txt="(no baseline yet — run: sudo bash $SCRIPT_PATH baseline)"
  fi

  base=$(baseline_30min_snapshot procs)
  proc_txt=""
  if [ -n "$base" ]; then
    proc_txt=$(procs_now | comm -23 - "$base" 2>/dev/null)
    [ -n "$proc_txt" ] && n_proc=$(printf '%s\n' "$proc_txt" | grep -c .)
  fi

  ip_now=$(ips_now)
  ip_new=""
  if [ -f "$BASE_DIR/remote_ips.baseline" ] && [ -n "$ip_now" ]; then
    ip_new=$(printf '%s\n' "$ip_now" | comm -23 - "$BASE_DIR/remote_ips.baseline" 2>/dev/null)
    [ -n "$ip_new" ] && n_ip=$(printf '%s\n' "$ip_new" | grep -c .)
  fi

  n_all=$((n_acct + n_proc + n_ip))
  # a "(no baseline...)" hint isn't an alert
  [ -f "$BASE_DIR/accounts.baseline" ] || n_all=$((n_proc + n_ip))
  if [ "$n_all" -eq 0 ]; then status="${C_GRN}${C_BOLD}● ALL CLEAR${C_RST}"
  else status="${C_RED}${C_BOLD}▲ ${n_all} ALERT(S)${C_RST}"; fi

  # ---- header
  add "${C_BOLD}${C_CYN}◢◤ A P O L L O ◥◣${C_RST}  ${C_DIM}live monitor${C_RST}      $(date '+%a %b %-d, %-I:%M:%S %p')      $status"
  add "${C_DIM}daemon:${C_RST} $(collector_status_line)"
  add "${C_DIM}baseline:${C_RST} $(baseline_age)    ${C_DIM}keys:${C_RST} [a]ll [u]sers/accounts [p]rocesses [i]ps [q]uit"
  add "${C_DIM}────────────────────────────────────────────────────────────────────────${C_RST}"

  # ---- users + accounts
  if [ "$mode" = "all" ] || [ "$mode" = "users" ]; then
    head_ "LOGGED IN NOW"
    if [ -n "$(who 2>/dev/null)" ]; then add "$(who_pretty | sed 's/^/  /')"; else add "  (nobody)"; fi
    add ""
    head_ "RECENT LOGINS"
    add "$(last -n 5 -w 2>/dev/null | grep -Ev '^(wtmp|$)' | sed 's/^/  /')"
    add ""
    head_ "ACCOUNT CHANGES vs BASELINE   ${C_DIM}(users · sudo · ssh keys · passwd/shadow/sudoers)${C_RST}"
    if [ -f "$BASE_DIR/accounts.baseline" ]; then
      if [ -n "$acct_txt" ]; then
        add "$(printf '%s\n' "$acct_txt" | sed "s/^/  ${C_RED}/; s/\$/${C_RST}/")"
      else
        add "  ${C_GRN}none${C_RST}"
      fi
    else
      add "  ${C_YEL}${acct_txt}${C_RST}"
    fi
    add ""
  fi

  # ---- processes
  if [ "$mode" = "all" ] || [ "$mode" = "procs" ]; then
    head_ "PROCESSES NEW SINCE ~30 MIN AGO   ${C_DIM}(vs snapshot from $(snapshot_age_label "$base"))${C_RST}"
    if [ -z "$base" ]; then
      add "  (still building history — check back shortly)"
    elif [ -n "$proc_txt" ]; then
      add "$(printf '%s\n' "$proc_txt" | sed "s/^/  ${C_RED}NEW${C_RST}  /")"
    else
      add "  ${C_GRN}none${C_RST}"
    fi
    add ""
  fi

  # ---- ips + alert log
  if [ "$mode" = "all" ] || [ "$mode" = "ips" ]; then
    head_ "REMOTE IPs CONNECTED NOW"
    if [ -n "$ip_now" ]; then
      add "$(printf '%s\n' "$ip_now" | while IFS= read -r ip; do
        if printf '%s\n' "$ip_new" | grep -qxF -- "$ip"; then printf '  %sNEW%s  %s\n' "$C_RED" "$C_RST" "$ip"
        else printf '       %s\n' "$ip"; fi
      done)"
    else
      add "  (none)"
    fi
    add ""
    head_ "RECENT ALERTS   ${C_DIM}(from the daemon log)${C_RST}"
    add "$(tail -n 300 "$LOGFILE" 2>/dev/null | grep -E 'NEW (REMOTE IP|PROCESS)|ACCOUNT CHANGE|PASSWORD (CHANGE|SET)' | tail -n 8 | sed 's/^/  /')"
  fi

  rows=$(tput lines 2>/dev/null || echo 40)
  printf '\e[H'
  printf '%s\n' "$out" | head -n "$((rows - 1))" | sed $'s/$/\e[K/'
  printf '\e[J'
}

view_cleanup() { printf '\e[?25h\e[?1049l'; }

view_dashboard() {
  local mode="all" key
  if [ ! -d "$SNAP_DIR" ]; then
    bad "No monitor data yet. Start the daemon first: sudo bash $0 start" >&2
    exit 1
  fi
  mkdir -p "$LIVE_VIEW"
  banner; sleep 1
  printf '\e[?1049h\e[?25l'              # alternate screen, hide cursor
  trap 'view_cleanup; exit 0' INT TERM
  while true; do
    render_dashboard "$mode"
    if read -t "$VIEW_INTERVAL" -n 1 -s key; then
      case "$key" in
        u) mode="users" ;;
        p) mode="procs" ;;
        i) mode="ips" ;;
        a) mode="all" ;;
        q) break ;;
      esac
    fi
  done
  view_cleanup
}

# ---------------------------------------------------------------------------
# MONITOR — interactive master console: accounts, passwords, privileges, cron,
# processes/sessions, and removal. Every destructive action shows what it will do,
# asks first, and is written to $ACTION_LOG. Nothing runs unless you pick it.
# ---------------------------------------------------------------------------
ACTION_LOG="$MON_DIR/actions.log"
REMOVED_DIR="$MON_DIR/removed"          # backups of anything the console deletes
PROTECTED_PROCS='^(sshd|vsftpd|proftpd|pure-ftpd|nginx|apache2|httpd|mysqld|mariadbd|wazuh-agentd|wazuh-modulesd|systemd|init|cron|pathfinder-master.*)$'
CALLER="${SUDO_USER:-root}"

log_action() { mkdir -p "$MON_DIR"; printf '%s [%s] %s\n' "$(now_stamp)" "$CALLER" "$*" >> "$ACTION_LOG"; }
confirm() { local a; read -r -p "  $1 [y/N] " a || return 1; case "$a" in [Yy]*) return 0 ;; *) return 1 ;; esac; }
pause()   { local _; read -r -p "  Enter to continue..." _ || true; }
user_exists() { [ -n "$1" ] && id "$1" >/dev/null 2>&1; }
is_sudoer()   { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; }

# ---- password-change times ------------------------------------------------
# Linux stores only the DATE of a password change (days since 1970), never the time. So Pathfinder
# records it itself: pwd.track holds "user  fingerprint-of-hash  epoch". Whenever a hash differs
# from last time, the epoch becomes "now". The daemon and the console both keep it updated.
# epoch 0 = the password was already like that when tracking began (time unknown -> shown as --:--).
PWD_TRACK="$MON_DIR/pwd.track"
pwd_track() {
  local now init u h fp old ofp ots ts
  mkdir -p "$MON_DIR"
  now=$(date +%s); init=0; [ -s "$PWD_TRACK" ] && init=1
  : > "$PWD_TRACK.tmp"
  while IFS=: read -r u h; do
    [ -n "$u" ] || continue
    fp=$(printf '%s:%s' "$u" "$h" | sha256sum | cut -d' ' -f1)
    old=$(awk -v u="$u" '$1==u {print $2, $3}' "$PWD_TRACK" 2>/dev/null)
    if [ -z "$old" ]; then
      if [ "$init" = 1 ]; then ts=$now; echo "$(now_stamp)  PASSWORD SET (new account): $u" >> "$LOGFILE"; else ts=0; fi
    else
      read -r ofp ots <<< "$old"
      if [ "$ofp" = "$fp" ]; then ts=$ots; else ts=$now; echo "$(now_stamp)  PASSWORD CHANGE: $u" >> "$LOGFILE"; fi
    fi
    echo "$u $fp $ts" >> "$PWD_TRACK.tmp"
  done < <(awk -F: '{print $1":"$2}' /etc/shadow 2>/dev/null)
  mv "$PWD_TRACK.tmp" "$PWD_TRACK"
}

# "<sortkey>|<display>" for one user. lc = date from passwd -S (YYYY-MM-DD).
pwd_when() {
  local u="$1" lc="$2" ts
  ts=$(awk -v u="$u" '$1==u {print $3}' "$PWD_TRACK" 2>/dev/null)
  if [ "${ts:-0}" -gt 0 ] 2>/dev/null; then
    echo "$ts|$(fmt_ts "$ts")"
  else
    echo "$(date -d "$lc" +%s 2>/dev/null || echo 0)|$(date -d "$lc" '+%b %-d' 2>/dev/null || echo "$lc"), --:--"
  fi
}

# ---- accounts -------------------------------------------------------------
mon_accounts() {
  step "Accounts (root + UID >= 1000)"
  printf '  %s%-18s %-6s %-5s %-17s %-5s %s%s\n' "$C_BOLD" USER UID PWD "PW CHANGED" SUDO "SHELL  GROUPS" "$C_RST"
  pwd_track
  local u uid st lc sd sh grp
  while IFS=: read -r u uid sh; do
    read -r _ st lc _ < <(passwd -S "$u" 2>/dev/null) || true
    sd="no"; is_sudoer "$u" && sd="yes"
    grp=$(id -nG "$u" 2>/dev/null | sed "s/\b$u\b//; s/^ *//; s/ /,/g")
    local col=""
    if [ "$uid" = 0 ] && [ "$u" != root ]; then col="$C_RED"; fi
    if [ "${st:-}" = "L" ]; then col="$C_DIM"; fi
    printf '  %s%-18s %-6s %-5s %-17s %-5s %s  %s%s\n' "$col" "$u" "$uid" "${st:-?}" "$(pwd_when "$u" "${lc:-1970-01-01}" | cut -d'|' -f2)" "$sd" "${sh##*/}" "$grp" "$C_RST"
  done < <(getent passwd | awk -F: '$3==0 || ($3>=1000 && $3<65000) {print $1":"$3":"$7}')
  echo
  info "PWD: P=has password, L=locked, NP=no password (a finding). UID 0 accounts other than root print in red."
  info "PW CHANGED: Linux stores only the date; Pathfinder records the time when it sees a change. '--:--' = changed before Pathfinder was watching."
  echo "  --- Logged in now ---"
  who_pretty | sed 's/^/    /'
}

# ---- passwords ------------------------------------------------------------
mon_passwords() {
  local c u tmp w st lc
  while true; do
    pwd_track
    step "Password status — most recently changed first"
    printf '  %s%-18s %-5s %s%s\n' "$C_BOLD" USER PWD "CHANGED" "$C_RST"
    getent passwd | awk -F: '$3==0 || ($3>=1000 && $3<65000) {print $1}' | while read -r u; do
      read -r _ st lc _ < <(passwd -S "$u" 2>/dev/null) || true
      w=$(pwd_when "$u" "${lc:-1970-01-01}")
      printf '%s|  %-18s %-5s %s\n' "${w%%|*}" "$u" "${st:-?}" "${w#*|}"
    done | sort -t'|' -k1,1nr | cut -d'|' -f2-
    echo "  (time = when Pathfinder saw the change; '--:--' = already that way before tracking began)"
    echo
    echo "  --- Account / password / privilege changes vs baseline ---"
    if [ -f "$BASE_DIR/accounts.baseline" ]; then
      tmp=$(mktemp -d); account_changes "$tmp" | sed 's/^/    /'; rm -rf "$tmp"
    else
      echo "    (no baseline yet — run: sudo bash $0 baseline)"
    fi
    echo
    echo "  [s] set password  [l] lock  [u] unlock  [e] force change at next login  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      s|l|u|e)
        read -r -p "  Username: " u || return 0
        user_exists "$u" || { bad "No such user: $u"; pause; continue; }
        case "$c" in
          s) passwd "$u" && { pwd_track; log_action "password set for $u"; } ;;
          l) if [ "$u" = "$CALLER" ]; then bad "Refusing to lock yourself ($CALLER)."
             elif confirm "Lock $u (blocks password logins)?"; then passwd -l "$u" && log_action "locked $u"; fi ;;
          u) passwd -u "$u" && log_action "unlocked $u" ;;
          e) chage -d 0 "$u" && ok "$u must change password at next login." && log_action "forced password change for $u" ;;
        esac
        pause ;;
      b|"") return 0 ;;
    esac
  done
}

# ---- privileges -----------------------------------------------------------
mon_privileges() {
  local c u
  while true; do
    step "Privileges"
    echo "  --- UID 0 accounts (should be ONLY root) ---"
    awk -F: '$3==0 {print "    "$1}' /etc/passwd
    echo "  --- sudo / wheel / admin group members ---"
    getent group sudo wheel admin 2>/dev/null | while IFS=: read -r g _ _ m; do
      echo "    [$g]"; echo "$m" | tr ',' '\n' | sed '/^$/d; s/^/      /'
    done
    echo "  --- sudoers rules (non-comment) ---"
    grep -hEv '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/    /'
    echo "  --- NOPASSWD rules (risky) ---"
    grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | sed 's/^/    /'
    if [ -f "$BASE_DIR/suid.baseline" ]; then
      echo "  --- SUID/SGID binaries not in baseline ---"
      find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort \
        | comm -13 "$BASE_DIR/suid.baseline" - | sed 's/^/    /'
    fi
    echo
    echo "  [a] add user to sudo  [r] remove user from sudo  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      a) read -r -p "  Username: " u || return 0
         user_exists "$u" || { bad "No such user."; pause; continue; }
         confirm "Give $u full sudo?" && usermod -aG sudo "$u" && ok "$u added to sudo." && log_action "added $u to sudo" ;;
      r) read -r -p "  Username: " u || return 0
         user_exists "$u" || { bad "No such user."; pause; continue; }
         if [ "$u" = "$CALLER" ]; then bad "Refusing to remove your own sudo ($CALLER) — you'd lock yourself out."
         elif confirm "Remove $u from sudo?"; then gpasswd -d "$u" sudo && log_action "removed $u from sudo"; fi ;;
      b|"") return 0 ;;
    esac
    pause
  done
}

# ---- cron -----------------------------------------------------------------
mon_cron() {
  local c t f
  while true; do
    step "Scheduled jobs"
    echo "  --- /etc/crontab ---"
    grep -Ev '^\s*(#|$)' /etc/crontab 2>/dev/null | sed 's/^/    /'
    echo "  --- /etc/cron.d ---"
    for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "    == $f"; grep -Ev '^\s*(#|$)' "$f" | sed 's/^/      /'; }; done
    echo "  --- per-user crontabs ---"
    for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && { echo "    == $(basename "$f")"; grep -Ev '^\s*(#|$)' "$f" | sed 's/^/      /'; }; done
    echo "  --- cron.hourly/daily/weekly/monthly ---"
    ls /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null | sed 's/^/    /'
    echo "  --- systemd timers ---"
    systemctl list-timers --all --no-pager 2>/dev/null | sed 's/^/    /' | head -20
    command -v atq >/dev/null 2>&1 && { echo "  --- at jobs ---"; atq | sed 's/^/    /'; }
    if [ -f "$BASE_DIR/cron.baseline" ]; then
      echo "  --- cron changes vs baseline ---"
      { for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && { echo "== $f =="; cat "$f" 2>/dev/null; }; done
        echo "== /etc/cron.d =="; ls /etc/cron.d/ 2>/dev/null; } | diff "$BASE_DIR/cron.baseline" - | grep -E '^[<>]' | sed 's/^/    /'
    fi
    echo
    echo "  [d] delete a user's crontab or a /etc/cron.d file (backed up first)  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      d) read -r -p "  Username (crontab) or file name in /etc/cron.d: " t || return 0
         case "$t" in ""|*/*|.*) bad "Invalid name."; pause; continue ;; esac
         mkdir -p "$REMOVED_DIR"
         if [ -f "/etc/cron.d/$t" ]; then
           confirm "Move /etc/cron.d/$t to $REMOVED_DIR ?" && mv "/etc/cron.d/$t" "$REMOVED_DIR/cron.d-$t.$(date +%s)" && ok "Removed." && log_action "removed /etc/cron.d/$t"
         elif [ -f "/var/spool/cron/crontabs/$t" ]; then
           confirm "Delete $t's crontab (backup kept in $REMOVED_DIR)?" \
             && cp "/var/spool/cron/crontabs/$t" "$REMOVED_DIR/crontab-$t.$(date +%s)" \
             && crontab -r -u "$t" && ok "Removed." && log_action "removed crontab of $t"
         else
           bad "Nothing found for '$t'."
         fi
         pause ;;
      b|"") return 0 ;;
    esac
  done
}

# ---- processes & sessions --------------------------------------------------
mon_procs() {
  local c p sig name u tty
  while true; do
    step "Processes & sessions"
    printf '  %s%-7s %-14s %-10s %-6s %s%s\n' "$C_BOLD" PID USER ELAPSED CPU COMMAND "$C_RST"
    ps -eo pid=,ppid=,user=,etime=,pcpu=,args= --sort=-pcpu 2>/dev/null \
      | awk '$1 != 2 && $2 != 2 {c=$6; for(i=7;i<=NF;i++) c=c" "$i; printf "  %-7s %-14s %-10s %-6s %s\n",$1,$3,$4,$5,substr(c,1,70)}' \
      | head -40
    echo
    echo "  --- Logged-in sessions ---"
    who_pretty | sed 's/^/    /'
    echo
    echo "  [k] kill PID  [n] kill by name  [u] kill ALL of a user's processes  [s] kick a session (tty)  [r] refresh  [b] back"
    read -r -p "  > " c || return 0
    case "$c" in
      k) read -r -p "  PID: " p || return 0
         case "$p" in ""|*[!0-9]*) bad "PID must be a number."; pause; continue ;; esac
         if [ "$p" -le 1 ] || [ "$p" = "$$" ]; then bad "Refusing (PID $p is init or this console)."; pause; continue; fi
         ps -p "$p" -o pid,user,etime,args 2>/dev/null | sed 's/^/    /' || true
         ps -p "$p" >/dev/null 2>&1 || { bad "No such process."; pause; continue; }
         name=$(ps -p "$p" -o comm= 2>/dev/null)
         [[ "$name" =~ $PROTECTED_PROCS ]] && warn "'$name' is a protected/scored service — killing it can fail a scored check."
         read -r -p "  Signal [15=polite, 9=force] (default 15): " sig || return 0
         sig="${sig:-15}"; case "$sig" in 9|15) ;; *) bad "Use 9 or 15."; pause; continue ;; esac
         confirm "Kill PID $p with signal $sig?" && kill -"$sig" "$p" && ok "Sent." && log_action "kill -$sig $p ($name)"
         pause ;;
      n) read -r -p "  Process name (exact): " name || return 0
         [ -n "$name" ] || continue
         [[ "$name" =~ $PROTECTED_PROCS ]] && warn "'$name' is a protected/scored service — killing it can fail a scored check."
         pgrep -a -x "$name" | sed 's/^/    /' || { bad "No process named $name."; pause; continue; }
         confirm "Kill ALL of the above (SIGKILL)?" && pkill -9 -x "$name" && ok "Killed." && log_action "pkill -9 -x $name"
         pause ;;
      u) read -r -p "  Username: " u || return 0
         user_exists "$u" || { bad "No such user."; pause; continue; }
         if [ "$u" = "$CALLER" ] || [ "$u" = root ]; then bad "Refusing to kill all of $u's processes."; pause; continue; fi
         pgrep -a -u "$u" | sed 's/^/    /'
         confirm "SIGKILL everything owned by $u (also ends their SSH sessions)?" && pkill -9 -u "$u" && ok "Done." && log_action "pkill -9 -u $u"
         pause ;;
      s) read -r -p "  TTY to kick (e.g. pts/1): " tty || return 0
         case "$tty" in pts/[0-9]*|tty[0-9]*) ;; *) bad "Enter a tty like pts/1."; pause; continue ;; esac
         who -u | grep -w "$tty" | sed 's/^/    /' || { bad "No session on $tty."; pause; continue; }
         confirm "Kill every process on $tty?" && pkill -9 -t "$tty" && ok "Session killed." && log_action "kicked session $tty"
         pause ;;
      r|"") ;;
      b) return 0 ;;
    esac
  done
}

# ---- delete a user ---------------------------------------------------------
mon_delete_user() {
  local u uid home ts
  read -r -p "  Username to DELETE: " u || return 0
  user_exists "$u" || { bad "No such user: $u"; pause; return 0; }
  uid=$(id -u "$u"); home=$(getent passwd "$u" | cut -d: -f6)
  if [ "$u" = root ] || [ "$uid" -lt 1000 ]; then bad "Refusing: $u is a system account (UID $uid)."; pause; return 0; fi
  if [ "$u" = "$CALLER" ]; then bad "Refusing: that's you ($CALLER)."; pause; return 0; fi
  step "About to delete $u"
  info "UID $uid · home $home · groups: $(id -nG "$u")"
  info "Processes: $(pgrep -c -u "$u" 2>/dev/null || echo 0) · sessions: $(who | awk -v u="$u" '$1==u' | wc -l)"
  info "Their crontab and home directory are backed up to $REMOVED_DIR first (useful as incident-report evidence)."
  local typed
  read -r -p "  Type the username again to confirm: " typed || return 0
  [ "$typed" = "$u" ] || { warn "Names didn't match — cancelled."; pause; return 0; }
  ts=$(date +%s); mkdir -p "$REMOVED_DIR"
  pkill -9 -u "$u" 2>/dev/null || true
  [ -f "/var/spool/cron/crontabs/$u" ] && cp "/var/spool/cron/crontabs/$u" "$REMOVED_DIR/crontab-$u.$ts"
  [ -d "$home" ] && tar -czf "$REMOVED_DIR/home-$u.$ts.tgz" -C "$(dirname "$home")" "$(basename "$home")" 2>/dev/null
  if userdel -r "$u" 2>/dev/null || userdel "$u"; then
    ok "Deleted $u."
    log_action "deleted user $u (uid $uid), backups in $REMOVED_DIR (*.$ts*)"
  else
    bad "userdel failed for $u."
  fi
  pause
}

monitor_menu() {
  local c
  mkdir -p "$MON_DIR"
  while true; do
    pwd_track        # catch up on any password changes since the last look
    printf '\e[2J\e[H' 2>/dev/null
    banner
    printf '  %sMASTER MONITOR%s   caller: %s   baseline: %s\n' "$C_BOLD" "$C_RST" "$CALLER" \
      "$([ -f "$BASE_DIR/accounts.baseline" ] && echo "saved $(date -r "$BASE_DIR/accounts.baseline" '+%b %-d, %-I:%M %p')" || echo 'NONE (run baseline)')"
    printf '  %sdaemon:%s %s\n\n' "$C_DIM" "$C_RST" "$(collector_status_line)"
    echo "   1) Accounts        who exists, sudo, locked, logged in"
    echo "   2) Passwords       last-change dates, lock / unlock / set / expire"
    echo "   3) Privileges      UID 0, sudo group, sudoers, SUID changes, add/remove sudo"
    echo "   4) Cron & timers   every scheduled job, delete a crontab"
    echo "   5) Processes       list, kill PID / name / user, kick a session"
    echo "   6) Delete a user   kills their processes, backs up, removes"
    echo "   7) Changes vs baseline   everything new since 'baseline'"
    echo "   8) Activity log    console actions + every change Pathfinder detected"
    echo "   q) Quit"
    echo
    read -r -p "  > " c || break
    case "$c" in
      1) mon_accounts; pause ;;
      2) mon_passwords ;;
      3) mon_privileges ;;
      4) mon_cron ;;
      5) mon_procs ;;
      6) mon_delete_user ;;
      7) if [ -f "$BASE_DIR/accounts.baseline" ]; then watch_once; else bad "No baseline yet: sudo bash $0 baseline"; fi; pause ;;
      8) step "Console actions (what you did here)"
         if [ -s "$ACTION_LOG" ]; then tail -n 25 "$ACTION_LOG" | sed 's/^/  /'; else info "Nothing logged yet."; fi
         step "Detected changes (new IPs, processes, accounts, password changes — last 30)"
         if grep -qE 'NEW (REMOTE IP|PROCESS)|ACCOUNT CHANGE|PASSWORD' "$LOGFILE" 2>/dev/null; then
           grep -E 'NEW (REMOTE IP|PROCESS)|ACCOUNT CHANGE|PASSWORD' "$LOGFILE" | tail -n 30 | sed 's/^/  /'
         else info "Nothing detected yet."; fi
         service_active || [ -f "$PIDFILE" ] || warn "Daemon is NOT running — changes are only caught while this console is open. Run: sudo bash $0 start"
         pause ;;
      q|Q) break ;;
    esac
  done
}

# ---------------------------------------------------------------------------
case "$MODE" in
  harden)        banner; require_root; harden ;;
  baseline)      banner; require_root; baseline ;;
  watch)         require_root; watch_mode "$@" ;;
  start)         banner; require_root; start_collector ;;
  stop)          require_root; stop_collector ;;
  status)        require_root; info "Daemon: $(collector_status_line)" ;;
  view)          require_root; view_dashboard ;;
  monitor)       require_root; monitor_menu ;;
  install)       banner; require_root; install_service ;;
  uninstall)     require_root; uninstall_service ;;
  __collector__) collector_loop ;;  # internal — used by start_collector/systemd, don't run directly
  *)
    banner
    echo "  Usage: sudo bash $0 {harden|baseline|monitor|watch [-n seconds]|start|view|stop|status|install|uninstall}"
    echo
    echo "  ${C_BOLD}Typical order:${C_RST}  harden → baseline → start → view   (then 'install' to survive a reboot)"
    exit 1
    ;;
esac
