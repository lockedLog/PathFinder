#!/bin/bash

# Pathfinder English/US locale + keyboard watchdog
# Run continuously:
#   sudo bash locale-guard.sh
#
# One-time repair:
#   sudo bash locale-guard.sh once
#
# Faster monitoring:
#   sudo INTERVAL=1 bash locale-guard.sh

set -u

INTERVAL="${INTERVAL:-2}"

TARGET_LANGUAGE="en_US:en"
TARGET_KEYMAP="us"

LOG_FILE="/var/log/pathfinder-locale-guard.log"
STATE_DIR="/root/pathfinder-locale-guard"
PIDFILE="$STATE_DIR/guard.pid"

# Prefer en_US.UTF-8, fall back to C.UTF-8 if it isn't installed.
if locale -a 2>/dev/null | grep -Eqi '^en_US\.utf-?8$'; then
    TARGET_LANG="en_US.UTF-8"
elif locale -a 2>/dev/null | grep -Eqi '^C\.utf-?8$'; then
    TARGET_LANG="C.UTF-8"
else
    TARGET_LANG="C"
fi


require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run as root:"
        echo "sudo bash $0"
        exit 1
    fi
}


log() {
    printf '%s  %s\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" \
        "$*" | tee -a "$LOG_FILE"
}


hash_file() {
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}


replace_if_changed() {
    local file="$1"
    local tmp="$2"

    local before
    local after

    before="$(hash_file "$file")"
    after="$(hash_file "$tmp")"

    if [ "$before" != "$after" ]; then

        # Preserve evidence of what Red Team changed.
        if [ -e "$file" ]; then
            cp -a "$file" \
                "$STATE_DIR/$(basename "$file").changed.$(date +%s)" \
                2>/dev/null || true
        fi

        cp "$tmp" "$file"

        log "REPAIRED: $file"
    fi
}


fix_locale_file() {

    local tmp
    tmp="$(mktemp)"

    cat > "$tmp" <<EOF
LANG=$TARGET_LANG
LANGUAGE=$TARGET_LANGUAGE
LC_MESSAGES=$TARGET_LANG
EOF

    replace_if_changed /etc/default/locale "$tmp"

    rm -f "$tmp"
}


fix_locale_conf() {

    local tmp
    tmp="$(mktemp)"

    cat > "$tmp" <<EOF
LANG=$TARGET_LANG
LC_MESSAGES=$TARGET_LANG
EOF

    replace_if_changed /etc/locale.conf "$tmp"

    rm -f "$tmp"
}


fix_environment() {

    local tmp
    tmp="$(mktemp)"

    # Preserve unrelated environment variables.
    if [ -f /etc/environment ]; then

        awk '
        !/^[[:space:]]*(LANG|LANGUAGE|LC_MESSAGES)=/
        ' /etc/environment > "$tmp"

    fi

    cat >> "$tmp" <<EOF
LANG=$TARGET_LANG
LANGUAGE=$TARGET_LANGUAGE
LC_MESSAGES=$TARGET_LANG
EOF

    replace_if_changed /etc/environment "$tmp"

    rm -f "$tmp"
}


fix_keyboard_file() {

    local file="/etc/default/keyboard"
    local tmp

    tmp="$(mktemp)"

    if [ -f "$file" ]; then

        awk '
        !/^[[:space:]]*XKBLAYOUT=/ &&
        !/^[[:space:]]*XKBVARIANT=/ &&
        !/^[[:space:]]*XKBOPTIONS=/
        ' "$file" > "$tmp"

    else
        echo 'XKBMODEL="pc105"' > "$tmp"
    fi

    cat >> "$tmp" <<EOF
XKBLAYOUT="us"
XKBVARIANT=""
XKBOPTIONS=""
EOF

    replace_if_changed "$file" "$tmp"

    rm -f "$tmp"
}


fix_profile() {

    local file="/etc/profile.d/00-pathfinder-english.sh"
    local tmp

    tmp="$(mktemp)"

    cat > "$tmp" <<EOF
# Managed by Pathfinder locale guard

export LANG="$TARGET_LANG"
export LANGUAGE="$TARGET_LANGUAGE"
export LC_MESSAGES="$TARGET_LANG"
EOF

    replace_if_changed "$file" "$tmp"

    chmod 644 "$file" 2>/dev/null || true

    rm -f "$tmp"
}


fix_localectl() {

    command -v localectl >/dev/null 2>&1 || return

    local status

    status="$(localectl status 2>/dev/null || true)"


    # Locale

    if ! echo "$status" |
         grep -Fq "LANG=$TARGET_LANG"; then

        if localectl set-locale \
            "LANG=$TARGET_LANG" \
            "LC_MESSAGES=$TARGET_LANG" \
            >/dev/null 2>&1
        then
            log "REPAIRED: system locale -> $TARGET_LANG"
        fi

    fi


    # Virtual console keyboard

    local keymap

    keymap="$(
        echo "$status" |
        sed -n 's/^[[:space:]]*VC Keymap:[[:space:]]*//p'
    )"

    if [ "$keymap" != "us" ]; then

        if localectl set-keymap us >/dev/null 2>&1; then
            log "REPAIRED: console keyboard -> US"
        elif command -v loadkeys >/dev/null 2>&1; then
            loadkeys us >/dev/null 2>&1 || true
            log "REPAIRED: console keyboard -> US (loadkeys)"
        fi

    fi


    # X11 keyboard layout

    local x11

    x11="$(
        echo "$status" |
        sed -n 's/^[[:space:]]*X11 Layout:[[:space:]]*//p'
    )"

    if [ "$x11" != "us" ]; then

        if localectl set-x11-keymap us >/dev/null 2>&1; then
            log "REPAIRED: X11 keyboard -> US"
        fi

    fi
}


enforce() {

    fix_locale_file
    fix_locale_conf
    fix_environment
    fix_keyboard_file
    fix_profile
    fix_localectl
}


cleanup() {

    rm -f "$PIDFILE"

    log "Locale guard stopped"
}


require_root

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

MODE="${1:-watch}"


case "$MODE" in

    once)

        enforce

        echo
        echo "Locale:"
        locale

        echo
        echo "Localectl:"
        localectl status 2>/dev/null || true

        ;;


    watch)

        if [ -f "$PIDFILE" ] &&
           kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then

            echo "Locale guard already running."
            echo "PID: $(cat "$PIDFILE")"

            exit 1
        fi

        echo $$ > "$PIDFILE"

        trap cleanup EXIT INT TERM

        log "Locale guard started"
        log "Target locale: $TARGET_LANG"
        log "Target keyboard: US"
        log "Polling every ${INTERVAL}s"

        enforce

        while true; do

            enforce

            sleep "$INTERVAL"

        done

        ;;


    status)

        if [ -f "$PIDFILE" ] &&
           kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then

            echo "Locale guard RUNNING"
            echo "PID $(cat "$PIDFILE")"

        else

            echo "Locale guard NOT RUNNING"

        fi

        echo
        localectl status 2>/dev/null || true

        ;;


    *)

        echo "Usage:"
        echo "  sudo bash $0"
        echo "  sudo bash $0 once"
        echo "  sudo bash $0 status"

        exit 1

        ;;

esac
