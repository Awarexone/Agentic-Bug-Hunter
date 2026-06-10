#!/usr/bin/env bash
# tools/banner.sh — shared ASCII "BUGHUNTER" banner for shell scripts.
# Source this file, then call:
#   print_banner "subtitle" "target" "Label|description" "Label|description" ...
# Each trailing arg is one workflow step. Use "|" to separate label and detail
# (e.g. "Recon|subdomain enum, URL crawl"); pass just "Recon" for label-only.
# Respects NO_COLOR. Falls back to plain 8-color when TERM isn't 256-capable.

_BB_LOGO_WIDTH=78

_bb_use_color() {
    [ -n "${NO_COLOR:-}" ] && return 1
    [ -t 1 ] || return 1
    return 0
}

_bb_should_skip() {
    [ -n "${BBHUNT_BANNER_SHOWN:-}" ] && return 0
    [ -n "${BBHUNT_NO_BANNER:-}" ]    && return 0
    [ -t 1 ] || return 0
    return 1
}

_bb_center() {
    # _bb_center <text> <width>  →  prints text padded with leading spaces.
    local text="$1" width="$2" len=${#1}
    local pad=$(( (width - len) / 2 ))
    [ "$pad" -lt 0 ] && pad=0
    printf '%*s%s' "$pad" '' "$text"
}

print_banner() {
    local subtitle="${1:-}"
    local target="${2:-}"
    shift 2 2>/dev/null || true
    local steps=("$@")

    if _bb_should_skip; then
        return 0
    fi

    local C1 C2 C3 C4 C5 C6 CYAN MAGENTA BOLD DIM NC
    if _bb_use_color; then
        case "${COLORTERM:-}:${TERM:-}" in
            truecolor:*|24bit:*|*:*256*|*:xterm*)
                C1=$'\033[38;5;196m'; C2=$'\033[38;5;202m'; C3=$'\033[38;5;208m'
                C4=$'\033[38;5;214m'; C5=$'\033[38;5;220m'; C6=$'\033[38;5;226m'
                ;;
            *)
                C1=$'\033[1;31m'; C2=$'\033[0;31m'; C3=$'\033[1;33m'
                C4=$'\033[0;33m'; C5=$'\033[1;33m'; C6=$'\033[0;33m'
                ;;
        esac
        CYAN=$'\033[1;36m'; MAGENTA=$'\033[1;35m'; BOLD=$'\033[1m'
        DIM=$'\033[2m'; NC=$'\033[0m'
    else
        C1=''; C2=''; C3=''; C4=''; C5=''; C6=''
        CYAN=''; MAGENTA=''; BOLD=''; DIM=''; NC=''
    fi

    echo
    printf '  %s██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ %s\n' "$C1" "$NC"
    printf '  %s██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗%s\n' "$C2" "$NC"
    printf '  %s██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝%s\n' "$C3" "$NC"
    printf '  %s██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗%s\n' "$C4" "$NC"
    printf '  %s██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║%s\n' "$C5" "$NC"
    printf '  %s╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝%s\n' "$C6" "$NC"

    if [ -n "$subtitle" ]; then
        local bar=''
        bar=$(printf '─%.0s' $(seq 1 $_BB_LOGO_WIDTH))
        printf '  %s%s%s\n' "$CYAN" "$bar" "$NC"
        printf '  %s%s%s\n' "$CYAN" "$(_bb_center "$subtitle" $_BB_LOGO_WIDTH)" "$NC"
    fi
    printf '  %s%s%s\n' "$DIM" "$(_bb_center 'bughunter.fun  ·  github.com/shuvonsec/claude-bug-bounty' $_BB_LOGO_WIDTH)" "$NC"
    if [ -n "$target" ]; then
        printf '  %s%s%s\n' "$MAGENTA" "$(_bb_center "▸ target: $target" $_BB_LOGO_WIDTH)" "$NC"
    fi

    if [ ${#steps[@]} -gt 0 ]; then
        # Find max label width for alignment
        local max_label=0
        local s label
        for s in "${steps[@]}"; do
            label="${s%%|*}"
            [ ${#label} -gt $max_label ] && max_label=${#label}
        done
        echo
        printf '  %s%s%s\n' "$DIM" "$(_bb_center '── Workflow ──' $_BB_LOGO_WIDTH)" "$NC"
        local idx=1
        for s in "${steps[@]}"; do
            label="${s%%|*}"
            local desc=""
            [[ "$s" == *"|"* ]] && desc="${s#*|}"
            printf '   %s%d.%s  %s%-*s%s  %s%s%s\n' \
                "$CYAN" "$idx" "$NC" \
                "$BOLD" "$max_label" "$label" "$NC" \
                "$DIM" "$desc" "$NC"
            idx=$((idx + 1))
        done
    fi
    echo
    # Mark printed so child scripts inherit it and skip re-printing.
    export BBHUNT_BANNER_SHOWN=1
}
