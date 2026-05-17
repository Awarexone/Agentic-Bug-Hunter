#!/bin/bash
# Shared active-operation approval guard for POST/PUT/DELETE/PATCH/uploads.

ACTIVE_APPROVED=0
APPROVAL_REASON=""
SESSION_LOG=""

parse_active_approval_arg() {
    case "${1:-}" in
        --approve-active)
            ACTIVE_APPROVED=1
            return 0
            ;;
        --approval-reason)
            APPROVAL_REASON="${2:-}"
            return 2
            ;;
        --session-log)
            SESSION_LOG="${2:-}"
            return 2
            ;;
    esac
    return 1
}

require_active_approval() {
    local operation="$1"
    local log_path="${SESSION_LOG:-$PWD/session.log}"
    if [ "$ACTIVE_APPROVED" != "1" ]; then
        echo "[active-gate] REFUSED $operation: missing --approve-active"
        echo "[active-gate] REFUSED $operation: missing --approve-active" >> "$log_path"
        return 1
    fi
    if [ -z "$APPROVAL_REASON" ]; then
        echo "[active-gate] REFUSED $operation: missing --approval-reason"
        echo "[active-gate] REFUSED $operation: missing --approval-reason" >> "$log_path"
        return 1
    fi
    echo "[active-gate] APPROVED $operation: $APPROVAL_REASON" >> "$log_path"
    return 0
}
