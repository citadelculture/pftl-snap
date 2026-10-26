#!/bin/sh
# Trusted pinned-image gate. No repository or Node/Yarn code runs in this loop.
set -eu
phase=$1
nonce=$2
case "$phase" in immutable|compiler-identity|typecheck|production-build) ;; *) exit 70 ;; esac
case "$nonce" in ''|*[!0-9a-f]*) exit 71 ;; esac
tries=0
while [ "$tries" -lt 600 ]; do
    if [ -f /lane-gate/release ]; then
        IFS= read -r received < /lane-gate/release
        [ "$received" = "$nonce" ] || exit 72
        exec /usr/local/bin/node /lane/container-entry.cjs "$phase"
    fi
    tries=$((tries + 1))
    sleep 0.1
done
exit 73
