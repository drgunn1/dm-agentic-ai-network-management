#!/bin/sh
# Copyright 2026 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
# Capture network traffic with Wireshark's dumpcap and feed it to the demo.
#
# dumpcap writes into a staging folder and starts a new file every
# ROTATE_SECONDS. Each finished file is moved into pcap_files as
# capture_<YYYYmmdd_HHMMSS>.pcapng, where the PCAP monitor parses it once.
# The file still being written never appears in pcap_files, so it is not
# parsed half-written. Only the newest KEEP_FILES capture_* files are kept;
# other files in pcap_files are never touched.
#
# Settings (environment, or /etc/default/bacnet-capture for the service):
#   CAPTURE_INTERFACE  interface to capture on           (default eth0)
#   CAPTURE_FILTER     capture filter (BPF)              (default: all UDP, ARP and
#                      BACnet/Ethernet frames; UDP covers BACnet/IP on any port)
#   ROTATE_SECONDS     seconds per capture file          (default 300)
#   KEEP_FILES         capture files kept in pcap_files  (default 24)
#   PCAP_DIR           where finished files go           (default <project>/pcap_files)
#   STAGING_DIR        where dumpcap writes              (default /var/lib/bacnet-capture)

set -u
PROJECT_DIR=$(cd "$(dirname "$0")" && pwd)

CAPTURE_INTERFACE=${CAPTURE_INTERFACE:-eth0}
CAPTURE_FILTER=${CAPTURE_FILTER:-udp or arp or (ether[12:2] <= 1500 and ether[14] == 0x82)}
ROTATE_SECONDS=${ROTATE_SECONDS:-300}
KEEP_FILES=${KEEP_FILES:-24}
PCAP_DIR=${PCAP_DIR:-$PROJECT_DIR/pcap_files}
STAGING_DIR=${STAGING_DIR:-/var/lib/bacnet-capture}

mkdir -p "$PCAP_DIR" "$STAGING_DIR" || exit 1

# Move finished staging files into PCAP_DIR. With "all", the newest file is
# moved too (used after dumpcap has exited); otherwise it is still being written.
publish() {
    files=$(ls -1 "$STAGING_DIR"/live_*.pcapng 2>/dev/null | sort)
    [ -n "$files" ] || return 0
    [ "${1:-}" = all ] || files=$(echo "$files" | sed '$d')
    for f in $files; do
        # dumpcap names ring files live_<n>_<YYYYmmddHHMMSS>.pcapng
        stamp=$(basename "$f" .pcapng | sed 's/.*_\([0-9]\{8\}\)\([0-9]\{6\}\)$/\1_\2/')
        packets=$(capinfos -Mc "$f" 2>/dev/null | awk '/Number of packets/ {print $NF}')
        if [ "${packets:-0}" = 0 ]; then
            rm -f "$f"          # nothing captured in this interval
            continue
        fi
        mv "$f" "$PCAP_DIR/capture_$stamp.pcapng" &&
            echo "[*] Captured $packets packets -> $PCAP_DIR/capture_$stamp.pcapng"
    done
    # Keep only the newest KEEP_FILES capture files
    ls -1 "$PCAP_DIR"/capture_*.pcapng 2>/dev/null | sort | head -n "-$KEEP_FILES" |
        while read -r old; do rm -f "$old" && echo "[*] Removed old capture $(basename "$old")"; done
}

publish all             # files left over from an earlier run

echo "[*] Capturing on $CAPTURE_INTERFACE, new file every ${ROTATE_SECONDS}s, keeping $KEEP_FILES"
echo "[*] Filter: $CAPTURE_FILTER"
dumpcap -q -i "$CAPTURE_INTERFACE" -f "$CAPTURE_FILTER" -b "duration:$ROTATE_SECONDS" \
    -w "$STAGING_DIR/live.pcapng" &
dumpcap_pid=$!

stop() {
    kill "$dumpcap_pid" 2>/dev/null
    wait "$dumpcap_pid" 2>/dev/null
    publish all         # the last file is complete once dumpcap has exited
    exit 0
}
trap stop INT TERM

while kill -0 "$dumpcap_pid" 2>/dev/null; do
    publish
    sleep 10 &
    wait $!             # returns at once on SIGTERM so stop() runs promptly
done

wait "$dumpcap_pid"
status=$?
echo "[!] dumpcap exited with status $status"
publish all
exit "$status"
