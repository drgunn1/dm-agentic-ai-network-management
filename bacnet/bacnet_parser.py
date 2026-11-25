"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

BACnet Protocol Parser
Extracts device information and detects anomalies from BACnet packets.

Decodes BACnet/IP (BVLC, incl. Forwarded-NPDU from BBMDs), BACnet/Ethernet
(802.2 LLC) and BACnet MS/TP frames down to the NPDU / APDU, and checks for:

  Addressing      duplicate IP / instance / MS/TP address, ARP conflicts,
                  invalid instance numbers, device identity changes (spoofing)
  Transactions    unanswered confirmed requests, retries, slow responses,
                  Error / Reject / Abort PDUs, segmentation problems
  Security        DeviceCommunicationControl, ReinitializeDevice, file writes,
                  object create/delete, priority 1-2 writes, cleartext
                  passwords, password brute force, BBMD table changes
  Traffic         Who-Is / I-Am / COV floods, broadcast storms, duplicate
                  broadcasts from BBMD loops, time-sync conflicts, devices
                  searched for but never answering Who-Is
  Network layer   Reject-Message-To-Network, Router-Busy, conflicting routers,
                  routing loops (hop count), unreachable networks
  Link layer      malformed BVLC/NPDU/APDU, BVLC-Result NAKs, non-standard
                  UDP ports, MS/TP CRC errors, invalid MS/TP masters

Run standalone to analyse a capture:  python -m bacnet.bacnet_parser file.pcap
"""

import hashlib
import json
import multiprocessing
import os
import sys
from collections import defaultdict, Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

try:
    from .bacnet_constants import *  # noqa: F401,F403
    from . import packet_extract
except ImportError:  # executed as a plain script
    from bacnet_constants import *  # noqa: F401,F403
    import packet_extract


def default_workers() -> int:
    """Decoder processes to use: BACNET_PARSER_WORKERS, else one per core minus the
    core that runs the analysis itself (5 on a 6-core i.MX 95)."""
    env = os.environ.get('BACNET_PARSER_WORKERS')
    if env and env.strip().isdigit():
        return max(1, int(env))
    return max(1, (os.cpu_count() or 1) - 1)


# Short operator guidance attached to every anomaly (read by the AI agent)
RECOMMENDED_ACTIONS = {
    'duplicate_ip': 'Find both MACs on the switch and re-address one device.',
    'duplicate_instance': 'Give each device a unique Device object instance number.',
    'multi_instance_ip': 'Check whether this IP is a gateway; otherwise look for a duplicate device.',
    'mac_multi_ip': 'Confirm the MAC belongs to a router/gateway; otherwise check for IP changes or spoofing.',
    'arp_conflict': 'Locate the conflicting MACs; investigate ARP spoofing if unexpected.',
    'mstp_conflict': 'Set a unique MAC address on each MS/TP device on the trunk.',
    'device_identity_change': 'Verify the physical device; treat as possible spoofing until explained.',
    'invalid_device_instance': 'Configure a valid device instance (0-4194302) on the device.',
    'device_unresponsive': 'Check power, cabling and IP/MS/TP settings of the device.',
    'request_timeouts': 'Check device load, network path and APDU timeout settings.',
    'request_retries': 'Check link quality and increase APDU timeout if the device is slow.',
    'slow_response': 'Reduce polling load on the device or raise client APDU timeout.',
    'access_denied': 'Confirm the client is authorised; investigate if the source is unknown.',
    'device_busy': 'Reduce request rate to the device; check its CPU/resources.',
    'bacnet_errors': 'Review client configuration for wrong object/property references.',
    'bacnet_reject': 'Check client/device protocol revision and service support.',
    'bacnet_abort': 'Check max-APDU and segmentation settings on client and device.',
    'segmentation_issue': 'Align max-APDU / segmentation support; reduce ReadPropertyMultiple size.',
    'sensitive_command': 'Confirm this command was authorised by an operator.',
    'cleartext_password': 'BACnet passwords are not encrypted; restrict access or use BACnet/SC.',
    'password_bruteforce': 'Block the source and change the device password immediately.',
    'bbmd_config_change': 'Verify the BDT/FDT change was authorised; restore known-good table.',
    'bbmd_reconnaissance': 'Confirm the source is a known management workstation.',
    'foreign_device_registration': 'Confirm each foreign device is expected; restrict BBMD access.',
    'who_is_flood': 'Limit discovery rate on the source; use bounded Who-Is ranges.',
    'i_am_flood': 'Check device firmware/config for periodic I-Am or Who-Is loops.',
    'cov_flood': 'Increase COV increment on the device objects.',
    'service_flood': 'Identify why the source floods this service and rate-limit it.',
    'broadcast_storm': 'Find the top broadcaster; check for BBMD loops or discovery storms.',
    'duplicate_broadcast': 'Ensure one BBMD per subnet and correct BDT masks.',
    'missing_device': 'Check whether the searched device is powered and reachable.',
    'time_sync_conflict': 'Keep a single time master on the network.',
    'protocol_violation': 'Update or reconfigure the source device firmware.',
    'router_conflict': 'Ensure each BACnet network number is unique and has one path.',
    'network_number_conflict': 'Configure the same network number on all routers of this segment.',
    'network_reject': 'Check router configuration and the route to the destination network.',
    'router_busy': 'Check router load and the downstream network (often MS/TP).',
    'who_is_router_flood': 'Check the source for missing routes or misconfiguration.',
    'unreachable_network': 'Add or fix the router serving this network number.',
    'routing_loop': 'Look for duplicate network numbers or BBMD/router loops.',
    'excessive_hops': 'Review the BACnet routing topology.',
    'bvlc_nak': 'Check BBMD configuration (foreign device support, BDT).',
    'nonstandard_port': 'Confirm the non-default UDP port is intentional.',
    'malformed_packet': 'Update the source firmware; investigate if the source is unknown.',
    'mstp_crc_error': 'Check RS-485 wiring, termination, biasing and baud rate.',
    'mstp_invalid_master': 'Set the device MAC to 0-127 or configure it as a slave.',
    'file_transfer_failed': 'Check the file object is writable (not locked/read-only, device not busy) and retry the download.',
    'file_transfer_stalled': 'Check the path to the device (router, MS/TP trunk load) and restart the download.',
    'backup_restore_incomplete': 'Send end-restore/abort-restore (ReinitializeDevice) or power-cycle the device, then retry.',
    'backup_restore': 'Confirm the backup/restore was planned; check devices not completed.',
    'duplicate_packets': 'Capture from a single interface, or look for a switching loop.',
    'remote_network_load': 'Send to specific devices instead of broadcasting into the remote network; pause other broadcasts during downloads.',
}


@dataclass
class DetectionThresholds:
    """Tunable limits for the rate / timing based detectors."""
    apdu_timeout: float = 3.0            # s, BACnet default APDU timeout
    retry_window: float = 30.0           # s, same invoke ID re-sent within this = retry
    slow_response: float = 1.0          # s, p95 response time considered slow
    unanswered_ratio: float = 0.2        # fraction of unanswered requests to report
    min_requests_for_ratio: int = 3
    rate_window: float = 1.0             # s, window for rate checks
    who_is_per_source: int = 5           # per window
    who_has_per_source: int = 5
    i_am_per_source: int = 10
    cov_per_source: int = 25
    time_sync_per_source: int = 2
    who_is_router_per_source: int = 3
    unconfirmed_other_per_source: int = 25
    broadcast_total: int = 100           # broadcasts per window on one segment
    remote_broadcast_total: int = 20     # broadcasts per window into one remote network
    remote_broadcast_bytes_per_s: int = 1000  # sustained broadcast load into a remote network
    error_count: int = 5                 # benign Error PDUs before reporting
    password_failures: int = 3           # per client/server pair
    max_hops: int = 8                    # 255 - hop_count above this = suspicious
    duplicate_broadcast_window: float = 1.0
    missing_device_whois: int = 2        # targeted Who-Is with no I-Am
    restart_window: float = 120.0        # s after an accepted reinitialize in which
                                         # timeouts / retries / slow replies are expected
    procedure_stall: float = 60.0        # s without progress = stuck transfer / restore
    duplicate_frame_window: float = 0.01 # s, identical frames closer than this are copies
    min_retry_interval: float = 0.25     # s, faster re-sends are capture duplicates


class BACnetParser:
    """Parser for BACnet protocol packets."""

    # Packets decoded per task sent to a worker process
    BATCH_SIZE = 2000
    # Smaller captures are decoded in-process: starting workers would cost more
    PARALLEL_MIN_BYTES = 4 * 1024 * 1024
    # Seconds to wait for one batch before giving up on the worker pool
    WORKER_TIMEOUT = 120

    def __init__(self, thresholds: Optional[DetectionThresholds] = None,
                 workers: Optional[int] = None):
        """
        Args:
            thresholds: detection limits (defaults to DetectionThresholds()).
            workers: decoder processes for large captures. None = one per CPU core
                minus one (or BACNET_PARSER_WORKERS); 1 = decode in this process.
        """
        self.thresholds = thresholds or DetectionThresholds()
        self.workers = workers if workers is not None else default_workers()
        self._pool = None
        self._reset()

    # ------------------------------------------------------------------
    # Worker pool
    # ------------------------------------------------------------------
    def _get_pool(self):
        """Create the decoder pool once and keep it for later captures."""
        if self._pool is None:
            # 'fork' on Linux: workers start instantly with the decoder already
            # loaded. Measured on i.MX 95, 'forkserver' was ~20x slower at returning
            # decoded batches and re-imports the server's main script (and its AI
            # stack) in every worker. The workers only run pure decoding code, so
            # forking from the threaded web server is safe here.
            methods = multiprocessing.get_all_start_methods()
            ctx = multiprocessing.get_context('fork' if 'fork' in methods else None)
            self._pool = ctx.Pool(self.workers)
        return self._pool

    def close(self):
        """Stop the decoder worker processes."""
        if self._pool is not None:
            self._pool.terminate()
            self._pool.join()
            self._pool = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _batches(self, pcap_file: str):
        batch = []
        for rec in packet_extract.read_raw(pcap_file):
            batch.append(rec)
            if len(batch) >= self.BATCH_SIZE:
                yield batch
                batch = []
        if batch:
            yield batch

    def _jobs(self, pcap_file: str):
        """Units of decoding work: (function, argument) pairs in capture order.

        pcap / pcapng files are split into byte ranges that a worker reads itself,
        so the main process never touches packet data. Other formats are read
        here and handed out as batches of raw records.
        """
        slices = packet_extract.index_capture(pcap_file, self.BATCH_SIZE)
        if slices is not None:
            for start, end, ctx in slices:
                yield packet_extract.decode_slice, (pcap_file, start, end, ctx)
            return
        for batch in self._batches(pcap_file):
            yield packet_extract.extract_batch, batch

    def _records(self, pcap_file: str):
        """Decoded records in capture order; decoding runs on all cores for big files."""
        try:
            size = os.path.getsize(pcap_file)
        except OSError:
            size = 0
        if self.workers <= 1 or size < self.PARALLEL_MIN_BYTES:
            for func, arg in self._jobs(pcap_file):
                yield from func(arg)
            return

        try:
            pool = self._get_pool()
        except Exception as e:
            print(f"[!] Parallel decoding unavailable ({e}); decoding in-process")
            pool = None
        in_flight = deque()                       # bounded: memory stays flat
        max_in_flight = self.workers * 3

        def collect():
            nonlocal pool
            func, arg, result = in_flight.popleft()
            if result is not None:
                try:
                    return result.get(timeout=self.WORKER_TIMEOUT)
                except Exception as e:
                    # A worker died or hung: finish this capture in-process and
                    # rebuild the pool next time instead of blocking forever.
                    print(f"[!] Decoder worker failed ({type(e).__name__}); "
                          "continuing in-process")
                    self.close()
                    pool = None
                    for i, (f, a, _) in enumerate(in_flight):
                        in_flight[i] = (f, a, None)
            return func(arg)

        try:
            for func, arg in self._jobs(pcap_file):
                result = pool.apply_async(func, (arg,)) if pool is not None else None
                in_flight.append((func, arg, result))
                if len(in_flight) >= max_in_flight:
                    yield from collect()
            while in_flight:
                yield from collect()
        finally:
            in_flight.clear()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    def _reset(self):
        # Addressing (kept from the original implementation)
        self.device_instances = defaultdict(list)
        self.ip_to_instances = defaultdict(set)
        self.ip_routed_instances = defaultdict(dict)   # ip -> {instance: routed address}
        self.ip_to_macs = defaultdict(set)
        self.mac_to_ips = defaultdict(set)
        self.mstp_to_instances = defaultdict(set)
        self.device_info = {}
        self.arp_table = defaultdict(set)
        self.ip_packet_count = defaultdict(lambda: defaultdict(int))
        self.addr_packet_count = Counter()

        # Timing
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

        # Counters for statistics
        self.pdu_type_counts = Counter()
        self.service_counts = Counter()
        self.bvlc_counts = Counter()
        self.network_msg_counts = Counter()
        self.mstp_frame_counts = Counter()

        # Transactions
        self.pending = {}                                   # (client, server, invoke) -> txn
        self.requests_per_server = Counter()
        self.retry_events = []                              # (server, service, t)
        self.unanswered_events = []                         # (server, service, t)
        self.latencies = defaultdict(list)                  # server -> [(t, s)]
        self.restarts = defaultdict(list)                   # server -> [t accepted reinit]
        self.reinit_log = []                                # every answered reinitialize
        self.file_writes = Counter()                        # (client, server) -> requests
        self.file_progress = defaultdict(list)              # (client, server) -> [(t, pos)]
        self.file_errors = defaultdict(list)                # (client, server) -> [(t, label)]
        self.access_events = []                             # (client, server, svc, label, t)
        self.accepted = defaultdict(list)                   # (client, server, svc) -> [t]
        self.last_seen = {}                                 # addr -> last packet time
        self.pair_last = {}                                 # (src, dst) -> last packet time
        self.identity_links = defaultdict(set)              # addr -> physical identity keys
        self.recent_frames = {}                             # frame hash -> t
        self.duplicate_frames = 0
        self.errors = defaultdict(Counter)                  # server -> (class, code, svc) -> n
        self.rejects = defaultdict(Counter)                 # server -> (reason, svc) -> n
        self.aborts = defaultdict(Counter)                  # sender -> (reason, by_server) -> n
        self.segment_naks = Counter()                       # (src, dst) -> n
        self.password_failures = Counter()                  # (client, server) -> n
        self.sensitive_events = []
        self.protocol_violations = defaultdict(Counter)     # src -> description -> n

        # Unconfirmed services / rates
        self.unconfirmed_times = defaultdict(list)          # (src, service) -> [t]
        self.broadcast_times = []
        self.broadcast_by_target = defaultdict(list)        # target -> [t]
        self.broadcast_bytes = Counter()                    # target -> NPDU bytes
        self.broadcast_senders = defaultdict(Counter)       # target -> src -> n
        self.who_is_global = Counter()
        self.who_is_targets = defaultdict(lambda: {'count': 0, 'sources': set()})
        self.iam_instances = set()
        self.time_sync_sources = defaultdict(set)           # service -> {src}
        self.device_identity = defaultdict(lambda: {
            'vendor_ids': set(), 'max_apdu': set(), 'segmentation': set()})
        self.invalid_instances = defaultdict(set)           # src -> {instance/obj}

        # Network layer
        self.router_networks = defaultdict(set)             # dnet -> {router}
        self.network_rejects = Counter()                    # (router, dnet, reason) -> n
        self.router_busy = defaultdict(set)                 # router -> {dnet}
        self.who_is_router_times = defaultdict(list)
        self.who_is_router_dnets = Counter()
        self.min_hop_count = {}                             # src -> hop count
        self.network_numbers = defaultdict(set)             # net -> {router}
        self.routing_table_inits = Counter()                # (src, dst) -> n

        # BVLC / BBMD
        self.bvlc_naks = Counter()                          # (src, dst, code) -> n
        self.bbmd_writes = Counter()                        # (src, dst, func) -> n
        self.bbmd_reads = Counter()
        self.foreign_devices = {}                           # src -> ttl
        self.broadcast_copies = defaultdict(list)           # (orig, npdu hash) -> [(t, via)]
        self.nonstandard_ports = Counter()                  # (ip, port) -> n
        self.server_ports = Counter()                       # (ip, port) BACnet servers

        # Malformed / link layer
        self.malformed = defaultdict(Counter)               # src -> reason -> n
        self.mstp_crc_errors = Counter()                    # (src, kind) -> n
        self.mstp_invalid_master = Counter()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def analyze_pcap(self, pcap_file: str) -> dict:
        """
        Analyze a PCAP file for BACnet traffic.

        Args:
            pcap_file: Path to the PCAP file

        Returns:
            dict: Analysis results containing devices, anomalies, and statistics
        """
        self._reset()

        counts = Counter()
        total = 0
        try:
            # Records are streamed (and decoded in parallel for large captures);
            # the analysis below consumes them strictly in capture order.
            for rec in self._records(pcap_file):
                total += 1
                try:
                    self._process_record(rec, counts)
                except Exception as e:  # never let one odd packet kill the analysis
                    counts['decode_errors'] += 1
                    self._malformed('unknown', f'decoder exception: {type(e).__name__}')
        except Exception as e:
            print(f"[!] Error reading pcap file: {e}")
            if not total:
                return {}

        devices = self._extract_devices()
        self.total_packets = total
        anomalies = self._detect_anomalies()
        statistics = {
            'total_packets': total,
            'bacnet_ip_packets': counts['bip'],
            'bacnet_mstp_packets': counts['mstp'],
            'bacnet_ethernet_packets': counts['eth'],
            'arp_packets': counts['arp'],
            'total_devices': len(self.device_info),
            'total_anomalies': len(anomalies),
            'capture_duration_s': round((self.last_ts or 0) - (self.first_ts or 0), 3),
            'pdu_types': dict(self.pdu_type_counts),
            'services': dict(self.service_counts.most_common(20)),
            'bvlc_functions': dict(self.bvlc_counts),
            'network_messages': dict(self.network_msg_counts),
            'mstp_frames': dict(self.mstp_frame_counts),
            'confirmed_requests': sum(self.requests_per_server.values()),
            'unanswered_requests': len(self.unanswered_events),
            'retransmissions': len(self.retry_events),
            'error_pdus': sum(sum(c.values()) for c in self.errors.values()),
            'reject_pdus': sum(sum(c.values()) for c in self.rejects.values()),
            'abort_pdus': sum(sum(c.values()) for c in self.aborts.values()),
            'duplicate_frames': self.duplicate_frames,
        }

        return {
            'devices': devices,
            'anomalies': anomalies,
            'statistics': statistics
        }

    # ------------------------------------------------------------------
    # Packet dispatch
    # ------------------------------------------------------------------
    def _process_record(self, rec: tuple, counts: Counter):
        kind, t = rec[0], rec[1]
        if self.first_ts is None:
            self.first_ts = t
        self.last_ts = t

        if kind == 'x':
            return

        if kind == 'arp':
            counts['arp'] += 1
            _, _, op, sender_ip, sender_mac = rec
            if op in (1, 2) and sender_ip != '0.0.0.0':    # ARP probes are not conflicts
                self.arp_table[sender_ip].add(sender_mac)
                self.ip_to_macs[sender_ip].add(sender_mac)
                self.mac_to_ips[sender_mac].add(sender_ip)
            return

        if kind in ('udp', 'dup'):
            # Captures taken on several interfaces / SPAN ports often hold every
            # frame twice; copies would look like retries and inflate rates.
            key = rec[2]
            prev = self.recent_frames.get(key)
            self.recent_frames[key] = t
            if prev is not None and t - prev <= self.thresholds.duplicate_frame_window:
                self.duplicate_frames += 1
                return
            if len(self.recent_frames) > 4096:
                cutoff = t - self.thresholds.duplicate_frame_window
                self.recent_frames = {k: v for k, v in self.recent_frames.items() if v >= cutoff}
            if kind == 'udp':
                _, _, _, src_ip, dst_ip, sport, dport, payload, eth_src, on_port = rec
                counts['bip'] += 1
                self._process_bip(src_ip, dst_ip, sport, dport, payload, eth_src, t)
            return

        if kind == 'llc':
            counts['eth'] += 1
            _, _, src_mac, dst_mac, npdu = rec
            self._process_npdu(npdu, t, f"ETH:{src_mac}", f"ETH:{dst_mac}",
                               dst_mac.lower() == 'ff:ff:ff:ff:ff:ff')
            return

        if kind == 'raw':
            # A capture with the MS/TP link type gives one bare frame per record;
            # anything else is only scanned for frames with a valid header CRC.
            if self._process_mstp(rec[2], t, rec[3]):
                counts['mstp'] += 1

    @staticmethod
    def _looks_like_bvlc(payload: bytes) -> bool:
        return packet_extract.looks_like_bvlc(payload)

    # ------------------------------------------------------------------
    # BACnet/IP (BVLC)
    # ------------------------------------------------------------------
    def _process_bip(self, src_ip: str, dst_ip: str, sport: int, dport: int,
                     payload: bytes, src_mac: Optional[str], t: float):
        if sport in BACNET_PORT_RANGE and sport != BACNET_DEFAULT_PORT:
            self.nonstandard_ports[(src_ip, sport)] += 1

        src_base = self._ip_addr(src_ip, sport)
        dst_base = self._ip_addr(dst_ip, dport)

        if src_mac:
            self.mac_to_ips[src_mac].add(src_ip)
            self.ip_to_macs[src_ip].add(src_mac)
            self.ip_packet_count[src_ip][src_mac] += 1

        npdu, func, orig = self.parse_bvlc(payload, src_base, dst_base, t)
        if npdu is None:
            return

        # A Forwarded-NPDU was originally sent by the address in the BVLC header,
        # not by the BBMD that relays it.
        if func == BVLC_FORWARDED_NPDU and orig:
            src_base = orig
        dst_bcast = func in (0x04, 0x09, 0x0B) or dst_ip.endswith('.255') \
            or dst_ip == '255.255.255.255'
        self._process_npdu(npdu, t, src_base, dst_base, dst_bcast)

    @staticmethod
    def _ip_addr(ip: str, port: int) -> str:
        return ip if port == BACNET_DEFAULT_PORT else f"{ip}:{port}"

    def parse_bvlc(self, payload: bytes, src: str, dst: str, t: float
                   ) -> Tuple[Optional[bytes], Optional[int], Optional[str]]:
        """Decode the BVLC header. Returns (npdu, function, original source)."""
        if len(payload) < 4:
            self._malformed(src, 'truncated BVLC header')
            return None, None, None
        if payload[0] != BVLC_TYPE_BIP:
            self._malformed(src, f'BVLC type 0x{payload[0]:02X} (expected 0x81)')
            return None, None, None

        func = payload[1]
        length = int.from_bytes(payload[2:4], 'big')
        name = BVLC_FUNCTIONS.get(func)
        if name is None:
            self._malformed(src, f'unknown BVLC function 0x{func:02X}')
            return None, None, None
        self.bvlc_counts[name] += 1
        if length != len(payload):
            self._malformed(src, f'BVLC length {length} != UDP payload {len(payload)}')
            if length > len(payload):
                return None, func, None
            payload = payload[:length]

        body = payload[4:]
        if func == 0x00:                                     # BVLC-Result
            if len(body) >= 2:
                code = int.from_bytes(body[:2], 'big')
                if code != 0:
                    self.bvlc_naks[(src, dst, code)] += 1
            return None, func, None
        if func in (0x01, 0x08):                             # Write-BDT / Delete-FDT
            self.bbmd_writes[(src, dst, name)] += 1
            return None, func, None
        if func in (0x02, 0x06):                             # Read-BDT / Read-FDT
            self.bbmd_reads[(src, dst, name)] += 1
            return None, func, None
        if func == 0x05:                                     # Register-Foreign-Device
            ttl = int.from_bytes(body[:2], 'big') if len(body) >= 2 else None
            self.foreign_devices[src] = ttl
            return None, func, None
        if func not in BVLC_FUNCTIONS_WITH_NPDU:
            return None, func, None

        orig = None
        if func == BVLC_FORWARDED_NPDU:
            if len(body) < 6:
                self._malformed(src, 'truncated Forwarded-NPDU')
                return None, func, None
            o_ip = '.'.join(str(b) for b in body[:4])
            o_port = int.from_bytes(body[4:6], 'big')
            orig = self._ip_addr(o_ip, o_port)
            body = body[6:]

        # Track broadcast copies to spot BBMD loops / duplicate BBMDs
        if func in (0x04, 0x0B):
            key = (orig or src, hashlib.sha1(body).hexdigest()[:16])
            self.broadcast_copies[key].append((t, src, BVLC_FUNCTIONS[func]))
        return body, func, orig

    # ------------------------------------------------------------------
    # NPDU (network layer)
    # ------------------------------------------------------------------
    def decode_npdu(self, npdu: bytes) -> Optional[dict]:
        """Decode the NPCI. Returns None if this is not a BACnet NPDU."""
        if len(npdu) < 2:
            return {'error': 'truncated NPDU'}
        if npdu[0] != 0x01:
            return {'error': f'NPDU version {npdu[0]} (expected 1)'}
        control = npdu[1]
        out = {'control': control, 'dnet': None, 'dadr': b'', 'snet': None,
               'sadr': b'', 'hop': None, 'net_msg': None, 'vendor': None,
               'expecting_reply': bool(control & 0x04), 'priority': control & 0x03}
        if control & 0x50:
            out['warning'] = 'reserved NPCI control bits set'
        off = 2
        try:
            if control & 0x20:
                out['dnet'] = int.from_bytes(npdu[off:off + 2], 'big')
                dlen = npdu[off + 2]
                out['dadr'] = npdu[off + 3:off + 3 + dlen]
                off += 3 + dlen
            if control & 0x08:
                out['snet'] = int.from_bytes(npdu[off:off + 2], 'big')
                slen = npdu[off + 2]
                if slen == 0 or out['snet'] == 0xFFFF:
                    return {'error': 'invalid SNET/SLEN in NPCI'}
                out['sadr'] = npdu[off + 3:off + 3 + slen]
                off += 3 + slen
            if control & 0x20:
                out['hop'] = npdu[off]
                off += 1
            if control & 0x80:
                out['net_msg'] = npdu[off]
                off += 1
                if out['net_msg'] >= 0x80:
                    out['vendor'] = int.from_bytes(npdu[off:off + 2], 'big')
                    off += 2
        except IndexError:
            return {'error': 'truncated NPCI'}
        if off > len(npdu):
            return {'error': 'truncated NPCI'}
        out['data'] = npdu[off:]
        return out

    def parse_bacnet_npdu(self, payload: bytes) -> Optional[bytes]:
        """Backwards compatible helper: return the NPDU carried by a BVLC frame."""
        npdu, _, _ = self.parse_bvlc(payload, '?', '?', 0.0)
        return npdu

    def _process_npdu(self, npdu: bytes, t: float, src_base: str, dst_base: str,
                      dst_bcast: bool):
        n = self.decode_npdu(npdu)
        if n is None:
            return
        if 'error' in n:
            self._malformed(src_base, n['error'])
            return
        if 'warning' in n:
            self._malformed(src_base, n['warning'])

        src = self._routed(src_base, n['snet'], n['sadr'])
        dst = self._routed(dst_base, n['dnet'], n['dadr'])
        if n['dnet'] == 0xFFFF or (n['dnet'] is not None and not n['dadr']):
            dst_bcast = True
        self.addr_packet_count[src] += 1
        self.last_seen[src] = t
        self.pair_last[(src, dst)] = t

        if n['hop'] is not None:
            prev = self.min_hop_count.get(src_base)
            self.min_hop_count[src_base] = n['hop'] if prev is None else min(prev, n['hop'])

        if dst_bcast:
            # Where the broadcast lands: this segment, every network, or one remote
            # network behind a router (often a slow MS/TP trunk)
            if n['dnet'] == 0xFFFF:
                target = 'all networks (global broadcast)'
            elif n['dnet'] is not None:
                target = f'network {n["dnet"]} via router {dst_base}'
            else:
                target = 'local segment'
            self.broadcast_times.append(t)
            self.broadcast_by_target[target].append(t)
            self.broadcast_bytes[target] += len(npdu)
            self.broadcast_senders[target][src] += 1

        if n['net_msg'] is not None:
            self._process_network_message(n, n['data'], t, src_base, dst)
            return
        self._process_apdu(n['data'], t, src, dst, dst_bcast, src_base, n)

    @staticmethod
    def _routed(base: str, net: Optional[int], adr: bytes) -> str:
        if net is None:
            return base
        if net == 0xFFFF:
            return f"{base} [global broadcast]"
        return f"{base} [net {net}, mac {adr.hex() if adr else 'broadcast'}]"

    def _process_network_message(self, n: dict, data: bytes, t: float, src: str, dst: str):
        msg = n['net_msg']
        name = NETWORK_MESSAGES.get(msg)
        if name is None:
            if msg < 0x80:
                self._malformed(src, f'unknown network message type 0x{msg:02X}')
            name = f'vendor-0x{msg:02X}' if msg >= 0x80 else f'0x{msg:02X}'
        self.network_msg_counts[name] += 1

        if msg == 0x00:                                       # Who-Is-Router
            self.who_is_router_times[src].append(t)
            if len(data) >= 2:
                self.who_is_router_dnets[int.from_bytes(data[:2], 'big')] += 1
        elif msg == 0x01:                                     # I-Am-Router
            for i in range(0, len(data) - 1, 2):
                self.router_networks[int.from_bytes(data[i:i + 2], 'big')].add(src)
        elif msg == 0x03:                                     # Reject-Message
            reason = data[0] if data else 0
            dnet = int.from_bytes(data[1:3], 'big') if len(data) >= 3 else None
            self.network_rejects[(src, dnet, reason)] += 1
        elif msg == 0x04:                                     # Router-Busy
            nets = [int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data) - 1, 2)]
            self.router_busy[src].update(nets or ['all'])
        elif msg == 0x06:                                     # Initialize-Routing-Table
            if data and data[0] > 0:                          # 0 ports = query only
                self.routing_table_inits[(src, dst)] += 1
        elif msg == 0x13:                                     # Network-Number-Is
            if len(data) >= 2:
                self.network_numbers[int.from_bytes(data[:2], 'big')].add(src)

    # ------------------------------------------------------------------
    # APDU (application layer)
    # ------------------------------------------------------------------
    def _process_apdu(self, apdu: bytes, t: float, src: str, dst: str, dst_bcast: bool,
                      src_base: str, n: dict):
        if not apdu:
            self._malformed(src, 'NPDU without APDU')
            return
        ptype = apdu[0] >> 4
        tname = PDU_TYPES.get(ptype)
        if tname is None:
            self._malformed(src, f'invalid APDU type {ptype}')
            return
        self.pdu_type_counts[tname] += 1

        try:
            if ptype == 0:
                self._confirmed_request(apdu, t, src, dst, dst_bcast)
            elif ptype == 1:
                self._unconfirmed_request(apdu, t, src, dst, src_base, n)
            elif ptype in (2, 3, 5, 6, 7):
                self._response(ptype, apdu, t, src, dst)
            elif ptype == 4:
                if apdu[0] & 0x02:                            # NAK bit
                    self.segment_naks[(src, dst)] += 1
        except IndexError:
            self._malformed(src, f'truncated {tname}')

    def _confirmed_request(self, apdu: bytes, t: float, src: str, dst: str, dst_bcast: bool):
        segmented = bool(apdu[0] & 0x08)
        invoke = apdu[2]
        if segmented:
            seq = apdu[3]
            service = apdu[5]
            body = apdu[6:]
            if seq != 0:
                return                                         # continuation segment
        else:
            service = apdu[3]
            body = apdu[4:]
        sname = CONFIRMED_SERVICES.get(service, f'confirmed-{service}')
        self.service_counts[sname] += 1

        if dst_bcast:
            self.protocol_violations[src][f'{sname} confirmed request sent as broadcast'] += 1
            return

        key = (src, dst, invoke)
        prev = self.pending.get(key)
        if prev and prev['service'] == service and t - prev['t'] <= self.thresholds.retry_window:
            if t - prev['last_t'] >= self.thresholds.min_retry_interval:
                prev['retries'] += 1
                self.retry_events.append((dst, sname, t))
            prev['last_t'] = t                                 # replies are timed from here
            return
        if prev:                                               # invoke ID reused unanswered
            self._close_unanswered(key, prev)
        txn = {'t': t, 'last_t': t, 'service': service, 'retries': 0}
        self.pending[key] = txn
        self.requests_per_server[dst] += 1
        if not dst.startswith(('ETH:', 'MS/TP:')):
            base, _, port = dst.split(' ')[0].partition(':')
            self.server_ports[(base, int(port) if port else BACNET_DEFAULT_PORT)] += 1

        if service == SVC_REINITIALIZE_DEVICE:
            tags = self.parse_tags(body)
            txn['reinit_state'] = next((int.from_bytes(tg['value'], 'big') for tg in tags
                                        if tg['context'] and tg['tag'] == 0), None)
        elif service == SVC_ATOMIC_WRITE_FILE:
            self.file_writes[(src, dst)] += 1
        self._check_sensitive(service, sname, body, t, src, dst, key)

    def _close_unanswered(self, key, txn):
        server = key[1]
        if (self.last_ts or txn['last_t']) - txn['last_t'] >= self.thresholds.apdu_timeout:
            self.unanswered_events.append(
                (server, CONFIRMED_SERVICES.get(txn['service'], str(txn['service'])), txn['t']))

    def _response(self, ptype: int, apdu: bytes, t: float, src: str, dst: str):
        invoke = apdu[1]
        service = None
        if ptype == 2:                                         # SimpleACK
            service = apdu[2]
            outcome = 'accepted (SimpleACK)'
        elif ptype == 3:                                       # ComplexACK
            if apdu[0] & 0x08:
                if apdu[2] != 0:
                    return                                     # later segment
                service = apdu[4]
                body = apdu[5:]
            else:
                service = apdu[2]
                body = apdu[3:]
            outcome = 'accepted (ComplexACK)'
            if service in (SVC_ATOMIC_READ_FILE, SVC_ATOMIC_WRITE_FILE):
                self._file_ack(service, body, t, dst, src)
            inst = self._find_device_object(body)
            if inst is not None and inst not in self.device_info:
                self._record_instance(inst, src)               # responder is the device
        elif ptype == 5:                                       # Error
            service = apdu[2]
            ecls, ecode = self._parse_error(apdu[3:])
            sname = CONFIRMED_SERVICES.get(service, str(service))
            self.errors[src][(ecls, ecode, sname)] += 1
            label = f'{ERROR_CLASSES.get(ecls, ecls)}/{ERROR_CODES.get(ecode, ecode)}'
            if ecode == ERROR_CODE_PASSWORD_FAILURE:
                self.password_failures[(dst, src)] += 1
            if service in (SVC_ATOMIC_READ_FILE, SVC_ATOMIC_WRITE_FILE):
                self.file_errors[(dst, src)].append((t, f'{sname}: {label}'))
            elif ecls == ERROR_CLASS_SECURITY or ecode in ACCESS_DENIED_ERROR_CODES:
                self.access_events.append((dst, src, sname, label, t))
            outcome = (f'error {ERROR_CLASSES.get(ecls, ecls)}/'
                       f'{ERROR_CODES.get(ecode, ecode)}')
        elif ptype == 6:                                       # Reject
            reason = apdu[2]
            outcome = f'rejected ({REJECT_REASONS.get(reason, reason)})'
        else:                                                  # Abort
            by_server = bool(apdu[0] & 0x01)
            reason = apdu[2]
            self.aborts[src][(reason, by_server)] += 1
            outcome = f'aborted ({ABORT_REASONS.get(reason, reason)})'
            if not by_server:                                  # client abort: src is client
                self.pending.pop((src, dst, invoke), None)
                self._set_outcome((src, dst, invoke), outcome)
                return

        key = (dst, src, invoke)                               # (client, server, invoke)
        txn = self.pending.pop(key, None)
        if ptype == 6:
            sname = CONFIRMED_SERVICES.get(txn['service'], '?') if txn else '?'
            self.rejects[src][(apdu[2], sname)] += 1
        if txn:
            self.latencies[src].append((t, t - txn['last_t']))
            self._set_outcome(key, outcome)
            ok = ptype in (2, 3)
            if ok:
                self.accepted[(dst, src, txn['service'])].append(t)
            if txn['service'] == SVC_REINITIALIZE_DEVICE:
                state = txn.get('reinit_state')
                self.reinit_log.append({'client': dst, 'server': src, 'state': state,
                                        't': t, 'accepted': ok, 'outcome': outcome})
                if ok and state in RESTARTING_REINIT_STATES:
                    self.restarts[src].append(t)
        elif ptype == 2 and service == SVC_REINITIALIZE_DEVICE:
            # Request not in the capture, but the device acknowledged a reinitialize
            self.restarts[src].append(t)

    def _set_outcome(self, key, outcome: str):
        for ev in self.sensitive_events:
            if ev.get('_key') == key and 'outcome' not in ev:
                ev['outcome'] = outcome

    def _unconfirmed_request(self, apdu: bytes, t: float, src: str, dst: str,
                             src_base: str, n: dict):
        service = apdu[1]
        body = apdu[2:]
        sname = UNCONFIRMED_SERVICES.get(service, f'unconfirmed-{service}')
        self.service_counts[sname] += 1
        self.unconfirmed_times[(src, sname)].append(t)

        if service == SVC_I_AM:
            self._handle_i_am(body, src)
        elif service == SVC_I_HAVE:
            tags = self.parse_tags(body)
            if tags and tags[0]['tag'] == 12 and not tags[0]['context']:
                otype, inst = self._object_id(tags[0]['value'])
                if otype == OBJECT_TYPE_DEVICE:
                    self._record_instance(inst, src)
        elif service == SVC_WHO_IS:
            tags = self.parse_tags(body)
            lo = hi = None
            for tg in tags:
                if tg['context'] and tg['tag'] == 0:
                    lo = int.from_bytes(tg['value'], 'big')
                elif tg['context'] and tg['tag'] == 1:
                    hi = int.from_bytes(tg['value'], 'big')
            if lo is None:
                self.who_is_global[src] += 1
            elif lo == hi:
                target = self.who_is_targets[lo]
                target['count'] += 1
                target['sources'].add(src)
        elif service in (SVC_TIME_SYNC, SVC_UTC_TIME_SYNC):
            self.time_sync_sources[sname].add(src)

    def _handle_i_am(self, body: bytes, src: str):
        tags = self.parse_tags(body)
        if len(tags) < 4 or tags[0]['context'] or tags[0]['tag'] != 12:
            # Fall back to the legacy byte scan for truncated / odd encodings
            inst = self.parse_i_am(body)
            if inst is None:
                self._malformed(src, 'undecodable I-Am')
            else:
                self._record_instance(inst, src)
            return
        otype, inst = self._object_id(tags[0]['value'])
        if otype != OBJECT_TYPE_DEVICE:
            self.invalid_instances[src].add(f'object type {otype} instance {inst} in I-Am')
            return
        if inst == WILDCARD_INSTANCE:
            self.invalid_instances[src].add(f'wildcard instance {inst} in I-Am')
            return
        self.iam_instances.add(inst)
        ident = self.device_identity[inst]
        ident['max_apdu'].add(int.from_bytes(tags[1]['value'], 'big'))
        ident['segmentation'].add(SEGMENTATION_SUPPORT.get(
            int.from_bytes(tags[2]['value'], 'big'), 'invalid'))
        ident['vendor_ids'].add(int.from_bytes(tags[3]['value'], 'big'))
        self._record_instance(inst, src)

    def _record_instance(self, instance: int, addr: str):
        info = self.device_info.setdefault(instance, {'ips': set(), 'mstp': set(),
                                                      'macs': set(), 'addrs': set()})
        info['addrs'].add(addr)
        self.device_instances[instance].append(addr)
        self.identity_links[addr].update(self._identity_keys(addr))
        base = addr.split(' ')[0]
        if ':' in base and not base.startswith(('MS/TP', 'ETH')) and '[' not in addr:
            ip, _, port = base.partition(':')
            self.server_ports[(ip, int(port))] += 1
        routed = '[' in addr
        if base.startswith('MS/TP:'):
            mstp = int(base[6:])
            self.mstp_to_instances[mstp].add(instance)
            info['mstp'].add(str(mstp))
        elif base.startswith('ETH:'):
            info['macs'].add(base[4:])
        else:
            ip = base.split(':')[0]
            if routed:
                info['mstp'].add(addr)                         # routed: keep full path
                self.ip_routed_instances[ip][instance] = addr
            else:
                info['ips'].add(ip)
                self.ip_to_instances[ip].add(instance)
                info['macs'].update(self.ip_to_macs.get(ip, set()))

    # ------------------------------------------------------------------
    # Security-sensitive services
    # ------------------------------------------------------------------
    def _check_sensitive(self, service: int, sname: str, body: bytes, t: float,
                         src: str, dst: str, key):
        ev = None
        tags = self.parse_tags(body)
        if service == SVC_DEVICE_COMM_CONTROL:
            state = next((int.from_bytes(tg['value'], 'big') for tg in tags
                          if tg['context'] and tg['tag'] == 1), None)
            duration = next((int.from_bytes(tg['value'], 'big') for tg in tags
                             if tg['context'] and tg['tag'] == 0), None)
            pw = any(tg['context'] and tg['tag'] == 2 and self._cleartext(tg['value'])
                     for tg in tags)
            sev = 'critical' if state in (1, 2) else 'medium'
            ev = {'severity': sev, 'detail': f"set communication to "
                  f"'{DCC_ENABLE_DISABLE.get(state, state)}'"
                  + (f" for {duration} min" if duration else ' indefinitely'),
                  'password_sent': pw}
        elif service == SVC_REINITIALIZE_DEVICE:
            state = next((int.from_bytes(tg['value'], 'big') for tg in tags
                          if tg['context'] and tg['tag'] == 0), None)
            pw = any(tg['context'] and tg['tag'] == 1 and self._cleartext(tg['value'])
                     for tg in tags)
            # backup / restore steps are reported per procedure, not per command
            ev = {'severity': None if state in BACKUP_RESTORE_STATES else 'critical',
                  'password_sent': pw,
                  'detail': f"reinitialize ({REINITIALIZE_STATES.get(state, state)})"}
        elif service == SVC_ATOMIC_WRITE_FILE:
            ev = {'severity': 'medium', 'detail': 'file write (firmware / configuration upload)'}
        elif service == SVC_CREATE_OBJECT:
            ev = {'severity': 'medium', 'detail': 'object created'}
        elif service == SVC_DELETE_OBJECT:
            ev = {'severity': 'high', 'detail': 'object deleted'}
        elif service in (SVC_WRITE_PROPERTY, SVC_WRITE_PROPERTY_MULTIPLE):
            prio = None
            if service == SVC_WRITE_PROPERTY and len(body) >= 3 \
                    and body[-3] == 0x3F and body[-2] == 0x49:
                prio = body[-1]
            if prio in (1, 2):
                ev = {'severity': 'high',
                      'detail': f'write at priority {prio} (manual life safety / '
                                'automatic life safety) overrides all other control'}
        if ev:
            ev.update({'service': sname, 'source': src, 'target': dst, 't': t, '_key': key})
            self.sensitive_events.append(ev)

    # ------------------------------------------------------------------
    # MS/TP
    # ------------------------------------------------------------------
    @staticmethod
    def _mstp_header_crc(data: bytes) -> int:
        crc = 0xFF
        for b in data:
            c = crc ^ b
            c = c ^ (c << 1) ^ (c << 2) ^ (c << 3) ^ (c << 4) ^ (c << 5) ^ (c << 6) ^ (c << 7)
            crc = (c & 0xFE) ^ ((c >> 8) & 1)
        return crc

    @staticmethod
    def _mstp_data_crc(data: bytes) -> int:
        crc = 0xFFFF
        for b in data:
            lo = (crc & 0xFF) ^ b
            crc = ((crc >> 8) ^ (lo << 8) ^ (lo << 3) ^ (lo << 12) ^ (lo >> 4)
                   ^ (lo & 0x0F) ^ ((lo & 0x0F) << 7)) & 0xFFFF
        return crc

    def _process_mstp(self, payload: bytes, t: float, native: bool) -> bool:
        """Scan payload for MS/TP frames. Returns True if any BACnet data frame was found."""
        found = False
        idx = 0
        while idx <= len(payload) - 8:
            if payload[idx] != 0x55 or payload[idx + 1] != 0xFF:
                idx += 1
                continue
            hdr = payload[idx + 2:idx + 8]                     # type,dst,src,lenhi,lenlo,crc
            ftype, dst, src = hdr[0], hdr[1], hdr[2]
            length = int.from_bytes(hdr[3:5], 'big')
            header_ok = self._mstp_header_crc(hdr) == 0x55
            if not header_ok:
                if native:
                    self.mstp_crc_errors[(f'MS/TP:{src}', 'header')] += 1
                    return found
                idx += 1
                continue

            self.mstp_frame_counts[MSTP_FRAME_TYPES.get(ftype, f'proprietary-{ftype}')] += 1
            if src == MSTP_BROADCAST:
                self._malformed(f'MS/TP:{src}', 'MS/TP frame with broadcast source address')
            if ftype in (0, 1, 2) and src > MSTP_MAX_MASTER:
                self.mstp_invalid_master[src] += 1

            data_start = idx + 8
            if length and data_start + length + 2 <= len(payload):
                data = payload[data_start:data_start + length + 2]
                if self._mstp_data_crc(data) != 0xF0B8:
                    self.mstp_crc_errors[(f'MS/TP:{src}', 'data')] += 1
                elif ftype in MSTP_DATA_FRAMES:
                    found = True
                    self._process_npdu(data[:-2], t, f'MS/TP:{src}', f'MS/TP:{dst}',
                                       dst == MSTP_BROADCAST)
                idx = data_start + length + 2
            elif length and native:
                self._malformed(f'MS/TP:{src}', 'truncated MS/TP data frame')
                return found
            else:
                idx = data_start
        return found

    def parse_bacnet_mstp(self, payload: bytes) -> Tuple[Optional[bytes], Optional[int]]:
        """Backwards compatible helper: first MS/TP data frame (npdu, source)."""
        idx = 0
        while idx <= len(payload) - 8:
            if payload[idx] == 0x55 and payload[idx + 1] == 0xFF:
                ftype, src = payload[idx + 2], payload[idx + 4]
                length = int.from_bytes(payload[idx + 5:idx + 7], 'big')
                if ftype in MSTP_DATA_FRAMES and length > 0 \
                        and idx + 8 + length <= len(payload):
                    return payload[idx + 8:idx + 8 + length], src
            idx += 1
        return None, None

    # ------------------------------------------------------------------
    # Tag helpers
    # ------------------------------------------------------------------
    @staticmethod
    def parse_tags(data: bytes, limit: int = 64) -> List[dict]:
        """Decode a flat list of BACnet tags (opening/closing tags included)."""
        tags = []
        i = 0
        while i < len(data) and len(tags) < limit:
            b = data[i]
            i += 1
            tag = b >> 4
            ctx = bool(b & 0x08)
            lvt = b & 0x07
            if tag == 15:
                if i >= len(data):
                    break
                tag = data[i]
                i += 1
            if ctx and lvt == 6:
                tags.append({'tag': tag, 'context': True, 'kind': 'open', 'value': b''})
                continue
            if ctx and lvt == 7:
                tags.append({'tag': tag, 'context': True, 'kind': 'close', 'value': b''})
                continue
            if not ctx and tag == 1:                         # application boolean
                tags.append({'tag': 1, 'context': False, 'kind': 'prim',
                             'value': bytes([lvt])})
                continue
            length = lvt
            if lvt == 5:
                if i >= len(data):
                    break
                length = data[i]
                i += 1
                if length == 254:
                    length = int.from_bytes(data[i:i + 2], 'big')
                    i += 2
                elif length == 255:
                    length = int.from_bytes(data[i:i + 4], 'big')
                    i += 4
            if i + length > len(data):
                break
            tags.append({'tag': tag, 'context': ctx, 'kind': 'prim',
                         'value': data[i:i + length]})
            i += length
        return tags

    def _parse_error(self, data: bytes) -> Tuple[Optional[int], Optional[int]]:
        """Return (error-class, error-code): the first two application enumerateds."""
        enums = [int.from_bytes(tg['value'], 'big') for tg in self.parse_tags(data)
                 if not tg['context'] and tg['tag'] == 9 and tg['kind'] == 'prim']
        if len(enums) >= 2:
            return enums[0], enums[1]
        return None, None

    @staticmethod
    def _object_id(value: bytes) -> Tuple[int, int]:
        oid = int.from_bytes(value[:4].rjust(4, b'\0'), 'big')
        return (oid >> 22) & 0x3FF, oid & 0x3FFFFF

    def _find_device_object(self, body: bytes) -> Optional[int]:
        """Device instance in the first object identifier of an ACK, if it is a device."""
        tags = self.parse_tags(body, limit=2)
        if tags and tags[0]['kind'] == 'prim' and tags[0]['tag'] in (0, 12) \
                and len(tags[0]['value']) == 4:
            otype, inst = self._object_id(tags[0]['value'])
            if otype == OBJECT_TYPE_DEVICE and inst < WILDCARD_INSTANCE:
                return inst
        return None

    def parse_i_am(self, data: bytes) -> Optional[int]:
        """Legacy I-Am scan: find an application-tagged device object identifier."""
        idx = 0
        while idx + 4 < len(data):
            if data[idx] == 0xC4:
                otype, inst = self._object_id(data[idx + 1:idx + 5])
                if otype == OBJECT_TYPE_DEVICE and inst != WILDCARD_INSTANCE:
                    return inst
                idx += 5
            else:
                idx += 1
        return None

    def _file_ack(self, service: int, body: bytes, t: float, client: str, server: str):
        """Record progress of an AtomicReadFile / AtomicWriteFile transfer."""
        pos = None
        for tg in self.parse_tags(body, limit=4):
            if tg['context'] and tg['kind'] == 'prim' and tg['tag'] in (0, 1):
                pos = int.from_bytes(tg['value'], 'big', signed=True)
                break
            if not tg['context'] and tg['tag'] in (2, 3) and service == SVC_ATOMIC_READ_FILE:
                pos = int.from_bytes(tg['value'], 'big', signed=tg['tag'] == 3)
        self.file_progress[(client, server)].append((t, pos))

    @staticmethod
    def _cleartext(value: bytes) -> bool:
        """True if a CharacterString is a readable password (charset 0 = UTF-8/ANSI)."""
        if len(value) < 2 or value[0] != 0:
            return False
        return all(32 <= b < 127 for b in value[1:])

    def _identity_keys(self, addr: str) -> set:
        """Keys identifying the physical device behind a BACnet address.

        Two addresses sharing a key are one device seen through different router
        ports, e.g. a BACnet/Ethernet device that a router re-announces on BACnet/IP.
        """
        keys = {addr}
        base, _, routed = addr.partition(' [')
        if routed.startswith('net '):
            net, _, mac = routed.rstrip(']').partition(', mac ')
            keys.add(f'route:{net[4:]}:{mac}')
            if len(mac) == 12:
                keys.add('mac:' + ':'.join(mac[i:i + 2] for i in range(0, 12, 2)))
            return keys
        if base.startswith('ETH:'):
            keys.add('mac:' + base[4:].lower())
        elif not base.startswith('MS/TP:'):
            ip = base.split(':')[0]
            for mac in self.ip_to_macs.get(ip, ()):
                if len(self.mac_to_ips.get(mac, ())) == 1:     # not a shared router MAC
                    keys.add('mac:' + mac.lower())
        return keys

    def _distinct_devices(self, addrs) -> List[List[str]]:
        """Group addresses that are provably the same physical device."""
        groups: List[Tuple[set, List[str]]] = []
        for a in sorted(addrs):
            keys = self._identity_keys(a) | self.identity_links.get(a, set())
            merged = [g for g in groups if g[0] & keys]
            for g in merged:
                groups.remove(g)
                keys |= g[0]
            groups.append((keys, sorted([a] + [x for g in merged for x in g[1]])))
        return [g[1] for g in groups]

    def _in_restart(self, server: str, t: float) -> bool:
        return any(0 <= t - r <= self.thresholds.restart_window
                   for r in self.restarts.get(server, ()))

    def _rel(self, t: float) -> str:
        return f'+{t - (self.first_ts or t):.1f}s'

    def _malformed(self, src: str, reason: str):
        self.malformed[src][reason] += 1

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def _extract_devices(self) -> List[dict]:
        """Extract device information."""
        devices = []
        for instance, info in self.device_info.items():
            ident = self.device_identity.get(instance, {})
            devices.append({
                'instance_number': instance,
                'ip_addresses': sorted(info['ips']),
                'mac_addresses': sorted(info['macs']),
                'mstp_addresses': sorted(info['mstp']),
                'last_seen': datetime.now().isoformat(),
                'packet_count': sum(self.addr_packet_count[a] for a in info['addrs']),
                'vendor_ids': sorted(ident.get('vendor_ids', [])),
            })
        return devices

    @staticmethod
    def _max_rate(times: List[float], window: float) -> int:
        """Largest number of events inside any sliding window of `window` seconds."""
        if not times:
            return 0
        times = sorted(times)
        best = lo = 0
        for hi, t in enumerate(times):
            while t - times[lo] > window:
                lo += 1
            best = max(best, hi - lo + 1)
        return best

    def _detect_anomalies(self) -> List[dict]:
        """Run every detector over the state collected from the capture."""
        anomalies: List[dict] = []

        def add(atype, severity, description, **details):
            details = {k: v for k, v in details.items() if v is not None}
            if atype in RECOMMENDED_ACTIONS:
                details['recommended_action'] = RECOMMENDED_ACTIONS[atype]
            anomalies.append({'type': atype, 'severity': severity,
                              'description': description, 'details': details})

        th = self.thresholds
        self._detect_addressing(add)
        self._detect_transactions(add, th)
        self._detect_security(add, th)
        self._detect_traffic(add, th)
        self._detect_network_layer(add, th)
        self._detect_link_layer(add)

        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        anomalies.sort(key=lambda a: order.get(a['severity'], 4))
        return anomalies

    # --- addressing (original checks, with false-positive fixes) ---------
    def _detect_addressing(self, add):
        router_macs = {mac for mac, ips in self.mac_to_ips.items() if len(ips) >= 3}

        for ip, macs in self.ip_to_macs.items():
            if len(macs) > 1:
                add('duplicate_ip', 'critical',
                    f'Duplicate IP address {ip} detected on {len(macs)} different devices',
                    ip_address=ip, mac_addresses=sorted(macs),
                    packet_counts={mac: self.ip_packet_count[ip][mac] for mac in macs})

        for instance, addr_list in self.device_instances.items():
            groups = self._distinct_devices(set(addr_list))
            if len(groups) > 1:
                ident = self.device_identity.get(instance, {})
                add('duplicate_instance', 'high',
                    f'Device instance {instance} found on {len(groups)} different devices',
                    instance_number=instance, addresses=[', '.join(g) for g in groups],
                    vendor_ids=sorted(ident.get('vendor_ids', [])))

        for ip in sorted(set(self.ip_to_instances) | set(self.ip_routed_instances)):
            instances = self.ip_to_instances.get(ip, set())
            routed = {i: a for i, a in self.ip_routed_instances.get(ip, {}).items()
                      if i not in instances}
            if len(instances) > 1:
                # Several instances answer directly from one IP: a real conflict
                add('multi_instance_ip', 'high',
                    f'IP address {ip} is used by {len(instances)} different device instances',
                    ip_address=ip, mac_addresses=sorted(self.ip_to_macs.get(ip, set())),
                    instance_numbers=sorted(instances | set(routed)),
                    routed_instances=routed or None)
            elif routed and len(instances) + len(routed) > 1:
                # One device answers itself and forwards I-Ams from networks behind
                # it: a BACnet router, reported so the shared IP stays visible
                behind = ', '.join(f"{i} (net {a.split('[net ')[1].split(',')[0]})"
                                   for i, a in sorted(routed.items()))
                own = f'{sorted(instances)[0]} directly, ' if instances else ''
                add('multi_instance_ip', 'low',
                    f'IP address {ip} is used by {len(instances) + len(routed)} device instances: '
                    f'{own}{behind} routed through it - a BACnet router, not a conflict '
                    f'unless these devices are unexpected',
                    ip_address=ip, mac_addresses=sorted(self.ip_to_macs.get(ip, set())),
                    instance_numbers=sorted(instances | set(routed)),
                    routed_instances=routed)

        for mac, ips in self.mac_to_ips.items():
            if len(ips) > 1:
                likely_router = mac in router_macs
                add('mac_multi_ip', 'low' if likely_router else 'medium',
                    f'MAC address {mac} seen with {len(ips)} different IP addresses'
                    + (' (likely an IP router forwarding off-subnet traffic)'
                       if likely_router else ''),
                    mac_address=mac, ip_addresses=sorted(ips))

        for ip, macs in self.arp_table.items():
            if len(macs) > 1:
                add('arp_conflict', 'critical',
                    f'ARP conflict for IP {ip}: multiple MAC addresses claiming this IP',
                    ip_address=ip, mac_addresses=sorted(macs))

        for mstp_addr, instances in self.mstp_to_instances.items():
            if len(instances) > 1:
                add('mstp_conflict', 'high',
                    f'MS/TP address {mstp_addr} is used by {len(instances)} '
                    'different device instances',
                    mstp_address=mstp_addr, instance_numbers=sorted(instances))

        for inst, ident in self.device_identity.items():
            changed = {k: sorted(v, key=str) for k, v in ident.items() if len(v) > 1}
            if changed:
                add('device_identity_change', 'high',
                    f'Device {inst} announced conflicting identities in I-Am '
                    f'({", ".join(changed)}) - possible spoofing or duplicate device',
                    instance_number=inst, conflicting_fields=changed,
                    addresses=sorted(set(self.device_instances.get(inst, []))))

        for src, items in self.invalid_instances.items():
            add('invalid_device_instance', 'medium',
                f'{src} announced an invalid device identifier',
                source=src, problems=sorted(items))

    # --- confirmed-service transactions ----------------------------------
    def _detect_transactions(self, add, th):
        for key, txn in list(self.pending.items()):
            self._close_unanswered(key, txn)
        self.pending.clear()

        # Timeouts, retries and slow replies right after a device was told to
        # restart are expected and only reported as context.
        unanswered = defaultdict(Counter)
        for server, svc, t in self.unanswered_events:
            if not self._in_restart(server, t):
                unanswered[server][svc] += 1
        for server, total in self.requests_per_server.items():
            missing = sum(unanswered[server].values())
            if not missing:
                continue
            ratio = missing / total
            if missing == total and total >= 2:
                add('device_unresponsive', 'high',
                    f'{server} did not answer any of {total} confirmed requests',
                    device=server, requests=total, unanswered=missing,
                    services=dict(unanswered[server]))
            elif total >= th.min_requests_for_ratio and ratio >= th.unanswered_ratio:
                add('request_timeouts', 'medium',
                    f'{server} left {missing} of {total} confirmed requests '
                    f'({ratio:.0%}) unanswered',
                    device=server, requests=total, unanswered=missing,
                    services=dict(unanswered[server]))

        retries = defaultdict(Counter)
        for server, svc, t in self.retry_events:
            if not self._in_restart(server, t):
                retries[server][svc] += 1
        for server, svc in retries.items():
            n = sum(svc.values())
            add('request_retries', 'medium' if n >= 3 else 'low',
                f'{n} retransmitted requests to {server} (client did not get a reply in time)',
                device=server, retries=n, services=dict(svc))

        for server, samples in self.latencies.items():
            lat = sorted(d for t, d in samples if not self._in_restart(server, t))
            if len(lat) < 2:
                continue
            p95 = lat[min(len(lat) - 1, int(0.95 * len(lat)))]
            if p95 >= th.slow_response:
                add('slow_response', 'high' if p95 >= th.apdu_timeout else 'medium',
                    f'{server} responds slowly: p95 {p95 * 1000:.0f} ms '
                    f'(max {lat[-1] * 1000:.0f} ms, {len(lat)} replies)',
                    device=server, p95_ms=round(p95 * 1000), max_ms=round(lat[-1] * 1000),
                    median_ms=round(lat[len(lat) // 2] * 1000), replies=len(lat))

        for server, errs in self.errors.items():
            health = Counter()
            other = Counter()
            for (ecls, ecode, svc), n in errs.items():
                label = (f'{svc}: {ERROR_CLASSES.get(ecls, ecls)}/'
                         f'{ERROR_CODES.get(ecode, ecode)}')
                if ecls == ERROR_CLASS_SECURITY or ecode in ACCESS_DENIED_ERROR_CODES \
                        or svc in ('atomicReadFile', 'atomicWriteFile'):
                    continue                                   # reported elsewhere
                if ecode in DEVICE_HEALTH_ERROR_CODES or ecls == 3:
                    health[label] += n
                elif ecode not in BENIGN_ERROR_CODES:
                    other[label] += n
            benign = sum(n for (c, code, s), n in errs.items() if code in BENIGN_ERROR_CODES)
            if health:
                add('device_busy', 'medium',
                    f'{server} returned {sum(health.values())} busy/timeout/resource errors',
                    device=server, errors=dict(health))
            if sum(other.values()) + benign >= th.error_count:
                all_errs = {f'{s}: {ERROR_CLASSES.get(c, c)}/{ERROR_CODES.get(e, e)}': n
                            for (c, e, s), n in errs.items()}
                add('bacnet_errors', 'medium' if other else 'low',
                    f'{server} returned {sum(errs.values())} Error PDUs'
                    + ('' if other else ' (unknown object/property - usually harmless probing)'),
                    device=server, errors=all_errs)

        for server, rej in self.rejects.items():
            detail = {f'{svc}: {REJECT_REASONS.get(r, r)}': n for (r, svc), n in rej.items()}
            unrec = any(r == 9 for r, _ in rej)
            add('bacnet_reject', 'medium',
                f'{server} rejected {sum(rej.values())} requests'
                + (' (unrecognized service - client/firmware mismatch)' if unrec else ''),
                device=server, reasons=detail)

        for sender, ab in self.aborts.items():
            seg = sum(n for (r, _), n in ab.items() if r in SEGMENTATION_ABORT_REASONS)
            detail = {f'{ABORT_REASONS.get(r, r)} (by {"server" if s else "client"})': n
                      for (r, s), n in ab.items()}
            add('segmentation_issue' if seg else 'bacnet_abort',
                'high' if any(r in (5, 6) for r, _ in ab) else 'medium',
                f'{sender} aborted {sum(ab.values())} transactions'
                + (' - max-APDU / segmentation mismatch' if seg else ''),
                device=sender, reasons=detail)

        for (src, dst), n in self.segment_naks.items():
            add('segmentation_issue', 'medium',
                f'{n} negative Segment-ACKs from {src} to {dst} (lost or out-of-order segments)',
                source=src, destination=dst, segment_naks=n)

        self._detect_file_transfers(add, th)
        self._detect_procedures(add, th)

    def _detect_file_transfers(self, add, th):
        """Failed or stalled AtomicWriteFile / AtomicReadFile transfers (downloads)."""
        end = self.last_ts or 0
        for key in set(self.file_progress) | set(self.file_errors):
            client, server = key
            progress = sorted(self.file_progress.get(key, []), key=lambda x: x[0])
            errors = sorted(self.file_errors.get(key, []))
            chunks = len(progress)
            last_ok = progress[-1][0] if progress else None
            positions = [p for _, p in progress if p is not None]
            # Largest silence between accepted chunks, or before the failure
            times = [t for t, _ in progress] + ([errors[0][0]] if errors else [])
            gaps = [b - a for a, b in zip(times, times[1:])]
            stall = max(gaps) if gaps else 0.0
            detail = dict(client=client, device=server, chunks_accepted=chunks,
                          last_position=max(positions) if positions else None,
                          longest_gap_s=round(stall, 1),
                          started=self._rel(progress[0][0]) if progress else None,
                          last_progress=self._rel(last_ok) if last_ok else None)
            if errors:
                t_err, label = errors[0]
                add('file_transfer_failed', 'high',
                    f'File transfer from {client} to {server} failed at {self._rel(t_err)} '
                    f'with {label} after {chunks} accepted chunk(s)'
                    + (f'; no progress for {stall:.0f}s before the failure'
                       if stall >= th.procedure_stall else ''),
                    error=label, errors=len(errors), **detail)
            elif last_ok is not None and end - last_ok >= th.procedure_stall \
                    and self._transfer_open(client, server, last_ok):
                add('file_transfer_stalled', 'high',
                    f'File transfer from {client} to {server} stopped at {self._rel(last_ok)} '
                    f'after {chunks} chunk(s) and never finished',
                    **detail)
            elif stall >= th.procedure_stall:
                add('file_transfer_stalled', 'medium',
                    f'File transfer from {client} to {server} paused for {stall:.0f}s '
                    f'({chunks} chunks)', **detail)

    def _transfer_open(self, client: str, server: str, t: float) -> bool:
        """No reinitialize / end-restore followed the last chunk."""
        return not any(e['server'] == server and e['client'] == client and e['t'] >= t
                       and e['accepted'] for e in self.reinit_log) \
            and not any(r >= t for r in self.restarts.get(server, ()))

    def _detect_procedures(self, add, th):
        """Backup / restore procedures driven by ReinitializeDevice (clause 19.1)."""
        end = self.last_ts or 0
        runs = defaultdict(list)                                # (client, kind) -> [summary]
        for (client, server) in {(e['client'], e['server']) for e in self.reinit_log}:
            steps = sorted((e for e in self.reinit_log
                            if e['client'] == client and e['server'] == server),
                           key=lambda e: e['t'])
            open_step = None
            for e in steps:
                if not e['accepted']:
                    continue
                if e['state'] in (2, 4):                      # start-backup / start-restore
                    open_step = e
                elif e['state'] in (3, 5, 6) and open_step:   # end / abort
                    kind = 'backup' if open_step['state'] == 2 else 'restore'
                    runs[(client, kind)].append({
                        'device': server, 'result': 'aborted' if e['state'] == 6 else 'completed',
                        'duration_s': round(e['t'] - open_step['t'], 1),
                        'files_written': self.file_writes.get((client, server), 0)})
                    open_step = None
            if open_step:
                kind = 'backup' if open_step['state'] == 2 else 'restore'
                client_last = self.pair_last.get((client, server), open_step['t'])
                device_last = self.last_seen.get(server, open_step['t'])
                runs[(client, kind)].append({
                    'device': server, 'result': 'incomplete',
                    'started': self._rel(open_step['t']),
                    'files_written': self.file_writes.get((client, server), 0)})
                if end - open_step['t'] >= th.procedure_stall:
                    who = ('the client stopped talking to the device at '
                           f'{self._rel(client_last)}'
                           if end - client_last >= th.procedure_stall else
                           'the client is still talking to the device')
                    alive = ('device still on the network' if end - device_last < th.procedure_stall
                             else f'device silent since {self._rel(device_last)}')
                    add('backup_restore_incomplete', 'high',
                        f'{kind.capitalize()} of {server} was started by {client} at '
                        f'{self._rel(open_step["t"])} but no end-{kind} followed in '
                        f'{end - open_step["t"]:.0f}s; {who}, {alive} - device is '
                        f'probably stuck in {kind} mode',
                        client=client, device=server, procedure=kind,
                        started=self._rel(open_step['t']),
                        client_last_request=self._rel(client_last),
                        device_last_seen=self._rel(device_last),
                        files_written=self.file_writes.get((client, server), 0))

        for (client, kind), devs in runs.items():
            done = sum(d['result'] == 'completed' for d in devs)
            add('backup_restore', 'medium',
                f'{client} ran a {kind} on {len(devs)} device(s): {done} completed, '
                f'{len(devs) - done} not completed',
                client=client, procedure=kind, devices=devs)

    # --- security ------------------------------------------------------------
    def _detect_security(self, add, th):
        grouped = defaultdict(list)
        for ev in self.sensitive_events:
            if ev['severity'] is None:
                continue
            # File writes that belong to a backup/restore are part of that procedure
            if ev['service'] == 'atomicWriteFile' and any(
                    e['client'] == ev['source'] and e['server'] == ev['target']
                    for e in self.reinit_log):
                continue
            grouped[(ev['service'], ev['source'], ev['detail'], ev['severity'])].append(ev)
        for (svc, src, detail, sev), evs in grouped.items():
            targets = sorted({ev['target'] for ev in evs})
            outcomes = Counter(ev.get('outcome', 'no response seen') for ev in evs)
            where = targets[0] if len(targets) == 1 else f'{len(targets)} devices'
            add('sensitive_command', sev,
                f'{src} sent {svc} to {where}: {detail} (x{len(evs)})',
                service=svc, source=src, targets=targets, count=len(evs),
                outcomes=dict(outcomes))

        clear = defaultdict(set)
        for ev in self.sensitive_events:
            if ev.get('password_sent'):
                clear[(ev['service'], ev['source'])].add(ev['target'])
        for (svc, src), targets in clear.items():
            add('cleartext_password', 'high',
                f'{src} sent a readable password in {svc} to {len(targets)} device(s)',
                service=svc, source=src, targets=sorted(targets))

        for (client, server), n in self.password_failures.items():
            if n >= th.password_failures:
                add('password_bruteforce', 'critical',
                    f'{n} password failures from {client} against {server} - '
                    'possible password guessing',
                    source=client, target=server, failures=n)

        # Access denials: high if never followed by success, low if the client
        # recovered (e.g. a tool trying a default password before the real one).
        denied = defaultdict(lambda: {'servers': set(), 'recovered': set(), 'labels': Counter()})
        svc_ids = {v: k for k, v in CONFIRMED_SERVICES.items()}
        for client, server, svc, label, t in self.access_events:
            d = denied[client]
            d['servers'].add(server)
            d['labels'][f'{svc}: {label}'] += 1
            later = self.accepted.get((client, server, svc_ids.get(svc)), [])
            if any(x > t for x in later):
                d['recovered'].add(server)
        for client, d in denied.items():
            unresolved = d['servers'] - d['recovered']
            if unresolved:
                add('access_denied', 'high',
                    f'{len(unresolved)} device(s) refused requests from {client} '
                    'for security reasons',
                    source=client, devices=sorted(unresolved), errors=dict(d['labels']))
            else:
                add('access_denied', 'low',
                    f'{client} was refused by {len(d["servers"])} device(s) but succeeded on '
                    'retry (e.g. default password tried first)',
                    source=client, devices=sorted(d['servers']), errors=dict(d['labels']))

        for (src, dst, func), n in self.bbmd_writes.items():
            add('bbmd_config_change', 'critical',
                f'{src} sent {func} to {dst} (x{n}) - BBMD tables changed over the network',
                source=src, target=dst, function=func, count=n)
        for (src, dst, func), n in self.bbmd_reads.items():
            add('bbmd_reconnaissance', 'low',
                f'{src} read BBMD tables from {dst} ({func} x{n})',
                source=src, target=dst, function=func, count=n)
        if self.foreign_devices:
            add('foreign_device_registration', 'low',
                f'{len(self.foreign_devices)} foreign device(s) registered with a BBMD',
                foreign_devices={k: v for k, v in self.foreign_devices.items()})
        for (src, dst), n in self.routing_table_inits.items():
            add('sensitive_command', 'high',
                f'{src} rewrote the routing table of {dst} (Initialize-Routing-Table x{n})',
                service='Initialize-Routing-Table', source=src, targets=[dst], count=n)

        total = getattr(self, 'total_packets', 0)
        if self.duplicate_frames and total and self.duplicate_frames >= 0.01 * total:
            add('duplicate_packets', 'low',
                f'{self.duplicate_frames} of {total} frames appear twice - capture taken '
                'on several interfaces/SPAN ports, or a layer-2 loop',
                duplicates=self.duplicate_frames, total_packets=total)

    # --- traffic patterns ----------------------------------------------------
    def _detect_traffic(self, add, th):
        limits = {'who-Is': th.who_is_per_source, 'who-Has': th.who_has_per_source,
                  'i-Am': th.i_am_per_source,
                  'unconfirmedCOVNotification': th.cov_per_source,
                  'timeSynchronization': th.time_sync_per_source,
                  'utcTimeSynchronization': th.time_sync_per_source}
        for (src, svc), times in self.unconfirmed_times.items():
            limit = limits.get(svc, th.unconfirmed_other_per_source)
            peak = self._max_rate(times, th.rate_window)
            if peak > limit:
                atype = {'who-Is': 'who_is_flood', 'i-Am': 'i_am_flood',
                         'unconfirmedCOVNotification': 'cov_flood'}.get(svc, 'service_flood')
                add(atype, 'high' if peak > 4 * limit else 'medium',
                    f'{src} sent {peak} {svc} messages in {th.rate_window:g}s '
                    f'(limit {limit}, {len(times)} total)',
                    source=src, service=svc, peak_per_window=peak, total=len(times),
                    global_who_is=self.who_is_global.get(src, 0) if svc == 'who-Is' else None)

        for target, times in self.broadcast_by_target.items():
            peak = self._max_rate(times, th.rate_window)
            remote = target.startswith('network')
            limit = th.remote_broadcast_total if remote else th.broadcast_total
            if peak <= limit:
                continue
            avg = self.broadcast_bytes[target] // max(len(times), 1)
            top = self.broadcast_senders[target].most_common(3)
            add('broadcast_storm', 'critical' if peak > 4 * limit else 'high',
                f'Broadcast storm onto {target}: {peak} broadcasts in {th.rate_window:g}s '
                f'(avg {avg} bytes, top sender {top[0][0]})'
                + (' - devices on that network (and a slow MS/TP trunk) are flooded'
                   if remote else ''),
                target=target, peak_per_window=peak, total_broadcasts=len(times),
                avg_npdu_bytes=avg, top_senders={s: n for s, n in top})

        # Sustained broadcast load pushed through a router into a remote network.
        # Short bursts may pass the rate check while the average still eats a large
        # share of a slow trunk (an MS/TP trunk at 76.8 kbit/s carries ~7.6 kB/s).
        for target, times in self.broadcast_by_target.items():
            if not target.startswith('network') or len(times) < 2:
                continue
            span = max(times) - min(times)
            if span < 60:
                continue
            rate = self.broadcast_bytes[target] / span
            if rate >= th.remote_broadcast_bytes_per_s:
                top = self.broadcast_senders[target].most_common(1)[0][0]
                add('remote_network_load', 'high' if rate >= 3 * th.remote_broadcast_bytes_per_s
                    else 'medium',
                    f'{len(times)} broadcasts ({self.broadcast_bytes[target] / 1e6:.1f} MB) sent '
                    f'onto {target} over {span / 60:.0f} min - avg {rate / 1000:.1f} kB/s '
                    f'(~{rate / 7680:.0%} of a 76.8 kbit/s MS/TP trunk), mostly from {top}',
                    target=target, broadcasts=len(times),
                    bytes=self.broadcast_bytes[target], duration_s=round(span),
                    avg_bytes_per_s=round(rate), top_sender=top)

        # The same broadcast arriving through a different path (original + forwarded,
        # or forwarded by two BBMDs) within a short window. Identical messages that a
        # device simply repeats arrive through the same path and are not counted.
        for (orig, _), copies in self.broadcast_copies.items():
            copies.sort()
            for i in range(1, len(copies)):
                if copies[i][0] - copies[i - 1][0] <= th.duplicate_broadcast_window                         and copies[i][1:] != copies[i - 1][1:]:
                    add('duplicate_broadcast', 'high',
                        f'Broadcast from {orig} arrived via more than one path - '
                        'BBMD loop, two BBMDs on one subnet or wrong BDT mask',
                        original_source=orig, copies=len(copies),
                        relayed_by=sorted({c[1] for c in copies}),
                        forms=sorted({c[2] for c in copies}))
                    break

        for inst, info in self.who_is_targets.items():
            if inst not in self.iam_instances and info['count'] >= th.missing_device_whois:
                add('missing_device', 'medium',
                    f'Device {inst} was searched for {info["count"]} times (Who-Is) '
                    'but never answered - offline or unreachable',
                    instance_number=inst, who_is_count=info['count'],
                    searched_by=sorted(info['sources']))

        for svc, sources in self.time_sync_sources.items():
            if len(sources) > 1:
                add('time_sync_conflict', 'medium',
                    f'{len(sources)} different devices send {svc} - clocks may fight',
                    service=svc, sources=sorted(sources))

        for src, viol in self.protocol_violations.items():
            add('protocol_violation', 'medium',
                f'{src}: {", ".join(viol)}', source=src, violations=dict(viol))

    # --- network layer -------------------------------------------------------
    def _detect_network_layer(self, add, th):
        for dnet, routers in self.router_networks.items():
            if len(routers) > 1:
                add('router_conflict', 'high',
                    f'Network {dnet} is advertised by {len(routers)} routers - '
                    'duplicate network number or routing loop',
                    network=dnet, routers=sorted(routers))

        if len(self.network_numbers) > 1:
            add('network_number_conflict', 'medium',
                f'Routers announce {len(self.network_numbers)} different network numbers '
                'for this segment',
                network_numbers={n: sorted(r) for n, r in self.network_numbers.items()})

        for (router, dnet, reason), n in self.network_rejects.items():
            add('network_reject', 'high' if reason in (1, 5) else 'medium',
                f'{router} rejected {n} messages to network {dnet}: '
                f'{NETWORK_REJECT_REASONS.get(reason, reason)}',
                router=router, network=dnet, reason=NETWORK_REJECT_REASONS.get(reason, reason),
                count=n)

        for router, nets in self.router_busy.items():
            add('router_busy', 'medium',
                f'{router} reported Router-Busy for networks {sorted(nets, key=str)}',
                router=router, networks=sorted(nets, key=str))

        for src, times in self.who_is_router_times.items():
            peak = self._max_rate(times, th.rate_window)
            if peak > th.who_is_router_per_source:
                add('who_is_router_flood', 'medium',
                    f'{src} sent {peak} Who-Is-Router-To-Network in {th.rate_window:g}s',
                    source=src, peak_per_window=peak, total=len(times))

        for dnet, n in self.who_is_router_dnets.items():
            if dnet not in self.router_networks and n >= 2:
                add('unreachable_network', 'medium',
                    f'Network {dnet} was searched for {n} times but no router answered',
                    network=dnet, searches=n)

        for src, hop in self.min_hop_count.items():
            used = 255 - hop
            if hop == 0:
                add('routing_loop', 'high',
                    f'Packets from {src} arrived with hop count 0 - routing loop',
                    source=src, min_hop_count=hop)
            elif used > th.max_hops:
                add('excessive_hops', 'medium',
                    f'Packets from {src} crossed {used} routers (hop count {hop})',
                    source=src, min_hop_count=hop)

    # --- link layer ----------------------------------------------------------
    def _detect_link_layer(self, add):
        for (src, dst, code), n in self.bvlc_naks.items():
            add('bvlc_nak', 'high',
                f'{src} answered {dst} with {BVLC_RESULT_CODES.get(code, hex(code))} (x{n})',
                source=src, target=dst, result_code=f'0x{code:04X}',
                result=BVLC_RESULT_CODES.get(code, 'unknown'), count=n)

        by_port = defaultdict(set)
        for (ip, port) in set(self.nonstandard_ports) | set(self.server_ports):
            if port != BACNET_DEFAULT_PORT and (ip, port) in self.server_ports:
                by_port[port].add(ip)
        for port, ips in by_port.items():
            add('nonstandard_port', 'low',
                f'{len(ips)} BACnet device(s) listen on UDP {port} instead of 47808 - '
                'tools scanning only 47808 will miss them',
                port=port, ip_addresses=sorted(ips))

        for src, reasons in self.malformed.items():
            total = sum(reasons.values())
            add('malformed_packet', 'medium' if total >= 3 else 'low',
                f'{total} malformed BACnet packets from {src}',
                source=src, reasons=dict(reasons))

        for (src, kind), n in self.mstp_crc_errors.items():
            add('mstp_crc_error', 'medium',
                f'{n} MS/TP {kind} CRC errors from {src} - wiring, termination, '
                'baud mismatch or noise', source=src, crc=kind, count=n)

        for src, n in self.mstp_invalid_master.items():
            add('mstp_invalid_master', 'medium',
                f'MS/TP:{src} passes tokens but master addresses must be 0-127',
                mstp_address=src, frames=n)


def _main(argv: List[str]) -> int:
    if len(argv) < 2:
        print('usage: python -m bacnet.bacnet_parser <capture.pcap> [--json] [--workers N]')
        return 2
    workers = None
    if '--workers' in argv:
        workers = int(argv[argv.index('--workers') + 1])
    parser = BACnetParser(workers=workers)
    try:
        result = parser.analyze_pcap(argv[1])
    finally:
        parser.close()
    if '--json' in argv:
        print(json.dumps(result, indent=2, default=str))
        return 0
    stats = result.get('statistics', {})
    print(f"Packets: {stats.get('total_packets')}  BACnet/IP: {stats.get('bacnet_ip_packets')}  "
          f"MS/TP: {stats.get('bacnet_mstp_packets')}  Devices: {stats.get('total_devices')}")
    for a in result.get('anomalies', []):
        print(f"[{a['severity'].upper():8}] {a['type']:26} {a['description']}")
    return 0


if __name__ == '__main__':
    sys.exit(_main(sys.argv))
