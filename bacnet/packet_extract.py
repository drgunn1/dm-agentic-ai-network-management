"""
Copyright 2026 NXP
SPDX-License-Identifier: BSD-3-Clause

Stateless packet decoding for the BACnet parser.

Turns raw capture records into small tuples ("records") that hold only what the
BACnet analysis needs. Nothing here keeps state, so batches of packets can be
decoded in parallel worker processes while the stateful analysis consumes the
records in capture order.

Common link types (Ethernet incl. VLAN and 802.3/LLC, Linux cooked capture,
raw IP, null/loopback, MS/TP) are decoded straight from the bytes, which is far
faster than a full scapy dissection. Anything else falls back to scapy.

Record formats:
    ('x',   t)                                         irrelevant packet
    ('dup', t, key)                                    non-BACnet UDP (duplicate check only)
    ('arp', t, op, sender_ip, sender_mac)
    ('udp', t, key, src_ip, dst_ip, sport, dport, payload, eth_src_or_None, on_bacnet_port)
    ('llc', t, src_mac, dst_mac, npdu)                 BACnet/Ethernet (ISO 8802-2)
    ('raw', t, data, native)                           bytes that may hold MS/TP frames
"""

import hashlib
import mmap
import socket
import struct
from typing import Iterator, List, Optional, Tuple

try:
    from .bacnet_constants import BACNET_PORT_RANGE, BVLC_FUNCTIONS, BVLC_TYPE_BIP
except ImportError:  # executed as a plain script
    from bacnet_constants import BACNET_PORT_RANGE, BVLC_FUNCTIONS, BVLC_TYPE_BIP

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
VLAN_TAGS = (0x8100, 0x88A8, 0x9100)

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_MSTP = 165
LINKTYPE_IPV4 = 228
LINKTYPE_LINUX_SLL2 = 276

MSTP_PREAMBLE = b'\x55\xff'

RawRecord = Tuple[int, float, bytes]          # (linktype, timestamp, frame bytes)


def _mac(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)


def looks_like_bvlc(payload: bytes) -> bool:
    return (len(payload) >= 4 and payload[0] == BVLC_TYPE_BIP
            and payload[1] in BVLC_FUNCTIONS
            and int.from_bytes(payload[2:4], 'big') == len(payload))


def _ipv4(t: float, raw: bytes, off: int, eth_src: Optional[str]):
    if len(raw) < off + 20 or raw[off] >> 4 != 4:
        return ('x', t)
    ihl = (raw[off] & 0x0F) * 4
    total = int.from_bytes(raw[off + 2:off + 4], 'big')
    end = min(len(raw), off + total) if total else len(raw)
    proto = raw[off + 9]
    if proto != 17:
        data = raw[off + ihl:end]
        return ('raw', t, data, False) if MSTP_PREAMBLE in data else ('x', t)
    frag = int.from_bytes(raw[off + 6:off + 8], 'big')
    udp = off + ihl
    if frag & 0x1FFF or len(raw) < udp + 8:      # non-first fragment / truncated
        return ('x', t)
    key = hashlib.blake2b(raw[off:end], digest_size=8).digest()
    sport = int.from_bytes(raw[udp:udp + 2], 'big')
    dport = int.from_bytes(raw[udp + 2:udp + 4], 'big')
    ulen = int.from_bytes(raw[udp + 4:udp + 6], 'big')
    payload = raw[udp + 8:end]
    if ulen >= 8:
        payload = payload[:ulen - 8]              # strip link-layer padding
    on_port = sport in BACNET_PORT_RANGE or dport in BACNET_PORT_RANGE
    if not (on_port or looks_like_bvlc(payload)):
        return ('dup', t, key)
    return ('udp', t, key, socket.inet_ntoa(raw[off + 12:off + 16]),
            socket.inet_ntoa(raw[off + 16:off + 20]), sport, dport, payload, eth_src, on_port)


def _arp(t: float, raw: bytes, off: int):
    if len(raw) < off + 28:
        return ('x', t)
    op = int.from_bytes(raw[off + 6:off + 8], 'big')
    return ('arp', t, op, socket.inet_ntoa(raw[off + 14:off + 18]), _mac(raw[off + 8:off + 14]))


def _ethernet(t: float, raw: bytes):
    if len(raw) < 14:
        return ('x', t)
    dst, src = raw[0:6], raw[6:12]
    off = 12
    etype = int.from_bytes(raw[off:off + 2], 'big')
    while etype in VLAN_TAGS and len(raw) >= off + 6:
        off += 4
        etype = int.from_bytes(raw[off:off + 2], 'big')
    off += 2
    if etype <= 1500:                             # IEEE 802.3 length + 802.2 LLC
        frame = raw[off:off + etype]
        if len(frame) >= 3 and frame[0] == 0x82 and frame[1] == 0x82:
            return ('llc', t, _mac(src), _mac(dst), frame[3:])
        return ('raw', t, raw, False) if MSTP_PREAMBLE in raw else ('x', t)
    if etype == ETH_P_IP:
        return _ipv4(t, raw, off, _mac(src))
    if etype == ETH_P_ARP:
        return _arp(t, raw, off)
    return ('raw', t, raw, False) if MSTP_PREAMBLE in raw else ('x', t)


def _by_protocol(t: float, raw: bytes, proto: int, off: int):
    if proto == ETH_P_IP:
        return _ipv4(t, raw, off, None)
    if proto == ETH_P_ARP:
        return _arp(t, raw, off)
    return ('x', t)


def extract(linktype: int, t: float, raw: bytes):
    """Decode one capture record into a BACnet-relevant record tuple."""
    if linktype == LINKTYPE_ETHERNET:
        return _ethernet(t, raw)
    if linktype == LINKTYPE_MSTP:
        return ('raw', t, raw, raw[:2] == MSTP_PREAMBLE)
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4):
        return _ipv4(t, raw, 0, None)
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        family = int.from_bytes(raw[:4], 'little') if linktype == LINKTYPE_NULL \
            else int.from_bytes(raw[:4], 'big')
        return _ipv4(t, raw, 4, None) if family == socket.AF_INET else ('x', t)
    if linktype == LINKTYPE_LINUX_SLL:
        return _by_protocol(t, raw, int.from_bytes(raw[14:16], 'big'), 16)
    if linktype == LINKTYPE_LINUX_SLL2:
        return _by_protocol(t, raw, int.from_bytes(raw[0:2], 'big'), 20)
    return _extract_scapy(linktype, t, raw)


def _extract_scapy(linktype: int, t: float, raw: bytes):
    """Fallback for link types without a fast path: dissect with scapy."""
    from scapy.all import conf, IP, UDP, Ether, Raw, ARP
    from scapy.layers.l2 import LLC, Dot3

    cls = conf.l2types.num2layer.get(linktype, conf.raw_layer)
    try:
        pkt = cls(raw)
    except Exception:
        return ('x', t)
    if ARP in pkt:
        return ('arp', t, pkt[ARP].op, pkt[ARP].psrc, pkt[ARP].hwsrc)
    if IP in pkt and UDP in pkt:
        ip_bytes = bytes(pkt[IP])
        return _ipv4(t, ip_bytes, 0, pkt[Ether].src if Ether in pkt else None)
    if LLC in pkt and pkt[LLC].dsap == 0x82 and pkt[LLC].ssap == 0x82:
        l2 = pkt[Dot3] if Dot3 in pkt else (pkt[Ether] if Ether in pkt else None)
        npdu = bytes(pkt[LLC].payload)
        if Dot3 in pkt and pkt[Dot3].len:
            npdu = npdu[:max(pkt[Dot3].len - 3, 0)]
        return ('llc', t, l2.src if l2 is not None else '?', l2.dst if l2 is not None else '',
                npdu)
    data = bytes(pkt[Raw].load) if Raw in pkt else raw
    native = Ether not in pkt and Dot3 not in pkt and data[:2] == MSTP_PREAMBLE
    return ('raw', t, data, native) if MSTP_PREAMBLE in data else ('x', t)


def extract_batch(batch: List[RawRecord]) -> list:
    """Worker entry point: decode a batch of raw capture records."""
    out = []
    for linktype, t, raw in batch:
        try:
            out.append(extract(linktype, t, raw))
        except Exception:
            out.append(('x', t))
    return out


# ---------------------------------------------------------------------------
# Capture indexing: split a pcap / pcapng file into slices that worker
# processes read and decode on their own. Only record headers are touched here.
# ---------------------------------------------------------------------------
PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', False), b'\xa1\xb2\xc3\xd4': ('>', False),
    b'\x4d\x3c\xb2\xa1': ('<', True), b'\xa1\xb2\x3c\x4d': ('>', True),
}
PCAPNG_SHB = 0x0A0D0D0A


def _pcapng_tsresol(body: bytes, endian: str) -> int:
    """if_tsresol option of an Interface Description Block (default microseconds)."""
    off = 8                                        # linktype, reserved, snaplen
    while off + 4 <= len(body):
        code, length = struct.unpack_from(endian + 'HH', body, off)
        if code == 0:
            break
        if code == 9 and length >= 1:
            v = body[off + 4]
            return 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
        off += 4 + ((length + 3) & ~3)
    return 1000000


def index_capture(pcap_file: str, batch_size: int):
    """Split a capture into slices of about `batch_size` records.

    Returns a list of (start, end, context) tuples for decode_slice(), or None if
    the format is not plain pcap / pcapng (then read_raw() is used instead).
    """
    slices = []
    with open(pcap_file, 'rb') as f:
        try:
            m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:                         # empty file
            return []
        with m:
            size = len(m)
            head = m[:4]
            if head in PCAP_MAGICS:
                endian, nano = PCAP_MAGICS[head]
                if size < 24:
                    return []
                linktype = struct.unpack_from(endian + 'I', m, 20)[0] & 0x0FFFFFFF
                ctx = ('pcap', endian, nano, linktype)
                off = start = 24
                n = 0
                while off + 16 <= size:
                    caplen = struct.unpack_from(endian + 'I', m, off + 8)[0]
                    off += 16 + caplen
                    n += 1
                    if n >= batch_size:
                        slices.append((start, min(off, size), ctx))
                        start, n = off, 0
                if n:
                    slices.append((start, min(off, size), ctx))
                return slices

            if struct.unpack_from('<I', m, 0)[0] != PCAPNG_SHB:
                return None
            endian = '<'
            interfaces = []                        # (linktype, tsresol) per interface
            off = start = 0
            n = 0
            ctx = None
            while off + 12 <= size:
                if struct.unpack_from('<I', m, off)[0] == PCAPNG_SHB:
                    endian = '<' if m[off + 8:off + 12] == b'\x4d\x3c\x2b\x1a' else '>'
                    if n:                          # a new section starts a new slice
                        slices.append((start, off, ctx))
                        n = 0
                    interfaces = []
                    start = off
                btype, blen = struct.unpack_from(endian + 'II', m, off)
                if blen < 12 or off + blen > size:
                    break                          # truncated capture
                if btype == 1:                     # Interface Description Block
                    linktype = struct.unpack_from(endian + 'H', m, off + 8)[0]
                    interfaces.append((linktype, _pcapng_tsresol(m[off + 8:off + blen - 4],
                                                                 endian)))
                    if n:                          # new interface: start a new slice
                        slices.append((start, off, ctx))
                        start, n = off, 0
                elif btype in (2, 3, 6):           # packet blocks
                    if n == 0:
                        ctx = ('pcapng', endian, tuple(interfaces))
                        start = off
                    n += 1
                off += blen
                if n >= batch_size:
                    slices.append((start, off, ctx))
                    start, n = off, 0
            if n:
                slices.append((start, off, ctx))
            return slices


def _slice_records(data: bytes, ctx: tuple) -> Iterator[RawRecord]:
    if ctx[0] == 'pcap':
        _, endian, nano, linktype = ctx
        div = 1e9 if nano else 1e6
        hdr = struct.Struct(endian + 'IIII')
        off = 0
        while off + 16 <= len(data):
            sec, frac, caplen, _ = hdr.unpack_from(data, off)
            yield linktype, sec + frac / div, data[off + 16:off + 16 + caplen]
            off += 16 + caplen
        return
    _, endian, interfaces = ctx
    off = 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from(endian + 'II', data, off)
        if blen < 12:
            break
        if btype == 6:                             # Enhanced Packet Block
            iface, hi, lo, caplen = struct.unpack_from(endian + 'IIII', data, off + 8)
            lt, res = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1000000)
            yield lt, ((hi << 32) | lo) / res, data[off + 28:off + 28 + caplen]
        elif btype == 2:                           # (obsolete) Packet Block
            iface = struct.unpack_from(endian + 'H', data, off + 8)[0]
            hi, lo, caplen = struct.unpack_from(endian + 'III', data, off + 12)
            lt, res = interfaces[iface] if iface < len(interfaces) else (LINKTYPE_ETHERNET, 1000000)
            yield lt, ((hi << 32) | lo) / res, data[off + 28:off + 28 + caplen]
        elif btype == 3:                           # Simple Packet Block: no timestamp
            lt = interfaces[0][0] if interfaces else LINKTYPE_ETHERNET
            yield lt, 0.0, data[off + 12:off + blen - 4]
        off += blen


def decode_slice(job: Tuple[str, int, int, tuple]) -> list:
    """Worker entry point: read one slice of the capture file and decode it."""
    path, start, end, ctx = job
    with open(path, 'rb') as f:
        f.seek(start)
        data = f.read(end - start)
    return extract_batch(list(_slice_records(data, ctx)))


def read_raw(pcap_file: str) -> Iterator[RawRecord]:
    """Yield (linktype, timestamp, bytes) for every record of a pcap / pcapng file
    without dissecting it (about 40x faster than scapy's PcapReader)."""
    from scapy.utils import RawPcapReader

    with RawPcapReader(pcap_file) as reader:
        default_lt = getattr(reader, 'linktype', LINKTYPE_ETHERNET)
        nano = bool(getattr(reader, 'nano', False))
        for raw, md in reader:
            if hasattr(md, 'tshigh'):                             # pcapng
                if md.tshigh is not None and md.tsresol:
                    t = ((md.tshigh << 32) | md.tslow) / md.tsresol
                else:
                    t = 0.0
                lt = md.linktype if md.linktype is not None else default_lt
            else:                                                 # classic pcap
                t = md.sec + md.usec / (1e9 if nano else 1e6)
                lt = default_lt
            yield lt, t, raw
