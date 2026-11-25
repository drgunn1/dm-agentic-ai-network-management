"""Build synthetic BACnet captures exercising each detector. Usage: make_test_pcaps.py <repo> <outdir>"""
import sys, os
sys.path.insert(0, sys.argv[1])
from scapy.all import Ether, IP, UDP, Raw, ARP, wrpcap
from bacnet.bacnet_parser import BACnetParser

out = sys.argv[2]
pkts = []
T = [1000.0]

MAC = {}
def mac(ip):
    return MAC.setdefault(ip, '02:00:00:00:%02x:%02x' % (len(MAC) // 256, len(MAC) % 256))

def bip(src, dst, npdu, func=0x0A, t=None, sport=47808, dport=47808, extra=b'', badlen=False):
    body = extra + npdu
    ln = 4 + len(body) + (3 if badlen else 0)
    payload = bytes([0x81, func]) + ln.to_bytes(2, 'big') + body
    p = Ether(src=mac(src), dst='ff:ff:ff:ff:ff:ff' if dst.endswith('255') else mac(dst)) / \
        IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)
    p.time = T[0] if t is None else t
    pkts.append(p)

def adv(dt): T[0] += dt

def oid(otype, inst): return ((otype << 22) | inst).to_bytes(4, 'big')
NP = b'\x01\x00'
NP_REPLY = b'\x01\x04'
def iam(inst, vendor=5): return NP + b'\x10\x00' + b'\xc4' + oid(8, inst) + b'\x22\x05\xc4' + b'\x91\x00' + b'\x21' + bytes([vendor])
def whois(lo=None, hi=None):
    b = NP + b'\x10\x08'
    if lo is not None: b += b'\x09' + bytes([lo & 0xff]) if lo < 256 else b'\x0a' + lo.to_bytes(2, 'big')
    if hi is not None: b += b'\x19' + bytes([hi & 0xff]) if hi < 256 else b'\x1a' + hi.to_bytes(2, 'big')
    return b
def readprop(invoke, inst): return NP_REPLY + bytes([0x00, 0x05, invoke, 0x0C]) + b'\x0c' + oid(8, inst) + b'\x19\x4d'
def cack_rp(invoke, inst): return NP + bytes([0x30, invoke, 0x0C]) + b'\x0c' + oid(8, inst) + b'\x19\x4d\x3e\x75\x04\x00ABC\x3f'
def error(invoke, svc, cls, code): return NP + bytes([0x50, invoke, svc, 0x91, cls, 0x91, code])

# Normal discovery, incl. a routed MS/TP trunk behind router 10.0.0.1 (net 5)
bip('10.0.0.5', '10.0.0.255', whois(), func=0x0B)
adv(0.01); bip('10.0.0.10', '10.0.0.255', iam(100), func=0x0B)
adv(0.01); bip('10.0.0.11', '10.0.0.255', iam(101), func=0x0B)
for i, inst in enumerate((501, 502, 503)):
    adv(0.01)
    routed = b'\x01\x08' + b'\x00\x05\x01' + bytes([10 + i]) + b'\x10\x00' + iam(inst)[4:]
    bip('10.0.0.1', '10.0.0.255', routed, func=0x0B)

# Normal ReadProperty: must NOT attribute device 100 to the client
for inv in range(5):
    adv(0.5); bip('10.0.0.5', '10.0.0.10', readprop(inv, 100))
    adv(0.04); bip('10.0.0.10', '10.0.0.5', cack_rp(inv, 100))

# Slow device 101 (1.5 s replies)
for inv in range(10, 14):
    adv(0.2); bip('10.0.0.5', '10.0.0.11', readprop(inv, 101))
    adv(1.5); bip('10.0.0.11', '10.0.0.5', cack_rp(inv, 101))

# Unresponsive 10.0.0.12 with retries
for inv in (20, 21):
    for _ in range(3):
        adv(1.0); bip('10.0.0.5', '10.0.0.12', readprop(inv, 102))

# Benign Error PDUs: unknown-property x6
for inv in range(30, 36):
    adv(0.1); bip('10.0.0.5', '10.0.0.10', readprop(inv, 100))
    adv(0.01); bip('10.0.0.10', '10.0.0.5', error(inv, 12, 2, 32))

# DCC disable with password + password failures from rogue host
dcc = NP_REPLY + bytes([0x00, 0x05, 40, 17]) + b'\x09\x3c' + b'\x19\x01' + b'\x2d\x07\x00secret'
for inv in range(40, 44):
    adv(0.3); bip('10.0.0.99', '10.0.0.11', NP_REPLY + bytes([0x00, 0x05, inv]) + dcc[5:])
    adv(0.02); bip('10.0.0.11', '10.0.0.99', error(inv, 17, 4, 26))
# ReinitializeDevice accepted
adv(0.3); bip('10.0.0.99', '10.0.0.10', NP_REPLY + bytes([0x00, 0x05, 50, 20]) + b'\x09\x00')
adv(0.02); bip('10.0.0.10', '10.0.0.99', NP + bytes([0x20, 50, 20]))
# Priority-1 write
adv(0.1); bip('10.0.0.99', '10.0.0.10', NP_REPLY + bytes([0x00, 0x05, 51, 15]) + b'\x0c' + oid(1, 3) + b'\x19\x55\x3e\x44\x42\x48\x00\x00\x3f\x49\x01')
adv(0.02); bip('10.0.0.10', '10.0.0.99', NP + bytes([0x20, 51, 15]))

# Who-Is flood
adv(1.0)
for i in range(30):
    bip('10.0.0.66', '10.0.0.255', whois(), func=0x0B, t=T[0] + i * 0.02)
adv(1.0)

# Spoofed / duplicate device 100 with different vendor
adv(0.1); bip('10.0.0.20', '10.0.0.255', iam(100, vendor=99), func=0x0B)

# Targeted Who-Is for missing device 555
for _ in range(3):
    adv(0.5); bip('10.0.0.5', '10.0.0.255', whois(555, 555), func=0x0B)

# Network layer: Reject-Message-To-Network, I-Am-Router conflict, hop count 0
adv(0.1); bip('10.0.0.1', '10.0.0.5', b'\x01\x80\x03\x01\x00\x07')
adv(0.1); bip('10.0.0.1', '10.0.0.255', b'\x01\x80\x01\x00\x05', func=0x0B)
adv(0.1); bip('10.0.0.2', '10.0.0.255', b'\x01\x80\x01\x00\x05', func=0x0B)
adv(0.1); bip('10.0.0.3', '10.0.0.5', b'\x01\x20\x00\x09\x00\x00' + b'\x10\x08')

# BVLC: Register-FD NAK, Write-BDT, Forwarded-NPDU duplicate
adv(0.1); bip('10.0.0.1', '10.0.0.77', b'', func=0x00, extra=b'\x00\x30')
adv(0.1); bip('10.0.0.77', '10.0.0.1', b'', func=0x01, extra=b'\x0a\x00\x00\x02\xba\xc0\xff\xff\xff\x00')
orig = b'\xc0\xa8\x01\x05\xba\xc0'
adv(0.1); bip('10.0.0.1', '10.0.0.255', whois(), func=0x04, extra=orig)
adv(0.05); bip('10.0.0.2', '10.0.0.255', whois(), func=0x04, extra=orig)

# Abort: segmentation not supported
adv(0.1); bip('10.0.0.5', '10.0.0.10', readprop(60, 100))
adv(0.01); bip('10.0.0.10', '10.0.0.5', NP + bytes([0x71, 60, 4]))

# Malformed length and non-standard port
for _ in range(3):
    adv(0.1); bip('10.0.0.44', '10.0.0.255', whois(), func=0x0B, badlen=True)
adv(0.1); bip('10.0.0.45', '10.0.0.255', iam(4500), func=0x0B, sport=47809, dport=47809)

# ARP conflict
for m in ('02:aa:00:00:00:01', '02:aa:00:00:00:02'):
    a = Ether(src=m) / ARP(op=2, psrc='10.0.0.50', hwsrc=m); a.time = T[0]; pkts.append(a)

adv(10.0)
last = Ether() / IP(src='10.0.0.5', dst='10.0.0.6') / UDP(sport=1, dport=2); last.time = T[0]; pkts.append(last)
wrpcap(os.path.join(out, 'bip_test.pcap'), pkts)

# ---------------- MS/TP capture (DLT 165) ----------------
P = BACnetParser
def mstp(ftype, dst, src, data=b'', corrupt_hdr=False, corrupt_data=False):
    hdr = bytes([ftype, dst, src]) + len(data).to_bytes(2, 'big')
    hcrc = (~P._mstp_header_crc(hdr)) & 0xFF
    if corrupt_hdr: hcrc ^= 0x01
    f = b'\x55\xff' + hdr + bytes([hcrc])
    if data:
        c = (~P._mstp_data_crc(data)) & 0xFFFF
        if corrupt_data: c ^= 1
        f += data + bytes([c & 0xFF, c >> 8])
    return f

m = []
t0 = 2000.0
frames = [mstp(0, 2, 1), mstp(1, 3, 2), mstp(6, 255, 1, iam(7001)), mstp(6, 255, 2, iam(7002)),
          mstp(6, 255, 1, iam(7003)),                     # second instance on MS/TP 1 -> conflict
          mstp(0, 1, 2, corrupt_hdr=True), mstp(6, 255, 2, iam(7002), corrupt_data=True),
          mstp(0, 1, 200)]                                 # token from address > 127
for i, f in enumerate(frames):
    r = Raw(f); r.time = t0 + i * 0.01; m.append(r)
wrpcap(os.path.join(out, 'mstp_test.pcap'), m, linktype=165)
print('written')
