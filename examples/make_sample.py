#!/usr/bin/env python3
"""Builds examples/sample.pcap: a deterministic, fully synthetic capture (RFC 5737 / private addresses)."""
import struct, sys

pkts, t = [], 1700000000.0

def ip(s): return bytes(int(x) for x in s.split("."))

def frame(src, dst, proto, l4):
    total = 20 + len(l4)
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, proto, 0, ip(src), ip(dst))
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00" + h + l4

def tcp(sp, dp, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sp, dp, 1, 1, 5 << 4, flags, 65535, 0, 0) + payload

def udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload

def add(dt, f):
    global t
    t += dt
    pkts.append((t, f))

# 1. a port scan: 203.0.113.9 probes 40 ports on 10.0.0.5
for i, port in enumerate(list(range(20, 60))):
    add(0.01, frame("203.0.113.9", "10.0.0.5", 6, tcp(40000 + i, port, 0x02)))
# 2. a host sweep: 198.51.100.77 probes port 445 on 30 hosts
for i in range(1, 31):
    add(0.02, frame("198.51.100.77", "10.0.1.%d" % i, 6, tcp(41000 + i, 445, 0x02)))
# 3. FTP login in cleartext
add(0.5, frame("10.0.0.20", "10.0.0.5", 6, tcp(50001, 21, 0x18, b"USER backup-svc\r\n")))
add(0.1, frame("10.0.0.20", "10.0.0.5", 6, tcp(50001, 21, 0x18, b"PASS Summer2026!\r\n")))
# 4. HTTP basic auth to an internal admin panel (alice:correcthorse)
add(0.3, frame("10.0.0.21", "10.0.0.8", 6, tcp(50002, 8080, 0x18, b"GET /admin HTTP/1.1\r\nHost: panel.lan\r\nAuthorization: Basic YWxpY2U6Y29ycmVjdGhvcnNl\r\n\r\n")))
# 5. normal traffic: a big HTTPS download and DNS
for i in range(60):
    add(0.05, frame("10.0.0.30", "192.0.2.50", 6, tcp(50003, 443, 0x10, b"x" * 1200)))
for i in range(12):
    add(0.2, frame("10.0.0.30", "10.0.0.1", 17, udp(53000 + i, 53, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01")))

out = sys.argv[1] if len(sys.argv) > 1 else "examples/sample.pcap"
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, p in pkts:
        f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(p), len(p)) + p)
