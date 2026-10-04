"""Generate a harmless synthetic capture; never transmit packets."""

import hashlib
import ipaddress
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def message(name, ident=1, response=False, rcode=0, qtype=1):
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"
    flags = (0x8180 if response else 0x0100) | rcode
    return struct.pack("!6H", ident, flags, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def frame(payload, source="192.0.2.10", destination="192.0.2.53", sport=45000, dport=53, ipv6=False, vlan=False):
    source_bytes = ipaddress.ip_address(source).packed
    destination_bytes = ipaddress.ip_address(destination).packed
    udp_size = 8 + len(payload)
    pseudo = (source_bytes + destination_bytes + struct.pack("!I3xB", udp_size, 17) if ipv6
              else source_bytes + destination_bytes + struct.pack("!BBH", 0, 17, udp_size))
    udp = struct.pack("!4H", sport, dport, udp_size, 0) + payload
    udp_sum = checksum(pseudo + udp) or 65535
    udp = struct.pack("!4H", sport, dport, udp_size, udp_sum) + payload
    if ipv6:
        ip = struct.pack("!IHBB", 6 << 28, udp_size, 17, 64) + source_bytes + destination_bytes
        ethertype = 0x86DD
    else:
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + udp_size, 1, 0, 64, 17, 0) + source_bytes + destination_bytes
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        ethertype = 0x0800
    ethernet = b"\x02\0\0\0\0\x53\x02\0\0\0\0\x10"
    if vlan:
        ethernet += struct.pack("!HH", 0x8100, 7)
    return ethernet + struct.pack("!H", ethertype) + ip + udp


def pcap(records, endian="<", nanosecond=False, linktype=1):
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    result = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype))
    scale = 1_000_000_000 if nanosecond else 1_000_000
    for timestamp, data in records:
        seconds = int(timestamp)
        fraction = round((timestamp - seconds) * scale)
        if fraction == scale:
            seconds, fraction = seconds + 1, 0
        result.extend(struct.pack(endian + "IIII", seconds, fraction, len(data), len(data)))
        result.extend(data)
    return bytes(result)


def pcapng(records, endian="<", resolution=6, offset=0):
    def block(kind, body):
        return struct.pack(endian + "II", kind, len(body) + 12) + body + struct.pack(endian + "I", len(body) + 12)
    section = block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = struct.pack(endian + "HHB3x", 9, 1, resolution)
    opts += struct.pack(endian + "HHq", 14, 8, offset) + b"\0" * 4
    interface = block(1, struct.pack(endian + "HHI", 1, 0, 65535) + opts)
    result = bytearray(section + interface)
    scale = (2 if resolution & 128 else 10) ** (resolution & 127)
    for timestamp, data in records:
        ticks = round((timestamp - offset) * scale)
        body = struct.pack(endian + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
        body += data + b"\0" * ((-len(data)) % 4)
        result.extend(block(6, body))
    return bytes(result)


def records():
    rows = []
    ident = 0
    def add(name, timestamp, client="192.0.2.10", qtype=1, rcode=0):
        nonlocal ident
        ident += 1
        rows.append((timestamp, frame(message(name, ident, qtype=qtype), source=client, sport=45000 + ident)))
        rows.append((timestamp + 0.05, frame(message(name, ident, True, rcode, qtype),
                                            source="192.0.2.53", destination=client, sport=53, dport=45000 + ident)))
    base = 1_700_000_000
    for index in range(24):
        label = hashlib.sha256(f"synthetic-dns-demo-{index}".encode()).hexdigest()[:48]
        add(label + ".channel.example.test", base + index, qtype=16, rcode=3)
    for index in range(30):
        add(["www.school.test", "mail.school.test", "api.app.test"][index % 3], base + index * 2)
    # A token-like but low-cardinality benign control should not be flagged.
    token = hashlib.sha256(b"stable-telemetry-id").hexdigest()[:48]
    for index in range(20):
        add(token + ".telemetry.service.test", base + index, client="192.0.2.20")
    # Tenant boundaries matter: separate github.io owners are not one domain.
    for index in range(15):
        add(f"tenant{index}.github.io", base + index, client="192.0.2.30")
    return sorted(rows, key=lambda row: row[0])
