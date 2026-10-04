"""Bounded PCAP/PCAPNG and UDP DNS parsing, without network access."""

from dataclasses import dataclass
import ipaddress
import struct


class ParseError(ValueError):
    """Malformed or unsupported capture evidence."""


MAX_RECORD = 16 * 1024 * 1024


@dataclass(frozen=True)
class Packet:
    number: int
    timestamp: float
    linktype: int
    data: bytes
    original_length: int


@dataclass(frozen=True)
class DNS:
    packet: int
    timestamp: float
    source: str
    destination: str
    source_port: int
    destination_port: int
    transaction: int
    response: bool
    rcode: int
    questions: tuple


def read_exact(stream, size):
    if size < 0 or size > MAX_RECORD:
        raise ParseError("Record exceeds the 16 MiB allocation limit")
    data = stream.read(size)
    if len(data) != size:
        raise ParseError("Truncated capture record")
    return data


def options(data, endian):
    pos = 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise ParseError("Truncated PCAPNG option")
        code, size = struct.unpack_from(endian + "HH", data, pos)
        pos += 4
        if code == 0:
            if size:
                raise ParseError("Invalid PCAPNG end option")
            return
        padded = (size + 3) & ~3
        if pos + padded > len(data):
            raise ParseError("Invalid PCAPNG option length")
        yield code, data[pos:pos + size]
        pos += padded


def packets(stream):
    magic = read_exact(stream, 4)
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from pcapng(stream, magic)
        return
    if magic not in formats:
        raise ParseError("Not a supported PCAP or PCAPNG capture")
    endian, resolution = formats[magic]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", read_exact(stream, 20))
    if (major, minor) != (2, 4) or not snaplen:
        raise ParseError("Unsupported PCAP version or invalid snapshot length")
    number = 0
    while header := stream.read(16):
        if len(header) != 16:
            raise ParseError("Truncated PCAP packet header")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", header)
        if captured > original or captured > snaplen or fraction >= resolution:
            raise ParseError("Invalid PCAP packet length or timestamp")
        number += 1
        yield Packet(number, seconds + fraction / resolution, linktype & 0xFFFF,
                     read_exact(stream, captured), original)


def pcapng(stream, first):
    endian = None
    interfaces = []
    number = 0
    kind_bytes = first
    while kind_bytes:
        if len(kind_bytes) != 4:
            raise ParseError("Truncated PCAPNG block header")
        length_bytes = read_exact(stream, 4)
        if kind_bytes == b"\x0a\x0d\x0d\x0a":
            bom = read_exact(stream, 4)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ParseError("Invalid PCAPNG byte-order magic")
            length = struct.unpack(endian + "I", length_bytes)[0]
            if length < 28 or length % 4:
                raise ParseError("Invalid PCAPNG section size")
            rest = read_exact(stream, length - 12)
            body = bom + rest[:-4]
            if struct.unpack(endian + "I", rest[-4:])[0] != length:
                raise ParseError("PCAPNG block lengths disagree")
            major, minor = struct.unpack_from(endian + "HH", body, 4)
            if (major, minor) != (1, 0):
                raise ParseError("Unsupported PCAPNG section version")
            interfaces = []
        else:
            if endian is None:
                raise ParseError("Missing PCAPNG section")
            length = struct.unpack(endian + "I", length_bytes)[0]
            if length < 12 or length % 4:
                raise ParseError("Invalid PCAPNG block size")
            rest = read_exact(stream, length - 8)
            body = rest[:-4]
            if struct.unpack(endian + "I", rest[-4:])[0] != length:
                raise ParseError("PCAPNG block lengths disagree")
            kind = struct.unpack(endian + "I", kind_bytes)[0]
            if kind == 1:
                if len(body) < 8:
                    raise ParseError("Truncated interface description")
                linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
                resolution, offset = 1e-6, 0
                for code, value in options(body[8:], endian):
                    if code == 9:
                        if len(value) != 1:
                            raise ParseError("Invalid interface timestamp resolution")
                        exponent = value[0] & 127
                        resolution = (2 if value[0] & 128 else 10) ** -exponent
                    elif code == 14:
                        if len(value) != 8:
                            raise ParseError("Invalid interface timestamp offset")
                        offset = struct.unpack(endian + "q", value)[0]
                if len(interfaces) >= 1024:
                    raise ParseError("PCAPNG exceeds 1024 interfaces per section")
                interfaces.append((linktype, snaplen, resolution, offset))
            elif kind == 6:
                if len(body) < 20:
                    raise ParseError("Truncated enhanced packet block")
                interface, high, low, captured, original = struct.unpack_from(endian + "IIIII", body)
                if interface >= len(interfaces):
                    raise ParseError("Unknown PCAPNG interface")
                linktype, snaplen, resolution, offset = interfaces[interface]
                if captured > original or (snaplen and captured > snaplen):
                    raise ParseError("Invalid PCAPNG captured length")
                padded = (captured + 3) & ~3
                if 20 + padded > len(body):
                    raise ParseError("Truncated PCAPNG packet data")
                list(options(body[20 + padded:], endian))
                number += 1
                yield Packet(number, ((high << 32) | low) * resolution + offset,
                             linktype, body[20:20 + captured], original)
            elif kind in (2, 3):
                raise ParseError("Legacy/simple PCAPNG packet blocks are not supported; convert to enhanced blocks")
        kind_bytes = stream.read(4)


def dns_name(message, start):
    pos, end, labels, seen = start, None, [], set()
    wire_length = 1
    for _ in range(128):
        if pos >= len(message) or pos in seen:
            raise ParseError("DNS name is truncated or contains a pointer cycle")
        seen.add(pos)
        size = message[pos]
        if size & 0xC0 == 0xC0:
            if pos + 1 >= len(message):
                raise ParseError("Truncated DNS compression pointer")
            target = ((size & 63) << 8) | message[pos + 1]
            if target >= pos or target < 12:
                raise ParseError("Invalid forward/header DNS compression pointer")
            if end is None:
                end = pos + 2
            pos = target
        elif size & 0xC0:
            raise ParseError("Unsupported DNS label encoding")
        elif not size:
            return ".".join(labels), end if end is not None else pos + 1
        else:
            pos += 1
            if pos + size > len(message):
                raise ParseError("Truncated DNS label")
            label = message[pos:pos + size]
            # Escaping makes arbitrary wire octets unambiguous; analysis ignores
            # escaped names rather than inventing a registrable domain for them.
            labels.append("".join(chr(c).lower() if 33 <= c <= 126 and c not in (46, 92)
                                  else "\\%03d" % c for c in label))
            wire_length += size + 1
            if wire_length > 255:
                raise ParseError("DNS name exceeds 255 wire bytes")
            pos += size
    raise ParseError("DNS name exceeds compression traversal limit")


def dns_message(message):
    if len(message) < 12:
        raise ParseError("Truncated DNS header")
    ident, flags, question_count, answers, authority, additional = struct.unpack_from("!6H", message)
    if (flags >> 11) & 15:
        raise ParseError("Only standard DNS queries are supported")
    if flags & 0x200:
        raise ParseError("DNS truncated-message flag is set")
    if question_count > 64 or answers + authority + additional > 4096:
        raise ParseError("DNS record-count limit exceeded")
    pos, questions = 12, []
    for _ in range(question_count):
        name, pos = dns_name(message, pos)
        if pos + 4 > len(message):
            raise ParseError("Truncated DNS question")
        qtype, qclass = struct.unpack_from("!HH", message, pos)
        pos += 4
        questions.append((name, qtype, qclass))
    # Validate resource record framing too: a valid question is not enough to
    # call a truncated response complete. RDATA contents remain uninterpreted.
    for _ in range(answers + authority + additional):
        _, pos = dns_name(message, pos)
        if pos + 10 > len(message):
            raise ParseError("Truncated DNS resource record")
        size = struct.unpack_from("!H", message, pos + 8)[0]
        pos += 10 + size
        if pos > len(message):
            raise ParseError("Truncated DNS resource data")
    if pos != len(message):
        raise ParseError("Unexpected trailing DNS bytes")
    return ident, bool(flags & 0x8000), flags & 15, tuple(questions)


def decode(packet):
    data = packet.data
    if len(data) < packet.original_length:
        raise ParseError("Snapshot-truncated packet")
    if packet.linktype == 1:
        if len(data) < 14:
            raise ParseError("Truncated Ethernet header")
        protocol = struct.unpack_from("!H", data, 12)[0]
        pos = 14
        for _ in range(4):
            if protocol not in (0x8100, 0x88A8):
                break
            if len(data) < pos + 4:
                raise ParseError("Truncated VLAN header")
            protocol = struct.unpack_from("!H", data, pos + 2)[0]
            pos += 4
        if protocol in (0x8100, 0x88A8):
            raise ParseError("VLAN nesting limit exceeded")
        if protocol not in (0x0800, 0x86DD):
            return None
        data = data[pos:]
    elif packet.linktype not in (101, 228, 229):
        raise ParseError("Unsupported link type %s" % packet.linktype)
    if not data:
        raise ParseError("Missing IP header")
    version = data[0] >> 4
    if packet.linktype in (228, 229) and version != {228: 4, 229: 6}[packet.linktype]:
        raise ParseError("Raw IP version disagrees with link type")
    if packet.linktype == 1 and version != {0x0800: 4, 0x86DD: 6}[protocol]:
        raise ParseError("IP version disagrees with Ethernet type")
    if version == 4:
        if len(data) < 20:
            raise ParseError("Truncated IPv4 header")
        pos = (data[0] & 15) * 4
        size = struct.unpack_from("!H", data, 2)[0]
        if pos < 20 or size < pos or size > len(data):
            raise ParseError("Invalid IPv4 header or total length")
        if struct.unpack_from("!H", data, 6)[0] & 0x3FFF:
            raise ParseError("Fragmented IPv4 is not reassembled")
        transport = data[9]
        source, destination = str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
    elif version == 6:
        if len(data) < 40:
            raise ParseError("Truncated IPv6 header")
        payload = struct.unpack_from("!H", data, 4)[0]
        size = 40 + payload
        if not payload or size > len(data):
            raise ParseError("Invalid IPv6 payload length or unsupported jumbogram")
        source, destination = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
        transport, pos = data[6], 40
        for _ in range(8):
            if transport == 44:
                raise ParseError("Fragmented IPv6 is not reassembled")
            if transport not in (0, 43, 60):
                break
            if pos + 2 > size:
                raise ParseError("Truncated IPv6 extension")
            transport, extension_size = data[pos], (data[pos + 1] + 1) * 8
            pos += extension_size
            if pos > size:
                raise ParseError("Invalid IPv6 extension length")
        if transport in (0, 43, 60):
            raise ParseError("IPv6 extension limit exceeded")
    else:
        raise ParseError("Unsupported IP version")
    if transport == 6:
        if pos + 4 > size:
            raise ParseError("Truncated TCP header")
        if 53 in struct.unpack_from("!HH", data, pos):
            raise ParseError("TCP DNS is not reassembled in this version")
        return None
    if transport != 17:
        return None
    if pos + 8 > size:
        raise ParseError("Truncated UDP header")
    sport, dport, udp_size, _ = struct.unpack_from("!4H", data, pos)
    if udp_size < 8 or pos + udp_size > size:
        raise ParseError("Invalid UDP length")
    if 53 not in (sport, dport):
        return None
    ident, response, rcode, questions = dns_message(data[pos + 8:pos + udp_size])
    return DNS(packet.number, packet.timestamp, source, destination, sport, dport,
               ident, response, rcode, questions)
