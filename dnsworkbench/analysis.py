"""Explainable DNS heuristics: review signals, never malware verdicts."""

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
import hashlib
import math
from itertools import islice
from pathlib import Path

from .capture import ParseError, decode, packets


@dataclass(frozen=True)
class Config:
    window_seconds: float = 60
    min_unique: int = 10
    min_label_length: int = 20
    min_entropy: float = 3.5
    min_suspicious_fraction: float = 0.5
    max_packets: int = 250_000
    max_questions: int = 100_000
    max_file_mib: int = 128

    def __post_init__(self):
        if not math.isfinite(self.window_seconds) or self.window_seconds <= 0:
            raise ValueError("Window must be positive and finite")
        if not math.isfinite(self.min_entropy) or not 0 <= self.min_entropy <= 8:
            raise ValueError("Entropy threshold must be between 0 and 8")
        if not 0 < self.min_suspicious_fraction <= 1:
            raise ValueError("Suspicious fraction must be in (0, 1]")
        if any(type(v) is not int or v < 1 for v in
               (self.min_unique, self.min_label_length, self.max_packets,
                self.max_questions, self.max_file_mib)):
            raise ValueError("Count and size limits must be positive integers")


class SuffixList:
    """PSL prevailing-rule algorithm, including PRIVATE tenant boundaries."""

    def __init__(self, path=None):
        source = Path(path) if path else Path(__file__).parent / "data/public_suffix_list.dat"
        raw = source.read_bytes()
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.version = next((l.removeprefix("// VERSION: ") for l in raw.decode("utf-8").splitlines()
                             if l.startswith("// VERSION: ")), "custom")
        self.exact, self.wildcards, self.exceptions = set(), set(), set()
        for line in raw.decode("utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!" ):
                self.exceptions.add(line[1:].encode("idna").decode("ascii").lower())
            elif line.startswith("*."):
                self.wildcards.add(line[2:].encode("idna").decode("ascii").lower())
            else:
                self.exact.add(line.encode("idna").decode("ascii").lower())

    def registrable(self, name):
        labels = name.lower().rstrip(".").split(".")
        suffix_length = 1
        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            length = len(labels) - index
            if candidate in self.exceptions:
                suffix_length = length - 1
                break
            if candidate in self.exact:
                suffix_length = max(suffix_length, length)
            if index > 0 and candidate in self.wildcards:
                suffix_length = max(suffix_length, length + 1)
        return ".".join(labels[-(suffix_length + 1):]) if len(labels) > suffix_length else None


def entropy(text):
    if not text:
        return 0.0
    return -sum((count / len(text)) * math.log2(count / len(text))
                for count in Counter(text).values())


def normalize_allowlist(domains):
    result = set()
    for domain in domains:
        name = domain.strip().lower().rstrip(".")
        if not name or any(not label or len(label) > 63 for label in name.split(".")):
            raise ValueError("Invalid allowlisted domain")
        if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-." for c in name):
            raise ValueError("Use ASCII/punycode domain names in the allowlist")
        result.add(name)
    return sorted(result)


def allowlisted(name, domains):
    return any(name == domain or name.endswith("." + domain) for domain in domains)


def summarize(observations, suffixes, config, allowlist=()):
    groups = defaultdict(list)
    excluded = Counter()
    ungroupable = 0
    for row in observations:
        if allowlisted(row["name"], allowlist):
            excluded[row["name"]] += 1
            continue
        domain = suffixes.registrable(row["name"])
        if domain is None or "\\" in row["name"]:
            ungroupable += 1
            continue
        groups[(row["client"], domain)].append(row)
    results = []
    for (client, domain), rows in sorted(groups.items()):
        rows.sort(key=lambda r: (r["timestamp"], r["packet"]))
        window, names = deque(), Counter()
        suspicious_window = 0
        best = None
        suspicious_total = 0
        max_entropy, max_length = 0.0, 0
        for row in rows:
            subdomain = row["name"][:-(len(domain) + 1)] if row["name"] != domain else ""
            labels = subdomain.split(".") if subdomain else []
            eligible = [label for label in labels if len(label) >= config.min_label_length]
            candidate_entropy = max((entropy(label) for label in eligible), default=0)
            length = max((len(label) for label in labels), default=0)
            suspicious = bool(eligible) and candidate_entropy >= config.min_entropy
            suspicious_total += suspicious
            max_entropy = max(max_entropy, candidate_entropy)
            max_length = max(max_length, length)
            while window and window[0][0]["timestamp"] < row["timestamp"] - config.window_seconds:
                previous, was_suspicious = window.popleft()
                if was_suspicious:
                    suspicious_window -= 1
                    names[previous["name"]] -= 1
                    if not names[previous["name"]]:
                        del names[previous["name"]]
            window.append((row, suspicious))
            if suspicious:
                suspicious_window += 1
                names[row["name"]] += 1
            fraction = suspicious_window / len(window)
            if len(names) >= config.min_unique and fraction >= config.min_suspicious_fraction:
                strength = (len(names), fraction)
                if best is None or strength > best["strength"]:
                    evidence = list(islice((item for item, flagged in window if flagged), 8))
                    best = {"strength": strength, "start": window[0][0]["timestamp"],
                            "end": row["timestamp"], "window_queries": len(window),
                            "unique_encoded_names": len(names), "suspicious_fraction": round(fraction, 4),
                            "packet_numbers": [item["packet"] for item in evidence],
                            "names": [item["name"] for item in evidence]}
        response_codes = Counter(str(row["rcode"]) for row in rows if row["rcode"] is not None)
        finding = bool(best)
        if best:
            best.pop("strength")
        results.append({"client": client, "domain": domain, "queries": len(rows),
                        "unique_names": len({row["name"] for row in rows}),
                        "long_encoded_queries": suspicious_total, "max_label_length": max_length,
                        "max_entropy_bits_per_character": round(max_entropy, 3),
                        "response_codes": dict(sorted(response_codes.items())),
                        "matched_responses": sum(response_codes.values()),
                        "status": "review" if finding else "no-pattern-flagged",
                        "evidence": best,
                        "explanation": (
                            f"At least {best['unique_encoded_names']} distinct names with long, high-entropy "
                            f"subdomain labels occur within {config.window_seconds:g}s; "
                            f"{best['suspicious_fraction']:.0%} of queries in that window meet the label criteria."
                            if finding else "The combined length, entropy, distinct-name and time-window thresholds were not met."),
                        "alternative_explanation": "Telemetry IDs, anti-abuse tokens, trackers or CDN traffic can produce similar labels."})
    results.sort(key=lambda row: (row["status"] != "review", -row["queries"], row["client"], row["domain"]))
    return results, sum(excluded.values()), ungroupable


def analyze(path, config=None, allowlist=(), suffixes=None):
    config = config or Config()
    allowlist = normalize_allowlist(allowlist)
    suffixes = suffixes or SuffixList()
    path = Path(path)
    gaps = Counter()
    observations, response_events = [], []
    count = dns_packets = queries = responses = 0
    examples = []
    with path.open("rb") as stream:
        import os
        before = os.fstat(stream.fileno())
        if before.st_size > config.max_file_mib * 1024 * 1024:
            raise ValueError("Capture exceeds configured file-size limit")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        stream.seek(0)
        try:
            for packet in packets(stream):
                if count >= config.max_packets:
                    gaps["Packet processing limit reached"] += 1
                    break
                count += 1
                try:
                    event = decode(packet)
                except ParseError as exc:
                    gaps[str(exc)] += 1
                    if len(examples) < 8:
                        examples.append({"packet": packet.number, "reason": str(exc)})
                    continue
                if event is None:
                    continue
                dns_packets += 1
                if event.response:
                    responses += 1
                else:
                    queries += 1
                for name, qtype, qclass in event.questions:
                    if len(observations) + len(response_events) >= config.max_questions:
                        gaps["DNS question processing limit reached"] += 1
                        break
                    if qclass != 1:
                        gaps["Non-IN DNS question not analyzed"] += 1
                        continue
                    client = event.destination if event.response else event.source
                    resolver = event.source if event.response else event.destination
                    client_port = event.destination_port if event.response else event.source_port
                    resolver_port = event.source_port if event.response else event.destination_port
                    row = {"name": name, "type": qtype, "client": client, "resolver": resolver,
                           "key": (client, client_port, resolver, resolver_port, event.transaction, name, qtype),
                           "packet": event.packet, "timestamp": event.timestamp,
                           "rcode": event.rcode if event.response else None}
                    (response_events if event.response else observations).append(row)
                else:
                    continue
                if "DNS question processing limit reached" in gaps:
                    break
        except ParseError as exc:
            gaps["Capture framing: " + str(exc)] += 1
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            gaps["Input changed while it was being read"] += 1
    # Pair one response with one observed question, using full endpoints,
    # transaction ID, name and type. Older identical requests are superseded.
    pending = {}
    ordered = [(r["timestamp"], r["packet"], False, r) for r in observations]
    ordered += [(r["timestamp"], r["packet"], True, r) for r in response_events]
    for _, _, response, row in sorted(ordered, key=lambda item: item[:3]):
        if not response:
            pending[row["key"]] = row
        else:
            request = pending.pop(row["key"], None)
            if request is not None and 0 <= row["timestamp"] - request["timestamp"] <= 30:
                request["rcode"] = row["rcode"]
    results, excluded, ungroupable = summarize(observations, suffixes, config, allowlist)
    if ungroupable:
        gaps["Question has no registrable domain or contains escaped wire labels"] += ungroupable
    flagged = sum(row["status"] == "review" for row in results)
    return {"schema_version": 1, "tool": "DNS Investigation Workbench", "input": path.name,
            "input_sha256": digest, "input_bytes": before.st_size, "config": asdict(config),
            "public_suffix_list": {"version": suffixes.version, "sha256": suffixes.sha256},
            "coverage": {"status": "limited" if gaps else "complete-for-supported-scope",
                         "packets_processed": count, "dns_packets": dns_packets,
                         "query_packets": queries, "response_packets": responses,
                         "questions_analyzed": len(observations), "allowlisted_questions": excluded,
                         "gaps": dict(sorted(gaps.items())), "examples": examples,
                         "scope": "UDP port 53 DNS over Ethernet/VLAN or raw IPv4/IPv6. No TCP DNS, IP reassembly, DoH, DoT or checksum verification."},
            "finding_count": flagged, "allowlist": allowlist, "groups": results,
            "verdict": "Review suggested" if flagged else "No configured patterns flagged in analyzed questions",
            "warning": "Heuristic evidence is not proof of a tunnel or absence of compromise. Synthetic demos do not establish real-world detection accuracy."}
