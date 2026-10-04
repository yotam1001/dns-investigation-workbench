# DNS Investigation Workbench

**Follow suspicious DNS query patterns back to packet evidence.** Analyze a saved PCAP or PCAPNG locally, then open a self-contained report showing which client/domain groups deserve review and why.

The workbench combines long, high-entropy subdomain labels with distinct-name counts in a sliding time window. Every signal includes thresholds, packet numbers, example names and alternative explanations. Malformed input, missing supported coverage and processing limits remain visible.

**[Open the synthetic example report](docs/index.html)** · [Parser](dnsworkbench/capture.py) · [Detection logic](dnsworkbench/analysis.py) · [Regression tests](tests/test_workbench.py)

## Try it in one minute

Requires Python 3.11 or later. No third-party runtime packages, administrator access, account or API key.

From this repository:

```sh
python -m dnsworkbench demo
```

Open `demo-output/report.html`. The command creates an ordinary packet-capture file and analyzes it through the same parser as real input. It does **not** capture or transmit network traffic.

The deterministic demo contains:

- 24 distinct encoded-looking names under `example.test`, generating one review signal.
- Ordinary school/application lookups that stay below the thresholds.
- Repeated long telemetry tokens that do not trigger because they have low distinct-name counts.
- Different `github.io` tenants that remain separate because the Public Suffix List includes private suffixes.
- Paired DNS responses with valid IP/UDP checksums. Documentation/test addresses and reserved test domains are used.

The demo is synthetic. It establishes reproducibility, not real-world accuracy. Tests also include legitimate-looking unique telemetry IDs that **do** trigger a false positive; their behavior is documented rather than hidden.

## Inspect a capture

```sh
python -m dnsworkbench analyze capture.pcapng --html report.html --json report.json
```

Source captures are opened read-only. Output files must be new; existing files are never overwritten. The report works offline, contains no external assets or analytics, and has keyboard-accessible evidence panels and group filters.

Tune the analysis explicitly:

```sh
python -m dnsworkbench analyze capture.pcap --window 120 --min-unique 20 --min-label 24 --entropy 3.7 --allow-domain known-service.test --html review.html
```

An allowlisted domain and its subdomains are excluded; a mere string suffix such as `notknown-service.test` is not. Exclusions and counts appear in the report. The allowlist is empty by default.

Exit codes: `0` means no configured pattern was flagged in the supported analyzed scope; `1` means review signals were found; `2` means an error or coverage limitation. Coverage limitations take precedence over review signals. Neither `0` nor `1` establishes whether the network is compromised. `demo` returns `0` after successful artifact generation.

## Engineering details

- **Binary parsing:** classic PCAP in both byte orders and micro/nanosecond resolutions; PCAPNG section byte order, interface timestamp resolution/offset and Enhanced Packet Blocks. Section changes reset interface state. Inconsistent lengths and oversized records are rejected before payload allocation.
- **Network decoding:** Ethernet, up to four VLAN tags, raw IP, IPv4 and IPv6 UDP port 53. IPv6 hop-by-hop, routing and destination-options headers have a bounded traversal.
- **DNS:** length-bounded labels, backwards compression pointers, loop detection, question and resource-record framing. Record data is not interpreted; this version examines question names and basic header RCODEs.
- **Domain boundaries:** bundled Public Suffix List with exact, wildcard, exception, IDN and PRIVATE rules. Different clients and tenants are not combined into one detection window.
- **Analysis:** Shannon label entropy plus length, distinct-name counts and a minimum suspicious-query fraction. Sorted capture timestamps allow out-of-order packet records. Response pairing checks both endpoints/ports, transaction ID, name, type and a 30-second interval.
- **Reproducibility:** JSON includes all thresholds, input SHA-256, parser coverage and the PSL version/hash. The same input and configuration produce identical JSON and HTML on the same Python runtime. Exact float serialization across Python versions is not promised.
- **Bounded work:** defaults are 128 MiB input, 250,000 inspected packets, 100,000 retained query/response questions and 16 MiB per record. Limits are configurable and limit hits are reported. HTML displays at most 200 review cards and 500 group rows; JSON retains all analyzed group summaries. Parsing streams packets, while correlation/analysis retains bounded observations in memory.

## Limits and interpretation

This is a small offline investigation companion, not a replacement for Wireshark, Zeek or a production IDS.

It does not support live capture, DNS over TCP, DoH/DoT, IP fragment reassembly, IPv6 jumbograms, all IPv6 extension types, non-Ethernet capture link layers such as Wi-Fi radiotap/Linux cooked capture, or legacy/simple PCAPNG packet blocks. It does not verify incoming checksums, decode answer RDATA or extended EDNS response codes, reconstruct payloads, resolve names, consult threat-intelligence services or block traffic.

High-entropy labels can be legitimate tracking/telemetry IDs. Low-rate tunnels, short labels, small captures and encrypted DNS can evade this heuristic. Capture placement, dropped packets and timestamp quality affect what can be inferred. No detection-rate claim has been established against real attack traffic.

Response matching uses the latest observed identical query, without counting a response twice. Retries can therefore leave older query observations unmatched. A response observed before its query timestamp is not paired. Missing responses do not prove failure or malicious activity.

Input hashes identify the bytes read for hashing; hashing and parsing are separate reads, not an atomic snapshot. Changes to input size/mtime during analysis are reported, but an adversarial same-size rewrite that restores timestamps may evade that check. Analyze a stable copy when evidence integrity matters.

## Verify

```sh
python -m unittest discover -s tests -v
python -m compileall -q dnsworkbench tests
```

Tests cover capture formats, timestamp units, DNS compression, malformed/truncated input, resource limits, private suffixes, benign controls, known false positives, time/client separation, source preservation, output refusal and report escaping.

If `tshark` is on PATH, an additional independent test compares parsed query names against Wireshark and checks the generated packets for malformed data and bad IP/UDP checksums. That test is explicitly skipped when unavailable. See [VALIDATION.md](docs/VALIDATION.md) for executed results.

## Privacy and attribution

Real reports contain observed client addresses and queried domain names. Keep them private or inspect them before sharing. The public example is generated entirely from synthetic data. No personal captures are included.

The project was developed with Codex assistance. Validation and limitations are recorded so reviewers can inspect the implementation, not rely on unsupported claims of authorship or detection quality.

Original source code: [MIT](LICENSE). Bundled Public Suffix List: Mozilla Public License 2.0; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).
