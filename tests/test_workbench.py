import io
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

from dnsworkbench.analysis import Config, SuffixList, analyze, entropy, allowlisted
from dnsworkbench.capture import DNS, Packet, ParseError, decode, dns_message, dns_name, packets
from dnsworkbench.demo import frame, message, pcap, pcapng, records
from dnsworkbench.__main__ import main
from dnsworkbench.report import render


class WorkbenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suffixes = SuffixList()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def inspect_bytes(self, content, config=None, allowlist=()):
        path = self.root / "capture.pcap"
        path.write_bytes(content)
        return analyze(path, config, allowlist, self.suffixes)

    def query_rows(self, names, interval=1, client="192.0.2.10"):
        return [(100 + index * interval, frame(message(name, index), source=client))
                for index, name in enumerate(names)]

    def test_demo_flags_one_group_with_replayable_packet_evidence(self):
        report = self.inspect_bytes(pcap(records()))
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["coverage"]["status"], "complete-for-supported-scope")
        group = report["groups"][0]
        self.assertEqual(group["domain"], "example.test")
        self.assertEqual(group["matched_responses"], 24)
        self.assertEqual(group["response_codes"], {"3": 24})
        decoded = {packet.number: decode(packet) for packet in packets(io.BytesIO(pcap(records())))}
        for number, name in zip(group["evidence"]["packet_numbers"], group["evidence"]["names"]):
            self.assertEqual(decoded[number].questions[0][0], name)

    def test_all_classic_endian_and_timestamp_formats(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    rows = [(123.125, frame(message("www.example.test")))]
                    packet = list(packets(io.BytesIO(pcap(rows, endian, nano))))[0]
                    self.assertAlmostEqual(packet.timestamp, 123.125)
                    self.assertEqual(decode(packet).questions[0][0], "www.example.test")

    def test_pcapng_endian_decimal_binary_resolution_and_offset(self):
        for endian in ("<", ">"):
            for resolution in (6, 9, 128 + 10):
                with self.subTest(endian=endian, resolution=resolution):
                    packet = list(packets(io.BytesIO(pcapng([(123.125, frame(message("a.test")))], endian, resolution, 100))))[0]
                    self.assertAlmostEqual(packet.timestamp, 123.125)
                    self.assertEqual(decode(packet).questions[0][0], "a.test")

    def test_pcapng_sections_reset_byte_order_and_interfaces(self):
        content = pcapng([(1, frame(message("a.test")))], "<")
        content += pcapng([(2, frame(message("b.test")))], ">")
        parsed = list(packets(io.BytesIO(content)))
        self.assertEqual([p.number for p in parsed], [1, 2])
        self.assertEqual([p.timestamp for p in parsed], [1, 2])

    def test_vlan_and_ipv6_and_raw_ip(self):
        variants = [frame(message("a.test"), vlan=True),
                    frame(message("a.test"), source="2001:db8::10", destination="2001:db8::53", ipv6=True)]
        for data in variants:
            event = decode(Packet(1, 1, 1, data, len(data)))
            self.assertEqual(event.questions[0][0], "a.test")
        data = variants[1][14:]
        self.assertIsInstance(decode(Packet(1, 1, 229, data, len(data))), DNS)

    def test_snapshot_truncation_is_a_coverage_gap(self):
        data = frame(message("a.test"))
        content = pcap([(1, data)])
        content = content[:36] + struct.pack("<I", len(data) + 1) + content[40:]
        report = self.inspect_bytes(content)
        self.assertEqual(report["coverage"]["status"], "limited")
        self.assertIn("Snapshot-truncated packet", report["coverage"]["gaps"])

    def test_truncated_container_retains_prior_evidence_and_marks_limited(self):
        report = self.inspect_bytes(pcap(records()) + b"\0")
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["coverage"]["status"], "limited")
        self.assertIn("Capture framing: Truncated PCAP packet header", report["coverage"]["gaps"])

    def test_oversize_records_rejected_before_allocation(self):
        content = pcap([]) + struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF)
        with self.assertRaises(ParseError):
            list(packets(io.BytesIO(content)))

    def test_block_footer_mismatch(self):
        content = pcapng([(1, frame(message("a.test")))])
        report = self.inspect_bytes(content[:-4] + b"\0" * 4)
        self.assertEqual(report["coverage"]["status"], "limited")
        self.assertTrue(any("disagree" in key for key in report["coverage"]["gaps"]))

    def test_invalid_pcapng_interface(self):
        content = bytearray(pcapng([(1, frame(message("a.test")))]))
        interface_block_length = struct.unpack_from("<I", content, 28 + 4)[0]
        struct.pack_into("<I", content, 28 + interface_block_length + 8, 999)
        report = self.inspect_bytes(bytes(content))
        self.assertIn("Capture framing: Unknown PCAPNG interface", report["coverage"]["gaps"])

    def test_compressed_question_and_resource_record(self):
        header = struct.pack("!6H", 1, 0x8180, 2, 1, 0, 0)
        name = b"\x03www\x07example\x04test\0"
        question = name + struct.pack("!HH", 1, 1)
        second = b"\xc0\x0c" + struct.pack("!HH", 28, 1)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 10, 4) + b"\xc0\0\x02\x01"
        result = dns_message(header + question + second + answer)
        self.assertEqual(result[-1], (("www.example.test", 1, 1), ("www.example.test", 28, 1)))

    def test_pointer_cycle_forward_and_header_pointers_rejected(self):
        for content in (b"\xc0\x0c", b"\xc0\xff", b"\xc0\0"):
            with self.subTest(content=content), self.assertRaises(ParseError):
                dns_name(b"\0" * 12 + content, 12)

    def test_dns_name_overflow(self):
        content = b"\0" * 12 + (b"\x3f" + b"a" * 63) * 4 + b"\0"
        with self.assertRaises(ParseError):
            dns_name(content, 12)

    def test_resource_record_truncation_not_silently_accepted(self):
        content = bytearray(message("a.test", response=True))
        struct.pack_into("!H", content, 6, 1)
        with self.assertRaises(ParseError):
            dns_message(content)

    def test_dns_truncated_flag_is_gap(self):
        content = bytearray(message("a.test"))
        content[2] |= 2
        report = self.inspect_bytes(pcap([(1, frame(content))]))
        self.assertIn("DNS truncated-message flag is set", report["coverage"]["gaps"])

    def test_unsupported_link_does_not_produce_clean_coverage(self):
        report = self.inspect_bytes(pcap([(1, frame(message("a.test")))], linktype=127))
        self.assertEqual(report["coverage"]["status"], "limited")
        self.assertEqual(report["finding_count"], 0)

    def test_fragments_and_tcp_dns_are_explicit(self):
        for offset, value, reason in [(20, b"\x20\0", "Fragmented IPv4"), (23, b"\x06", "TCP DNS")]:
            data = bytearray(frame(message("a.test")))
            data[offset:offset + len(value)] = value
            report = self.inspect_bytes(pcap([(1, data)]))
            self.assertTrue(any(key.startswith(reason) for key in report["coverage"]["gaps"]))

    def test_packet_and_question_limits_visible(self):
        for config in (Config(max_packets=5), Config(max_questions=5)):
            report = self.inspect_bytes(pcap(records()), config)
            self.assertEqual(report["coverage"]["status"], "limited")
            self.assertTrue(any("limit" in gap for gap in report["coverage"]["gaps"]))

    def test_file_limit_before_processing(self):
        path = self.root / "large.pcap"
        path.write_bytes(b"0" * (1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            analyze(path, Config(max_file_mib=1), suffixes=self.suffixes)

    def test_allowlist_is_label_bounded_and_visible(self):
        self.assertTrue(allowlisted("a.good.test", ["good.test"]))
        self.assertFalse(allowlisted("notgood.test", ["good.test"]))
        report = self.inspect_bytes(pcap(records()), allowlist=["EXAMPLE.TEST."])
        self.assertEqual(report["finding_count"], 0)
        self.assertEqual(report["coverage"]["allowlisted_questions"], 24)

    def test_psl_private_multi_label_wildcard_exception_and_idn(self):
        expected = {"x.owner.github.io": "owner.github.io", "a.school.co.uk": "school.co.uk",
                    "www.city.kawasaki.jp": "city.kawasaki.jp", "a.b.ck": "a.b.ck",
                    "a.www.ck": "www.ck", "co.uk": None, "localhost": None,
                    "x.xn--85x722f.xn--55qx5d.cn": "xn--85x722f.xn--55qx5d.cn"}
        for name, domain in expected.items():
            with self.subTest(name=name):
                self.assertEqual(self.suffixes.registrable(name), domain)

    def test_repeated_random_token_benign_control_not_flagged(self):
        name = "0123456789abcdef0123456789abcdef0123456789abcdef.metrics.test"
        report = self.inspect_bytes(pcap(self.query_rows([name] * 40)))
        self.assertEqual(report["finding_count"], 0)

    def test_many_short_benign_names_not_flagged(self):
        report = self.inspect_bytes(pcap(self.query_rows([f"host{i}.school.test" for i in range(100)])))
        self.assertEqual(report["finding_count"], 0)

    def test_many_long_low_entropy_names_not_flagged(self):
        report = self.inspect_bytes(pcap(self.query_rows(["a" * 40 + str(i) + ".service.test" for i in range(30)])))
        self.assertEqual(report["finding_count"], 0)

    def test_legitimate_unique_tokens_can_be_false_positive(self):
        import hashlib
        names = [hashlib.sha256(str(i).encode()).hexdigest()[:48] + ".metrics.service.test" for i in range(24)]
        report = self.inspect_bytes(pcap(self.query_rows(names)))
        self.assertEqual(report["finding_count"], 1)
        self.assertIn("Telemetry", report["groups"][0]["alternative_explanation"])

    def test_slow_or_distributed_names_do_not_cross_time_or_client_boundaries(self):
        import hashlib
        names = [hashlib.sha256(str(i).encode()).hexdigest()[:48] + ".channel.test" for i in range(24)]
        report = self.inspect_bytes(pcap(self.query_rows(names, interval=61)))
        self.assertEqual(report["finding_count"], 0)
        rows = self.query_rows(names[:8], client="192.0.2.10") + self.query_rows(names[8:16], client="192.0.2.20")
        self.assertEqual(self.inspect_bytes(pcap(rows))["finding_count"], 0)

    def test_out_of_order_capture_is_sorted_for_analysis(self):
        normal = self.inspect_bytes(pcap(records()))
        reverse = self.inspect_bytes(pcap(list(reversed(records()))))
        self.assertEqual(normal["finding_count"], reverse["finding_count"])
        self.assertEqual(normal["groups"][0]["matched_responses"], reverse["groups"][0]["matched_responses"])

    def test_response_pairing_checks_full_endpoints_not_only_transaction(self):
        query = frame(message("a.test", 1), sport=45001)
        wrong = frame(message("a.test", 1, True, 3), source="192.0.2.54", destination="192.0.2.10", sport=53, dport=45001)
        report = self.inspect_bytes(pcap([(1, query), (1.1, wrong)]))
        self.assertEqual(report["groups"][0]["matched_responses"], 0)

    def test_input_unchanged_and_outputs_cannot_overwrite(self):
        source = self.root / "source.pcap"
        data = pcap(records())
        source.write_bytes(data)
        report = self.root / "report.json"
        self.assertEqual(main(["analyze", str(source), "--json", str(report)]), 1)
        self.assertEqual(source.read_bytes(), data)
        before = report.read_bytes()
        self.assertEqual(main(["analyze", str(source), "--json", str(report)]), 2)
        self.assertEqual(report.read_bytes(), before)
        self.assertEqual(main(["analyze", str(source), "--html", str(source)]), 2)
        self.assertEqual(source.read_bytes(), data)

    def test_deterministic_reports(self):
        first = self.inspect_bytes(pcap(records()))
        second = self.inspect_bytes(pcap(records()))
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(render(first), render(second))

    def test_untrusted_strings_are_escaped_in_html(self):
        report = self.inspect_bytes(pcap(records()))
        report["input"] = '<img src=x onerror="alert(1)">'
        report["groups"][0]["domain"] = "</script><script>alert(1)</script>"
        report["groups"][0]["evidence"]["names"][0] = "<svg onload=alert(1)>"
        output = render(report)
        self.assertNotIn('<img src=x', output)
        self.assertNotIn('</script><script>alert', output)
        self.assertNotIn('<svg onload', output)
        self.assertIn('&lt;img', output)

    def test_threshold_validation(self):
        for changes in ({"window_seconds": float("nan")}, {"min_entropy": float("inf")},
                        {"min_unique": 0}, {"max_packets": -1}, {"min_suspicious_fraction": 0}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                Config(**changes)

    def test_entropy_character_distribution(self):
        self.assertEqual(entropy("aaaa"), 0)
        self.assertEqual(entropy("abcd"), 2)

    def test_randomized_untrusted_bytes_do_not_escape_parser_contract(self):
        rng = random.Random(723)
        for _ in range(500):
            content = rng.randbytes(rng.randrange(0, 250))
            try:
                dns_message(content)
            except ParseError:
                pass
            try:
                decode(Packet(1, 1, rng.choice([1, 101, 228, 229]), content, len(content)))
            except ParseError:
                pass

    @unittest.skipUnless(shutil.which("tshark"), "Optional independent oracle: tshark is not installed")
    def test_independent_tshark_question_names_and_checksums(self):
        path = self.root / "oracle.pcapng"
        path.write_bytes(pcapng(records()))
        run = subprocess.run([shutil.which("tshark"), "-r", str(path), "-n",
                              "-o", "udp.check_checksum:true", "-o", "ip.check_checksum:true",
                              "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        independent = run.stdout.splitlines()
        native = [decode(p).questions[0][0] for p in packets(io.BytesIO(path.read_bytes())) if not decode(p).response]
        self.assertEqual(independent, native)
        bad = subprocess.run([shutil.which("tshark"), "-r", str(path), "-n",
                              "-o", "udp.check_checksum:true", "-o", "ip.check_checksum:true",
                              "-Y", "udp.checksum.status == 0 || ip.checksum.status == 0 || _ws.malformed",
                              "-T", "fields", "-e", "frame.number"], capture_output=True, text=True, timeout=30)
        self.assertEqual(bad.returncode, 0, bad.stderr)
        self.assertEqual(bad.stdout.strip(), "")
        rewritten = self.root / "tshark-written.pcapng"
        transcode = subprocess.run([shutil.which("tshark"), "-r", str(path), "-n", "-w", str(rewritten)],
                                   capture_output=True, text=True, timeout=30)
        self.assertEqual(transcode.returncode, 0, transcode.stderr)
        native_report = analyze(path, suffixes=self.suffixes)
        rewritten_report = analyze(rewritten, suffixes=self.suffixes)
        self.assertEqual(native_report["groups"], rewritten_report["groups"])
        self.assertEqual(rewritten_report["coverage"]["status"], "complete-for-supported-scope")


if __name__ == "__main__":
    unittest.main()
