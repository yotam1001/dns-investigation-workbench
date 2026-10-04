# Executed validation

Checked 4 October 2026 on Windows with Python 3.12.10 and TShark 4.6.8.

- `python -m unittest discover -s tests -v`: **35 tests passed**.
- The optional independent tshark test ran, rather than skipping: all 89 generated
  query names agreed with tshark, and the generated capture had no packets matching
  bad IP checksum, bad UDP checksum or malformed-packet filters.
  A PCAPNG file rewritten by tshark produced identical grouped analysis results.
- `python -m compileall -q dnsworkbench tests`: passed.
- The Python wheel was built in pip's temporary isolated build environment. Its
  bundled package and PSL/license data were inspected and its demo was executed
  from an extracted wheel outside the source tree. No global dependency install
  was needed.
- `python -m dnsworkbench demo`: generated 178 packets / 89 query questions, one
  review group, 19 total groups and no supported-parser gaps. Generated report and
  JSON identify the data as synthetic.
- Browser inspection: the example report rendered; the Review signals filter
  displayed one table row, No pattern flagged displayed 18, and the packet evidence
  panel opened successfully. No external report assets are used.
- One local synthetic throughput sample: 25,000 repeated ordinary DNS questions
  were processed in 0.509 seconds, with no review signals or parser gaps. This is
  a single warm local measurement including hashing/parsing/analysis, not a portable
  performance guarantee or a memory benchmark.

## What this does not establish

No live traffic was captured, and no actual DNS tunneling tool was run. There is
no real-world detection-rate estimate, penetration-test result or production
deployment claim. Legitimate diverse telemetry IDs intentionally trigger the
heuristic in a regression test. Slow/distributed traffic intentionally stays below
the default thresholds in other tests.

Cross-platform CI is configured for Windows, Linux and macOS on Python 3.11 and
3.13, but has not run on GitHub because this project has not been published.
The optional tshark oracle can be skipped on machines without tshark; its skip
is visible in test output. Parser smoke fuzzing uses 500 seeded random inputs,
not exhaustive fuzzing or a claim of memory/resource safety under every input.
