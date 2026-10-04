# Contributing

Use Python 3.11+. Run `python -m unittest discover -s tests -v` before submitting a change.
Add a small regression fixture generated in code for parser or detection changes.
Do not attach private captures, real DNS logs, credentials or client identifiers.

Keep false positives, unsupported formats and coverage gaps explicit. New protocol
support needs both malformed-input coverage and comparison with an independent
decoder such as tshark. Tests that need tshark must skip clearly when it is absent.

Describe what was verified, what was not and any AI assistance used. Do not claim
real-world detection accuracy from synthetic examples.
