# Third-party material

`dnsworkbench/data/public_suffix_list.dat` is an unmodified snapshot downloaded
from https://publicsuffix.org/list/public_suffix_list.dat on 4 October 2026.

- Version: `2026-10-01_23-02-52_UTC`.
- Upstream commit: `6cd82aff889e3d64e5e03bc5c1f43da1934a960a`.
- Source: https://github.com/publicsuffix/list.
- License: Mozilla Public License 2.0, retained in the data file's header and
  distributed in `dnsworkbench/data/MPL-2.0.txt`.
- The original DNS Workbench implementation is MIT licensed separately.

The list is used offline. Runtime analysis never downloads updates. Refresh it
deliberately, preserve its license and update this notice when its version changes.

Format references (no code copied): [DNS RFC 1035](https://www.rfc-editor.org/rfc/rfc1035),
[PCAP format draft](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-02.html),
[PCAPNG format draft](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html),
and [PSL matching rules](https://github.com/publicsuffix/list/wiki/Format).
The capture-format references are Internet-Drafts, not final standards.
