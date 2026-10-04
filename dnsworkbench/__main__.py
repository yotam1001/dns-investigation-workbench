import argparse
import json
from pathlib import Path
import sys

from .analysis import Config, analyze
from .demo import pcap, records
from .report import render


def write_new(path, content):
    path = Path(path)
    mode = "xb" if isinstance(content, bytes) else "x"
    kwargs = {} if mode == "xb" else {"encoding": "utf-8", "newline": "\n"}
    with path.open(mode, **kwargs) as stream:
        stream.write(content)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline UDP DNS evidence analysis. No capture, blocking or network requests.")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Generate synthetic traffic and its reproducible report")
    demo.add_argument("--output", type=Path, default=Path("demo-output"))
    inspect = commands.add_parser("analyze", help="Inspect a local PCAP/PCAPNG; source files are read only")
    inspect.add_argument("capture", type=Path)
    inspect.add_argument("--html", type=Path)
    inspect.add_argument("--json", type=Path)
    inspect.add_argument("--allow-domain", action="append", default=[], help="Exact domain and its subdomains, ASCII/punycode")
    inspect.add_argument("--window", type=float, default=60)
    inspect.add_argument("--min-unique", type=int, default=10)
    inspect.add_argument("--min-label", type=int, default=20)
    inspect.add_argument("--entropy", type=float, default=3.5)
    inspect.add_argument("--max-packets", type=int, default=250_000)
    inspect.add_argument("--max-questions", type=int, default=100_000)
    inspect.add_argument("--max-file-mib", type=int, default=128)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            args.output.mkdir(parents=True, exist_ok=False)
            capture = args.output / "synthetic-dns.pcap"
            write_new(capture, pcap(records()))
            report = analyze(capture)
            report["synthetic_demo"] = True
            write_new(args.output / "report.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
            write_new(args.output / "report.html", render(report, demo=True))
            print("Synthetic demo: " + str(args.output / "report.html"))
            return 0
        outputs = [p for p in (args.html, args.json) if p is not None]
        if len({p.resolve() for p in outputs}) != len(outputs):
            raise ValueError("HTML and JSON output paths must differ")
        for output in outputs:
            if output.resolve() == args.capture.resolve() or output.exists() or output.is_symlink():
                raise ValueError("Output must be a new file, different from the input: " + str(output))
        config = Config(window_seconds=args.window, min_unique=args.min_unique,
                        min_label_length=args.min_label, min_entropy=args.entropy,
                        max_packets=args.max_packets, max_questions=args.max_questions,
                        max_file_mib=args.max_file_mib)
        report = analyze(args.capture, config, args.allow_domain)
        if args.html:
            write_new(args.html, render(report))
        if args.json:
            write_new(args.json, json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(report["verdict"])
        print(f"{report['coverage']['questions_analyzed']} questions; {report['finding_count']} review groups; coverage {report['coverage']['status']}")
        return 2 if report["coverage"]["gaps"] else 1 if report["finding_count"] else 0
    except (OSError, ValueError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
