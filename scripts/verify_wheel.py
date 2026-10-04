"""Verify the built package without installing anything globally."""

from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def main():
    wheel = next(Path("dist").glob("*.whl"))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            for required in ("dnsworkbench/data/public_suffix_list.dat", "dnsworkbench/data/MPL-2.0.txt"):
                if required not in names:
                    raise RuntimeError("Missing packaged data: " + required)
            for name in names:
                if "__pycache__" in name or name.startswith("tests/"):
                    raise RuntimeError("Unexpected development artifact in wheel")
                if not (root / name).resolve().is_relative_to(root.resolve()):
                    raise RuntimeError("Unsafe archive path")
            archive.extractall(root)
        command = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from dnsworkbench.__main__ import main; "
            "raise SystemExit(main(['demo', '--output', 'wheel-demo']))"
        )
        result = subprocess.run([sys.executable, "-I", "-c", command, str(root)],
                                cwd=root, capture_output=True, text=True, timeout=30)
        if result.returncode or not (root / "wheel-demo/report.html").is_file():
            raise RuntimeError(result.stderr or "Packaged demo failed")
        print("Wheel contents and demo execution verified outside source tree.")


if __name__ == "__main__":
    main()
