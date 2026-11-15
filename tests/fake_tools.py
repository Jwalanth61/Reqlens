"""Fake stand-ins for hashcat and jwt_tool. Each logs exactly what it received (arguments,
working directory contents, environment variable names, input) as JSON lines next to itself,
so tests can prove what reqlens handed to an external tool."""

from __future__ import annotations

import json
from pathlib import Path

FAKE_HASHCAT = r"""
import json, os, sys
from pathlib import Path
log = Path(__file__).with_suffix(".log")
args = sys.argv[1:]
entry = {"argv": args, "cwd": os.getcwd(), "listing": sorted(os.listdir()),
         "env": sorted(os.environ)}
if "--identify" in args:
    entry["sample"] = Path(args[-1]).read_text(encoding="utf-8")
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(entry) + "\n")
if args == ["--version"]:
    print("v6.2.6")
    sys.exit(0)
sample = entry.get("sample", "").strip()
if sample.startswith("$2"):
    rows = [(3200, "bcrypt $2*$, Blowfish (Unix)", "Operating System")]
elif len(sample) == 32:
    rows = [(900, "MD4", "Raw Hash"), (0, "MD5", "Raw Hash"), (1000, "NTLM", "Operating System")]
else:
    print("No hash-mode match found.")
    sys.exit(0)
print("The following hash-modes match the structure of your input hash:\n")
print("      # | Name                                     | Category")
print("  ======+==========================================+==================")
for mode, name, category in rows:
    print(f"  {mode:>5} | {name:<40} | {category}")
"""

FAKE_JWT_TOOL = r"""
import base64, json, os, sys
from pathlib import Path
log = Path(__file__).with_suffix(".log")
arg = sys.argv[1] if len(sys.argv) > 1 else ""
entry = {"argv": sys.argv[1:], "cwd": os.getcwd(), "listing": sorted(os.listdir()),
         "env": sorted(os.environ)}
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(entry) + "\n")
if arg == "-h":
    print("jwt_tool  Version 2.2.7  \x1b[32m(colour)\x1b[0m")
    sys.exit(0)
def part(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
header_b64, payload_b64, _ = arg.split(".")
print("Token header values:")
for key, value in part(header_b64).items():
    print(f'[+] {key} = "{value}"')
print("Token payload values:")
for key, value in part(payload_b64).items():
    print(f"[+] {key} = {value}")
print("[-] Signature verification not performed (no key)")
"""


def install(directory: Path) -> tuple[Path, Path]:
    """Write both fakes into ``directory``; return (hashcat_path, jwt_tool_path)."""
    hashcat = directory / "fake_hashcat.py"
    jwt_tool = directory / "jwt_tool.py"
    hashcat.write_text(FAKE_HASHCAT, encoding="utf-8")
    jwt_tool.write_text(FAKE_JWT_TOOL, encoding="utf-8")
    return hashcat, jwt_tool


def read_log(tool: Path) -> list[dict]:
    """Every invocation the fake recorded."""
    log = tool.with_suffix(".log")
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
