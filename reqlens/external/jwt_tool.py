"""jwt_tool, decode mode only, on a token *rebuilt from redacted data*.

jwt_tool (github.com/ticarpi/jwt_tool) is a Python script. reqlens runs it through a small
fixed wrapper that reads the token from stdin and hands it to jwt_tool in-process, so the
token never appears on a command line or in a process list. No target URL, scanning
(-M), tampering (-X), cracking (-C) or other mode is ever passed: jwt_tool only decodes.

The rebuilt token carries the redacted header and claims (identity values are already
fingerprints), a dummy signature, and ``jku``/``x5u`` pointed at a ``.invalid`` host so that
nothing derived from the capture could be fetched.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field

from reqlens.external import ToolStatus, locate, run_sandboxed
from reqlens.model import TokenRecord

ENV_VAR = "REQLENS_JWT_TOOL"
PYTHON_ENV_VAR = "REQLENS_JWT_TOOL_PYTHON"
NEUTRAL_URL = "https://reqlens-neutralised.invalid/"
DUMMY_SIGNATURE = "cmVxbGVucy1yZWRhY3RlZC1zaWduYXR1cmU"  # base64url("reqlens-redacted-signature")

WRAPPER = (
    "import os, runpy, sys\n"
    "token = sys.stdin.readline().strip()\n"
    "path = sys.argv[1]\n"
    "sys.argv = [path] + ([token] if token else ['-h'])\n"
    "sys.path.insert(0, os.path.dirname(os.path.abspath(path)))\n"
    "runpy.run_path(path, run_name='__main__')\n"
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_PLUS_LINE = re.compile(r"^\[\+\]\s*([\w-]+)\s*=\s*\"?(.*?)\"?\s*$")


@dataclass
class JwtToolResult:
    """What jwt_tool said about the rebuilt token."""

    header: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    problem: str = ""
    """Set when jwt_tool could not be run or its output not understood."""


def _b64url(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True, default=str).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def rebuild_token(record: TokenRecord) -> str:
    """A JWT made only of redacted parts, safe to show to a local tool."""
    header = dict(record.jwt_header)
    for key in ("jku", "x5u"):
        if key in header:
            header[key] = NEUTRAL_URL
    signature = DUMMY_SIGNATURE if record.format == "jwt" else ""
    return f"{_b64url(header)}.{_b64url(record.jwt_claims)}.{signature}"


def _interpreter() -> str:
    return os.environ.get(PYTHON_ENV_VAR) or sys.executable


def detect() -> ToolStatus:
    """Find jwt_tool.py (``REQLENS_JWT_TOOL`` or PATH) and read its version from ``-h``."""
    path = locate(ENV_VAR, "jwt_tool.py", "jwt_tool")
    if path is None:
        return ToolStatus("jwt_tool", False, "not found")
    if not path.lower().endswith(".py"):
        return ToolStatus(
            "jwt_tool",
            False,
            "found, but not as jwt_tool.py; set REQLENS_JWT_TOOL to the script so the token "
            "can be passed on stdin",
        )
    command = [_interpreter(), "-c", WRAPPER, path]
    result = run_sandboxed(command, stdin="\n", timeout=20)
    text = result.stdout + "\n" + result.stderr
    if result.timed_out:
        return ToolStatus("jwt_tool", False, "found but timed out on start-up")
    if "ModuleNotFoundError" in text or "ImportError" in text:
        return ToolStatus(
            "jwt_tool",
            False,
            f"found but its Python dependencies are missing for {_interpreter()}; set "
            f"{PYTHON_ENV_VAR} to the interpreter you use for jwt_tool",
        )
    match = re.search(r"[Vv]ersion[:\s]*v?(\d+(?:\.\d+)+)|jwt_tool[^\n]*?v(\d+(?:\.\d+)+)", text)
    version = next((g for g in match.groups() if g), None) if match else None
    return ToolStatus("jwt_tool", True, version or "present", command)


def parse_decode(output: str) -> JwtToolResult:
    """Read the header values and warnings from jwt_tool's decode output."""
    result = JwtToolResult()
    section = None
    for raw in output.splitlines():
        line = raw.strip()
        lowered = line.lower()
        if "token header values" in lowered:
            section = "header"
            continue
        if "token payload values" in lowered:
            section = "payload"
            continue
        match = _PLUS_LINE.match(line)
        if match and section == "header":
            result.header[match.group(1)] = match.group(2)[:120]
        elif line.startswith(("[-]", "[!]")) and len(result.notes) < 5:
            result.notes.append(line[:200])
    if not result.header:
        result.problem = (
            "jwt_tool ran but printed no header values (on its first run it only "
            "creates its config; run it once by hand)"
        )
    return result


def decode(status: ToolStatus, record: TokenRecord) -> JwtToolResult:
    """Decode the rebuilt token with jwt_tool (no target, no attack modes)."""
    if not status.available or status.command is None:
        return JwtToolResult(problem="jwt_tool not available")
    token = rebuild_token(record)
    if not _TOKEN_RE.fullmatch(token):
        return JwtToolResult(problem="rebuilt token was not well-formed; skipped")
    result = run_sandboxed(status.command, stdin=token + "\n", timeout=30)
    if result.timed_out:
        return JwtToolResult(problem="jwt_tool timed out")
    return parse_decode(result.stdout)
