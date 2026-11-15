"""hashcat, identification only: ``hashcat --identify`` on a *synthetic* sample.

reqlens never gives hashcat a captured value. It builds a sample with the same shape as the
captured one (e.g. 32 hex characters, or a bcrypt-shaped string) and asks hashcat which hash
modes match that structure. No cracking mode is ever started.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from reqlens.external import ToolStatus, command_for, locate, run_sandboxed

ENV_VAR = "REQLENS_HASHCAT"
MAX_MODES = 12
_HEX = "0123456789abcdef"
_BCRYPT = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_MODE_LINE = re.compile(r"^\s*(\d+)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*$")


@dataclass(frozen=True)
class HashMode:
    """One hashcat mode that matches a sample's structure."""

    mode: int
    name: str
    category: str


def _cycle(alphabet: str, length: int) -> str:
    return (alphabet * (length // len(alphabet) + 1))[:length]


def sample_for_format(fmt: str) -> str | None:
    """A made-up value with the same structure as format ``fmt`` (``None`` if unsupported)."""
    match = re.fullmatch(r"hex:(\d+)", fmt)
    if match and 16 <= int(match.group(1)) <= 256:
        return _cycle(_HEX, int(match.group(1)))
    samples = {
        "bcrypt": "$2b$12$" + _cycle(_BCRYPT, 53),
        "sha512-crypt": "$6$reqlenssalt$" + _cycle(_BCRYPT, 86),
        "sha256-crypt": "$5$reqlenssalt$" + _cycle(_BCRYPT, 43),
        "md5-crypt": "$1$reqlenss$" + _cycle(_BCRYPT, 22),
        "apr1-md5": "$apr1$reqlenss$" + _cycle(_BCRYPT, 22),
        "django-pbkdf2-sha256": "pbkdf2_sha256$260000$reqlenssalt$" + _cycle(_B64, 43) + "=",
        "ldap-ssha": "{SSHA}" + _cycle(_B64, 32),
        "ldap-sha": "{SHA}" + _cycle(_B64, 27) + "=",
    }
    return samples.get(fmt)


def detect() -> ToolStatus:
    """Find hashcat and read its version (``hashcat --version``)."""
    path = locate(ENV_VAR, "hashcat", "hashcat.exe", "hashcat.bin")
    if path is None:
        return ToolStatus("hashcat", False, "not found")
    command = command_for(path)
    result = run_sandboxed(command + ["--version"], timeout=15)
    match = re.search(r"v?\d+\.\d+(?:\.\d+)?[\w.+-]*", result.stdout)
    if result.timed_out or result.returncode is None:
        return ToolStatus(
            "hashcat", False, f"found but did not start ({result.stderr or 'timeout'})"
        )
    return ToolStatus("hashcat", True, match.group(0) if match else "present", command)


def parse_identify(output: str) -> list[HashMode]:
    """Parse the mode table printed by ``hashcat --identify``."""
    modes = []
    for line in output.splitlines():
        match = _MODE_LINE.match(line)
        if match and not match.group(2).strip().startswith("Name"):
            modes.append(HashMode(int(match.group(1)), match.group(2), match.group(3)))
    return modes[:MAX_MODES]


def identify_format(status: ToolStatus, fmt: str) -> list[HashMode] | None:
    """Modes hashcat considers possible for format ``fmt``; ``None`` if it couldn't tell."""
    sample = sample_for_format(fmt)
    if not status.available or status.command is None or sample is None:
        return None
    result = run_sandboxed(
        status.command + ["--identify", "{box}/sample.hash"],
        files={"sample.hash": sample + "\n"},
        timeout=30,
    )
    if result.timed_out:
        return None
    return parse_identify(result.stdout)
