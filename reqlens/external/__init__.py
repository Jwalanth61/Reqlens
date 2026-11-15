"""Optional external tools (jwt_tool, hashcat). reqlens works fully without them.

Safety model
------------
* Tools never receive captured secrets. They get *redacted shapes* only: a JWT rebuilt
  from the redacted header and claims (dummy signature, key URLs neutralised), or a
  synthetic sample with the same format as a captured hash.
* No shell is ever used. Captured-derived content is passed on stdin or in a file inside a
  fresh, empty temporary directory that is also the tool's working directory, and that
  directory is deleted afterwards.
* The tool's environment is reduced to what a program needs to start (PATH, system and
  profile folders); API keys and every other variable are dropped.
* Tools are never installed, updated, or pointed at a target. Only identification modes
  are used (hashcat ``--identify``, jwt_tool plain decode).

reqlens cannot OS-sandbox a child process: a tool runs with your user's permissions. That is
why it is only ever given redacted data.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from reqlens.sanitize import clean_text, truncate

MAX_OUTPUT_CHARS = 200_000
_ENV_KEEP = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "LANG",
    "LC_ALL",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
)


@dataclass
class ToolStatus:
    """Whether an optional tool is usable in this run."""

    name: str
    available: bool
    detail: str
    """Version string when available; otherwise why not ('not found', 'disabled', ...)."""
    command: list[str] | None = None
    """Command prefix used to run it (no shell)."""

    @property
    def label(self) -> str:
        """Short text for reports, e.g. ``v6.2.6`` or ``not found``."""
        return self.detail


@dataclass
class RunResult:
    """Outcome of one sandboxed tool run (output already sanitised)."""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


def minimal_env(box: str) -> dict[str, str]:
    """Environment for a child tool: start-up essentials only; temp dirs point to ``box``."""
    env = {key: os.environ[key] for key in _ENV_KEEP if key in os.environ}
    env.update(
        {
            "TEMP": box,
            "TMP": box,
            "TMPDIR": box,
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_COLOR": "1",
            "TERM": "dumb",
        }
    )
    return env


def command_for(path: str) -> list[str]:
    """How to start a tool at ``path`` without a shell (Python scripts via this interpreter)."""
    if path.lower().endswith(".py"):
        return [sys.executable, path]
    return [path]


def locate(env_var: str, *names: str) -> str | None:
    """Find a tool: the ``env_var`` override first, then ``PATH``."""
    override = os.environ.get(env_var)
    if override:
        return override if Path(override).is_file() else None
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def run_sandboxed(
    argv: list[str],
    *,
    stdin: str | None = None,
    files: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> RunResult:
    """Run ``argv`` (no shell) in a fresh empty directory with a minimal environment.

    ``files`` are written into that directory first; ``{box}`` in any argument is replaced
    with the directory path. Output is decoded leniently, sanitised and size-limited.
    """
    with tempfile.TemporaryDirectory(prefix="reqlens-tool-") as box:
        for name, content in (files or {}).items():
            (Path(box) / name).write_text(content, encoding="utf-8")
        resolved = [arg.replace("{box}", box) for arg in argv]
        kwargs: dict = {}
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            proc = subprocess.run(
                resolved,
                input=stdin if stdin is not None else None,
                stdin=subprocess.DEVNULL if stdin is None else None,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=box,
                env=minimal_env(box),
                timeout=timeout,
                shell=False,
                check=False,
                **kwargs,
            )
        except subprocess.TimeoutExpired:
            return RunResult(None, "", "", timed_out=True)
        except OSError as exc:
            return RunResult(None, "", f"could not start: {exc.strerror or exc}")
    return RunResult(
        proc.returncode,
        truncate(clean_text(proc.stdout or ""), MAX_OUTPUT_CHARS),
        truncate(clean_text(proc.stderr or ""), MAX_OUTPUT_CHARS),
    )


def detect_tools(enabled: bool = True) -> dict[str, ToolStatus]:
    """Detect optional tools (cheap version checks only). Never installs anything."""
    from reqlens.external import hashcat, jwt_tool

    if not enabled:
        return {
            "jwt_tool": ToolStatus("jwt_tool", False, "disabled (--no-external)"),
            "hashcat": ToolStatus("hashcat", False, "disabled (--no-external)"),
        }
    return {"jwt_tool": jwt_tool.detect(), "hashcat": hashcat.detect()}
