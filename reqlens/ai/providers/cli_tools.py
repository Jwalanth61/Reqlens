"""Provider that runs an official AI command-line tool you are already signed in to.

This is how a subscription plan (for example ChatGPT Plus through the Codex CLI) is used
without an API key. reqlens never sees the login.

Safety rules followed here, because the digest holds text written by the application:
  - The prompt only ever travels on standard input, never as a command argument.
  - Each tool is started with its tools switched off or read-only.
  - Each tool runs in an empty temporary folder, so it has no project files to read.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile

from reqlens.ai.constants import CLI_TIMEOUT_SECONDS
from reqlens.ai.prompt import SYSTEM_PROMPT
from reqlens.ai.providers.base import Answer, Usage
from reqlens.ai.text import one_line
from reqlens.errors import AIError

# Providers whose CLI wraps the answer in a JSON envelope.
_JSON_ENVELOPE_PROVIDERS = ("claude", "gemini")


def ask(provider: str, model: str | None, digest_text: str) -> Answer:
    """Run the provider's CLI with the digest on standard input and return its answer.

    Raises:
        AIError: the CLI is missing, failed, timed out or returned nothing.
    """
    executable = shutil.which(provider)
    if not executable:
        raise AIError(f"The '{provider}' command isn't installed or isn't on PATH.")

    prompt = f"{SYSTEM_PROMPT}\n\n<digest>\n{digest_text}\n</digest>\n"
    output = _run(provider, build_command(provider, executable, model), prompt)

    usage = None
    if provider in _JSON_ENVELOPE_PROVIDERS:
        output, usage = _open_envelope(provider, output)
    if not output:
        raise AIError(f"The {provider} CLI returned an empty answer.")
    return Answer(output, usage, model or f"{provider} default")


def build_command(provider: str, executable: str, model: str | None) -> list[str]:
    """Return the command line. It never contains capture data."""
    if provider == "codex":
        command = [executable, "exec", "--skip-git-repo-check", "--ephemeral"]
        command += ["--sandbox", "read-only"]
        if model:
            command += ["-m", model]
        return [*command, "-"]  # "-" reads the prompt from standard input

    if provider == "claude":
        command = [executable, "-p", "--output-format", "json"]
        command += ["--tools", ""]  # no built-in tools
        command += ["--disallowedTools", "mcp__*"]  # no MCP tools
        command += ["--strict-mcp-config"]  # don't load configured MCP servers
        command += ["--max-turns", "1", "--no-session-persistence"]
        # Replacing the default system prompt also saves several thousand tokens.
        command += [
            "--system-prompt",
            "You are a web application security analyst. Reply with JSON only.",
        ]
        if model:
            command += ["--model", model]
        return command

    # gemini
    command = [
        executable,
        "-p",
        "Follow the instructions above and reply with the JSON object only.",
    ]
    command += ["--output-format", "json"]
    command += ["--approval-mode", "default"]  # never auto-approve tool use
    if model:
        command += ["-m", model]
    return command


def _run(provider: str, command: list[str], prompt: str) -> str:
    with tempfile.TemporaryDirectory(prefix="reqlens-ai-") as workdir:
        try:
            process = subprocess.run(
                command,
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=workdir,
                timeout=CLI_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise AIError(
                f"The {provider} CLI didn't answer within {CLI_TIMEOUT_SECONDS} seconds."
            ) from None
        except OSError as error:
            raise AIError(f"Couldn't start the {provider} CLI: {one_line(error, 200)}") from None

    if process.returncode != 0:
        detail = one_line((process.stderr or process.stdout)[-400:], 400)
        raise AIError(
            f"The {provider} CLI failed (exit {process.returncode}). Are you signed in? {detail}"
        )
    return process.stdout.strip()


def _open_envelope(provider: str, output: str) -> tuple[str, Usage | None]:
    """Pull the answer text and token usage out of a CLI's JSON envelope.

    If the output is not the expected envelope, it is returned unchanged.
    """
    try:
        envelope = json.loads(output)
    except ValueError:
        return output, None
    if not isinstance(envelope, dict):
        return output, None

    if envelope.get("is_error") or envelope.get("error"):
        detail = envelope.get("error") or envelope.get("result") or "unknown error"
        raise AIError(f"The {provider} CLI reported an error: {one_line(detail, 300)}")

    text = str(envelope.get("result") or envelope.get("response") or "")

    usage = None
    raw_usage = envelope.get("usage")
    if isinstance(raw_usage, dict) and "output_tokens" in raw_usage:
        input_keys = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
        tokens_in = sum(raw_usage.get(key, 0) or 0 for key in input_keys)
        usage = Usage(tokens_in, raw_usage.get("output_tokens", 0) or 0)
    return text, usage
