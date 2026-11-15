"""Optional AI analysis of a redacted capture (``--ai``). Off by default.

The flow mirrors Inicon's and is built to use few tokens:
  1. Condense the *strictly redacted* capture locally into one small digest (digest.py),
     with secrets replaced by aliases and values by shapes. No tokens are spent here.
  2. Send that digest to an AI model once per run (providers/; the only network code).
  3. Cache the answer so re-running on the same capture costs nothing (cache.py).

Captured content is written by the application, so it is untrusted throughout: it is never
a command-line argument, CLI providers run with their tools off or read-only, and the
model's answer is validated, stripped of code and control characters, and only ever text.
Nothing the model returns is executed.
"""

from reqlens.ai.analysis import AIOutcome, run
from reqlens.ai.settings import check_settings
from reqlens.errors import AIError

__all__ = ["AIError", "AIOutcome", "check_settings", "run"]
