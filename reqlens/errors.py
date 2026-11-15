"""Exception types. Every error reqlens raises on purpose derives from :class:`ReqlensError`."""


class ReqlensError(Exception):
    """Base class for expected, user-facing errors (printed without a traceback)."""

    exit_code = 1


class UsageError(ReqlensError):
    """Invalid combination of command-line options."""

    exit_code = 2


class InputError(ReqlensError):
    """A capture file is missing, unreadable, too large, or malformed."""


class FormatDetectionError(InputError):
    """The capture format could not be detected; suggest ``--input-format``."""


class ScopeError(ReqlensError):
    """No scope was given, or the scope matches nothing in the capture."""


class RedactionError(ReqlensError):
    """Redaction failed. Analysis stops rather than risk leaking unredacted data."""


class ReportError(ReqlensError):
    """A report could not be written."""


class SafetyViolation(ReqlensError):
    """A structural safety guarantee was about to be broken (for example a model claiming
    a finding is 'confirmed'). This always indicates a bug and must never be caught silently."""

    exit_code = 3
