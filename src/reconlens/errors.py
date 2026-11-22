"""Expected errors. These are safe to show to a user."""


class ReconLensError(Exception):
    """Base class for failures the CLI knows how to report."""


class TargetError(ReconLensError):
    """The target value is not valid for the command that received it."""


class UsageError(ReconLensError):
    """The invocation itself is not valid."""


class ConfigError(ReconLensError):
    """A config file was missing or could not be parsed."""


class SourceError(ReconLensError):
    """One source failed. The runner records it and continues with the others."""


class ReportError(ReconLensError):
    """A saved report could not be read."""
