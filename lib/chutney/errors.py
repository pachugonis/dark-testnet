from __future__ import annotations

from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    # Imports needed only for type-checking.
    # Conditional to break dependency-cycles.
    from chutney.known_bins import KnownBin


class ChutneyError(Exception):
    """Base class for "normal" errors originating from this module

    i.e. any public functions in this module raising an exception that *isn't*
    a subclass of this indicates a programming error in this module.
    """

    pass


class ChutneyUnimplementedError(ChutneyError):
    """Requested functionality is unimplemented."""

    pass


class ChutneyMissingBinaryError(ChutneyError):
    def __init__(self, known_bin: Optional[KnownBin], cmdline: List[str]) -> None:
        """Create an exception for a missing tor binary, with help for how to fix it."""
        self._cmdline = cmdline

        if known_bin is None:
            self._name = cmdline[0]
            self._help = ""
            return

        self._name = known_bin.name()
        self._help = (
            f"Set the '{known_bin.config_envvar()}' environment variable"
            + f" to the path of '{known_bin.name()}'."
        )

        test_network_sh_hint = known_bin.test_network_sh_hint()
        if test_network_sh_hint is not None:
            self._help += (
                " Alternatively, if using test-network.sh: " + test_network_sh_hint
            )

    def __str__(self) -> str:
        return (
            f"Cannot find the {self._name} binary"
            + f" at '{self._cmdline[0]}'"
            + f" for the command line '{' '.join(self._cmdline)}'."
            + f" {self._help}"
        )


class ChutneyTimeoutError(ChutneyError):
    pass


class ChutneyErrorGroup(ChutneyError):
    """A list of errors.

    For use in methods like `start` where we want to continue after the first error,
    but collect all of the errors.

    Analogous to python 3.11's `ExceptionGroup`
    """

    def __init__(self, description: str, errs: List[ChutneyError]):
        self._description = description
        self._errs = errs
        ChutneyError.__init__(self, description, errs)

    def __str__(self) -> str:
        return (
            self._description
            + " [\n  "
            + "\n  ".join([str(e) for e in self._errs])
            + "\n]\n"
        )


class ChutneyInternalError(ChutneyError):
    """Indicates a bug in Chutney"""

    pass
