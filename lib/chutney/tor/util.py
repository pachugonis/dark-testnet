import logging
import re
import textwrap

from typing import List

import chutney
import chutney.errors
import chutney.launcher
import chutney.Util

from chutney.known_bins import TorBin

logger = logging.getLogger(__name__)


def run_tor(
    launcher: chutney.launcher.Launcher,
    cmdline: List[str],
    tolerate_error: bool = False,
) -> str:
    """Run the tor command line cmdline, which must start with the path or
    name of a tor binary.

    Returns the combined stdout and stderr of the process.

    raises `ChutneyMissingBinaryException` if the tor binary is missing.

    If `tolerate_error` is set, ignore the return code from the binary.
    """
    res = launcher.run(
        cmdline,
        capture_strategy=chutney.launcher.Capture.MERGED,
        text=True,
        known_bin=TorBin(),
    )
    stdouterr = res.stdout
    if res.returncode != 0 and not tolerate_error:
        raise chutney.errors.ChutneyError(
            f"Failed to run cmdline: {cmdline}. Output: {stdouterr}"
        )
    logger.debug(
        "Output for " + str(cmdline) + ":\n" + textwrap.indent(stdouterr, "    ")
    )
    return stdouterr


@chutney.Util.memoized
def get_tor_version(launcher: chutney.launcher.Launcher, tor: str) -> str:
    """Return the version of the tor binary.
    Versions are cached for each unique tor path.
    """
    cmdline = [
        tor,
        "--version",
    ]
    tor_version = run_tor(launcher, cmdline)
    # Keep only the first line of the output: since #32102 a bunch of more
    # lines have been added to --version and we only care about the first
    tor_version = tor_version.split("\n")[0]
    # clean it up a bit
    tor_version = tor_version.strip()
    tor_version = tor_version.replace("version ", "")
    tor_version = tor_version.replace(").", ")")
    # check we received a tor version, and nothing else
    assert re.match(
        r"^[-+.() A-Za-z0-9]+$", tor_version
    ), f"Couldn't parse tor_version '{tor_version}'"

    return tor_version
