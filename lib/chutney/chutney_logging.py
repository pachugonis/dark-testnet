import logging
from typing import Optional


def logging_basic_config(level: Optional[int] = None) -> None:
    """Configure logging as the chutney CLI does.

    Useful e.g. for non-chutney programs that use chutney as a module, that want
    logging output consistent with the chutney CLI."""
    import chutney.envvars

    if level is None:
        level = logging.DEBUG if chutney.envvars.DEBUG.get() else logging.INFO
    logging.basicConfig(
        level=level, format="%(levelname)s:%(name)s:%(asctime)s:%(message)s"
    )
