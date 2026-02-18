"""
This module is an entry point to run TorNet.__main__().

We use this stub module instead of executing the TorNet module directly, so that
the TorNet module doesn't get loaded with module name `__main__`, which would
cause it be loaded a second time with name `TorNet` if anything else tries to
import it.
"""

import chutney.TorNet

assert __name__ == "__main__", "This module should *only* be used as a stub entry-point"
chutney.TorNet.__main__()
