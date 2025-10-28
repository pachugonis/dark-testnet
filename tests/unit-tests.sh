#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

# Output is prefixed with the name of the script
myname=$(basename "$0")

# Respect the user's $PYTHON
PYTHON=${PYTHON:-python3}
echo "$myname: using python '$PYTHON'"

echo "$myname: finding chutney directory"
TEST_DIR=$(dirname "$0")
CHUTNEY_DIR=$(dirname "$TEST_DIR")

echo "$myname: changing to chutney directory"
cd "$CHUTNEY_DIR"

echo "$myname: running Traffic.py tests"

LOG_FILE=$(mktemp)
export LOG_FILE
test -n "$LOG_FILE"

# Choose an arbitrary port
PYTHONPATH="${PYTHONPATH:-}:lib" $PYTHON lib/chutney/Traffic.py 9999 \
    | tee "$LOG_FILE"

# Traffic.py produces output with a single newline. But we don't want to get
# too picky about the details: allow an extra line and a few extra chars.
LOG_FILE_LINES=$(wc -l < "$LOG_FILE")
test "$LOG_FILE_LINES" -le 2
LOG_FILE_CHARS=$(wc -c < "$LOG_FILE")
test "$LOG_FILE_CHARS" -le 4


# We don't test TorNet.py: it's integration tested with tor using the
# chutney/chutney script
