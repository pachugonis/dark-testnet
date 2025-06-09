#!/bin/sh
#
# 1. potentially stop running network
# 2. bootstrap a network from scratch as quickly as possible
# 3. tail -F all the tor log files
#
# NOTE: leaves debris around by renaming directory net/nodes
#       and creating a new net/nodes
#
# Usage:
#    tools/bootstrap-network.sh [network-flavour]
#    network-flavour: one of the files in the networks directory,
#                     (default: 'bridges+hs-v23')

set -o errexit
set -o nounset

# Set some default values if the variables are not already set
: "${CHUTNEY_WARNINGS_ONLY:=false}"
: "${CHUTNEY_WARNINGS_SKIP:=false}"
: "${CHUTNEY_DIAGNOSTICS_ONLY:=false}"
: "${NETWORK_DRY_RUN:=false}"
: "${USE_COVERAGE_BINARY:=false}"
: "${CHUTNEY_DIAGNOSTICS:=false}"
: "${CHUTNEY_DATA_DIR:=}"

# Get a working chutney path
if [ ! -d "$CHUTNEY_PATH" ] || [ ! -x "$CHUTNEY_PATH/chutney" ]; then
    # looks like a broken path: use the path to this tool instead
    TOOLS_PATH=$(dirname "$0")
    CHUTNEY_PATH=$(dirname "$TOOLS_PATH")
    export CHUTNEY_PATH
fi
if [ -d "$PWD/$CHUTNEY_PATH" ] && [ -x "$PWD/$CHUTNEY_PATH/chutney" ]; then
    # looks like a relative path: make chutney path absolute
    export CHUTNEY_PATH="$PWD/$CHUTNEY_PATH"
fi

CHUTNEY="$CHUTNEY_PATH/chutney"
myname=$(basename "$0")

[ -d "$CHUTNEY_PATH" ] || \
    { echo "$myname: missing chutney directory: $CHUTNEY_PATH"; exit 1; }
[ -x "$CHUTNEY" ] || \
    { echo "$myname: missing chutney: $CHUTNEY"; exit 1; }

# Set the variables for the chutney network flavour
export NETWORK_FLAVOUR="${NETWORK_FLAVOUR:-bridges+hs-v23}"
[ -n "${1-}" ] && { NETWORK_FLAVOUR=$1; shift; }
export CHUTNEY_NETWORK="$CHUTNEY_PATH/networks/$NETWORK_FLAVOUR"

[ -e "$CHUTNEY_NETWORK" ] || \
    { echo "$myname: missing network file: $CHUTNEY_NETWORK"; exit 1; }

"$CHUTNEY" stop "$CHUTNEY_NETWORK"

if ! "$CHUTNEY" supported "$CHUTNEY_NETWORK"; then
    echo "%myname: network not supported."
    exit 77
fi

$ECHO "$myname: bootstrapping network: $NETWORK_FLAVOUR"
if ! "$CHUTNEY" bootstrap "$CHUTNEY_NETWORK"; then
    "$DIAGNOSTICS"
    CHUTNEY_WARNINGS_IGNORE_EXPECTED=false \
    CHUTNEY_WARNINGS_SUMMARY=false \
    "$WARNING_COMMAND"
    "$WARNINGS"
    $ECHO "chutney boostrap failed"
    exit 1
fi

$ECHO "Chutney network launched and running. To stop the network, use:"
$ECHO "$CHUTNEY stop $CHUTNEY_NETWORK"
"$DIAGNOSTICS"
"$WARNINGS"
