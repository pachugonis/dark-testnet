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

myname=$(basename "$0")

# Get a working chutney
if [ -n "$CHUTNEY_PATH" ]; then
  # CHUTNEY_PATH is set; use the corresponding chutney bin
  CHUTNEY="$CHUTNEY_PATH/chutney"
  if [ ! -x "$CHUTNEY" ]; then
    echo "$myname: CHUTNEY_PATH was set to '$CHUTNEY_PATH', but doesn't contain a chutney executable"
    exit 1
  fi
else
  tools_dir_path=$(dirname "$0")
  chutney_dir_path=$(dirname "$tools_dir_path")
  CHUTNEY="$chutney_dir_path"/chutney
  if [ ! -x "$CHUTNEY" ]; then
    echo "$myname: No chutney executable found at $CHUTNEY. Try setting $CHUTNEY_PATH."
    exit 1
  fi
fi

# Set the variables for the chutney network flavour
NETWORK_FLAVOUR="${NETWORK_FLAVOUR:-bridges+hs-v23}"
[ -n "${1-}" ] && { NETWORK_FLAVOUR=$1; shift; }

if ! "$CHUTNEY" supported "$NETWORK_FLAVOUR"; then
    echo "$myname: network not supported."
    exit 77
fi

"$CHUTNEY" stop "$NETWORK_FLAVOUR"

$ECHO "$myname: bootstrapping network: $NETWORK_FLAVOUR"
if ! "$CHUTNEY" bootstrap "$NETWORK_FLAVOUR"; then
    "$DIAGNOSTICS"
    CHUTNEY_WARNINGS_IGNORE_EXPECTED=false \
    CHUTNEY_WARNINGS_SUMMARY=false \
    "$WARNING_COMMAND"
    "$WARNINGS"
    $ECHO "chutney boostrap failed"
    exit 1
fi

$ECHO "Chutney network launched and running. To stop the network, use:"
$ECHO "$CHUTNEY stop $NETWORK_FLAVOUR"
"$DIAGNOSTICS"
"$WARNINGS"
