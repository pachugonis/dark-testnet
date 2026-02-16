#!/bin/sh

set -o errexit
set -o nounset

usage () {
  cat <<EOF
Usage:
   tools/bootstrap-network.sh (--network-flavor network-flavor | --network-script path/to/script)

   --network-flavor: use a built-in network name (e.g. 'bridges+hs-v23')
   --network-script: use a chutney network script

1. potentially stop running network
2. bootstrap a network from scratch as quickly as possible
3. tail -F all the tor log files

NOTE: leaves debris around by renaming directory net/nodes
      and creating a new net/nodes
EOF
  exit 1
}

# Set some default values if the variables are not already set
: "${CHUTNEY_WARNINGS_ONLY:=false}"
: "${CHUTNEY_WARNINGS_SKIP:=false}"
: "${CHUTNEY_DIAGNOSTICS_ONLY:=false}"
: "${NETWORK_DRY_RUN:=false}"
: "${USE_COVERAGE_BINARY:=false}"
: "${CHUTNEY_DIAGNOSTICS:=false}"
: "${ECHO:=echo}"
: "${DIAGNOSTICS:=$(dirname "$0")/diagnostics.sh}"
myname=$(basename "$0")

NETWORK_ARG=""
until [ -z "${1:-}" ]
do
    case "$1" in
        --network-flavor=*|--network-flavour=*)
            NETWORK_ARG="--net=${1#*=}"
        ;;
        --network-flavor|--network-flavour)
            NETWORK_ARG="--net=$2"
            shift
        ;;
        --network-script=*)
            NETWORK_ARG="--net-from-script-path=${1#*=}"
        ;;
        --network-script)
            NETWORK_ARG="--net-from-script-path=$2"
            shift
        ;;
        *)
            $ECHO "$myname: Sorry, I don't know what to do with '$1'."
            usage
        ;;
    esac
    shift
done

if [ -z "$NETWORK_ARG" ]; then
  usage
fi

# Get a working chutney
if [ -n "${CHUTNEY_PATH:+x}" ]; then
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

# if CHUTNEY_DATA_DIR is not set, but CHUTNEY_PATH is, use the latter to set CHUTNEY_DATA_DIR
if [ -z "${CHUTNEY_DATA_DIR:+x}" ] && [ -n "${CHUTNEY_PATH:+x}" ]; then
    export CHUTNEY_DATA_DIR="$CHUTNEY_PATH"/net
fi

if ! "$CHUTNEY" supported "$NETWORK_ARG"; then
    echo "$myname: network not supported."
    exit 77
fi

"$CHUTNEY" stop || echo "Unable to stop previous network (possibly because there isn't one)"

$ECHO "$myname: bootstrapping network: $NETWORK_ARG"
"$CHUTNEY" init "$NETWORK_ARG"
if ! "$CHUTNEY" bootstrap; then
    "$DIAGNOSTICS"
    CHUTNEY_WARNINGS_IGNORE_EXPECTED=false \
    CHUTNEY_WARNINGS_SUMMARY=false \
    "$WARNING_COMMAND"
    "$WARNINGS"
    $ECHO "chutney boostrap failed"
    exit 1
fi

$ECHO "Chutney network launched and running. To stop the network, use:"
$ECHO "$CHUTNEY stop"
"$DIAGNOSTICS"
"$WARNINGS"
