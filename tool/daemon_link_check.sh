#!/bin/sh
# A consumer's main linked from `make daemon-flags` alone, sec 907, and run: the
# binary starts, says its version, and is the daemon. Bounded by the build and
# one short run; the scratch is this script's own, and removed.
set -eu
cc=$1
make=$2
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
flags=$("$make" -s daemon-flags)
cflags=$(printf '%s\n' "$flags" | sed -n 's/^FZN_DAEMON_CFLAGS=//p')
libs=$(printf '%s\n' "$flags" | sed -n 's/^FZN_DAEMON_LIBS=//p')
[ -n "$cflags" ] && [ -n "$libs" ] || { echo "daemon-link-check: no flags in: $flags"; exit 1; }
cat > "$scratch/main.c" <<'SOURCE'
#include "node/daemon.h"

int main(int argc, char **argv)
{
	return fzn_daemon_main(argc, argv, NULL);
}
SOURCE
# shellcheck disable=SC2086
"$cc" $cflags -c "$scratch/main.c" -o "$scratch/main.o"
# shellcheck disable=SC2086
"$cc" "$scratch/main.o" $libs -o "$scratch/daemon"
said=$(timeout 10 "$scratch/daemon" --version 2>&1) || true
case "$said" in
*fuzznet*) echo "daemon-link-check: a main of its own linked and ran: $said" ;;
*) echo "daemon-link-check: FAILED -- the program said: $said"; exit 1 ;;
esac
