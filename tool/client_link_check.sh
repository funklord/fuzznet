#!/bin/sh
# A consumer's client linked from `make client-flags` alone, sec 1418, and run:
# the typed client asks a procedure of a node that is not there and says so in
# its own words. Bounded by the build and one short run; the scratch is this
# script's own, and removed.
set -eu
cc=$1
make=$2
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
flags=$("$make" -s client-flags)
cflags=$(printf '%s\n' "$flags" | sed -n 's/^FZN_CLIENT_CFLAGS=//p')
libs=$(printf '%s\n' "$flags" | sed -n 's/^FZN_CLIENT_LIBS=//p')
[ -n "$cflags" ] && [ -n "$libs" ] || { echo "client-link-check: no flags in: $flags"; exit 1; }
cat > "$scratch/main.c" <<'SOURCE'
#include "local/rpc.h"
#include "local/rpc_err.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	static fzn_rpc_t c;
	uint8_t answer[64];
	size_t n = 0;
	int rc;

	(void)argc;
	memset(&c, 0, sizeof(c));
	snprintf(c.node_socket, sizeof(c.node_socket), "%s", argv[1]);
	rc = fzn_rpc_procedure(&c, "status", NULL, 0, answer, sizeof(answer), &n);
	printf("%d %s\n", rc, c.error);
	return rc == FZN_RPC_ERR_SEND_FAILED ? 0 : 1;
}
SOURCE
# shellcheck disable=SC2086
"$cc" $cflags -c "$scratch/main.c" -o "$scratch/main.o"
# shellcheck disable=SC2086
"$cc" "$scratch/main.o" $libs -o "$scratch/client"
if said=$(timeout 10 "$scratch/client" "$scratch/no-node.sock" 2>&1); then
	echo "client-link-check: a client of its own linked and ran: $said"
else
	echo "client-link-check: FAILED -- the program said: $said"
	exit 1
fi
