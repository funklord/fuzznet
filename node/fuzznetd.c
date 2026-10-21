/* fuzznetd: the shared node of sec 298 and sec 300, a daemon a consumer who
 * does not want to write its own can run. The node is node/daemon.c, a call
 * since sec 670; this is that call with no extension. */
#include "daemon.h"

#include <stddef.h>

int main(int argc, char **argv)
{
	return fzn_daemon_main(argc, argv, NULL);
}
