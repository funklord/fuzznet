/* The node runtime: fzn_node_find_peer directly, and fzn_node_run_once driven
 * over a real AF_UNIX listener without a fork. A client connects and sends a
 * request, one poll-and-dispatch iteration accepts and serves it, and the
 * client reads the status back -- the whole local path through the daemon
 * loop, bounded by the poll timeout so it cannot hang. */

#define _DEFAULT_SOURCE /* mkdtemp under -std=c11 */

#include "serve.h"
#include "../local/socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int checks;
static int failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL serve_test.c: %s\n", what);
	}
}

/* Connect a client to an AF_UNIX path. Returns the fd, or -1. */
static int connect_to(const char *path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void test_find_peer(void)
{
	fzn_node_peer_t peers[2];
	uint8_t want[FZN_PUBKEY_LEN], absent[FZN_PUBKEY_LEN];

	memset(peers, 0, sizeof(peers));
	memset(peers[0].sender, 0x11, FZN_PUBKEY_LEN);
	memset(peers[1].sender, 0x22, FZN_PUBKEY_LEN);
	memset(want, 0x22, sizeof(want));
	memset(absent, 0x33, sizeof(absent));
	ok(fzn_node_find_peer(peers, 2, want) == &peers[1],
	   "a provisioned sender is found");
	ok(fzn_node_find_peer(peers, 2, absent) == NULL,
	   "an unprovisioned sender is not found");
	ok(fzn_node_find_peer(peers, 0, want) == NULL,
	   "an empty peer table finds nobody");
	ok(fzn_node_find_peer(NULL, 0, want) == NULL, "a null table is safe");
}

static void test_run_once_local(void)
{
	char dir[] = "/tmp/fzn_serve_test_XXXXXX";
	char path[128];
	fzn_node_state_t state;
	int lfd = -1, cfd;
	char resp[128];
	ssize_t n;

	if (!mkdtemp(dir)) {
		ok(0, "a temporary directory could not be made");
		return;
	}
	snprintf(path, sizeof(path), "%s/sock", dir);

	if (fzn_socket_listen(path, 0700u, 8, &lfd) != FZN_SOCKET_OK) {
		ok(0, "the listener would not bind");
		(void)rmdir(dir);
		return;
	}

	memset(&state, 0, sizeof(state));
	state.config.uid = (uint32_t)getuid();
	state.config.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER) |
	                             FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL);
	state.listen_fd = lfd;
	state.udp_fd = -1;

	cfd = connect_to(path);
	ok(cfd >= 0, "a client connects to the node");
	if (cfd >= 0) {
		(void)write(cfd, "hello\n", 6);
		/* One iteration accepts the pending connection and serves it. */
		ok(fzn_node_run_once(&state, 1000) == 1,
		   "run_once accepts and serves one connection");
		n = read(cfd, resp, sizeof(resp) - 1);
		resp[n > 0 ? (size_t)n : 0] = '\0';
		ok(n > 0 && strstr(resp, "served") && strstr(resp, "origin 1"),
		   "the node's own user is served through the loop");
		(void)close(cfd);
	}

	/* An idle iteration returns 0 rather than blocking. */
	ok(fzn_node_run_once(&state, 50) == 0,
	   "an idle poll returns without blocking");

	fzn_socket_close(lfd, path);
	(void)rmdir(dir);
}

int main(void)
{
	test_find_peer();
	test_run_once_local();
	printf("serve_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
