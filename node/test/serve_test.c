/* The node runtime: fzn_node_find_peer directly, and fzn_node_run_once driven
 * over a real AF_UNIX listener without a fork. A client connects and sends a
 * request, one poll-and-dispatch iteration accepts and serves it, and the
 * client reads the status back -- the whole local path through the daemon
 * loop, bounded by the poll timeout so it cannot hang. */

#define _DEFAULT_SOURCE /* mkdtemp under -std=c11 */

#include "serve.h"
#include "../local/socket.h"
#include "../session/box.h" /* FZN_BOX_MARK */

#include <arpa/inet.h>
#include <netinet/in.h>

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

/* A LAN PROBE, sec 624: a datagram opening 0xFC goes to on_probe whole,
 * with where it came from -- the one thing a probe is answered by -- and a
 * box or a frame does not. */
static struct {
	int calls;
	size_t len;
	char host[FZN_UDP_HOST_MAX];
	uint16_t port;
} probed;

static void probe_heard(void *ctx, const uint8_t *probe, size_t len, const fzn_udp_addr_t *from)
{
	(void)ctx;
	(void)probe;
	probed.calls++;
	probed.len = len;
	if (fzn_udp_addr_text(from, probed.host, &probed.port) != FZN_UDP_OK)
		probed.host[0] = '\0';
}

static void test_run_once_probe(void)
{
	fzn_node_state_t state;
	uint8_t datagram[FZN_NODE_PROBE_LEN];
	struct sockaddr_in at;
	socklen_t at_len = sizeof(at);
	fzn_udp_addr_t to;
	uint16_t port, sender_port;
	int ufd = -1, sfd = -1;

	if (fzn_udp_bind(AF_INET, "127.0.0.1", 0, &ufd) != FZN_UDP_OK
	    || fzn_udp_bind(AF_INET, "127.0.0.1", 0, &sfd) != FZN_UDP_OK) {
		ok(0, "the datagram sockets would not bind");
		goto out;
	}
	if (getsockname(ufd, (struct sockaddr *)&at, &at_len) != 0) {
		ok(0, "the serving socket has no name");
		goto out;
	}
	port = ntohs(at.sin_port);
	at_len = sizeof(at);
	if (getsockname(sfd, (struct sockaddr *)&at, &at_len) != 0) {
		ok(0, "the sending socket has no name");
		goto out;
	}
	sender_port = ntohs(at.sin_port);
	(void)fzn_udp_resolve(AF_INET, "127.0.0.1", port, &to);
	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = ufd;
	state.on_probe = probe_heard;
	memset(&probed, 0, sizeof(probed));
	memset(datagram, 0, sizeof(datagram));
	datagram[0] = FZN_NODE_PROBE_MARK;
	datagram[1] = 1u;
	(void)fzn_udp_send(sfd, &to, datagram, sizeof(datagram));
	ok(fzn_node_run_once(&state, 1000) == 1, "run_once reads a probe");
	ok(probed.calls == 1 && probed.len == FZN_NODE_PROBE_LEN,
	   "a probe reached on_probe whole");
	ok(strcmp(probed.host, "127.0.0.1") == 0 && probed.port == sender_port,
	   "a probe came with the address it was sent from");
	datagram[0] = FZN_BOX_MARK;
	(void)fzn_udp_send(sfd, &to, datagram, sizeof(datagram));
	(void)fzn_node_run_once(&state, 1000);
	ok(probed.calls == 1, "a box reached on_probe");
	datagram[0] = FZN_NODE_PROBE_MARK;
	state.on_probe = NULL;
	(void)fzn_udp_send(sfd, &to, datagram, sizeof(datagram));
	(void)fzn_node_run_once(&state, 1000);
	ok(probed.calls == 1, "a probe with no handler went somewhere");
out:
	if (ufd >= 0)
		fzn_udp_close(ufd);
	if (sfd >= 0)
		fzn_udp_close(sfd);
}

/* A port bound on loopback, its fd and the address to send to it. */
static int bound(int *fd, fzn_udp_addr_t *to)
{
	struct sockaddr_in at;
	socklen_t at_len = sizeof(at);

	if (fzn_udp_bind(AF_INET, "127.0.0.1", 0, fd) != FZN_UDP_OK)
		return 0;
	if (getsockname(*fd, (struct sockaddr *)&at, &at_len) != 0)
		return 0;
	return fzn_udp_resolve(AF_INET, "127.0.0.1", ntohs(at.sin_port), to) == FZN_UDP_OK;
}

/* A WAIT THAT ANSWERS PEERS, sec 720: while a request asked in turn waits on
 * its own socket, what the node's socket receives is served -- two hosts
 * asking each other at once each waited out the other's timeout before --
 * and the wait ends when its own socket has something. */
static void test_wait_answering(void)
{
	fzn_node_state_t state;
	uint8_t datagram[FZN_NODE_PROBE_LEN], got[64];
	fzn_udp_addr_t to_node, to_asker, to_sender;
	size_t got_len = 0;
	int ufd = -1, wfd = -1, sfd = -1;

	if (!bound(&ufd, &to_node) || !bound(&wfd, &to_asker) || !bound(&sfd, &to_sender)) {
		ok(0, "the datagram sockets would not bind");
		goto out;
	}
	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = ufd;
	state.on_probe = probe_heard;
	memset(&probed, 0, sizeof(probed));
	memset(datagram, 0, sizeof(datagram));
	datagram[0] = FZN_NODE_PROBE_MARK;
	datagram[1] = 1u;
	ok(fzn_node_wait_answering(&state, wfd, 50u) == 0, "a wait with nothing came was not 0");
	(void)fzn_udp_send(sfd, &to_node, datagram, sizeof(datagram));
	(void)fzn_udp_send(sfd, &to_node, datagram, sizeof(datagram));
	ok(fzn_node_wait_answering(&state, wfd, 300u) == 0 && probed.calls == 2,
	   "what the node's socket received while a request waited was not served");
	(void)fzn_udp_send(sfd, &to_asker, (const uint8_t *)"answer", 6u);
	ok(fzn_node_wait_answering(&state, wfd, 3000u) == 1,
	   "the wait did not end when its own socket had something");
	ok(fzn_udp_recv(wfd, got, sizeof(got), &got_len, NULL) == FZN_UDP_OK && got_len == 6u
	           && memcmp(got, "answer", 6u) == 0,
	   "the wait took what came to its own socket");
	ok(fzn_node_wait_answering(&state, -1, 10u) == 0, "a wait on no socket was not 0");
out:
	if (ufd >= 0)
		fzn_udp_close(ufd);
	if (wfd >= 0)
		fzn_udp_close(wfd);
	if (sfd >= 0)
		fzn_udp_close(sfd);
}

int main(void)
{
	test_find_peer();
	test_run_once_local();
	test_run_once_probe();
	test_wait_answering();
	printf("serve_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
