/* gui rpc_ask_test -- the views' client on a host's socket, sec 1181: a view
 * given the socket ask is put on the node's socket itself, so it speaks the
 * binary messages where the node reads them; any other ask keeps the line
 * callback. Here the socket ask is this file's own, as a host's would be,
 * and a node is a listening socket answering one request in binary. */
#include "../rpc_ask.h"

extern "C" {
#include "../../wire/cmd.h"
#include "../../wire/status.h"
}

#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                   \
	do {                                                                                \
		checks++;                                                                   \
		if (!(cond)) {                                                              \
			failures++;                                                         \
			fprintf(stderr, "  FAIL rpc_ask_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                           \
	} while (0)

/* THE HOST'S SOCKET ASK, defined here as `notebook_view.cpp` defines it for a
 * real host; a line asked through it is a failure, since the client is to go
 * to the socket itself. */
static int lines_asked;

size_t fzn_notebook_view_socket_ask(void *ctx, const char *line, char *reply, size_t reply_cap)
{
	(void)ctx;
	(void)line;
	(void)reply;
	(void)reply_cap;
	lines_asked++;
	return 0;
}

static size_t other_ask(void *ctx, const char *line, char *reply, size_t reply_cap)
{
	(void)ctx;
	(void)line;
	(void)reply;
	(void)reply_cap;
	return 0;
}

/* ONE NODE, ONE REQUEST: accept, read the framed request, answer a pack row
 * and a STATUS ok in binary, close. */
struct node {
	int fd;
	uint8_t asked[64];
	size_t asked_len;
};

static void *serve_one(void *arg)
{
	struct node *n = (struct node *)arg;
	/* A PACK ROW, written by hand from node/stickers_local.situ's layout as
	 * its vectors are: CMD, op, root, length, held, estate, name. */
	static const uint8_t name[] = { 'c', 'a', 't', 's' };
	uint8_t msg[64], out[256];
	size_t at = 0, sn, msg_len = 0;
	ssize_t got;
	struct pollfd p = { n->fd, POLLIN, 0 };
	int c;

	/* BOUNDED: a client that never comes -- one asking through the line
	 * callback instead -- fails the test here rather than hanging it. */
	if (poll(&p, 1, 3000) != 1 || (c = accept(n->fd, nullptr, nullptr)) < 0)
		return nullptr;
	/* THE LENGTH, then that many: the client keeps its half open for the
	 * answer, so the request ends where its frame says. */
	while (n->asked_len < 2u
	       || (n->asked_len < sizeof(n->asked)
	           && n->asked_len < 2u + (((size_t)n->asked[0] << 8) | n->asked[1]))) {
		got = read(c, n->asked + n->asked_len, sizeof(n->asked) - n->asked_len);
		if (got <= 0)
			break;
		n->asked_len += (size_t)got;
	}
	msg[msg_len++] = (uint8_t)FZN_CMD_STICKERS;
	msg[msg_len++] = 0x81;
	memset(msg + msg_len, 0x6c, 32u);
	msg_len += 32u;
	memset(msg + msg_len, 0, 8u);
	msg[msg_len + 6u] = 0x10; /* 4096 */
	msg_len += 8u;
	msg[msg_len++] = 1;
	msg[msg_len++] = 0;
	msg[msg_len++] = sizeof(name);
	memcpy(msg + msg_len, name, sizeof(name));
	msg_len += sizeof(name);
	out[at++] = (uint8_t)(msg_len >> 8);
	out[at++] = (uint8_t)msg_len;
	memcpy(out + at, msg, msg_len);
	at += msg_len;
	sn = fzn_status_write(out + at + 2u, sizeof(out) - at - 2u, FZN_STATUS_OK, nullptr);
	out[at] = (uint8_t)(sn >> 8);
	out[at + 1u] = (uint8_t)sn;
	at += 2u + sn;
	if (write(c, out, at) != (ssize_t)at)
		n->asked_len = 0;
	close(c);
	return nullptr;
}

static void test_a_socket_host_is_asked_on_its_socket(void)
{
	char dir[] = "/tmp/fzn-rpc-ask.XXXXXX";
	char path[sizeof(dir) + 8u];
	struct sockaddr_un a;
	struct node n;
	pthread_t t;
	fzn_gui_rpc r;
	static fzn_rpc_sticker_packs_t packs;

	if (!mkdtemp(dir)) {
		CHECK(0, "fixture: no scratch directory");
		return;
	}
	snprintf(path, sizeof(path), "%s/node", dir);
	memset(&n, 0, sizeof(n));
	memset(&a, 0, sizeof(a));
	a.sun_family = AF_UNIX;
	snprintf(a.sun_path, sizeof(a.sun_path), "%s", path);
	n.fd = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(n.fd >= 0 && bind(n.fd, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(n.fd, 1) == 0,
	      "fixture: no listening socket");
	CHECK(pthread_create(&t, nullptr, serve_one, &n) == 0, "fixture: no node thread");

	fzn_gui_rpc_init(&r, fzn_notebook_view_socket_ask, path);
	CHECK(!r.c.answer && strcmp(r.c.node_socket, path) == 0,
	      "a host giving the socket ask was not put on its socket");
	CHECK(fzn_rpc_sticker_list(&r.c, &packs) == FZN_RPC_OK && packs.count == 1
	              && strcmp(packs.entries[0].name, "cats") == 0,
	      "a view on a host's socket did not read the node's binary answer");
	pthread_join(t, nullptr);
	CHECK(n.asked_len == 4u && n.asked[0] == 0 && n.asked[1] == 2 && n.asked[2] == FZN_CMD_STICKERS
	              && n.asked[3] == 0x80 && lines_asked == 0,
	      "the request on the socket was not the binary one, or a line was asked");
	fzn_rpc_sticker_packs_release(&packs);

	fzn_gui_rpc_init(&r, other_ask, path);
	CHECK(r.c.answer == fzn_gui_rpc_answer && !r.c.node_socket[0],
	      "a host's own ask was not kept as the line callback");
	fzn_gui_rpc_init(&r, fzn_notebook_view_socket_ask, nullptr);
	CHECK(r.c.answer == fzn_gui_rpc_answer, "a socket ask with no path was put on no socket");

	close(n.fd);
	unlink(path);
	rmdir(dir);
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_the_suite_can_tell_pass_from_fail();
	test_a_socket_host_is_asked_on_its_socket();
	if (failures) {
		fprintf(stderr, "gui rpc_ask_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("gui rpc_ask_test: all %d checks passed\n", checks);
	return 0;
}
