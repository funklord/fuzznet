/* The local access methods over a real socketpair: write a request, serve on
 * the node end, read the status. SAME_USER, LOCAL, a stranger's denial, an
 * unserved-but-authenticated denial, and an overlong request are all driven
 * over an actual AF_UNIX stream, with the peer credentials constructed since
 * a socketpair carries the test's own. */

#include "local.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int checks;
static int failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL local_test.c: %s\n", what);
	}
}

static void mk_peer(fzn_peer_t *p, uint32_t uid, int in_group, uint32_t gid)
{
	memset(p, 0, sizeof(*p));
	p->pid = 1;
	p->uid = uid;
	p->primary_gid = uid;
	p->groups_known = 1;
	if (in_group) {
		p->groups[0] = gid;
		p->group_count = 1;
	}
}

static void wr(int fd, const char *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n <= 0)
			return;
		off += (size_t)n;
	}
}

/* One request/response exchange over a socketpair. Fills `resp` with the
 * node's reply and returns the serve result. */
static fzn_node_serve_err_t exchange(const fzn_node_config_t *cfg,
                                     const fzn_peer_t *peer, const char *request,
                                     char *resp, size_t resp_cap)
{
	int sv[2];
	fzn_node_serve_err_t r;
	ssize_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return FZN_NODE_SERVE_IO;
	wr(sv[0], request, strlen(request));
	wr(sv[0], "\n", 1);
	r = fzn_node_serve_local(cfg, sv[1], peer);
	n = read(sv[0], resp, resp_cap - 1);
	resp[n > 0 ? (size_t)n : 0] = '\0';
	close(sv[0]);
	close(sv[1]);
	return r;
}

static fzn_node_config_t base_config(void)
{
	fzn_node_config_t cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.uid = 1000;
	cfg.has_service_gid = 1;
	cfg.service_gid = 44;
	cfg.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER) |
	                    FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL);
	cfg.serves_remote = 1;
	return cfg;
}

int main(void)
{
	fzn_node_config_t cfg = base_config();
	fzn_node_config_t c2;
	fzn_peer_t p;
	char resp[256];
	char big[700];
	size_t n;

	/* SAME_USER, over a real stream. */
	mk_peer(&p, 1000, 0, 0);
	ok(exchange(&cfg, &p, "hello", resp, sizeof(resp)) == FZN_NODE_SERVE_OK,
	   "the node's own user is served");
	ok(strstr(resp, "served") && strstr(resp, "origin 1"),
	   "the reply names SAME_USER");

	/* LOCAL, a service-group member. */
	mk_peer(&p, 2000, 1, 44);
	ok(exchange(&cfg, &p, "hello", resp, sizeof(resp)) == FZN_NODE_SERVE_OK,
	   "a group member is served");
	ok(strstr(resp, "origin 2") != NULL, "the reply names LOCAL");

	/* A stranger is denied over the wire. */
	mk_peer(&p, 2000, 0, 0);
	ok(exchange(&cfg, &p, "hello", resp, sizeof(resp)) == FZN_NODE_SERVE_DENIED,
	   "a stranger is denied");
	ok(strstr(resp, "denied") != NULL, "the denial says so");

	/* Authenticated but not served: a group member of a node that serves
	 * only SAME_USER. */
	c2 = cfg;
	c2.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER);
	mk_peer(&p, 2000, 1, 44);
	ok(exchange(&c2, &p, "hello", resp, sizeof(resp)) == FZN_NODE_SERVE_DENIED,
	   "an unserved LOCAL is denied though authenticated");

	/* An overlong request is refused, not grown. */
	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	mk_peer(&p, 1000, 0, 0);
	ok(exchange(&cfg, &p, big, resp, sizeof(resp)) == FZN_NODE_SERVE_DENIED,
	   "an overlong request is refused");

	/* The pure status line, both answers. */
	n = fzn_node_status_line(FZN_AUTHZ_GRANTED_UNGUARDED, FZN_ORIGIN_SAME_USER,
	                         resp, sizeof(resp));
	ok(n > 0 && strstr(resp, "served") != NULL, "a grant renders a served line");
	n = fzn_node_status_line(FZN_AUTHZ_DENIED, FZN_ORIGIN_LOCAL, resp,
	                         sizeof(resp));
	ok(n > 0 && strstr(resp, "denied") != NULL && strstr(resp, "origin") == NULL,
	   "a denial names no origin");

	printf("local_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
