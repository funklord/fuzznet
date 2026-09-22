/* The local access methods over a real socketpair: write a request, serve on
 * the node end, read the status. SAME_USER, LOCAL, a stranger's denial, an
 * unserved-but-authenticated denial, and an overlong request are all driven
 * over an actual AF_UNIX stream, with the peer credentials constructed since
 * a socketpair carries the test's own. */

#include "local.h"

#include "../../local/vocabulary.h"

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
static fzn_node_serve_err_t exchange_with(const fzn_node_config_t *cfg,
                                     const fzn_peer_t *peer, const char *request,
                                     fzn_node_local_handler_t on_local, void *ctx,
                                     char *resp, size_t resp_cap)
{
	int sv[2];
	fzn_node_serve_err_t r;
	ssize_t n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
		return FZN_NODE_SERVE_IO;
	wr(sv[0], request, strlen(request));
	wr(sv[0], "\n", 1);
	r = fzn_node_serve_local(cfg, sv[1], peer, on_local, ctx);
	n = read(sv[0], resp, resp_cap - 1);
	resp[n > 0 ? (size_t)n : 0] = '\0';
	close(sv[0]);
	close(sv[1]);
	return r;
}

/* The same exchange with no handler -- the node answering for itself, which
 * is what every case written before the seam existed drives. */
static fzn_node_serve_err_t exchange(const fzn_node_config_t *cfg,
                                     const fzn_peer_t *peer, const char *request,
                                     char *resp, size_t resp_cap)
{
	return exchange_with(cfg, peer, request, NULL, NULL, resp, resp_cap);
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


/* WHAT A HANDLER SAW, so the test can assert on bytes the node passed rather
 * than on the node having called something. */
struct seen {
	int calls;
	size_t len;
	char bytes[64];
	size_t claim;	/* what `reply` should claim to have written */
	const char *say;	/* what it writes, or NULL to write nothing */
	fzn_verb_t parsed;
	size_t arg_len;
};

static size_t record(void *ctx, fzn_authz_verdict_t verdict, fzn_origin_t origin,
                     const fzn_peer_t *peer, const fzn_request_t *request,
                     char *reply, size_t reply_cap)
{
	struct seen *s = (struct seen *)ctx;

	(void)verdict;
	(void)origin;
	(void)peer;
	s->calls++;
	s->len = request ? request->verb_len : 0u;
	s->parsed = request ? request->parsed : FZN_VERB_NONE;
	s->arg_len = request ? request->arg_len : 0u;
	if (request && request->verb && request->verb_len < sizeof(s->bytes)) {
		memcpy(s->bytes, request->verb, request->verb_len);
		s->bytes[request->verb_len] = '\0';
	}
	if (!s->say)
		return s->claim;	/* 0 for "node, answer for yourself" */
	if (strlen(s->say) <= reply_cap)
		memcpy(reply, s->say, strlen(s->say));
	return s->claim ? s->claim : strlen(s->say);
}

/* A CONSUMER'S VOCABULARY, which is the whole point of the seam: the node
 * hands over bytes, and the table that says which group may ask for what
 * lives out here. `local/vocabulary.h` is raidcfgd's requirement and until
 * the seam existed nothing on the local path could reach it. */
static size_t bounded(void *ctx, fzn_authz_verdict_t verdict, fzn_origin_t origin,
                      const fzn_peer_t *peer, const fzn_request_t *request,
                      char *reply, size_t reply_cap)
{
	/* The rule is built from fuzznet's own verb rather than from bytes
	 * spelled out here, which is what sec 361 added and what stops three
	 * consumers spelling `status` three ways. */
	const fzn_verb_rule_t rules[] = {
		{ 0u, NULL, 0u },
	};
	fzn_verb_rule_t table[1];
	const char *out;

	(void)verdict;
	(void)origin;
	(void)ctx;
	(void)rules;
	table[0] = fzn_verb_rule(44u, FZN_VERB_STATUS);
	out = (fzn_vocabulary_admit(peer, request->verb, request->verb_len, table, 1)
	       == FZN_PEER_MEMBER) ? "ok\n" : "refused\n";
	if (strlen(out) > reply_cap)
		return 0;
	memcpy(reply, out, strlen(out));
	return strlen(out);
}

int main(void)
{
	fzn_node_config_t cfg = base_config();
	fzn_node_config_t c2;
	fzn_peer_t p;
	char resp[256];
	char big[700];
	size_t n;
	struct seen seen;

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

	/* THE SEAM. The node reads the line and hands it on; until it did,
	 * local.c carried a literal `(void)line;` and the one access method
	 * whose peer the kernel had named was the one with nowhere to put a
	 * verb. */
	mk_peer(&p, 1000, 0, 0);
	memset(&seen, 0, sizeof(seen));
	ok(exchange_with(&cfg, &p, "status", record, &seen, resp, sizeof(resp))
	       == FZN_NODE_SERVE_OK, "a served caller with a handler is still served");
	ok(seen.calls == 1, "the handler was not called once");
	ok(seen.len == 6u && strcmp(seen.bytes, "status") == 0,
	   "the handler did not get the request bytes -- the node is reading or "
	   "trimming a line it is only meant to pass on");
	ok(strstr(resp, "served") != NULL,
	   "a handler that wrote nothing did not fall back to the status line");

	/* A handler's reply is what reaches the wire. */
	memset(&seen, 0, sizeof(seen));
	seen.say = "pong\n";
	ok(exchange_with(&cfg, &p, "ping", record, &seen, resp, sizeof(resp))
	       == FZN_NODE_SERVE_OK, "a handler-answered caller is served");
	ok(strcmp(resp, "pong\n") == 0 && strstr(resp, "served") == NULL,
	   "the node sent its own status line over the handler's reply");

	/* A handler claiming more than it was given wrote nothing sendable.
	 * Truncating would send a DIFFERENT reply, which is the failure
	 * `fzn_node_status_line` and the verb bound both already refuse. */
	memset(&seen, 0, sizeof(seen));
	seen.say = "pong\n";
	seen.claim = FZN_NODE_LOCAL_REPLY_MAX + 1u;
	ok(exchange_with(&cfg, &p, "ping", record, &seen, resp, sizeof(resp))
	       == FZN_NODE_SERVE_OK, "an over-claiming handler broke the exchange");
	ok(strstr(resp, "served") != NULL && strstr(resp, "pong") == NULL,
	   "a reply claiming more than the cap was sent anyway");

	/* NOT ON A DENIAL, which is where this seam differs from on_remote.
	 * A handler that is never called cannot widen a refusal. */
	mk_peer(&p, 2000, 0, 0);
	memset(&seen, 0, sizeof(seen));
	seen.say = "let-me-in\n";
	ok(exchange_with(&cfg, &p, "status", record, &seen, resp, sizeof(resp))
	       == FZN_NODE_SERVE_DENIED, "a stranger with a handler is still denied");
	ok(seen.calls == 0,
	   "the handler ran for a denied caller, so a seam can answer someone "
	   "the node just refused");
	ok(strcmp(resp, "denied\n") == 0,
	   "a denied caller got something other than the denial");

	/* THE REQUIREMENT THE SEAM EXISTS FOR, end to end: a group member may
	 * ask for the verb its group names and not for another. raidcfgd's
	 * rule -- a gid check that gates a connection is not enough. */
	mk_peer(&p, 2000, 1, 44);
	ok(exchange_with(&cfg, &p, "status", bounded, NULL, resp, sizeof(resp))
	       == FZN_NODE_SERVE_OK, "the bounded exchange did not complete");
	ok(strcmp(resp, "ok\n") == 0,
	   "a group member was refused the verb its group names");
	ok(exchange_with(&cfg, &p, "destroy", bounded, NULL, resp, sizeof(resp))
	       == FZN_NODE_SERVE_OK, "the bounded exchange did not complete");
	ok(strcmp(resp, "refused\n") == 0,
	   "a group member was admitted a verb no rule names, so the group "
	   "boundary is a root boundary wearing a different name");

	/* THE NODE'S OWN LINES READ AS REPLIES, which is the property that
	 * makes sec 365 worth anything: the daemon composes with the reply
	 * vocabulary and a client reads with it, so neither is matching
	 * substrings the other happens to emit. */
	{
		const uint8_t *detail = NULL;
		size_t detail_len = 0;
		size_t ln;

		mk_peer(&p, 1000, 0, 0);
		ok(exchange(&cfg, &p, "status", resp, sizeof(resp))
		       == FZN_NODE_SERVE_OK, "the served exchange did not complete");
		ln = strlen(resp);
		ok(ln > 0 && resp[ln - 1u] == '\n', "the reply has no terminator");
		ok(fzn_reply_of((const uint8_t *)resp, ln - 1u, &detail, &detail_len)
		       == FZN_REPLY_OK,
		   "a served caller's line does not read as FZN_REPLY_OK, so the node "
		   "and the client disagree about the wire");
		ok(detail_len > 0 && detail != NULL,
		   "the grant carries no detail, so `ok` says nothing about what was "
		   "served");

		mk_peer(&p, 2000, 0, 0);
		ok(exchange(&cfg, &p, "status", resp, sizeof(resp))
		       == FZN_NODE_SERVE_DENIED, "the denied exchange did not complete");
		ln = strlen(resp);
		ok(fzn_reply_of((const uint8_t *)resp, ln - 1u, &detail, &detail_len)
		       == FZN_REPLY_DENIED,
		   "a denial does not read as FZN_REPLY_DENIED");
		ok(detail == NULL && detail_len == 0u,
		   "a denial carries a detail, so it says more about the caller than "
		   "the refusal does");

		/* AND IT IS STILL THE OLD LINE. sec 365 added a leading token and
		 * changed nothing after it, so anything that matched the previous
		 * wording still matches -- which is what made the change safe to
		 * make while a consumer was mid-integration. */
		ok(strstr(resp, "denied") != NULL, "the denial stopped saying denied");
	}

	printf("local_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
