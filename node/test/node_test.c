/* The three access methods, decided without a socket or a key: a peer is a
 * struct here, so SAME_USER by uid, LOCAL by group membership and the
 * authorisation of each are all driven directly. The remote GRANT, which
 * needs a real capability chain, is proven in node/test/remote_test.c with
 * crypto; here the remote wiring is exercised on its deny paths. */

#include "node.h"

#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL node_test.c: %s\n", what);
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

	/* Access method 1: SAME_USER by uid. */
	mk_peer(&p, 1000, 0, 0);
	ok(fzn_node_local_origin(&cfg, &p) == FZN_ORIGIN_SAME_USER,
	   "own uid is SAME_USER");
	mk_peer(&p, 1000, 1, 44);
	ok(fzn_node_local_origin(&cfg, &p) == FZN_ORIGIN_SAME_USER,
	   "own uid wins over group membership");

	/* Access method 2: LOCAL by service-group membership. */
	mk_peer(&p, 2000, 1, 44);
	ok(fzn_node_local_origin(&cfg, &p) == FZN_ORIGIN_LOCAL,
	   "a service-group member is LOCAL");
	mk_peer(&p, 2000, 1, 99);
	ok(fzn_node_local_origin(&cfg, &p) == FZN_ORIGIN_NONE,
	   "a member of another group is NONE");
	mk_peer(&p, 2000, 0, 0);
	ok(fzn_node_local_origin(&cfg, &p) == FZN_ORIGIN_NONE,
	   "a non-member is NONE");
	mk_peer(&p, 2000, 0, 0);
	p.groups_known = 0;
	ok(fzn_node_local_origin(&cfg, &p) == FZN_ORIGIN_NONE,
	   "an unknown group list denies, not guesses");
	c2 = cfg;
	c2.has_service_gid = 0;
	mk_peer(&p, 2000, 1, 44);
	ok(fzn_node_local_origin(&c2, &p) == FZN_ORIGIN_NONE,
	   "a node with no service group never yields LOCAL");

	/* Authorisation of each method. Local origins are kernel-authenticated
	 * and served unguarded; the remote deny paths are exercised here and
	 * the remote grant in remote_test.c. */
	ok(fzn_node_decide(&cfg, FZN_ORIGIN_SAME_USER, NULL, 0, 0, NULL, NULL,
	                   NULL) == FZN_AUTHZ_GRANTED_UNGUARDED,
	   "SAME_USER is served unguarded");
	ok(fzn_node_decide(&cfg, FZN_ORIGIN_LOCAL, NULL, 0, 0, NULL, NULL,
	                   NULL) == FZN_AUTHZ_GRANTED_UNGUARDED,
	   "LOCAL is served unguarded");
	ok(fzn_node_decide(&cfg, FZN_ORIGIN_NONE, NULL, 0, 0, NULL, NULL,
	                   NULL) == FZN_AUTHZ_DENIED,
	   "NONE is denied");
	ok(fzn_node_decide(&cfg, FZN_ORIGIN_REMOTE, NULL, 0, 0, NULL, NULL,
	                   NULL) == FZN_AUTHZ_DENIED,
	   "REMOTE without a chain is denied");

	/* A node serving only SAME_USER denies a kernel-authenticated LOCAL:
	 * authentication is not authorisation. */
	c2 = cfg;
	c2.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER);
	ok(fzn_node_decide(&c2, FZN_ORIGIN_LOCAL, NULL, 0, 0, NULL, NULL,
	                   NULL) == FZN_AUTHZ_DENIED,
	   "an unserved LOCAL is denied though authenticated");
	ok(fzn_node_decide(&c2, FZN_ORIGIN_SAME_USER, NULL, 0, 0, NULL, NULL,
	                   NULL) == FZN_AUTHZ_GRANTED_UNGUARDED,
	   "the served SAME_USER is still granted");

	/* A node that does not serve remote denies REMOTE outright. */
	c2 = cfg;
	c2.serves_remote = 0;
	ok(fzn_node_decide(&c2, FZN_ORIGIN_REMOTE, NULL, 0, 0, NULL, NULL,
	                   NULL) == FZN_AUTHZ_DENIED,
	   "a node that does not serve remote denies it");

	printf("node_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
