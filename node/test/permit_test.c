/* node/permit.h, sec 852: which local users and groups the node's own user
 * lets read or change a verb's subject -- the grammar a setting holds, the
 * subjects never grantable, and a caller matched by user, primary group or
 * supplementary group, by number and by name. */
#include "../permit.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL permit_test.c: %s\n", what);
	}
}

static int allows(const char *value, const fzn_peer_t *p, unsigned right)
{
	return fzn_node_permit_allows((const uint8_t *)value, strlen(value), p, right);
}

static const char *check(const char *value)
{
	return fzn_node_permit_check((const uint8_t *)value, strlen(value));
}

static void peer_of(fzn_peer_t *p, uint32_t uid, uint32_t gid, int known, uint32_t extra)
{
	memset(p, 0, sizeof(*p));
	p->uid = uid;
	p->primary_gid = gid;
	p->groups_known = known;
	if (known && extra) {
		p->groups[0] = extra;
		p->group_count = 1;
	}
}

static const char *remote_check(const char *value)
{
	return fzn_node_remote_permit_check((const uint8_t *)value, strlen(value));
}

static int remote_rule(const char *value, const uint8_t *host, fzn_setting_rank_t rank)
{
	return fzn_node_remote_permit_allows((const uint8_t *)value, strlen(value), host, rank);
}

int main(void)
{
	fzn_peer_t p;

	/* THE GRAMMAR. */
	ok(check("local:alice=rw local:@netcfgd=r local:#1001=x") == NULL,
	   "a local user or group, as a principal, was refused");
	ok(check("local:=r") && check("local:@=r") && check("local:alice"),
	   "a local principal with no name or no rights was taken");
	ok(check("group:netcfgd=r") == NULL && check("user:alice=rw  group:#44=r") == NULL,
	   "well-formed grants were refused");
	ok(check("user:a=x") == NULL && check("user:a=rx") == NULL && check("user:a=rwx") == NULL,
	   "a call grant was refused");
	ok(check("user:a=xr") && check("user:a=rr") && check("user:a=wx") && check("user:a=rq"),
	   "rights out of order, twice, a change without a read or an unknown right were taken");
	ok(check("") && check("group:netcfgd") && check("group:netcfgd=w") && check("host:x=r")
	           && check("user:=r") && check("user:#=r") && check("user:#12a=r")
	           && check("user:a b=r") && check("user:al;ice=r"),
	   "a malformed grant was taken");
	/* THE TRUST, never grantable. */
	ok(fzn_node_permit_subject_ok("record", 6u) && fzn_node_permit_subject_ok("status", 6u),
	   "an ordinary subject was not grantable");
	ok(!fzn_node_permit_subject_ok("identity", 8u) && !fzn_node_permit_subject_ok("setting", 7u)
	           && !fzn_node_permit_subject_ok("permit", 6u) && !fzn_node_permit_subject_ok("join", 4u)
	           && !fzn_node_permit_subject_ok("events", 6u) && !fzn_node_permit_subject_ok("Record", 6u)
	           && !fzn_node_permit_subject_ok("a-b", 3u) && !fzn_node_permit_subject_ok("", 0u),
	   "a trust subject, or one no setting key can name, was grantable");
	/* BY NUMBER: user, primary group, supplementary group. */
	peer_of(&p, 2001, 2001, 1, 77);
	ok(allows("local:#2001=r", &p, FZN_PERMIT_READ) && allows("local:@#77=r", &p, FZN_PERMIT_READ)
	           && !allows("local:#2002=r", &p, FZN_PERMIT_READ),
	   "local: did not name the user and group it says");
	ok(allows("user:#2001=r", &p, FZN_PERMIT_READ) && !allows("user:#2001=r", &p, FZN_PERMIT_CHANGE),
	   "a read grant was not a read, or was a change");
	ok(allows("user:#2001=rw", &p, FZN_PERMIT_CHANGE) && allows("user:#2001=rw", &p, FZN_PERMIT_READ),
	   "a change grant did not give both");
	ok(allows("group:#77=r", &p, FZN_PERMIT_READ) && allows("group:#2001=r", &p, FZN_PERMIT_READ),
	   "a supplementary or primary group did not match");
	ok(!allows("user:#2002=rw group:#78=rw", &p, FZN_PERMIT_READ),
	   "a grant to somebody else was taken as this caller's");
	ok(allows("user:#9=r group:#77=rw", &p, FZN_PERMIT_CHANGE), "a later grant was not read");
	ok(allows("user:#2001=x", &p, FZN_PERMIT_CALL) && !allows("user:#2001=x", &p, FZN_PERMIT_READ)
	           && !allows("user:#2001=rw", &p, FZN_PERMIT_CALL),
	   "a call grant was not a call alone");
	/* ANY LOCAL USER, sec 883: a call, and nothing else. */
	ok(check("any=x") == NULL && check("user:a=r any=x") == NULL, "any=x was refused");
	ok(check("any=r") && check("any=rx") && check("any=rw") && check("any=rwx") && check("any=")
	           && check("any") && check("any:x=x"),
	   "any with more than a call was taken");
	ok(allows("any=x", &p, FZN_PERMIT_CALL), "any=x did not let a local user call");
	ok(!allows("any=x", &p, FZN_PERMIT_READ) && !allows("any=x", &p, FZN_PERMIT_CHANGE),
	   "any=x gave more than a call");
	/* A GROUP LIST NOT READ is no membership. */
	peer_of(&p, 2001, 2001, 0, 0);
	p.groups[0] = 77;
	p.group_count = 1;
	ok(!allows("group:#77=r", &p, FZN_PERMIT_READ),
	   "a group list the socket could not read was trusted");
	/* A VALUE THAT DOES NOT PARSE grants nothing, not its first half. */
	peer_of(&p, 2001, 2001, 1, 0);
	ok(!allows("user:#2001=r user:bad=q", &p, FZN_PERMIT_READ),
	   "half a malformed value was taken");
	/* BY NAME, from this machine's databases: root is uid 0, group root 0. */
	peer_of(&p, 0, 0, 1, 0);
	ok(allows("user:root=r", &p, FZN_PERMIT_READ) && allows("group:root=r", &p, FZN_PERMIT_READ),
	   "a name was not looked up");
	ok(!allows("user:no-such-user-here=rw", &p, FZN_PERMIT_READ),
	   "a name that does not resolve granted something");

	/* WHO MAY CALL FROM ANOTHER HOST, sec 921. */
	{
		static const char HEX_A[] =
		        "host:0101010101010101010101010101010101010101010101010101010101010101";
		uint8_t a[FZN_PUBKEY_LEN], b[FZN_PUBKEY_LEN];
		char two[160];

		memset(a, 1, sizeof(a));
		memset(b, 2, sizeof(b));
		ok(remote_rule("member", a, FZN_SETTING_RANK_HOST), "member let no member in");
		ok(!remote_rule("admin", a, FZN_SETTING_RANK_HOST)
		           && remote_rule("admin", a, FZN_SETTING_RANK_ADMIN)
		           && remote_rule("admin", a, FZN_SETTING_RANK_ROOT),
		   "admin was not admin and above");
		ok(!remote_rule("root", a, FZN_SETTING_RANK_ADMIN)
		           && remote_rule("root", a, FZN_SETTING_RANK_ROOT),
		   "root was not the root's");
		ok(!remote_rule("none", a, FZN_SETTING_RANK_ROOT), "none let the root in");
		ok(remote_rule(HEX_A, a, FZN_SETTING_RANK_HOST)
		           && !remote_rule(HEX_A, b, FZN_SETTING_RANK_ROOT),
		   "host:HEX did not name one host alone");
		(void)snprintf(two, sizeof(two), "root %s", HEX_A);
		ok(remote_rule(two, a, FZN_SETTING_RANK_HOST) && remote_rule(two, b, FZN_SETTING_RANK_ROOT)
		           && !remote_rule(two, b, FZN_SETTING_RANK_ADMIN),
		   "a list did not let in each it named, and only them");
		ok(remote_check("member") == NULL && remote_check(two) == NULL, "a rule was refused");
		ok(remote_check("") && remote_check(" member") && remote_check("member ")
		           && remote_check("member  root") && remote_check("host:01")
		           && remote_check("Member") && remote_check("none root"),
		   "a rule out of shape was taken");
		/* A VALUE THAT DOES NOT PARSE lets nobody in, not by its first half. */
		ok(!remote_rule("member nonsense", a, FZN_SETTING_RANK_ROOT),
		   "half a malformed rule was taken");
	}

	printf("permit_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
