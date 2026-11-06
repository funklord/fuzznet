#define _POSIX_C_SOURCE 200809L

#include "permit.h"

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/* THE ESTATE'S TRUST, never a person's outside fuzznet (sec 852). */
static const char *const RESERVED[] = {
	"identity", "backup", "join", "invite", "root", "admin", "peer",
	"grant",    "capability", "revocation", "events", "permit",
	/* AND EVERY SETTING, these grants among them: a grant on `setting`
	 * would let its holder write its own. */
	"setting",  "schema",
};

int fzn_node_permit_subject_ok(const char *subject, size_t n)
{
	size_t i;

	if (!subject || n == 0u || n > FZN_PERMIT_SUBJECT_MAX)
		return 0;
	for (i = 0; i < n; i++) {
		char c = subject[i];

		if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
			return 0;
	}
	for (i = 0; i < sizeof(RESERVED) / sizeof(RESERVED[0]); i++)
		if (strlen(RESERVED[i]) == n && memcmp(RESERVED[i], subject, n) == 0)
			return 0;
	return 1;
}

/* ONE GRANT, `KIND:NAME=RIGHTS`, parsed: 1 with its fields, or 0. */
struct grant {
	int group;		/* 1 a group, 0 a user */
	int anyone;		/* `any`: every local user */
	char name[64];		/* the name, or the digits after `#` */
	int numeric;
	unsigned rights;
};

static int parse_grant(const char *w, size_t n, struct grant *g)
{
	const char *eq = memchr(w, '=', n), *name;
	size_t name_len, i, r;

	memset(g, 0, sizeof(*g));
	/* ANY LOCAL USER, sec 883: a call alone, whose procedure is handed the
	 * caller and judges it. `r` and `w` reach fuzznet's own verbs, with no
	 * judge behind them, so those always name somebody. */
	if (n == 5u && memcmp(w, "any=x", 5u) == 0) {
		g->anyone = 1;
		g->rights = FZN_PERMIT_CALL;
		return 1;
	}
	/* `local:NAME` AND `local:@GROUP`, sec 904: a local user as a principal,
	 * the spelling every rule that names one takes. `user:` and `group:` are
	 * the same two, as they were first written. */
	if (n > 7u && memcmp(w, "local:@", 7u) == 0) {
		g->group = 1;
		name = w + 7;
	} else if (n > 6u && memcmp(w, "local:", 6u) == 0) {
		name = w + 6;
	} else if (n > 6u && memcmp(w, "group:", 6u) == 0) {
		g->group = 1;
		name = w + 6;
	} else if (n > 5u && memcmp(w, "user:", 5u) == 0) {
		name = w + 5;
	} else {
		return 0;
	}
	if (!eq || eq <= name)
		return 0;
	name_len = (size_t)(eq - name);
	if (name[0] == '#') {
		g->numeric = 1;
		name++;
		name_len--;
		if (name_len == 0u || name_len > 10u)
			return 0;
		for (i = 0; i < name_len; i++)
			if (name[i] < '0' || name[i] > '9')
				return 0;
	} else {
		if (name_len == 0u || name_len >= sizeof(g->name))
			return 0;
		for (i = 0; i < name_len; i++) {
			char c = name[i];

			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
			      || c == '-' || c == '_' || c == '.'))
				return 0;
		}
	}
	memcpy(g->name, name, name_len);
	g->name[name_len] = '\0';
	/* RIGHTS: `r`, `w` and `x`, in that order, each at most once; a change
	 * without a read is not a grant anybody means. */
	r = (size_t)((w + n) - (eq + 1));
	for (i = 1; i <= r; i++) {
		unsigned bit = eq[i] == 'r' ? FZN_PERMIT_READ
		               : eq[i] == 'w' ? FZN_PERMIT_CHANGE
		               : eq[i] == 'x' ? FZN_PERMIT_CALL
		                              : 0u;

		if (!bit || g->rights >= bit)
			return 0;
		g->rights |= bit;
	}
	if (!g->rights || ((g->rights & FZN_PERMIT_CHANGE) && !(g->rights & FZN_PERMIT_READ)))
		return 0;
	return 1;
}

/* EACH GRANT IN `value`, to `each`; 0 at the first that does not parse. */
static int walk(const uint8_t *value, size_t len, int (*each)(void *, const struct grant *),
                void *ctx, int *any)
{
	size_t at = 0;

	*any = 0;
	while (at < len) {
		struct grant g;
		size_t start;

		while (at < len && value[at] == ' ')
			at++;
		if (at == len)
			break;
		start = at;
		while (at < len && value[at] != ' ')
			at++;
		if (!parse_grant((const char *)value + start, at - start, &g))
			return 0;
		*any = 1;
		if (each && each(ctx, &g))
			return 1;
	}
	return 1;
}

const char *fzn_node_permit_check(const uint8_t *value, size_t len)
{
	int any = 0;

	if (!value || !walk(value, len, NULL, NULL, &any))
		return "grants are group:NAME=r, user:NAME=rwx -- r, w, x in order, w never without r "
		       "-- or #ID for a NAME, or any=x, apart by spaces";
	return any ? NULL : "no grant";
}

struct asking {
	const fzn_peer_t *peer;
	unsigned right;
	int allowed;
};

/* 1 when `g` names `peer` and gives the right asked. */
static int matches(void *ctx, const struct grant *g)
{
	struct asking *a = ctx;
	size_t i;

	if ((g->rights & a->right) != a->right)
		return 0;
	if (g->anyone) {
		a->allowed = 1;
		return 1;
	}
	if (!g->group) {
		uid_t uid;

		if (g->numeric) {
			uid = (uid_t)strtoul(g->name, NULL, 10);
		} else {
			struct passwd pw, *found = NULL;
			char buf[1024];

			if (getpwnam_r(g->name, &pw, buf, sizeof(buf), &found) != 0 || !found)
				return 0;
			uid = found->pw_uid;
		}
		if ((uint32_t)uid == a->peer->uid)
			a->allowed = 1;
	} else {
		gid_t gid;

		if (g->numeric) {
			gid = (gid_t)strtoul(g->name, NULL, 10);
		} else {
			struct group gr, *found = NULL;
			char buf[4096];

			if (getgrnam_r(g->name, &gr, buf, sizeof(buf), &found) != 0 || !found)
				return 0;
			gid = found->gr_gid;
		}
		if ((uint32_t)gid == a->peer->primary_gid)
			a->allowed = 1;
		for (i = 0; !a->allowed && a->peer->groups_known && i < a->peer->group_count; i++)
			if (a->peer->groups[i] == (uint32_t)gid)
				a->allowed = 1;
	}
	return a->allowed;
}

int fzn_node_permit_allows(const uint8_t *value, size_t len, const fzn_peer_t *peer,
                           unsigned right)
{
	struct asking a;
	int any = 0;

	if (!value || !peer
	    || (right != FZN_PERMIT_READ && right != FZN_PERMIT_CHANGE && right != FZN_PERMIT_CALL))
		return 0;
	a.peer = peer;
	a.right = right;
	a.allowed = 0;
	/* A VALUE THAT DOES NOT PARSE GRANTS NOTHING, not its first half. */
	if (fzn_node_permit_check(value, len))
		return 0;
	(void)walk(value, len, matches, &a, &any);
	return a.allowed;
}
