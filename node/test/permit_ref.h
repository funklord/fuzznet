/* THE LOCAL PERMIT'S GRAMMAR AS node/permit.c WROTE IT BY HAND, project.md
 * sec 1415: parse_grant, walk, the check, the events' check and the
 * matching, kept whole as the oracle the reading through node/permit.situ's
 * generated code is held to (`permit_agree_fuzz`). Header-only, so nothing
 * links it and no suite counts it as a test of its own. Not to be called
 * from anything but that fuzzer.
 */
#ifndef FZN_NODE_TEST_PERMIT_REF_H
#define FZN_NODE_TEST_PERMIT_REF_H

#include "../permit.h"

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define EVERYONE_HEARS "any=r"

struct ref_grant {
	int group;		/* 1 a group, 0 a user */
	int anyone;		/* `any`: every local user */
	char name[64];		/* the name, or the digits after `#` */
	int numeric;
	unsigned rights;
};

static inline int ref_parse_grant(const char *w, size_t n, struct ref_grant *g)
{
	const char *eq = memchr(w, '=', n), *name;
	size_t name_len, i, r;

	memset(g, 0, sizeof(*g));
	/* ANY LOCAL USER, sec 883: a call alone, whose procedure is handed the
	 * caller and judges it. `r` and `w` reach fuzznet's own verbs, with no
	 * judge behind them, so those always name somebody. */
	if (n == 5u && memcmp(w, "any=x", 5u) == 0) {
		g->anyone = 1;
		g->rights = FZN_PERMIT_RRPC;
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
		/* AND ONE A USER OR GROUP CAN HAVE, sec 1444: the hand parser
		 * took ten digits and the match wrapped them into a uid_t; both
		 * sides refuse past 4294967294 now. */
		if (name_len == 10u && memcmp(name, "4294967294", 10) > 0)
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
		               : eq[i] == 'x' ? FZN_PERMIT_RRPC
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
static inline int ref_walk(const uint8_t *value, size_t len, int (*each)(void *, const struct ref_grant *),
                void *ctx, int *any)
{
	size_t at = 0;

	*any = 0;
	while (at < len) {
		struct ref_grant g;
		size_t start;

		while (at < len && value[at] == ' ')
			at++;
		if (at == len)
			break;
		start = at;
		while (at < len && value[at] != ' ')
			at++;
		if (!ref_parse_grant((const char *)value + start, at - start, &g))
			return 0;
		*any = 1;
		if (each && each(ctx, &g))
			return 1;
	}
	return 1;
}

static inline const char *ref_permit_check(const uint8_t *value, size_t len)
{
	int any = 0;

	if (!value || !ref_walk(value, len, NULL, NULL, &any))
		return "grants are group:NAME=r, user:NAME=rwx -- r, w, x in order, w never without r "
		       "-- or #ID for a NAME, or any=x, apart by spaces";
	return any ? NULL : "no grant";
}

struct ref_asking {
	const fzn_peer_t *peer;
	unsigned right;
	int allowed;
};

/* 1 when `g` names `peer` and gives the right asked. */
static inline int ref_matches(void *ctx, const struct ref_grant *g)
{
	struct ref_asking *a = ctx;
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

static inline int ref_permit_allows(const uint8_t *value, size_t len, const fzn_peer_t *peer,
                           unsigned right)
{
	struct ref_asking a;
	int any = 0;

	if (!value || !peer
	    || (right != FZN_PERMIT_READ && right != FZN_PERMIT_CHANGE && right != FZN_PERMIT_RRPC))
		return 0;
	a.peer = peer;
	a.right = right;
	a.allowed = 0;
	/* A VALUE THAT DOES NOT PARSE GRANTS NOTHING, not its first half. */
	if (ref_permit_check(value, len))
		return 0;
	(void)ref_walk(value, len, ref_matches, &a, &any);
	return a.allowed;
}

/* EACH WORD OF `value`, to `each`, until it says stop: what it said. */
static inline int ref_each_word(const uint8_t *value, size_t len,
                     int (*each)(void *ctx, const uint8_t *word, size_t n), void *ctx)
{
	size_t at = 0;

	while (at < len) {
		size_t start;
		int said;

		while (at < len && value[at] == ' ')
			at++;
		if (at == len)
			break;
		start = at;
		while (at < len && value[at] != ' ')
			at++;
		if ((said = each(ctx, value + start, at - start)) != 0)
			return said;
	}
	return 0;
}

static inline int ref_is_everyone(const uint8_t *word, size_t n)
{
	return n == sizeof(EVERYONE_HEARS) - 1u && memcmp(word, EVERYONE_HEARS, n) == 0;
}

struct ref_hearing {
	const fzn_peer_t *peer;
	size_t words;
};

/* -1 AT THE FIRST WORD THAT IS NO GRANT. */
static inline int ref_word_checks(void *ctx, const uint8_t *word, size_t n)
{
	((struct ref_hearing *)ctx)->words++;
	return ref_is_everyone(word, n) || !ref_permit_check(word, n) ? 0 : -1;
}

/* 1 AT THE FIRST WORD THAT LETS THE CALLER HEAR. */
static inline int ref_word_lets_in(void *ctx, const uint8_t *word, size_t n)
{
	return ref_is_everyone(word, n)
	       || ref_permit_allows(word, n, ((struct ref_hearing *)ctx)->peer, FZN_PERMIT_READ);
}

static inline const char *ref_permit_events_check(const uint8_t *value, size_t len)
{
	struct ref_hearing h;

	h.peer = NULL;
	h.words = 0;
	if (!value || ref_each_word(value, len, ref_word_checks, &h) != 0)
		return "grants are local:NAME=r or local:@GROUP=r, or #ID for a NAME, or any=r for every "
		       "local user, apart by spaces";
	return h.words ? NULL : "no grant";
}

static inline int ref_permit_hears(const uint8_t *value, size_t len, const fzn_peer_t *peer)
{
	struct ref_hearing h;

	h.peer = peer;
	h.words = 0;
	if (!peer || ref_permit_events_check(value, len))
		return 0;
	return ref_each_word(value, len, ref_word_lets_in, &h) == 1;
}

#endif
