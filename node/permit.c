#define _POSIX_C_SOURCE 200809L

#include "permit.h"

#include "../wire/generated/permit.h"

#include <grp.h>
#include <stdio.h>
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

/* EVERY LOCAL USER MAY HEAR THE APPLICATION, sec 933: a word of `local/events`
 * and of nothing else, so no fuzznet verb is ever anyone's. */
#define EVERYONE_HEARS "any=r"

/* ONE GRANT, `KIND:NAME=RIGHTS`, parsed: 1 with its fields, or 0. */
struct grant {
	int group;		/* 1 a group, 0 a user */
	int anyone;		/* `any`: every local user */
	char name[64];		/* the name, or the digits after `#` */
	int numeric;
	unsigned rights;
};

/* `target` -- a name, or `#` and digits -- into `g`: 1, or 0 for no target. */
static int target_of(situ_view_t t, struct grant *g)
{
	situ_view_t b;

	if (fzn_permit_target_first_get(t) == '#') {
		uint64_t id = 0;

		if (fzn_permit_target_body_id_view(t, &b) != SITU_OK || fzn_permit_numeric_id_get(b, &id) != SITU_OK)
			return 0;
		g->numeric = 1;
		/* ITS DIGITS AS WRITTEN UP TO TEN, read back by `strtoul` where a
		 * caller is matched, as the hand parser kept them. */
		(void)snprintf(g->name, sizeof(g->name), "%llu", (unsigned long long)id);
		return 1;
	}
	if (fzn_permit_target_body_text_view(t, &b) != SITU_OK || fzn_permit_text_name_text_len(b) == 0u
	    || fzn_permit_text_name_text_len(b) >= sizeof(g->name))
		return 0;
	memcpy(g->name, fzn_permit_text_name_text_ptr(b), fzn_permit_text_name_text_len(b));
	g->name[fzn_permit_text_name_text_len(b)] = '\0';
	return 1;
}

/* RIGHTS by their spelling, one of five (`node/permit.situ`'s `rights_word`):
 * r, w and x in order, w never without r. 0 for none of them. */
static unsigned rights_of(const uint8_t *word, uint32_t len)
{
	switch (fzn_permit_rights_word_which(word, len)) {
	case FZN_PERMIT_RIGHTS_WORD_R:
		return FZN_PERMIT_READ;
	case FZN_PERMIT_RIGHTS_WORD_RW:
		return FZN_PERMIT_READ | FZN_PERMIT_CHANGE;
	case FZN_PERMIT_RIGHTS_WORD_RX:
		return FZN_PERMIT_READ | FZN_PERMIT_RRPC;
	case FZN_PERMIT_RIGHTS_WORD_RWX:
		return FZN_PERMIT_READ | FZN_PERMIT_CHANGE | FZN_PERMIT_RRPC;
	case FZN_PERMIT_RIGHTS_WORD_X:
		return FZN_PERMIT_RRPC;
	default:
		return 0u;
	}
}

/* ONE GRANT of a view that validated, into `g`: 1, or 0 for one this
 * grammar does not take -- `any=r`, which is the events' alone. */
static int grant_of(situ_view_t v, struct grant *g)
{
	situ_view_t b, w, t;
	const uint8_t *rights;
	uint32_t rights_len;

	memset(g, 0, sizeof(*g));
	switch (fzn_permit_grant_kind_get(v)) {
	case 'a':
		/* ANY LOCAL USER, sec 883: a call alone, whose procedure is handed
		 * the caller and judges it. `r` and `w` reach fuzznet's own verbs,
		 * with no judge behind them, so those always name somebody. */
		{
			const uint8_t *word = NULL;
			uint32_t word_len = 0;

			if (fzn_permit_grant_body_anyone_ptr(v, &word, &word_len) != SITU_OK || word_len != 5u
			    || memcmp(word, "any=x", 5u) != 0)
				return 0;
		}
		g->anyone = 1;
		g->rights = FZN_PERMIT_RRPC;
		return 1;
	case 'l':
		/* `local:NAME` AND `local:@GROUP`, sec 904: a local user as a
		 * principal, the spelling every rule that names one takes. */
		if (fzn_permit_grant_body_local_view(v, &b) != SITU_OK || fzn_permit_local_grant_who_view(b, &w) != SITU_OK)
			return 0;
		if (fzn_permit_local_target_first_get(w) == '@') {
			g->group = 1;
			if (fzn_permit_local_target_body_group_view(w, &t) != SITU_OK
			    || fzn_permit_group_target_who_view(t, &t) != SITU_OK)
				return 0;
		} else if (fzn_permit_local_target_body_user_view(w, &t) != SITU_OK) {
			return 0;
		}
		rights = fzn_permit_local_grant_rights_ptr(b);
		rights_len = fzn_permit_local_grant_rights_len(b);
		break;
	case 'g':
		/* `user:` AND `group:` are the same two, as they were first written. */
		g->group = 1;
		if (fzn_permit_grant_body_group_view(v, &b) != SITU_OK || fzn_permit_group_grant_who_view(b, &t) != SITU_OK)
			return 0;
		rights = fzn_permit_group_grant_rights_ptr(b);
		rights_len = fzn_permit_group_grant_rights_len(b);
		break;
	case 'u':
		if (fzn_permit_grant_body_user_view(v, &b) != SITU_OK || fzn_permit_user_grant_who_view(b, &t) != SITU_OK)
			return 0;
		rights = fzn_permit_user_grant_rights_ptr(b);
		rights_len = fzn_permit_user_grant_rights_len(b);
		break;
	default:
		return 0;
	}
	g->rights = rights_of(rights, rights_len);
	return g->rights && target_of(t, g);
}

/* EACH GRANT IN `value`, to `each`, read through node/permit.situ's code
 * (sec 1415); 0 when the value is no permit. Spaces after the last grant
 * are trimmed here, as situ's design leaves them (the run would ask for one
 * more grant there); that the grants reach the value's end is situ's since
 * b1b05486 (sec 1420), its run refusing what is left after the last one. */
static int walk(const uint8_t *value, size_t len, int (*each)(void *, const struct grant *),
                void *ctx, int *any)
{
	situ_msg_t m;
	situ_view_t p, v;
	uint32_t i, count;
	struct grant g;

	*any = 0;
	while (len && value[len - 1u] == ' ')
		len--;
	if (len == 0u)
		return 1;
	if (len > UINT32_MAX)
		return 0;
	situ_msg_init(&m, (uint8_t *)(uintptr_t)value, (uint32_t)len);
	if (fzn_permit_permit_view(&m, 0u, (uint32_t)len, &p) != SITU_OK || fzn_permit_permit_validate(p) != SITU_OK)
		return 0;
	count = fzn_permit_permit_grants_count(p);
	for (i = 0; i < count; i++)
		if (fzn_permit_permit_grants_at(p, i, &v) != SITU_OK || !grant_of(v, &g))
			return 0;
	for (i = 0; i < count; i++) {
		(void)fzn_permit_permit_grants_at(p, i, &v);
		(void)grant_of(v, &g);
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
	    || (right != FZN_PERMIT_READ && right != FZN_PERMIT_CHANGE && right != FZN_PERMIT_RRPC))
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

/* EACH WORD OF `value`, to `each`, until it says stop: what it said. */
static int each_word(const uint8_t *value, size_t len,
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

static int is_everyone(const uint8_t *word, size_t n)
{
	return n == sizeof(EVERYONE_HEARS) - 1u && memcmp(word, EVERYONE_HEARS, n) == 0;
}

struct hearing {
	const fzn_peer_t *peer;
	size_t words;
};

/* -1 AT THE FIRST WORD THAT IS NO GRANT. */
static int word_checks(void *ctx, const uint8_t *word, size_t n)
{
	((struct hearing *)ctx)->words++;
	return is_everyone(word, n) || !fzn_node_permit_check(word, n) ? 0 : -1;
}

/* 1 AT THE FIRST WORD THAT LETS THE CALLER HEAR. */
static int word_lets_in(void *ctx, const uint8_t *word, size_t n)
{
	return is_everyone(word, n)
	       || fzn_node_permit_allows(word, n, ((struct hearing *)ctx)->peer, FZN_PERMIT_READ);
}

const char *fzn_node_permit_events_check(const uint8_t *value, size_t len)
{
	struct hearing h;

	h.peer = NULL;
	h.words = 0;
	if (!value || each_word(value, len, word_checks, &h) != 0)
		return "grants are local:NAME=r or local:@GROUP=r, or #ID for a NAME, or any=r for every "
		       "local user, apart by spaces";
	return h.words ? NULL : "no grant";
}

int fzn_node_permit_hears(const uint8_t *value, size_t len, const fzn_peer_t *peer)
{
	struct hearing h;

	h.peer = peer;
	h.words = 0;
	if (!peer || fzn_node_permit_events_check(value, len))
		return 0;
	return each_word(value, len, word_lets_in, &h) == 1;
}

/* ---- who may call from another host, sec 921 -------------------------------- */

#define REMOTE_HOST_WORD "host:"
#define REMOTE_HOST_WORD_LEN 5u

static int hex_value(uint8_t c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static int word_is(const uint8_t *word, size_t n, const char *name)
{
	return n == strlen(name) && memcmp(word, name, n) == 0;
}

/* `word` as a key, when it is `host:HEX`. */
static int host_word(const uint8_t *word, size_t n, uint8_t key[FZN_PUBKEY_LEN])
{
	size_t i;

	if (n != REMOTE_HOST_WORD_LEN + 2u * FZN_PUBKEY_LEN
	    || memcmp(word, REMOTE_HOST_WORD, REMOTE_HOST_WORD_LEN) != 0)
		return 0;
	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		int hi = hex_value(word[REMOTE_HOST_WORD_LEN + 2u * i]);
		int lo = hex_value(word[REMOTE_HOST_WORD_LEN + 2u * i + 1u]);

		if (hi < 0 || lo < 0)
			return 0;
		key[i] = (uint8_t)((hi << 4) | lo);
	}
	return 1;
}

const char *fzn_node_remote_permit_check(const uint8_t *value, size_t len)
{
	static const char *const SHAPE =
	        "a rule is member, admin, root, host:HEX or none, apart by spaces";
	uint8_t key[FZN_PUBKEY_LEN];
	size_t at = 0, words = 0;
	int none = 0;

	if (!value || !len)
		return SHAPE;
	while (at < len) {
		size_t n = 0;

		while (at + n < len && value[at + n] != ' ')
			n++;
		if (!n)
			return SHAPE;
		if (word_is(value + at, n, "none"))
			none = 1;
		else if (!word_is(value + at, n, "member") && !word_is(value + at, n, "admin")
		         && !word_is(value + at, n, "root") && !host_word(value + at, n, key))
			return SHAPE;
		words++;
		at += n;
		if (at < len && ++at == len)
			return SHAPE;
	}
	return none && words > 1u ? "none stands alone" : NULL;
}

int fzn_node_remote_permit_allows(const uint8_t *value, size_t len,
                                  const uint8_t host[FZN_PUBKEY_LEN], fzn_setting_rank_t rank)
{
	uint8_t key[FZN_PUBKEY_LEN];
	size_t at = 0;

	if (!host || fzn_node_remote_permit_check(value, len))
		return 0;
	while (at < len) {
		size_t n = 0;

		while (at + n < len && value[at + n] != ' ')
			n++;
		if (word_is(value + at, n, "member")
		    || (word_is(value + at, n, "admin") && rank >= FZN_SETTING_RANK_ADMIN)
		    || (word_is(value + at, n, "root") && rank >= FZN_SETTING_RANK_ROOT)
		    || (host_word(value + at, n, key) && memcmp(key, host, FZN_PUBKEY_LEN) == 0))
			return 1;
		at += n + 1u;
	}
	return 0;
}
