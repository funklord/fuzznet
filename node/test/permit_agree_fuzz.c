/* THE LOCAL PERMIT READ THROUGH SITU'S CODE AGAINST THE PARSER IT REPLACED,
 * project.md sec 1415: node/permit.c, which reads a permit through the code
 * situ generates from node/permit.situ, and `node/test/permit_ref.h`, the
 * hand parser it was until then, kept whole as the oracle. Each is given the
 * same seeded values -- grants whole, grants broken, spaces leading, doubled
 * and trailing, names and ids at their bounds, stray bytes -- and every
 * verdict is compared: the permit's check, the events' check, whether each
 * right is granted to a caller, whether a caller hears.
 *
 * Callers are matched by NUMBER (`#ID`): a name is looked up in this
 * machine's user and group tables, which both sides read alike, but which
 * differ between machines -- `root` among the names drawn keeps one such
 * lookup in every run.
 *
 * NO DIFFERENCE IS ACCEPTED. Exit 0 when nothing differed; 1 with each kind
 * of difference, how often, and the first value. `make fuzz CASES=N` asks N.
 */

#define _POSIX_C_SOURCE 200809L

#include "../permit.h"
#include "permit_ref.h"
#include "remote_permit_ref.h"
#include "group_list_ref.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STEPS 200000u

static uint64_t rng = 0x1415u;

static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (uint32_t)rng;
}

/* THE PIECES A VALUE IS DRAWN FROM: the grammar's words, near misses of
 * them, and what lies between. */
static const char *const PARTS[] = {
	"local:", "group:", "user:", "local:@", "any=x", "any=r", "any=", "alice", "root", "wheel", "#1001", "#0",
	"#", "#4294967295", "#9999999999", "#99999999999", "#007", "@", "=", "r", "w", "x", "rw", "rx", "rwx", "wr",
	"xr", "rr", "=r", "=rw", "=rx", "=rwx", "=w", "=x", " ", "  ", "a.b-c_d", ",", "/", "Z9", ":", "local",
	"grp:", "=r=", "\t", "local:#1001=rwx", "group:#0=r", "user:#7=x", "local:@#1001=rw",
};

static unsigned differ[6];
static char first[6][256];

static void note(unsigned kind, const char *v)
{
	if (!differ[kind]++)
		snprintf(first[kind], sizeof(first[kind]), "%s", v);
}

/* A VALUE AT A BOUND: a name of 60 to 66 bytes or an id of 8 to 12 digits,
 * under one of the four ways to name somebody. */
static size_t bound(char *v, size_t cap)
{
	static const char *const pre[] = { "local:", "group:", "user:", "local:@" };
	const char *p = pre[next() % 4u];
	size_t n = (size_t)snprintf(v, cap, "%s", p), k;

	if (next() % 2u) {
		v[n++] = '#';
		for (k = 8u + next() % 5u; k && n + 4u < cap; k--)
			v[n++] = (char)('0' + next() % 10u);
	} else {
		for (k = 60u + next() % 7u; k && n + 4u < cap; k--)
			v[n++] = (char)('a' + next() % 26u);
	}
	n += (size_t)snprintf(v + n, cap - n, "=%s", next() % 2u ? "rw" : "x");
	return n;
}

/* THE REMOTE PERMIT'S PIECES, sec 1440: its words, near misses, a host key
 * at, below and past 64 digits, upper case, and what lies between. */
static const char *const REMOTE[] = {
	"member", "admin", "root", "none", "host:", " ", "  ", "nonee", "Member", "memb", "rootx", "host", "h",
	"n", "m", "a", "r", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", "0123456789abcdef", "f", "g",
	"\t", "=", ":",
};

/* Each value given to both remote checks: the same answer, word for word. */
static void remote_step(void)
{
	char v[400];
	size_t n = 0, k;
	const char *a, *b;

	v[0] = '\0';
	for (k = 1u + next() % 5u; k; k--) {
		n += (size_t)snprintf(v + n, sizeof(v) - n, "%s", REMOTE[next() % (sizeof(REMOTE) / sizeof(REMOTE[0]))]);
		if (next() % 2u && n + 1u < sizeof(v))
			v[n++] = ' ', v[n] = '\0';
	}
	if (next() % 3u == 0u && n)
		n--;
	if (next() % 10u == 0u && n)
		v[next() % n] = (char)(next() & 0x7fu);
	a = fzn_node_remote_permit_check((const uint8_t *)v, n);
	b = ref_remote_permit_check((const uint8_t *)v, n);
	if ((a == NULL) != (b == NULL) || (a && strcmp(a, b) != 0)) {
		v[n < sizeof(v) ? n : sizeof(v) - 1u] = '\0';
		note(4, v);
	}
}

/* THE GROUP LIST'S PIECES, sec 1441: names at, below and past 32, their
 * characters and near misses, names repeated, and the spaces between. */
static const char *const GROUPS[] = {
	"a", "b", "family", "work.team", "x_y-z", " ", "  ", "A", "a b", "0123456789abcdef0123456789abcdef",
	"0123456789abcdef0123456789abcdef0", "q", "family", "!", "\t", "z9", ".",
};

/* Each value given to both group checks, up to 20 names so past the 16. */
static void group_step(void)
{
	char v[800];
	size_t n = 0, k;
	const char *a, *b;

	v[0] = '\0';
	for (k = 1u + next() % 20u; k; k--) {
		n += (size_t)snprintf(v + n, sizeof(v) - n, "%s", GROUPS[next() % (sizeof(GROUPS) / sizeof(GROUPS[0]))]);
		if (next() % 3u && n + 1u < sizeof(v))
			v[n++] = ' ', v[n] = '\0';
	}
	if (next() % 3u == 0u && n)
		n--;
	a = fzn_node_group_list_check((const uint8_t *)v, n);
	b = ref_group_list_check((const uint8_t *)v, n);
	if ((a == NULL) != (b == NULL) || (a && strcmp(a, b) != 0)) {
		v[n < 255u ? n : 255u] = '\0';
		note(5, v);
	}
}

int main(int argc, char **argv)
{
	static const char *const kinds[6] = { "permit check", "events check", "a right granted", "heard", "remote permit", "group list" };
	static const unsigned rights[3] = { FZN_PERMIT_READ, FZN_PERMIT_CHANGE, FZN_PERMIT_RRPC };
	const unsigned steps = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : STEPS;
	unsigned step, taken = 0, granted = 0, i;
	char v[256];

	for (step = 0; step < steps; step++) {
		fzn_peer_t peer;
		size_t n = 0, k;
		int a, b;

		if (next() % 8u == 0u) {
			n = bound(v, sizeof(v));
		} else {
			v[0] = '\0';
			for (k = 1u + next() % 7u; k && n < 200u; k--)
				n += (size_t)snprintf(v + n, sizeof(v) - n, "%s", PARTS[next() % (sizeof(PARTS) / sizeof(PARTS[0]))]);
			if (next() % 8u == 0u && n)
				v[next() % n] = (char)(next() & 0x7fu);
			n = strlen(v);
		}
		a = fzn_node_permit_check((const uint8_t *)v, n) == NULL;
		b = ref_permit_check((const uint8_t *)v, n) == NULL;
		if (a != b)
			note(0, v);
		taken += (unsigned)a;
		if ((fzn_node_permit_events_check((const uint8_t *)v, n) == NULL)
		    != (ref_permit_events_check((const uint8_t *)v, n) == NULL))
			note(1, v);
		/* A CALLER BY NUMBER: its uid, primary group and one more, drawn
		 * from the ids the values name and some they do not. */
		memset(&peer, 0, sizeof(peer));
		peer.uid = next() % 3u == 0u ? 1001u : next() % 2u ? 7u : 0u;
		peer.primary_gid = next() % 2u ? 0u : 1001u;
		peer.groups[0] = next() % 2u ? 4294967295u : 1410065407u; /* 9999999999 as 32 bits */
		peer.group_count = 1u;
		peer.groups_known = (int)(next() % 2u);
		for (i = 0; i < 3u; i++) {
			a = fzn_node_permit_allows((const uint8_t *)v, n, &peer, rights[i]);
			b = ref_permit_allows((const uint8_t *)v, n, &peer, rights[i]);
			if (a != b)
				note(2, v);
			granted += (unsigned)a;
		}
		if (fzn_node_permit_hears((const uint8_t *)v, n, &peer) != ref_permit_hears((const uint8_t *)v, n, &peer))
			note(3, v);
		remote_step();
		group_step();
	}
	printf("permit_agree_fuzz: %u values, %u permits taken by both, %u rights granted by both, %u remote "
	       "permits and %u group lists alike; %u difference(s)\n",
	       steps, taken, granted, steps - differ[4], steps - differ[5],
	       differ[0] + differ[1] + differ[2] + differ[3] + differ[4] + differ[5]);
	for (i = 0; i < 6u; i++)
		if (differ[i])
			printf("  %s: %u, first \"%s\"\n", kinds[i], differ[i], first[i]);
	return differ[0] + differ[1] + differ[2] + differ[3] + differ[4] + differ[5] ? 1 : 0;
}
