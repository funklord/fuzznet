#define _POSIX_C_SOURCE 200809L
#include "log_list.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../local/escape.h"

/* ONE PAGE AT MOST: a reply is FZN_REPLY_MAX bytes and an entry at least a
 * dozen, so no page holds more than this many. */
#define PAGE_MAX (FZN_REPLY_MAX / 12u)
/* An entry's text in a reply, escaped: as much as leaves room for the
 * reply's head and the entry's other fields, so one entry always fits. */
#define TEXT_MAX (FZN_REPLY_MAX - 192u)

static int next_word(const uint8_t **at, size_t *left, const uint8_t **w, size_t *n)
{
	while (*left && **at == ' ') {
		(*at)++;
		(*left)--;
	}
	if (!*left)
		return 0;
	*w = *at;
	while (*left && **at != ' ') {
		(*at)++;
		(*left)--;
	}
	*n = (size_t)(*at - *w);
	return 1;
}

static int from_of(const uint8_t *w, size_t n, size_t *from)
{
	size_t i;

	if (!n || n > 10u)
		return 0;
	*from = 0;
	for (i = 0; i < n; i++) {
		if (w[i] < '0' || w[i] > '9')
			return 0;
		*from = *from * 10u + (size_t)(w[i] - '0');
	}
	return 1;
}

/* A level's letter read back, 0 for one that is not. */
static fzn_entry_level_t level_of(const uint8_t *w, size_t n)
{
	int l;

	if (n != 1u)
		return 0;
	for (l = FZN_ENTRY_CRITICAL; l <= FZN_ENTRY_TRACE; l++)
		if (fzn_entry_level_letter((fzn_entry_level_t)l) == (char)w[0])
			return (fzn_entry_level_t)l;
	return 0;
}

/* AN ENTRY KEPT FOR THE PAGE, copied: the ring's is valid only during the
 * walk. */
struct kept {
	uint64_t time_us;
	fzn_entry_level_t level;
	char subsystem[FZN_ENTRY_SUBSYSTEM_MAX + 1u];
	char text[TEXT_MAX + 1u];
	size_t text_len;
	int cut;
};

/* THE WALK, oldest first: entries at `level` or more severe counted, and
 * the ones from the `first`th to before the `last`th kept, which are the
 * page's once the walk knows how many there are. Two walks, the first to
 * count, since the page is counted back from the newest. */
struct walk {
	fzn_entry_level_t level;
	size_t seen, first, last;
	struct kept *kept;
	size_t n_kept;
};

static void counted(void *ctx, const fzn_entry_t *e)
{
	struct walk *w = ctx;

	if (e->level >= FZN_ENTRY_CRITICAL && e->level <= w->level)
		w->seen++;
}

static void taken(void *ctx, const fzn_entry_t *e)
{
	struct walk *w = ctx;
	struct kept *k;
	size_t used;

	if (e->level < FZN_ENTRY_CRITICAL || e->level > w->level)
		return;
	if (w->seen >= w->first && w->seen < w->last && w->n_kept < PAGE_MAX) {
		k = &w->kept[w->n_kept++];
		k->time_us = e->time_us;
		k->level = e->level;
		(void)snprintf(k->subsystem, sizeof(k->subsystem), "%s", e->subsystem);
		used = fzn_escape(e->text, e->text_len, k->text, sizeof(k->text) - 1u, &k->text_len);
		k->text[k->text_len] = '\0';
		k->cut = used < e->text_len;
	}
	w->seen++;
}

#define REPLY(...) ((size_t)snprintf(reply, cap, __VA_ARGS__))

size_t fzn_node_log_list_local(const fzn_ring_t *ring, fzn_origin_t origin,
                               const fzn_request_t *request, char *reply, size_t cap)
{
	static struct kept kept[PAGE_MAX];
	const uint8_t *at = request ? request->arg : NULL, *w;
	size_t left = request ? request->arg_len : 0u, n, from = 0, at_out, i;
	fzn_entry_level_t level = FZN_ENTRY_INFO;
	struct walk walk;

	if (!at || request->parsed != FZN_VERB_LIST || !next_word(&at, &left, &w, &n) || n != 3u
	    || memcmp(w, "log", 3u) != 0)
		return 0;
	if (!reply || cap < 2u)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return REPLY("denied this node's log is its own user's\n");
	if (next_word(&at, &left, &w, &n) && !from_of(w, n, &from))
		return REPLY("malformed list log [FROM] [LEVEL]\n");
	if (next_word(&at, &left, &w, &n) && (left || !(level = level_of(w, n))))
		return REPLY("malformed list log [FROM] [LEVEL], a level one of C E W N I V D T\n");
	if (!ring)
		return REPLY("error this node keeps no log to read\n");

	memset(&walk, 0, sizeof(walk));
	walk.level = level;
	(void)fzn_ring_walk(ring, counted, &walk);
	if (from > walk.seen)
		from = walk.seen;
	/* THE PAGE, newest first: the entries before the `from` newest, as many
	 * as one page may hold, taken oldest first and written the other way. */
	walk.last = walk.seen - from;
	walk.first = walk.last > PAGE_MAX ? walk.last - PAGE_MAX : 0u;
	walk.kept = kept;
	{
		size_t total = walk.seen;

		walk.seen = 0;
		(void)fzn_ring_walk(ring, taken, &walk);
		at_out = (size_t)snprintf(reply, cap, "ok %zu %zu", total, from);
	}
	for (i = walk.n_kept; i > 0u; i--) {
		const struct kept *k = &kept[i - 1u];
		int m;

		/* WHAT FITS: an entry that would pass the reply's end ends the
		 * page, with room for the newline kept. */
		m = snprintf(reply + at_out, cap - at_out, " %llu,%c,%s,%d,%s",
		             (unsigned long long)k->time_us, fzn_entry_level_letter(k->level),
		             k->subsystem, k->cut, k->text);
		if (m < 0 || (size_t)m + 1u >= cap - at_out) {
			reply[at_out] = '\0';
			break;
		}
		at_out += (size_t)m;
	}
	return at_out + (size_t)snprintf(reply + at_out, cap - at_out, "\n");
}
