/* See attachments.h. */

#include "attachments.h"

#include "../messages/line.h"
#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

/* An entry's row: its month, the size its reference claims, its file's
 * root, its hold's id, and whether its hold is released. */
#define E_EPOCH 0u
#define E_SIZE 4u
#define E_ROOT 12u
#define E_HOLD 44u
#define E_RELEASED 76u
#define E_LEN 77u

static const uint8_t NOBODY[32];

/* A row's place in FZN_PERSIST_ATTACHMENT: what it is, whose, and a
 * number. */
static int row_of(const fzn_attachments_t *a, const char *what, const uint8_t key[32],
                  uint64_t n, uint8_t row[32])
{
	static const char DOMAIN[] = "fuzznet.attachment.";
	uint8_t in[sizeof(DOMAIN) - 1u + 8u + 32u + 8u];
	size_t at = sizeof(DOMAIN) - 1u, w = strlen(what);

	memset(in, 0, sizeof(in));
	memcpy(in, DOMAIN, at);
	memcpy(in + at, what, w > 8u ? 8u : w);
	at += 8u;
	memcpy(in + at, key, 32u);
	fzn_put_be64(in + at + 32u, n);
	return a->hash->hash(a->hash->ctx, row, 32u, in, sizeof(in));
}

static uint64_t number(const fzn_attachments_t *a, const char *what, const uint8_t key[32])
{
	uint8_t row[32], b[8];
	size_t len = 0;

	if (!row_of(a, what, key, 0u, row)
	    || !a->store->load(a->store->ctx, FZN_PERSIST_ATTACHMENT, row, b, sizeof(b), &len)
	    || len != sizeof(b))
		return 0u;
	return fzn_get_be64(b);
}

static int number_save(const fzn_attachments_t *a, const char *what, const uint8_t key[32],
                       uint64_t v)
{
	uint8_t row[32], b[8];

	fzn_put_be64(b, v);
	return row_of(a, what, key, 0u, row)
	       && a->store->save(a->store->ctx, FZN_PERSIST_ATTACHMENT, row, b, sizeof(b));
}

static int ready(const fzn_attachments_t *a)
{
	return a && a->store && a->store->load && a->store->save && a->store->remove && a->hash
	       && a->hash->hash;
}

static fzn_file_holds_t holds_of(const fzn_attachments_t *a)
{
	fzn_file_holds_t h;

	h.store = a->store;
	h.hash = a->hash;
	return h;
}

uint64_t fzn_attachments_count(const fzn_attachments_t *a, const uint8_t contact[32])
{
	return ready(a) && contact ? number(a, "count", contact) : 0u;
}

static int entry_load(const fzn_attachments_t *a, const uint8_t contact[32], uint64_t i,
                      uint8_t e[E_LEN])
{
	uint8_t row[32];
	size_t len = 0;

	return row_of(a, "entry", contact, i, row)
	       && a->store->load(a->store->ctx, FZN_PERSIST_ATTACHMENT, row, e, E_LEN, &len)
	       && len == E_LEN;
}

static int entry_save(const fzn_attachments_t *a, const uint8_t contact[32], uint64_t i,
                      const uint8_t e[E_LEN])
{
	uint8_t row[32];

	return row_of(a, "entry", contact, i, row)
	       && a->store->save(a->store->ctx, FZN_PERSIST_ATTACHMENT, row, e, E_LEN);
}

/* THE CONVERSATIONS NOTED, in the order first noted. */
static int conversation_at(const fzn_attachments_t *a, uint64_t i, uint8_t contact[32])
{
	uint8_t row[32];
	size_t len = 0;

	return row_of(a, "conv", NOBODY, i, row)
	       && a->store->load(a->store->ctx, FZN_PERSIST_ATTACHMENT, row, contact, 32u, &len)
	       && len == 32u;
}

/* `contact` among them, once: its place, then the count, then the mark
 * that says it is listed, so a crash part way lists it again at worst --
 * and a conversation listed twice is trimmed twice, which changes
 * nothing the second time. */
static int conversation_add(const fzn_attachments_t *a, const uint8_t contact[32])
{
	uint8_t row[32];
	uint64_t n;

	if (number(a, "has", contact))
		return 1;
	n = number(a, "convs", NOBODY);
	return row_of(a, "conv", NOBODY, n, row)
	       && a->store->save(a->store->ctx, FZN_PERSIST_ATTACHMENT, row, contact, 32u)
	       && number_save(a, "convs", NOBODY, n + 1u) && number_save(a, "has", contact, 1u);
}

/* The id of the hold a line keeps on its file. */
static int hold_id(const fzn_attachments_t *a, const uint8_t contact[32], uint8_t direction,
                   const uint8_t id[16], uint8_t out[FZN_FILE_HOLD_ID_LEN])
{
	static const char DOMAIN[] = "fuzznet.attachment.hold";
	uint8_t in[sizeof(DOMAIN) - 1u + 32u + 1u + 16u];
	size_t at = sizeof(DOMAIN) - 1u;

	memcpy(in, DOMAIN, at);
	memcpy(in + at, contact, 32u);
	at += 32u;
	in[at++] = direction;
	memcpy(in + at, id, 16u);
	return a->hash->hash(a->hash->ctx, out, FZN_FILE_HOLD_ID_LEN, in, sizeof(in));
}

int fzn_attachments_take(const fzn_attachments_t *a, const uint8_t contact[32], uint8_t direction,
                         const uint8_t id[16], uint32_t epoch, const fzn_attachment_t *att,
                         int *added)
{
	fzn_file_holds_t h;
	uint8_t hold[FZN_FILE_HOLD_ID_LEN], e[E_LEN];
	uint64_t n;
	int new_hold = 0;

	if (added)
		*added = 0;
	if (!ready(a) || !contact || !id || !att || !added || !hold_id(a, contact, direction, id, hold))
		return 0;
	h = holds_of(a);
	/* THE HOLD FIRST: a line told again finds it and adds nothing, and a
	 * crash before its entry leaves a file held that no trim reaches --
	 * kept, as every crash here leaves things. */
	if (!fzn_file_hold_claim(&h, att->root, FZN_FILE_HOLD_ATTACHMENT, hold, &new_hold))
		return 0;
	if (!new_hold)
		return 1;
	if (!conversation_add(a, contact))
		return 0;
	memset(e, 0, sizeof(e));
	fzn_put_be32(e + E_EPOCH, epoch);
	fzn_put_be64(e + E_SIZE, att->size);
	memcpy(e + E_ROOT, att->root, 32u);
	memcpy(e + E_HOLD, hold, FZN_FILE_HOLD_ID_LEN);
	n = number(a, "count", contact);
	if (!entry_save(a, contact, n, e) || !number_save(a, "count", contact, n + 1u))
		return 0;
	*added = 1;
	return 1;
}

int fzn_attachments_backfilled(const fzn_attachments_t *a)
{
	return ready(a) && number(a, "filled", NOBODY) != 0u;
}

int fzn_attachments_backfill_end(const fzn_attachments_t *a, size_t *released)
{
	static const uint8_t LEGACY_ID[FZN_FILE_HOLD_ID_LEN];
	fzn_file_holds_t h;
	uint8_t contact[32], e[E_LEN];
	uint64_t n_conv, c, i, n, left;

	if (released)
		*released = 0;
	if (!ready(a) || !released)
		return 0;
	h = holds_of(a);
	n_conv = number(a, "convs", NOBODY);
	/* EACH FILE A LINE HOLDS is held by its lines from here: its hold from
	 * before the record let go. A crash part way lets go again what is
	 * left, and releasing what is not held writes nothing. */
	for (c = 0; c < n_conv; c++) {
		if (!conversation_at(a, c, contact))
			return 0;
		n = number(a, "count", contact);
		for (i = 0; i < n; i++) {
			if (!entry_load(a, contact, i, e))
				return 0;
			if (e[E_RELEASED]
			    || !fzn_file_hold_has(&h, e + E_ROOT, FZN_FILE_HOLD_LEGACY, LEGACY_ID))
				continue;
			if (!fzn_file_hold_release(&h, e + E_ROOT, FZN_FILE_HOLD_LEGACY, LEGACY_ID, &left))
				return 0;
			(*released)++;
		}
	}
	return number_save(a, "filled", NOBODY, 1u);
}

/* ---- the trim -------------------------------------------------------- */

/* EVERY CONTACT'S TOGETHER: each month's attachments held, their bytes and
 * how many. Attachments are few beside lines, so the trim sums them by
 * walking the index once rather than keeping sums as rows as sec 793's
 * messages do. */
typedef struct month_sum {
	uint32_t epoch;
	uint64_t bytes, count;
} month_sum_t;

typedef struct sums {
	month_sum_t *m;
	size_t n, room;
} sums_t;

static int sums_add(sums_t *s, uint32_t epoch, uint64_t bytes)
{
	size_t i;

	for (i = 0; i < s->n; i++)
		if (s->m[i].epoch == epoch) {
			s->m[i].bytes += bytes;
			s->m[i].count++;
			return 1;
		}
	if (s->n == s->room) {
		size_t want = s->room ? 2u * s->room : 16u;
		month_sum_t *more = realloc(s->m, want * sizeof(*more));

		if (!more)
			return 0;
		s->m = more;
		s->room = want;
	}
	s->m[s->n].epoch = epoch;
	s->m[s->n].bytes = bytes;
	s->m[s->n].count = 1u;
	s->n++;
	return 1;
}

/* What is newer than month `epoch`, every contact's. */
static void sums_newer(const sums_t *s, uint32_t epoch, uint64_t *bytes, uint64_t *count)
{
	size_t i;

	*bytes = *count = 0u;
	for (i = 0; i < s->n; i++)
		if (s->m[i].epoch > epoch) {
			*bytes += s->m[i].bytes;
			*count += s->m[i].count;
		}
}

/* Whether an attachment of month `epoch`, with `counted` attachments and
 * `bytes` before it, is within `r` at `now_us`; every contact's together
 * from `s`. A month is within when any of it is, as a message's. */
static int within(const fzn_retain_rule_t *r, uint32_t epoch, uint64_t counted, uint64_t bytes,
                  const sums_t *s, uint64_t now_us)
{
	uint64_t end_us;

	if (r->limit == FZN_RETAIN_AGE) {
		end_us = fzn_message_epoch_start(epoch + 1u) * 1000u;
		return end_us >= now_us || now_us - end_us <= r->value;
	}
	if (r->all_contacts) {
		if (!s->m)
			return 1;
		sums_newer(s, epoch, &bytes, &counted);
	}
	return r->limit == FZN_RETAIN_SIZE ? bytes < r->value : counted < r->value;
}

/* A conversation's months, and whether each stays. */
typedef struct month_stay {
	uint32_t epoch;
	int stays;
} month_stay_t;

static month_stay_t *stays;
static size_t stays_room;

/* A conversation's entries as the trim weighs them. */
typedef struct placed {
	uint32_t epoch;
	uint64_t size, place;
} placed_t;

static placed_t *order;
static size_t order_room;

static int newest_first(const void *x, const void *y)
{
	const placed_t *p = x, *q = y;

	if (p->epoch != q->epoch)
		return p->epoch < q->epoch ? 1 : -1;
	return p->place < q->place ? 1 : p->place > q->place ? -1 : 0;
}

/* ONE ENTRY LET GO: its file removed first when this was its last hold
 * and nothing else names it, then its hold released and the entry marked.
 * 0 when the removal cannot run now. */
static int let_go(const fzn_attachments_t *a, const uint8_t contact[32], uint64_t i,
                  uint8_t e[E_LEN], int (*held_elsewhere)(void *ctx, const uint8_t root[32]),
                  int (*remove)(void *ctx, const uint8_t root[32]), void *ctx,
                  fzn_attachments_tally_t *tally)
{
	fzn_file_holds_t h = holds_of(a);
	uint64_t count = 0, left = 0;

	if (fzn_file_hold_count(&h, e + E_ROOT, &count) && count == 1u
	    && fzn_file_hold_has(&h, e + E_ROOT, FZN_FILE_HOLD_ATTACHMENT, e + E_HOLD)
	    && !(held_elsewhere && held_elsewhere(ctx, e + E_ROOT))) {
		if (!remove || !remove(ctx, e + E_ROOT)) {
			tally->waiting++;
			return 0;
		}
		tally->removed++;
	}
	if (!fzn_file_hold_release(&h, e + E_ROOT, FZN_FILE_HOLD_ATTACHMENT, e + E_HOLD, &left))
		return 0;
	e[E_RELEASED] = 1u;
	if (!entry_save(a, contact, i, e))
		return 0;
	tally->released++;
	return 1;
}

/* ONE CONVERSATION OF THE TRIM. */
static int trim_one(const fzn_attachments_t *a, const uint8_t contact[32],
                    const fzn_retain_rule_t *rules, size_t n_rules, int drops, const sums_t *s,
                    uint64_t now_us, uint32_t current,
                    int (*held_elsewhere)(void *ctx, const uint8_t root[32]),
                    int (*remove)(void *ctx, const uint8_t root[32]), void *ctx,
                    fzn_attachments_tally_t *tally)
{
	uint64_t counted[FZN_RETAIN_RULES_MAX], bytes[FZN_RETAIN_RULES_MAX], n, i;
	int applies[FZN_RETAIN_RULES_MAX], any = 0;
	size_t r, k, o, n_order, n_months = 0, gone = 0;
	uint8_t e[E_LEN];

	for (r = 0; r < n_rules; r++) {
		applies[r] = fzn_retain_applies_to(rules, n_rules, r, FZN_RETAIN_ATTACHMENTS, contact);
		any |= applies[r];
		counted[r] = bytes[r] = 0u;
	}
	if (!any && !drops)
		return 1;
	n = number(a, "count", contact);
	/* BY THE MONTH, NEWEST FIRST, not in the order noted: a line can come
	 * late, and the lines kept before the index are noted after newer
	 * ones (sec 796). Within a month, the later noted first. */
	n_order = 0;
	for (i = n; i > 0u; i--) {
		if (!entry_load(a, contact, i - 1u, e))
			return 0;
		if (e[E_RELEASED])
			continue;
		if (n_order == order_room) {
			size_t want = order_room ? 2u * order_room : 64u;
			placed_t *more = realloc(order, want * sizeof(*more));

			if (!more)
				return 0;
			order = more;
			order_room = want;
		}
		order[n_order].epoch = fzn_get_be32(e + E_EPOCH);
		order[n_order].size = fzn_get_be64(e + E_SIZE);
		order[n_order].place = i - 1u;
		n_order++;
	}
	if (n_order > 1u)
		qsort(order, n_order, sizeof(*order), newest_first);
	for (o = 0; o < n_order; o++) {
		uint32_t epoch = order[o].epoch;
		uint64_t size = order[o].size;
		int pruned = 0, kept = 0;

		for (r = 0; r < n_rules; r++) {
			int in;

			if (!applies[r])
				continue;
			in = within(&rules[r], epoch, counted[r], bytes[r], s, now_us);
			if (rules[r].kind == FZN_RETAIN_PRUNE && !in)
				pruned = 1;
			if (rules[r].kind == FZN_RETAIN_KEEP && in)
				kept = 1;
			counted[r]++;
			bytes[r] += size;
		}
		for (k = 0; k < n_months && stays[k].epoch != epoch; k++)
			;
		if (k == n_months) {
			if (n_months == stays_room) {
				size_t want = stays_room ? 2u * stays_room : 16u;
				month_stay_t *more = realloc(stays, want * sizeof(*more));

				if (!more)
					return 0;
				stays = more;
				stays_room = want;
			}
			stays[n_months].epoch = epoch;
			stays[n_months].stays = 0;
			n_months++;
		}
		if (kept || (!pruned && !drops))
			stays[k].stays = 1;
	}
	/* THE MONTHS THAT GO, their attachments let go; never the current one. */
	for (k = 0; k < n_months; k++) {
		int let = 0;

		if (stays[k].stays || stays[k].epoch >= current)
			continue;
		for (i = n; i > 0u; i--) {
			if (!entry_load(a, contact, i - 1u, e))
				return 0;
			if (e[E_RELEASED] || fzn_get_be32(e + E_EPOCH) != stays[k].epoch)
				continue;
			let |= let_go(a, contact, i - 1u, e, held_elsewhere, remove, ctx, tally);
		}
		gone += (size_t)let;
	}
	tally->months += gone;
	return 1;
}

int fzn_attachments_trim(const fzn_attachments_t *a, const fzn_retain_rule_t *rules,
                         size_t n_rules, uint64_t now_ms,
                         int (*held_elsewhere)(void *ctx, const uint8_t root[32]),
                         int (*remove)(void *ctx, const uint8_t root[32]), void *ctx,
                         fzn_attachments_tally_t *tally)
{
	uint8_t contact[32], e[E_LEN];
	uint64_t n_conv, c, i, n;
	sums_t s;
	size_t r;
	int drops, all = 0, ok = 1;

	if (tally)
		memset(tally, 0, sizeof(*tally));
	if (!ready(a) || (!rules && n_rules) || n_rules > FZN_RETAIN_RULES_MAX || !tally)
		return 0;
	if (!n_rules)
		return 1;
	drops = fzn_retain_policy_drops(rules, n_rules, FZN_RETAIN_ATTACHMENTS);
	n_conv = number(a, "convs", NOBODY);
	memset(&s, 0, sizeof(s));
	for (r = 0; r < n_rules; r++)
		all |= rules[r].data == FZN_RETAIN_ATTACHMENTS && rules[r].kind != FZN_RETAIN_POLICY
		       && rules[r].all_contacts && rules[r].limit != FZN_RETAIN_AGE;
	/* EVERY CONTACT'S TOGETHER, summed once for the trim. */
	for (c = 0; all && c < n_conv && ok; c++) {
		if (!conversation_at(a, c, contact))
			ok = 0;
		n = ok ? number(a, "count", contact) : 0u;
		for (i = 0; ok && i < n; i++) {
			if (!entry_load(a, contact, i, e))
				ok = 0;
			else if (!e[E_RELEASED]
			         && !sums_add(&s, fzn_get_be32(e + E_EPOCH), fzn_get_be64(e + E_SIZE)))
				ok = 0;
		}
	}
	for (c = 0; ok && c < n_conv; c++)
		ok = conversation_at(a, c, contact)
		     && trim_one(a, contact, rules, n_rules, drops, &s, now_ms * 1000u,
		                 fzn_message_epoch_of(now_ms), held_elsewhere, remove, ctx, tally);
	free(s.m);
	return ok;
}
