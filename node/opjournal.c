/* See opjournal.h. */

#include "opjournal.h"

#include "../wire/bytes.h"

#include <string.h>

_Static_assert(FZN_OPJOURNAL_OFF_LENGTH + 4u == FZN_OPJOURNAL_ENTRY_LEN,
               "an entry is its fields and nothing past them");

int fzn_opjournal_entry_write(const fzn_opjournal_entry_t *e,
                              uint8_t out[FZN_OPJOURNAL_ENTRY_LEN])
{
	if (!e || !out
	    || (e->op != FZN_OPJOURNAL_OP_SAVE && e->op != FZN_OPJOURNAL_OP_REMOVE
	        && e->op != FZN_OPJOURNAL_OP_OPENED)
	    || (e->flags & (uint8_t)~(FZN_OPJOURNAL_HAS_SUBJECT | FZN_OPJOURNAL_BYTES_KEPT)))
		return 0;
	out[FZN_OPJOURNAL_OFF_VERSION] = FZN_OPJOURNAL_VERSION;
	out[FZN_OPJOURNAL_OFF_OP] = e->op;
	out[FZN_OPJOURNAL_OFF_SLOT] = e->slot;
	out[FZN_OPJOURNAL_OFF_FLAGS] = e->flags;
	memcpy(out + FZN_OPJOURNAL_OFF_SUBJECT, e->subject, FZN_PUBKEY_LEN);
	memcpy(out + FZN_OPJOURNAL_OFF_HASH, e->hash, sizeof(e->hash));
	fzn_put_be32(out + FZN_OPJOURNAL_OFF_LENGTH, e->length);
	return 1;
}

int fzn_opjournal_entry_open(const uint8_t *body, size_t len, fzn_opjournal_entry_t *out)
{
	if (!body || !out || len != FZN_OPJOURNAL_ENTRY_LEN
	    || body[FZN_OPJOURNAL_OFF_VERSION] != FZN_OPJOURNAL_VERSION
	    || (body[FZN_OPJOURNAL_OFF_OP] != FZN_OPJOURNAL_OP_SAVE
	        && body[FZN_OPJOURNAL_OFF_OP] != FZN_OPJOURNAL_OP_REMOVE
	        && body[FZN_OPJOURNAL_OFF_OP] != FZN_OPJOURNAL_OP_OPENED)
	    || (body[FZN_OPJOURNAL_OFF_FLAGS]
	        & (uint8_t)~(FZN_OPJOURNAL_HAS_SUBJECT | FZN_OPJOURNAL_BYTES_KEPT)))
		return 0;
	out->op = body[FZN_OPJOURNAL_OFF_OP];
	out->slot = body[FZN_OPJOURNAL_OFF_SLOT];
	out->flags = body[FZN_OPJOURNAL_OFF_FLAGS];
	memcpy(out->subject, body + FZN_OPJOURNAL_OFF_SUBJECT, FZN_PUBKEY_LEN);
	memcpy(out->hash, body + FZN_OPJOURNAL_OFF_HASH, sizeof(out->hash));
	out->length = fzn_get_be32(body + FZN_OPJOURNAL_OFF_LENGTH);
	return 1;
}

int fzn_opjournal_keeps(fzn_persist_slot_t slot)
{
	switch (slot) {
	/* SECRETS AND SESSIONS: an old state kept is a key that should be
	 * gone -- a ratchet's forward secrecy is its old keys erased. */
	case FZN_PERSIST_OWN_PREKEY:
	case FZN_PERSIST_PEER:
	case FZN_PERSIST_SEND_CHAIN:
	case FZN_PERSIST_RECV_CHAIN:
	case FZN_PERSIST_NODE_PEER:
	case FZN_PERSIST_OWN_IDENTITY:
	case FZN_PERSIST_PAIRED_NODE:
	case FZN_PERSIST_OWN_ROOT:
	/* A NOTE'S WRAP KEY, which a purge destroys (sec 520). */
	case FZN_PERSIST_NOTE_WRAP:
	/* AND ITS OWN BYTES, which are not a state to replay. */
	case FZN_PERSIST_OP_BYTES:
		return 0;
	default:
		return 1;
	}
}

/* ---- generations and entries ------------------------------------------- */

static fzn_node_journal_t *journal_of(const fzn_opjournal_t *oj, uint64_t g)
{
	if (g == 0u || g < oj->first || g > oj->last)
		return NULL;
	return oj->journals[g % FZN_OPJOURNAL_GENERATIONS_MAX];
}

static uint64_t held_in(const fzn_opjournal_t *oj, uint64_t g)
{
	fzn_node_journal_t *nj = journal_of(oj, g);

	return nj ? fzn_node_journal_received(nj, oj->issuer, FZN_OPJOURNAL_STREAM) : 0u;
}

uint64_t fzn_opjournal_entries(const fzn_opjournal_t *oj, uint64_t generation)
{
	if (!oj)
		return 0u;
	return held_in(oj, generation ? generation : oj->last);
}

/* WHERE AN ENTRY'S BYTES ARE KEPT: its generation and sequence, so no two
 * entries share a copy. */
static void bytes_key(uint64_t g, uint64_t seq, uint8_t key[FZN_PUBKEY_LEN])
{
	memset(key, 0, FZN_PUBKEY_LEN);
	fzn_put_be64(key, g);
	fzn_put_be64(key + 8u, seq);
}

/* Entry `seq` of generation `g`, read back. */
static int entry_at(fzn_opjournal_t *oj, uint64_t g, uint64_t seq, fzn_opjournal_entry_t *e)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_node_journal_t *nj = journal_of(oj, g);
	fzn_record_t rec;

	return nj
	       && fzn_record_store_get(&nj->store, oj->issuer, FZN_OPJOURNAL_STREAM, seq, buf,
	                               sizeof(buf), &rec)
	                  == FZN_RECORD_STORE_OK
	       && fzn_record_kind(rec) == FZN_OPJOURNAL_KIND
	       && fzn_opjournal_entry_open(fzn_record_body(rec), fzn_record_body_len(rec), e);
}

static int same_row(const fzn_opjournal_entry_t *e, uint8_t slot, uint8_t flags,
                    const uint8_t subject[FZN_PUBKEY_LEN])
{
	return e->slot == slot
	       && (e->flags & FZN_OPJOURNAL_HAS_SUBJECT) == (flags & FZN_OPJOURNAL_HAS_SUBJECT)
	       && memcmp(e->subject, subject, FZN_PUBKEY_LEN) == 0;
}

/* Whether entry (`g`, `seq`)'s kept bytes are still held. */
static int bytes_held(fzn_opjournal_t *oj, uint64_t g, uint64_t seq,
                      const fzn_opjournal_entry_t *e)
{
	static uint8_t probe[FZN_OPJOURNAL_BYTES_MAX];
	uint8_t key[FZN_PUBKEY_LEN];
	size_t len = 0;

	if (e->op != FZN_OPJOURNAL_OP_SAVE || !(e->flags & FZN_OPJOURNAL_BYTES_KEPT))
		return 0;
	bytes_key(g, seq, key);
	return oj->base->load(oj->base->ctx, FZN_PERSIST_OP_BYTES, key, probe, sizeof(probe), &len);
}

/* Erase an entry's kept bytes, if they are held, and count them out. */
static void erase_kept(fzn_opjournal_t *oj, uint64_t g, uint64_t seq,
                       const fzn_opjournal_entry_t *e)
{
	uint8_t key[FZN_PUBKEY_LEN];

	if (!bytes_held(oj, g, seq, e))
		return;
	bytes_key(g, seq, key);
	(void)oj->base->remove(oj->base->ctx, FZN_PERSIST_OP_BYTES, key);
	oj->kept = oj->kept > e->length ? oj->kept - e->length : 0u;
}

/*
 * ENTER `e` AS THE NEXT OF GENERATION `g`. Where `bytes` is given, they are
 * hashed into it and kept under its place first, and taken back out if the
 * entry does not take. Nonzero when the entry was written.
 */
static int enter(fzn_opjournal_t *oj, uint64_t g, fzn_opjournal_entry_t *e,
                 const uint8_t *bytes, size_t len)
{
	fzn_node_journal_t *nj = journal_of(oj, g);
	uint8_t body[FZN_OPJOURNAL_ENTRY_LEN];
	uint8_t key[FZN_PUBKEY_LEN] = { 0 };

	if (!nj) {
		oj->unrecorded++;
		return 0;
	}
	if (bytes) {
		e->length = (uint32_t)len;
		if (len > FZN_OPJOURNAL_BYTES_MAX
		    || !oj->hash->hash(oj->hash->ctx, e->hash, sizeof(e->hash), bytes, len)) {
			memset(e->hash, 0, sizeof(e->hash));
			oj->unkept++;
		} else {
			bytes_key(g, fzn_node_journal_received(nj, oj->issuer, FZN_OPJOURNAL_STREAM) + 1u,
			          key);
			if (oj->base->save(oj->base->ctx, FZN_PERSIST_OP_BYTES, key, bytes, len)) {
				e->flags |= FZN_OPJOURNAL_BYTES_KEPT;
				oj->kept += len;
			} else {
				oj->unkept++;
			}
		}
	}
	if (!fzn_opjournal_entry_write(e, body)
	    || fzn_node_journal_append_on(nj, oj->issuer, FZN_OPJOURNAL_STREAM, oj->sign,
	                                  FZN_OPJOURNAL_KIND, e->subject, body, sizeof(body),
	                                  oj->now ? oj->now() : 0u, NULL)
	               != FZN_NODE_JOURNAL_OK) {
		if (e->flags & FZN_OPJOURNAL_BYTES_KEPT) {
			(void)oj->base->remove(oj->base->ctx, FZN_PERSIST_OP_BYTES, key);
			oj->kept = oj->kept > len ? oj->kept - len : 0u;
		}
		oj->unrecorded++;
		return 0;
	}
	return 1;
}

/* Where generation `g` holds its OPENED entry, so its snapshot is whole;
 * 0 when it does not. */
static uint64_t opened_in(fzn_opjournal_t *oj, uint64_t g)
{
	fzn_opjournal_entry_t e;
	uint64_t seq, held = held_in(oj, g);

	for (seq = 1u; seq <= held; seq++)
		if (entry_at(oj, g, seq, &e) && e.op == FZN_OPJOURNAL_OP_OPENED)
			return seq;
	return 0u;
}

/* DROP GENERATION `g`, the oldest or the newest, whole: every byte its
 * entries kept, then the journal itself. */
static void drop_generation(fzn_opjournal_t *oj, uint64_t g)
{
	fzn_opjournal_entry_t e;
	uint64_t seq, held = held_in(oj, g);

	for (seq = 1u; seq <= held; seq++)
		if (entry_at(oj, g, seq, &e))
			erase_kept(oj, g, seq, &e);
	oj->generations.drop(oj->generations.ctx, g);
	oj->journals[g % FZN_OPJOURNAL_GENERATIONS_MAX] = NULL;
	if (g == oj->first && g == oj->last)
		oj->first = oj->last = 0u;
	else if (g == oj->first)
		oj->first++;
	else if (g == oj->last)
		oj->last--;
}

/* One row into generation `g`'s snapshot. A row that will not load is
 * skipped where it may be absent -- a whole-host slot nobody wrote -- and
 * fails the snapshot where it was listed. */
static int snapshot_row(fzn_opjournal_t *oj, uint64_t g, fzn_persist_slot_t slot,
                        const uint8_t *subject, int listed, uint64_t *count)
{
	static uint8_t bytes[FZN_OPJOURNAL_BYTES_MAX];
	fzn_opjournal_entry_t e;
	size_t len = 0;

	if (!oj->base->load(oj->base->ctx, slot, subject, bytes, sizeof(bytes), &len))
		return !listed;
	memset(&e, 0, sizeof(e));
	if (subject) {
		e.flags = FZN_OPJOURNAL_HAS_SUBJECT;
		memcpy(e.subject, subject, FZN_PUBKEY_LEN);
	}
	e.op = FZN_OPJOURNAL_OP_SAVE;
	e.slot = (uint8_t)slot;
	if (!enter(oj, g, &e, bytes, len) || !(e.flags & FZN_OPJOURNAL_BYTES_KEPT))
		return 0;
	(*count)++;
	return 1;
}

/*
 * OPEN GENERATION `g` AS THE NEWEST, WITH ITS SNAPSHOT: every row of every
 * slot that keeps its bytes, as the wrapped store holds it, then OPENED.
 * A snapshot that cannot be whole drops the generation, so none is left
 * that replays to something other than the state. Nonzero when opened.
 */
static int open_generation(fzn_opjournal_t *oj, uint64_t g)
{
	static uint8_t subjects[FZN_OPJOURNAL_SNAPSHOT_ROWS * FZN_PUBKEY_LEN];
	fzn_node_journal_t *nj = oj->generations.open(oj->generations.ctx, g);
	fzn_opjournal_entry_t e;
	uint64_t count = 0;
	unsigned slot;

	if (!nj)
		return 0;
	oj->journals[g % FZN_OPJOURNAL_GENERATIONS_MAX] = nj;
	if (oj->first == 0u)
		oj->first = g;
	oj->last = g;
	for (slot = 1u; slot < FZN_PERSIST_SLOT_END; slot++) {
		size_t n = 0, i;

		if (!fzn_opjournal_keeps((fzn_persist_slot_t)slot))
			continue;
		if (fzn_persist_slot_whole_host((fzn_persist_slot_t)slot)) {
			if (!snapshot_row(oj, g, (fzn_persist_slot_t)slot, NULL, 0, &count))
				goto cut_short;
			continue;
		}
		if (!oj->base->list
		    || !oj->base->list(oj->base->ctx, (fzn_persist_slot_t)slot, subjects,
		                       FZN_OPJOURNAL_SNAPSHOT_ROWS, &n))
			goto cut_short;
		for (i = 0; i < n; i++)
			if (!snapshot_row(oj, g, (fzn_persist_slot_t)slot,
			                  subjects + (i * FZN_PUBKEY_LEN), 1, &count))
				goto cut_short;
	}
	memset(&e, 0, sizeof(e));
	e.op = FZN_OPJOURNAL_OP_OPENED;
	e.length = (uint32_t)count;
	if (count > UINT32_MAX || !enter(oj, g, &e, NULL, 0))
		goto cut_short;
	oj->opened_at = held_in(oj, g);
	return 1;
cut_short:
	drop_generation(oj, g);
	return 0;
}

/* THE BUDGET, oldest first, across generations. */
static void retain(fzn_opjournal_t *oj)
{
	fzn_opjournal_entry_t e;

	while (oj->budget && oj->kept > oj->budget) {
		if (oj->oldest_generation < oj->first) {
			oj->oldest_generation = oj->first;
			oj->oldest = 1u;
		}
		if (oj->oldest_generation == 0u || oj->oldest_generation > oj->last)
			break;
		if (oj->oldest == 0u)
			oj->oldest = 1u;
		if (oj->oldest > held_in(oj, oj->oldest_generation)) {
			if (oj->oldest_generation >= oj->last)
				break;
			oj->oldest_generation++;
			oj->oldest = 1u;
			continue;
		}
		if (entry_at(oj, oj->oldest_generation, oj->oldest, &e))
			erase_kept(oj, oj->oldest_generation, oj->oldest, &e);
		oj->oldest++;
	}
}

/* ROTATE when the newest generation is full: the next opens with its
 * snapshot, and the oldest past `keep` go. A snapshot that cannot be taken
 * puts the rotation off by a quarter of a generation. */
static void rotate(fzn_opjournal_t *oj)
{
	uint64_t held = held_in(oj, oj->last);
	uint64_t writes = held > oj->opened_at ? held - oj->opened_at : 0u;
	uint64_t newest = oj->last, opened_at = oj->opened_at;

	if (!oj->rotate_at || writes < oj->rotate_at || writes < oj->retry_at)
		return;
	if (!open_generation(oj, oj->last + 1u)) {
		/* The attempt's drop leaves the newest where it was. */
		oj->last = newest;
		oj->opened_at = opened_at;
		oj->unrotated++;
		oj->retry_at = writes + (oj->rotate_at / 4u ? oj->rotate_at / 4u : 1u);
		return;
	}
	oj->retry_at = 0u;
	while (oj->last - oj->first + 1u > oj->keep)
		drop_generation(oj, oj->first);
}

int fzn_opjournal_start(fzn_opjournal_t *oj)
{
	fzn_opjournal_entry_t e;
	uint64_t g, seq, held;

	if (!oj || !oj->generations.open || !oj->generations.drop || !oj->base || !oj->base->load
	    || !oj->base->save || !oj->base->remove || !oj->hash || !oj->sign || !oj->issuer
	    || oj->keep == 0u || oj->keep >= FZN_OPJOURNAL_GENERATIONS_MAX
	    || (oj->first == 0u) != (oj->last == 0u) || oj->first > oj->last
	    || (oj->last && oj->last - oj->first >= FZN_OPJOURNAL_GENERATIONS_MAX))
		return 0;
	memset(oj->journals, 0, sizeof(oj->journals));
	oj->kept = 0u;
	oj->oldest_generation = 0u;
	oj->oldest = 0u;
	oj->retry_at = 0u;
	for (g = oj->first; g && g <= oj->last; g++) {
		oj->journals[g % FZN_OPJOURNAL_GENERATIONS_MAX] =
		        oj->generations.open(oj->generations.ctx, g);
		if (!oj->journals[g % FZN_OPJOURNAL_GENERATIONS_MAX])
			return 0;
	}
	/* A SNAPSHOT A CRASH CUT SHORT replays to nothing true. Only the newest
	 * can be one, since only a rotation writes a snapshot. */
	if (oj->last && !opened_in(oj, oj->last))
		drop_generation(oj, oj->last);
	if (oj->last == 0u && !open_generation(oj, 1u))
		return 0;
	oj->opened_at = opened_in(oj, oj->last);
	while (oj->last - oj->first + 1u > oj->keep)
		drop_generation(oj, oj->first);
	/* COUNTED FROM WHAT IS HELD, after the snapshot and the drops above
	 * have moved the running total: counting on from it would count a
	 * snapshot's bytes twice. */
	oj->kept = 0u;
	oj->oldest_generation = 0u;
	oj->oldest = 0u;
	for (g = oj->first; g <= oj->last; g++) {
		held = held_in(oj, g);
		for (seq = 1u; seq <= held; seq++) {
			if (!entry_at(oj, g, seq, &e))
				return 0;
			if (!bytes_held(oj, g, seq, &e))
				continue;
			if (oj->oldest_generation == 0u) {
				oj->oldest_generation = g;
				oj->oldest = seq;
			}
			oj->kept += e.length;
		}
	}
	retain(oj);
	return 1;
}

/* ---- the decorator ------------------------------------------------------- */

static int oj_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                   size_t cap, size_t *len)
{
	const fzn_opjournal_t *oj = (const fzn_opjournal_t *)ctx;

	return oj->base->load(oj->base->ctx, slot, subject, out, cap, len);
}

static int oj_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	const fzn_opjournal_t *oj = (const fzn_opjournal_t *)ctx;

	return oj->base->list && oj->base->list(oj->base->ctx, slot, out, max, count);
}

static void row_of(const uint8_t *subject, fzn_opjournal_entry_t *e)
{
	memset(e, 0, sizeof(*e));
	if (subject) {
		e->flags |= FZN_OPJOURNAL_HAS_SUBJECT;
		memcpy(e->subject, subject, FZN_PUBKEY_LEN);
	}
}

static int oj_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                   const uint8_t *bytes, size_t len)
{
	fzn_opjournal_t *oj = (fzn_opjournal_t *)ctx;
	fzn_opjournal_entry_t e;

	/* THE WRITE FIRST: see the header. */
	if (!oj->base->save(oj->base->ctx, slot, subject, bytes, len))
		return 0;
	row_of(subject, &e);
	e.op = FZN_OPJOURNAL_OP_SAVE;
	e.slot = (uint8_t)slot;
	(void)enter(oj, oj->last, &e, fzn_opjournal_keeps(slot) ? bytes : NULL, len);
	rotate(oj);
	retain(oj);
	return 1;
}

static int oj_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	fzn_opjournal_t *oj = (fzn_opjournal_t *)ctx;
	fzn_opjournal_entry_t e, past;
	uint64_t g, seq, held;

	if (!oj->base->remove || !oj->base->remove(oj->base->ctx, slot, subject))
		return 0;
	row_of(subject, &e);
	e.op = FZN_OPJOURNAL_OP_REMOVE;
	e.slot = (uint8_t)slot;
	/* THE ROW'S HISTORY GOES WITH IT, sec 523, in every generation held:
	 * every byte an entry kept for this row, so what was removed is not
	 * readable here either. */
	if (fzn_opjournal_keeps(slot))
		for (g = oj->first; g && g <= oj->last; g++) {
			held = held_in(oj, g);
			for (seq = 1u; seq <= held; seq++)
				if (entry_at(oj, g, seq, &past) && past.op == FZN_OPJOURNAL_OP_SAVE
				    && same_row(&past, e.slot, e.flags, e.subject))
					erase_kept(oj, g, seq, &past);
		}
	(void)enter(oj, oj->last, &e, NULL, 0);
	rotate(oj);
	return 1;
}

void fzn_opjournal_ops(fzn_opjournal_t *oj, fzn_persist_ops_t *ops)
{
	if (!oj || !ops)
		return;
	ops->load = oj_load;
	ops->save = oj_save;
	ops->list = oj_list;
	ops->remove = oj_remove;
	ops->ctx = oj;
}

/* ---- replay ------------------------------------------------------------- */

int fzn_opjournal_replay(fzn_opjournal_t *oj, uint64_t generation, uint64_t upto,
                         const fzn_persist_ops_t *into, fzn_opjournal_replay_tally_t *tally)
{
	static uint8_t bytes[FZN_OPJOURNAL_BYTES_MAX];
	uint8_t check[32], key[FZN_PUBKEY_LEN];
	fzn_opjournal_entry_t e;
	uint64_t g, seq, held;

	if (!oj || !into || !into->save || !tally)
		return 0;
	memset(tally, 0, sizeof(*tally));
	g = generation ? generation : oj->last;
	/* A GENERATION REPLAYS FROM ITS SNAPSHOT, so one without a whole
	 * snapshot replays to nothing true and is refused. */
	if (!journal_of(oj, g) || !opened_in(oj, g))
		return 0;
	held = held_in(oj, g);
	if (upto > held)
		upto = held;
	for (seq = 1u; seq <= upto; seq++) {
		const uint8_t *subject;
		size_t len = 0;

		if (!entry_at(oj, g, seq, &e))
			return 0;
		if (e.op == FZN_OPJOURNAL_OP_OPENED)
			continue;
		if (!fzn_opjournal_keeps((fzn_persist_slot_t)e.slot)) {
			tally->skipped++;
			continue;
		}
		subject = (e.flags & FZN_OPJOURNAL_HAS_SUBJECT) ? e.subject : NULL;
		if (e.op == FZN_OPJOURNAL_OP_REMOVE) {
			if (into->remove && !into->remove(into->ctx, (fzn_persist_slot_t)e.slot, subject))
				return 0;
			tally->removed++;
			continue;
		}
		/* THE BYTES AS KEPT, and only if they are what the entry names: a
		 * store that hands over something else is not believed. */
		bytes_key(g, seq, key);
		if (!(e.flags & FZN_OPJOURNAL_BYTES_KEPT)
		    || !oj->base->load(oj->base->ctx, FZN_PERSIST_OP_BYTES, key, bytes, sizeof(bytes),
		                       &len)
		    || len != e.length || !oj->hash->hash(oj->hash->ctx, check, sizeof(check), bytes, len)
		    || memcmp(check, e.hash, sizeof(check)) != 0) {
			tally->missing++;
			continue;
		}
		if (!into->save(into->ctx, (fzn_persist_slot_t)e.slot, subject, bytes, len))
			return 0;
		tally->saved++;
	}
	return 1;
}
