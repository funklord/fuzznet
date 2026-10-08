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
	    || (e->op != FZN_OPJOURNAL_OP_SAVE && e->op != FZN_OPJOURNAL_OP_REMOVE)
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
	        && body[FZN_OPJOURNAL_OFF_OP] != FZN_OPJOURNAL_OP_REMOVE)
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

/* ---- the entries -------------------------------------------------------- */

static void record(fzn_opjournal_t *oj, const fzn_opjournal_entry_t *e)
{
	uint8_t body[FZN_OPJOURNAL_ENTRY_LEN];

	if (!fzn_opjournal_entry_write(e, body)
	    || fzn_node_journal_append_on(oj->journal, oj->issuer, FZN_OPJOURNAL_STREAM, oj->sign,
	                                  FZN_OPJOURNAL_KIND, e->subject, body, sizeof(body),
	                                  oj->now ? oj->now() : 0u, NULL)
	               != FZN_NODE_JOURNAL_OK)
		oj->unrecorded++;
}

/* Entry `seq` of the journal, read back. */
static int entry_at(fzn_opjournal_t *oj, uint64_t seq, fzn_opjournal_entry_t *e)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;

	return fzn_record_store_get(&oj->journal->store, oj->issuer, FZN_OPJOURNAL_STREAM, seq, buf,
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

/* Whether entry `e`'s kept bytes are still held. */
static int bytes_held(fzn_opjournal_t *oj, const fzn_opjournal_entry_t *e)
{
	static uint8_t probe[FZN_OPJOURNAL_BYTES_MAX];
	size_t len = 0;

	return (e->flags & FZN_OPJOURNAL_BYTES_KEPT)
	       && oj->base->load(oj->base->ctx, FZN_PERSIST_OP_BYTES, e->hash, probe, sizeof(probe),
	                         &len);
}

/* Erase entry `e`'s kept bytes, if they are held, and count them out. */
static void erase_kept(fzn_opjournal_t *oj, const fzn_opjournal_entry_t *e)
{
	if (!bytes_held(oj, e))
		return;
	(void)oj->base->remove(oj->base->ctx, FZN_PERSIST_OP_BYTES, e->hash);
	oj->kept = oj->kept > e->length ? oj->kept - e->length : 0u;
}

/* THE BUDGET, oldest first. */
static void retain(fzn_opjournal_t *oj)
{
	uint64_t held = fzn_node_journal_received(oj->journal, oj->issuer, FZN_OPJOURNAL_STREAM);
	fzn_opjournal_entry_t e;

	if (oj->oldest == 0u)
		oj->oldest = 1u;
	while (oj->budget && oj->kept > oj->budget && oj->oldest <= held) {
		if (entry_at(oj, oj->oldest, &e) && e.op == FZN_OPJOURNAL_OP_SAVE)
			erase_kept(oj, &e);
		oj->oldest++;
	}
}

int fzn_opjournal_start(fzn_opjournal_t *oj)
{
	fzn_opjournal_entry_t e;
	uint64_t seq, held;

	if (!oj || !oj->journal || !oj->base)
		return 0;
	oj->kept = 0;
	oj->oldest = 0;
	held = fzn_node_journal_received(oj->journal, oj->issuer, FZN_OPJOURNAL_STREAM);
	for (seq = 1u; seq <= held; seq++) {
		if (!entry_at(oj, seq, &e))
			return 0;
		if (e.op != FZN_OPJOURNAL_OP_SAVE || !bytes_held(oj, &e))
			continue;
		if (oj->oldest == 0u)
			oj->oldest = seq;
		oj->kept += e.length;
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
	if (fzn_opjournal_keeps(slot)) {
		e.length = (uint32_t)len;
		if (len > FZN_OPJOURNAL_BYTES_MAX
		    || !oj->hash->hash(oj->hash->ctx, e.hash, sizeof(e.hash), bytes, len)) {
			memset(e.hash, 0, sizeof(e.hash));
			oj->unkept++;
		} else if (oj->base->save(oj->base->ctx, FZN_PERSIST_OP_BYTES, e.hash, bytes, len)) {
			e.flags |= FZN_OPJOURNAL_BYTES_KEPT;
			oj->kept += len;
		} else {
			oj->unkept++;
		}
	}
	record(oj, &e);
	retain(oj);
	return 1;
}

static int oj_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	fzn_opjournal_t *oj = (fzn_opjournal_t *)ctx;
	fzn_opjournal_entry_t e, past;
	uint64_t seq, held;

	if (!oj->base->remove || !oj->base->remove(oj->base->ctx, slot, subject))
		return 0;
	row_of(subject, &e);
	e.op = FZN_OPJOURNAL_OP_REMOVE;
	e.slot = (uint8_t)slot;
	/* THE ROW'S HISTORY GOES WITH IT, sec 523: every byte an entry kept
	 * for this row, so what was removed is not readable here either. */
	if (fzn_opjournal_keeps(slot)) {
		held = fzn_node_journal_received(oj->journal, oj->issuer, FZN_OPJOURNAL_STREAM);
		for (seq = 1u; seq <= held; seq++)
			if (entry_at(oj, seq, &past) && past.op == FZN_OPJOURNAL_OP_SAVE
			    && same_row(&past, e.slot, e.flags, e.subject))
				erase_kept(oj, &past);
	}
	record(oj, &e);
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

int fzn_opjournal_replay(fzn_opjournal_t *oj, uint64_t upto, const fzn_persist_ops_t *into,
                         fzn_opjournal_replay_tally_t *tally)
{
	static uint8_t bytes[FZN_OPJOURNAL_BYTES_MAX];
	uint8_t check[32];
	fzn_opjournal_entry_t e;
	uint64_t seq, held;

	if (!oj || !oj->journal || !into || !into->save || !tally)
		return 0;
	memset(tally, 0, sizeof(*tally));
	held = fzn_node_journal_received(oj->journal, oj->issuer, FZN_OPJOURNAL_STREAM);
	if (upto > held)
		upto = held;
	for (seq = 1u; seq <= upto; seq++) {
		const uint8_t *subject;
		size_t len = 0;

		if (!entry_at(oj, seq, &e))
			return 0;
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
		if (!(e.flags & FZN_OPJOURNAL_BYTES_KEPT)
		    || !oj->base->load(oj->base->ctx, FZN_PERSIST_OP_BYTES, e.hash, bytes, sizeof(bytes),
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
