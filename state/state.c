/* See state.h. */

#include "state.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* The cell for this subject and kind, or NULL. Scans every entry rather than
 * stopping at the first, so a state holding a duplicate cannot answer
 * differently depending on insertion order -- the argument
 * `local/vocabulary.c` makes about rule tables.
 *
 * TOMBSTONES MATCH. A cleared cell still names its writer and the sequence
 * that cleared it, and that is the whole point of keeping it: a lookup that
 * skipped tombstones would hand `put` a NULL, `put` would allocate a fresh
 * cell, and the replay the tombstone exists to refuse would be accepted.
 * `fzn_state_get` drops them instead, where the question being asked is what
 * the subject says rather than what is remembered about it.
 *
 * NOT KEYED BY STREAM. See state.h: keying by (subject, kind, stream) makes
 * two different issuers on two streams land in separate cells, and no
 * conflict is ever reported again. */
static fzn_state_entry_t *find(const fzn_state_t *state,
                                const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind)
{
	fzn_state_entry_t *hit = NULL;

	for (size_t i = 0; i < state->used; i++) {
		if (state->entries[i].kind == kind &&
		    fzn_ct_memeq(state->entries[i].subject, subject, FZN_SUBJECT_LEN))
			hit = &state->entries[i];
	}

	return hit;
}

static int usable(const fzn_state_t *state)
{
	return state && state->entries && state->used <= state->capacity;
}

/* A slot for a subject that has no cell yet, or NULL if there is none.
 *
 * Every slot below `used` holds a cell -- live or tombstone -- so growing the
 * array is the first move and forgetting a tombstone is the second. A set and
 * clear cycle on one subject never reaches either: `find` hits the tombstone
 * and `put` writes over it in place.
 *
 * The first tombstone by index is the one forgotten. Any deterministic choice
 * would do; what matters is that a LIVE cell is never a candidate, for the
 * reason `fzn_state_forgotten` gives. */
static fzn_state_entry_t *slot(fzn_state_t *state)
{
	/* `<` rather than `!=`, for the reason chain/revocation.c gives at the
	 * same place: the append writes at entries[used] and an inequality test
	 * lets a corrupt `used` through. */
	if (state->used < state->capacity)
		return &state->entries[state->used++];

	for (size_t i = 0; i < state->used; i++) {
		if (!state->entries[i].live) {
			state->forgotten++;
			return &state->entries[i];
		}
	}

	return NULL;
}

fzn_state_err_t fzn_state_init(fzn_state_t *state, fzn_state_entry_t *entries, size_t capacity)
{
	if (!state || !entries || capacity == 0)
		return FZN_STATE_ERR_MALFORMED;

	memset(entries, 0, capacity * sizeof(*entries));
	state->entries = entries;
	state->capacity = capacity;
	state->used = 0;
	state->forgotten = 0;

	return FZN_STATE_OK;
}

/* Write a record into a cell. Shared so that insert, supersede, resolve and
 * clear cannot drift apart in which fields they remember -- and `stream` is
 * one of them, because a cell whose writer is only half recorded compares
 * against half a writer for ever afterwards.
 *
 * Every field is read through a `record.h` accessor, so what is stored here
 * is what the issuer signed. A cell that named a writer nobody had signed for
 * was reachable before the record became a view over its own bytes: the
 * decoded fields and the signed region were separate, and moving a genuine
 * record to another stream wedged the cell it landed in at CROSS_STREAM for
 * ever, with the revocation that would have cleared it refused on arrival.
 *
 * `live` is 0 for a clear, which is the only difference between clearing and
 * setting: the writer and the sequence are recorded either way, and the value
 * recorded is absence. */
static void store(fzn_state_entry_t *e, fzn_record_t record, int live)
{
	memcpy(e->subject, fzn_record_subject(record), FZN_SUBJECT_LEN);
	memcpy(e->issuer, fzn_record_issuer(record), FZN_PUBKEY_LEN);
	e->kind = fzn_record_kind(record);
	e->stream = fzn_record_stream(record);
	e->seq = fzn_record_seq(record);
	e->body = live ? fzn_record_body(record) : NULL;
	e->body_len = live ? fzn_record_body_len(record) : 0;
	e->live = live;
}

/* The body of apply, resolve and clear -- one decision table, so that a
 * record meeting a tombstone is judged by exactly the rules that judge one
 * meeting a value.
 *
 *	no cell, setting             -> store, OK
 *	no cell, clearing            -> store a tombstone, ABSENT
 *	different issuer             -> CONFLICT
 *	same issuer, other stream    -> CROSS_STREAM
 *	same writer, seq  > e->seq   -> store, OK
 *	same writer, seq <= e->seq   -> STALE
 *
 * `override` is what separates resolve from apply: it is the caller having
 * said, in a function named for it, that another writer may take this subject
 * over. It skips the two contention rows and nothing else -- in particular it
 * does not compare sequences across writers, because there is no shared zero
 * to compare them against.
 *
 * ROW TWO STORES, AND USED TO RETURN ABSENT WITHOUT STORING. That dropped a
 * revocation whenever it outran the grant it superseded: measured, the set
 * { apply(alice/7, seq 5, "GRANT"), clear(alice/7, seq 10, "REVOKE") } left
 * the subject unset in one order and GRANTED in the other, with the refusal
 * in the second order spelled identically to clearing a subject nobody had
 * ever set. Both rows now take a slot, so the cell converges on the writer's
 * highest sequence whichever of the two arrived first -- which is what makes
 * the header's invariant true rather than nearly true. `slot` is what pays
 * for it: a tombstone is forgotten before a live setting is refused, so the
 * extra cells cannot deny room to a value. */
static fzn_state_err_t put(fzn_state_t *state, const fzn_record_t *record, int override, int live)
{
	fzn_state_entry_t *e;

	if (!usable(state) || !record)
		return FZN_STATE_ERR_MALFORMED;
	/* A view `fzn_record_open` never filled. The caller has skipped the
	 * parse, so there is nothing here to read -- and one check now replaces
	 * the two that used to stand for it. The null-body-with-a-length case
	 * is gone because a body and its length are no longer two things a
	 * caller sets: both are read out of the bytes the signature covers. */
	if (!fzn_record_is_open(*record))
		return FZN_STATE_ERR_MALFORMED;
	/* Sequence zero is reserved (`record.h`), and `fzn_record_open` already
	 * refuses it -- so this is defence in depth rather than the gate, kept
	 * because a comparison is cheaper than reasoning about every path a
	 * record can reach this by. */
	if (fzn_record_seq(*record) == 0)
		return FZN_STATE_ERR_MALFORMED;

	e = find(state, fzn_record_subject(*record), fzn_record_kind(*record));
	if (!e) {
		e = slot(state);
		if (!e)
			return FZN_STATE_ERR_FULL;

		store(e, *record, live);
		/* ABSENT reports what was here before, and the record is
		 * stored either way. It is deliberately not OK: a revoker
		 * learning that the grant it is revoking never reached this
		 * host is learning something -- usually that the journal is
		 * behind -- and it is the only way left to tell a clear that
		 * superseded a value from one that got in first. */
		return live ? FZN_STATE_OK : FZN_STATE_ABSENT;
	}

	if (!fzn_ct_memeq(e->issuer, fzn_record_issuer(*record), FZN_PUBKEY_LEN)) {
		if (!override)
			return FZN_STATE_ERR_CONFLICT;
		store(e, *record, live);
		return FZN_STATE_OK;
	}

	/* One issuer's streams are numbered from 1 each, so this record's `seq`
	 * and the cell's are two rulers with no shared zero. Measured before
	 * this test existed: stream 7 seq 100 then stream 9 seq 100 left stream
	 * 7's value and the reverse order left stream 9's, with no error either
	 * way -- the same record set giving two answers, which is the one thing
	 * this file is for. Checked BEFORE the sequence comparison below, so
	 * that a cross-stream record is never mistaken for a stale one.
	 *
	 * AND THE STREAM IS NOW THE ISSUER'S OWN, not a field somebody set
	 * beside a signature. Moving a genuine record between streams used to
	 * be free, which put a cell into CROSS_STREAM against a writer that had
	 * never written on that stream -- permanently, since the revocation
	 * that would have cleared it arrives on the real stream and meets the
	 * same refusal. `record.h` records the measurement. */
	if (e->stream != fzn_record_stream(*record)) {
		if (!override)
			return FZN_STATE_ERR_CROSS_STREAM;
		store(e, *record, live);
		return FZN_STATE_OK;
	}

	/* Same writer: its own sequence orders it, and only forwards. An older
	 * record arriving late must not undo a newer one -- which is what a
	 * re-delivery looks like, and it is the whole reason the sequence is
	 * carried into the cell and kept when the cell is cleared.
	 *
	 * THIS TEST IS ONLY WORTH ANYTHING BECAUSE THE SEQUENCE IS SIGNED. It
	 * was not: a decoded `seq` sat beside an opaque signed region and
	 * nothing compared them, so an attacker replayed an issuer's own signed
	 * grant with the sequence bumped and this row let it past a revocation
	 * that had already superseded it. Nothing forged, one genuine record
	 * re-presented -- and the permission came back. */
	if (fzn_record_seq(*record) <= e->seq)
		return FZN_STATE_ERR_STALE;

	store(e, *record, live);
	return FZN_STATE_OK;
}

fzn_state_err_t fzn_state_apply(fzn_state_t *state, const fzn_record_t *record)
{
	return put(state, record, 0, 1);
}

fzn_state_err_t fzn_state_resolve(fzn_state_t *state, const fzn_record_t *record)
{
	return put(state, record, 1, 1);
}

fzn_state_err_t fzn_state_clear(fzn_state_t *state, const fzn_record_t *record)
{
	/* A clear is an apply whose value is absence, so it goes through the
	 * same table rather than carrying a second copy of it. The cell is
	 * tombstoned in place: the array does not shift, so no pointer a caller
	 * holds into it moves. */
	return put(state, record, 0, 0);
}

fzn_state_err_t fzn_state_resolve_clear(fzn_state_t *state, const fzn_record_t *record)
{
	/* The fourth combination, and the last one to exist. `resolve` was
	 * (override, live) and `clear` was (neither), so there was no way to
	 * clear a cell another writer held: `clear` answered CONFLICT and
	 * dropped the revocation, and `resolve` -- the only call that returned
	 * OK -- stored the revocation as the subject's LIVE VALUE, so the
	 * permission read as granted by whoever had tried to revoke it.
	 *
	 * Its own name rather than a flag on `clear`, per chain.h: one function
	 * with an optional pin is a function somebody calls without the pin.
	 * Overriding another writer is the dangerous half of the axis, so it
	 * costs a name a caller has to type. */
	return put(state, record, 1, 0);
}

const fzn_state_entry_t *fzn_state_get(const fzn_state_t *state,
                                        const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind)
{
	const fzn_state_entry_t *e;

	if (!usable(state) || !subject)
		return NULL;

	e = find(state, subject, kind);

	return (e && e->live) ? e : NULL;
}

size_t fzn_state_count(const fzn_state_t *state)
{
	size_t n = 0;

	if (!usable(state))
		return 0;

	for (size_t i = 0; i < state->used; i++)
		n += state->entries[i].live ? 1u : 0u;

	return n;
}

uint64_t fzn_state_forgotten(const fzn_state_t *state)
{
	return usable(state) ? state->forgotten : 0u;
}

const char *fzn_state_err_str(fzn_state_err_t err)
{
	switch (err) {
	case FZN_STATE_OK:
		return "ok";
	case FZN_STATE_ERR_MALFORMED:
		return "malformed argument";
	case FZN_STATE_ERR_FULL:
		return "no room for another subject";
	case FZN_STATE_ERR_STALE:
		return "older than what is held";
	case FZN_STATE_ERR_CONFLICT:
		return "another issuer holds this";
	case FZN_STATE_ABSENT:
		return "nothing was set, and a tombstone now says so";
	case FZN_STATE_ERR_CROSS_STREAM:
		return "another stream of this issuer holds this";
	}

	return "unknown";
}
