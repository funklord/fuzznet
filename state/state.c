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
 * `live` is 0 for a clear, which is the only difference between clearing and
 * setting: the writer and the sequence are recorded either way, and the value
 * recorded is absence. */
static void store(fzn_state_entry_t *e, const fzn_record_t *record, int live)
{
	memcpy(e->subject, record->subject, FZN_SUBJECT_LEN);
	memcpy(e->issuer, record->issuer, FZN_PUBKEY_LEN);
	e->kind = record->kind;
	e->stream = record->stream;
	e->seq = record->seq;
	e->body = live ? record->body : NULL;
	e->body_len = live ? record->body_len : 0;
	e->live = live;
}

/* The body of apply, resolve and clear -- one decision table, so that a
 * record meeting a tombstone is judged by exactly the rules that judge one
 * meeting a value.
 *
 *	no cell, setting             -> store, OK
 *	no cell, clearing            -> ABSENT
 *	different issuer             -> CONFLICT
 *	same issuer, other stream    -> CROSS_STREAM
 *	same writer, seq  > e->seq   -> store, OK
 *	same writer, seq <= e->seq   -> STALE
 *
 * `override` is what separates resolve from apply: it is the caller having
 * said, in a function named for it, that another writer may take this subject
 * over. It skips the two contention rows and nothing else -- in particular it
 * does not compare sequences across writers, because there is no shared zero
 * to compare them against. */
static fzn_state_err_t put(fzn_state_t *state, const fzn_record_t *record, int override, int live)
{
	fzn_state_entry_t *e;

	if (!usable(state) || !record)
		return FZN_STATE_ERR_MALFORMED;
	if (!record->body && record->body_len != 0)
		return FZN_STATE_ERR_MALFORMED;
	/* Sequence zero is reserved (`record.h`), so a record carrying it has
	 * not been through `fzn_record_verify` and must not be trusted to
	 * order anything. */
	if (record->seq == 0)
		return FZN_STATE_ERR_MALFORMED;

	e = find(state, record->subject, record->kind);
	if (!e) {
		if (!live)
			return FZN_STATE_ERR_ABSENT;

		e = slot(state);
		if (!e)
			return FZN_STATE_ERR_FULL;

		store(e, record, live);
		return FZN_STATE_OK;
	}

	if (!fzn_ct_memeq(e->issuer, record->issuer, FZN_PUBKEY_LEN)) {
		if (!override)
			return FZN_STATE_ERR_CONFLICT;
		store(e, record, live);
		return FZN_STATE_OK;
	}

	/* One issuer's streams are numbered from 1 each, so this record's `seq`
	 * and the cell's are two rulers with no shared zero. Measured before
	 * this test existed: stream 7 seq 100 then stream 9 seq 100 left stream
	 * 7's value and the reverse order left stream 9's, with no error either
	 * way -- the same record set giving two answers, which is the one thing
	 * this file is for. Checked BEFORE the sequence comparison below, so
	 * that a cross-stream record is never mistaken for a stale one. */
	if (e->stream != record->stream) {
		if (!override)
			return FZN_STATE_ERR_CROSS_STREAM;
		store(e, record, live);
		return FZN_STATE_OK;
	}

	/* Same writer: its own sequence orders it, and only forwards. An older
	 * record arriving late must not undo a newer one -- which is what a
	 * re-delivery looks like, and it is the whole reason the sequence is
	 * carried into the cell and kept when the cell is cleared. */
	if (record->seq <= e->seq)
		return FZN_STATE_ERR_STALE;

	store(e, record, live);
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
	case FZN_STATE_ERR_ABSENT:
		return "nothing set for this subject";
	case FZN_STATE_ERR_CROSS_STREAM:
		return "another stream of this issuer holds this";
	}

	return "unknown";
}
