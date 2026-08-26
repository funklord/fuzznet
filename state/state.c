/* See state.h. */

#include "state.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* The entry for this subject and kind, or NULL. Scans every live entry rather
 * than stopping at the first, so a state holding a duplicate cannot answer
 * differently depending on insertion order -- the argument
 * `local/vocabulary.c` makes about rule tables. */
static fzn_state_entry_t *find(const fzn_state_t *state,
                                const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind)
{
	fzn_state_entry_t *hit = NULL;

	for (size_t i = 0; i < state->used; i++) {
		if (state->entries[i].live && state->entries[i].kind == kind &&
		    fzn_ct_memeq(state->entries[i].subject, subject, FZN_SUBJECT_LEN))
			hit = &state->entries[i];
	}

	return hit;
}

static int usable(const fzn_state_t *state)
{
	return state && state->entries && state->used <= state->capacity;
}

fzn_state_err_t fzn_state_init(fzn_state_t *state, fzn_state_entry_t *entries, size_t capacity)
{
	if (!state || !entries || capacity == 0)
		return FZN_STATE_ERR_MALFORMED;

	memset(entries, 0, capacity * sizeof(*entries));
	state->entries = entries;
	state->capacity = capacity;
	state->used = 0;

	return FZN_STATE_OK;
}

/* Write a record into an entry. Shared so that insert, supersede and resolve
 * cannot drift apart in which fields they remember. */
static void store(fzn_state_entry_t *e, const fzn_record_t *record)
{
	memcpy(e->subject, record->subject, FZN_SUBJECT_LEN);
	memcpy(e->issuer, record->issuer, FZN_PUBKEY_LEN);
	e->kind = record->kind;
	e->seq = record->seq;
	e->body = record->body;
	e->body_len = record->body_len;
	e->live = 1;
}

/* The body of both apply and resolve. `override` is what separates them: it
 * is the caller having said, in a function named for it, that a different
 * issuer may take this subject over. */
static fzn_state_err_t put(fzn_state_t *state, const fzn_record_t *record, int override)
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
		/* A CLEARED SLOT IS REUSED BEFORE THE ARRAY GROWS, or clearing
		 * leaks capacity: `used` never shrinks, so a state that sets
		 * and clears the same subject repeatedly would fill up while
		 * holding almost nothing. Found by state_test, which cleared
		 * one subject and then could not add a third into a state of
		 * three. */
		for (size_t i = 0; i < state->used; i++) {
			if (!state->entries[i].live) {
				e = &state->entries[i];
				break;
			}
		}

		if (!e) {
			/* `>=` rather than `==`, for the reason
			 * chain/revocation.c gives at the same place: the
			 * append writes at entries[used] and an equality test
			 * lets a corrupt `used` through. */
			if (state->used >= state->capacity)
				return FZN_STATE_ERR_FULL;
			e = &state->entries[state->used++];
		}

		store(e, record);
		return FZN_STATE_OK;
	}

	if (!fzn_ct_memeq(e->issuer, record->issuer, FZN_PUBKEY_LEN)) {
		if (!override)
			return FZN_STATE_ERR_CONFLICT;
		store(e, record);
		return FZN_STATE_OK;
	}

	/* Same issuer: its own sequence orders it, and only forwards. An older
	 * record arriving late must not undo a newer one -- which is what a
	 * re-delivery looks like, and it is the whole reason the sequence is
	 * carried into the entry. */
	if (record->seq <= e->seq)
		return FZN_STATE_ERR_STALE;

	store(e, record);
	return FZN_STATE_OK;
}

fzn_state_err_t fzn_state_apply(fzn_state_t *state, const fzn_record_t *record)
{
	return put(state, record, 0);
}

fzn_state_err_t fzn_state_resolve(fzn_state_t *state, const fzn_record_t *record)
{
	return put(state, record, 1);
}

fzn_state_err_t fzn_state_clear(fzn_state_t *state, const uint8_t subject[FZN_SUBJECT_LEN],
                                 uint32_t kind, const uint8_t issuer[FZN_PUBKEY_LEN],
                                 uint64_t seq)
{
	fzn_state_entry_t *e;

	if (!usable(state) || !subject || !issuer)
		return FZN_STATE_ERR_MALFORMED;
	if (seq == 0)
		return FZN_STATE_ERR_MALFORMED;

	e = find(state, subject, kind);
	if (!e)
		return FZN_STATE_ERR_ABSENT;
	if (!fzn_ct_memeq(e->issuer, issuer, FZN_PUBKEY_LEN))
		return FZN_STATE_ERR_CONFLICT;
	if (seq <= e->seq)
		return FZN_STATE_ERR_STALE;

	/* Cleared rather than compacted. The slot is reusable and the array
	 * does not shift, so no pointer a caller holds into it moves. */
	memset(e, 0, sizeof(*e));

	return FZN_STATE_OK;
}

const fzn_state_entry_t *fzn_state_get(const fzn_state_t *state,
                                        const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind)
{
	if (!usable(state) || !subject)
		return NULL;

	return find(state, subject, kind);
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
	}

	return "unknown";
}
