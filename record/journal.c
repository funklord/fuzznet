/* See journal.h. */

#include "journal.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* The entry for `issuer`, or NULL. Scans every entry rather than returning at
 * the first match, for the reason `local/vocabulary.c` gives:
 * a table with a duplicate in it should not give a different answer depending
 * on which copy is met first. */
static fzn_journal_entry_t *find(const fzn_journal_t *journal,
                                  const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	fzn_journal_entry_t *hit = NULL;

	for (size_t i = 0; i < journal->used; i++) {
		if (journal->entries[i].stream == stream &&
		    fzn_ct_memeq(journal->entries[i].issuer, issuer, FZN_PUBKEY_LEN))
			hit = &journal->entries[i];
	}

	return hit;
}

fzn_journal_err_t fzn_journal_init(fzn_journal_t *journal, fzn_journal_entry_t *entries,
                                    size_t capacity)
{
	if (!journal || !entries || capacity == 0)
		return FZN_JOURNAL_ERR_MALFORMED;

	memset(entries, 0, capacity * sizeof(*entries));
	journal->entries = entries;
	journal->capacity = capacity;
	journal->used = 0;

	return FZN_JOURNAL_OK;
}

/* Shared by admit and anchor: the guard every entry point needs, since both
 * read `used` and a corrupt one would run the scan past the array. */
static int usable(const fzn_journal_t *journal, const uint8_t *issuer)
{
	return journal && journal->entries && issuer && journal->used <= journal->capacity;
}

fzn_journal_err_t fzn_journal_admit(fzn_journal_t *journal,
                                     const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                                     uint64_t seq)
{
	fzn_journal_entry_t *e;

	if (!usable(journal, issuer))
		return FZN_JOURNAL_ERR_MALFORMED;
	if (seq == 0)
		return FZN_JOURNAL_ERR_MALFORMED;

	e = find(journal, issuer, stream);
	if (!e) {
		/* An issuer never seen. Only sequence 1 starts a stream
		 * implicitly; anything else is a join in progress and needs
		 * `fzn_journal_anchor`, so that adopting a stranger's arbitrary
		 * starting point is always a deliberate act. */
		if (seq != 1)
			return FZN_JOURNAL_ERR_GAP;
		/* `>=` rather than `==`, for the reason chain/revocation.c gives
		 * at the same place: the append below writes at entries[used],
		 * and an equality test lets a corrupt `used` through. */
		if (journal->used >= journal->capacity)
			return FZN_JOURNAL_ERR_FULL;

		e = &journal->entries[journal->used++];
		memcpy(e->issuer, issuer, FZN_PUBKEY_LEN);
		e->stream = stream;
		e->received = 1;
		e->applied = 0;
		return FZN_JOURNAL_OK;
	}

	if (seq <= e->received)
		return FZN_JOURNAL_ERR_DUPLICATE;
	if (seq > e->received + 1u)
		return FZN_JOURNAL_ERR_GAP;

	e->received = seq;
	return FZN_JOURNAL_OK;
}

fzn_journal_err_t fzn_journal_anchor(fzn_journal_t *journal,
                                      const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                                     uint64_t seq)
{
	fzn_journal_entry_t *e;

	if (!usable(journal, issuer))
		return FZN_JOURNAL_ERR_MALFORMED;

	e = find(journal, issuer, stream);
	if (!e) {
		if (journal->used >= journal->capacity)
			return FZN_JOURNAL_ERR_FULL;
		e = &journal->entries[journal->used++];
		memcpy(e->issuer, issuer, FZN_PUBKEY_LEN);
		e->stream = stream;
		e->applied = 0;
		e->received = 0;

		/* SEQUENCE ZERO MEANS "FOLLOW FROM THE BEGINNING", and this
		 * file reserved it for exactly that -- "no record yet, so an
		 * entry can start empty without a separate flag" -- and then
		 * refused it, which left no way to express the state.
		 *
		 * Found by the integration harness rather than by the unit
		 * tests, and it could not have been found by them: a test that
		 * admits records never needs to follow an issuer BEFORE
		 * receiving from one. A whole network does, because
		 * `record/sync.h` will not request from an issuer this host
		 * does not follow, so without this every host stayed at zero
		 * records for ever and the scenario converged on nothing. */
		if (seq == 0)
			return FZN_JOURNAL_OK;
	} else if (seq == 0) {
		/* Already following. Asking again is an echo, not a rewind. */
		return FZN_JOURNAL_ERR_DUPLICATE;
	}

	/* An anchor never moves BACKWARDS. Re-anchoring lower would readmit
	 * everything between, which is the replay this file exists to refuse --
	 * and a caller that wants to start again from further back wants a new
	 * journal, not a quietly rewound one. */
	if (seq <= e->received)
		return FZN_JOURNAL_ERR_DUPLICATE;

	e->received = seq;
	if (e->applied > e->received)
		e->applied = e->received;

	return FZN_JOURNAL_OK;
}

fzn_journal_err_t fzn_journal_confirm(fzn_journal_t *journal,
                                      const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                                     uint64_t seq)
{
	fzn_journal_entry_t *e;

	if (!usable(journal, issuer))
		return FZN_JOURNAL_ERR_MALFORMED;

	e = find(journal, issuer, stream);
	if (!e)
		return FZN_JOURNAL_ERR_UNKNOWN_ISSUER;
	if (seq > e->received)
		return FZN_JOURNAL_ERR_NOT_RECEIVED;
	if (seq <= e->applied)
		return FZN_JOURNAL_ERR_DUPLICATE;

	e->applied = seq;
	return FZN_JOURNAL_OK;
}

uint64_t fzn_journal_next(const fzn_journal_t *journal,
                          const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	const fzn_journal_entry_t *e;

	if (!usable(journal, issuer))
		return 1;

	e = find(journal, issuer, stream);
	if (!e)
		return 1u;

	/* SATURATE RATHER THAN WRAP. `received + 1` is UINT64_MAX + 1 == 0 once
	 * a stream has run to the top, and zero is the one sequence this
	 * library reserves -- `fzn_record_verify` refuses it by name
	 * ("sequence zero is reserved"), and journal.h builds the whole
	 * nothing-received-yet convention on it. So the wrap handed a caller
	 * the single value guaranteed to be rejected, as the answer to "what
	 * should I ask for next".
	 *
	 * Reachable through two public calls and no corruption at all:
	 * `fzn_journal_anchor(..., UINT64_MAX)` then `fzn_journal_next(...)`.
	 *
	 * UINT64_MAX is the honest answer instead. The stream is exhausted,
	 * there is no next sequence, and this is the only value that is neither
	 * reserved nor admissible -- `fzn_journal_admit` refuses it as a
	 * duplicate, which is exactly what a caller acting on it should meet. */
	if (e->received == UINT64_MAX)
		return UINT64_MAX;

	return e->received + 1u;
}

uint64_t fzn_journal_pending(const fzn_journal_t *journal,
                             const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	const fzn_journal_entry_t *e;

	if (!usable(journal, issuer))
		return 0;

	e = find(journal, issuer, stream);
	return e ? e->received - e->applied : 0u;
}

const char *fzn_journal_err_str(fzn_journal_err_t err)
{
	switch (err) {
	case FZN_JOURNAL_OK:
		return "ok";
	case FZN_JOURNAL_ERR_MALFORMED:
		return "malformed argument";
	case FZN_JOURNAL_ERR_DUPLICATE:
		return "already seen";
	case FZN_JOURNAL_ERR_GAP:
		return "ahead of what is held";
	case FZN_JOURNAL_ERR_FULL:
		return "no room to track another issuer";
	case FZN_JOURNAL_ERR_UNKNOWN_ISSUER:
		return "nothing received from this issuer";
	case FZN_JOURNAL_ERR_NOT_RECEIVED:
		return "confirming further than was received";
	}

	return "unknown";
}
