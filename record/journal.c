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
	if (!e)
		/* ADMITTING DOES NOT ADOPT. This used to create an entry for any
		 * unseen (issuer, stream) arriving at sequence 1, on the
		 * reasoning that only sequence 1 starts a stream implicitly and
		 * anything else needs a deliberate anchor.
		 *
		 * That reasoning was written when a position was per ISSUER, so
		 * the key space was the set of keys an attacker holds. `stream`
		 * is a uint32 the issuer chooses freely, which multiplied that
		 * space by 2^32, and the safety argument was never re-derived.
		 *
		 * Measured: one authorised key opens 64 entries in a 64-entry
		 * journal, and no other issuer can ever be followed again --
		 * permanently, because there is no forget and journal.h explains
		 * why there cannot be one.
		 *
		 * `record/sync.h` already claims this protection whole: "record/
		 * journal.h already makes adopting an issuer deliberate --
		 * fzn_journal_anchor. This file does not quietly undo that."
		 * Sync refuses to ASK from strangers; a PUSHED record was
		 * adopted anyway, and `fzn_sync_plan_offer` means unsolicited
		 * pushes are part of the design. The door sync guards had a
		 * second one beside it.
		 *
		 * A quota was considered and rejected: a reassembly slot is
		 * self-clearing, so a sender at quota is served again a moment
		 * later, while a journal entry is permanent -- the same shape
		 * would be a LIFETIME cap that locks out a legitimate issuer's
		 * next stream for ever. Refusing to adopt closes the vector with
		 * no quota, no new field and no new code.
		 *
		 * It also retires a wart: an unknown issuer at a sequence other
		 * than 1 used to be told GAP, because that test ran before the
		 * capacity test -- so a caller was instructed to fetch a range
		 * it had nowhere to put. UNKNOWN_ISSUER names the decision the
		 * caller actually has to make. */
		return FZN_JOURNAL_ERR_UNKNOWN_ISSUER;

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

	/* NOTHING CLAMPS `applied` HERE, AND THE REFUSAL ABOVE IS WHY. An
	 * anchor never moves backwards, so `received` only increases; `applied`
	 * is raised only by `fzn_journal_confirm`, which refuses anything above
	 * `received`. At this line the state is therefore
	 * `applied <= old_received < seq == received`, strictly -- so
	 * `applied <= received` holds by construction and there is no state for
	 * a clamp to repair.
	 *
	 * THERE WAS ONE UNTIL 2026-09-04, unreachable since the backwards
	 * refusal above was written, and found by coverage as the only
	 * never-executed line in this file. `record_guided` is the independent
	 * witness: it mirrors a successful anchor WITHOUT clamping its model's
	 * `applied`, and asserts `pending == received - applied`, so it would
	 * have diverged the first time the clamp fired. project.md sec 66.
	 *
	 * The invariant is STATED rather than defended, because a repair firing
	 * at one instant would not have helped anyone. A caller that pokes
	 * `applied` past `received` in its own entry array has already broken
	 * `fzn_journal_pending`, which underflows to something enormous, and
	 * that is not repaired by an anchor it may never make. Whoever lets an
	 * anchor move backwards has to come here anyway; this paragraph is what
	 * they need, and the two lines were not. */

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
	 * library reserves -- `fzn_record_open` refuses it by name ("sequence
	 * zero is reserved") and `fzn_record_sign` will not mint one, so it
	 * cannot enter or leave a record at all; and journal.h builds the whole
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
