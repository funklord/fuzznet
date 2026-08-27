/* See sync.h. */

#include "sync.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* The peer's position for (issuer, stream), or NULL.
 *
 * Scans every position rather than stopping at the first, and keeps the
 * LARGEST `received` among duplicates, so that a peer which sent the same
 * (issuer, stream) twice with different numbers cannot change the answer by
 * ordering them.
 *
 * It used to keep the LAST hit, under a comment claiming exactly the property
 * that does not give: with two different numbers the last one is whichever
 * the SENDER put last. That is the whole of the ordering fault in miniature,
 * and it sat under a comment saying it had been dealt with.
 *
 * Largest rather than smallest because the two directions disagree about
 * which way is safe and only one of them can lose anything. In an OFFER the
 * number decides how much this host SENDS, and the largest claim sends the
 * least. In a FETCH it decides how much this host ASKS FOR, which
 * `max_per_request` already bounds and which costs the peer rather than this
 * host. So the largest is conservative where it matters and merely bounded
 * where it does not. */
static const fzn_sync_position_t *theirs_for(const fzn_sync_position_t *theirs,
                                              size_t their_count,
                                              const uint8_t issuer[FZN_PUBKEY_LEN],
                                              uint32_t stream)
{
	const fzn_sync_position_t *hit = NULL;

	for (size_t i = 0; i < their_count; i++) {
		if (theirs[i].stream != stream ||
		    !fzn_ct_memeq(theirs[i].issuer, issuer, FZN_PUBKEY_LEN))
			continue;
		if (!hit || theirs[i].received > hit->received)
			hit = &theirs[i];
	}

	return hit;
}

/* Whether this host follows (issuer, stream). Scans all of them for the
 * reason `journal.c`'s own lookup does: a table with a duplicate in it should
 * not answer differently depending on which copy is met first. */
static int follows(const fzn_journal_t *journal, const uint8_t issuer[FZN_PUBKEY_LEN],
                   uint32_t stream)
{
	int found = 0;

	for (size_t i = 0; i < journal->used; i++) {
		if (journal->entries[i].stream == stream &&
		    fzn_ct_memeq(journal->entries[i].issuer, issuer, FZN_PUBKEY_LEN))
			found = 1;
	}

	return found;
}

/* How many of the peer's positions to look at, recording the rest.
 *
 * See `FZN_SYNC_MAX_POSITIONS` in sync.h for why there is a ceiling and why
 * it is this one. The point to keep in view here is that the excess is
 * REPORTED and not merely dropped, which is what makes a peer sending an
 * absurd digest something a consumer can see and act on rather than a quiet
 * slowdown. */
static size_t to_examine(size_t their_count, fzn_sync_plan_t *plan)
{
	if (their_count <= FZN_SYNC_MAX_POSITIONS)
		return their_count;

	plan->positions_ignored = their_count - FZN_SYNC_MAX_POSITIONS;
	return FZN_SYNC_MAX_POSITIONS;
}

size_t fzn_sync_digest(const fzn_journal_t *journal, fzn_sync_position_t *out, size_t out_cap,
                       size_t *dropped)
{
	size_t n = 0;

	/* `dropped` is required rather than optional, which is the whole point.
	 * An out-parameter a caller may pass NULL for is one every caller
	 * passes NULL for, and this function's silence is what sync.h forbids. */
	if (!dropped)
		return 0;

	*dropped = 0;

	if (!journal || !journal->entries || !out || journal->used > journal->capacity)
		return 0;

	/* THE LOOP NO LONGER STOPS AT `out_cap`, it keeps counting.
	 *
	 * It used to stop, return a short count, and say nothing -- which
	 * sync.h forbids by name: "EVERY BOUND IS REPORTED. A plan that did not
	 * fit says so, rather than returning a short list that looks complete: a
	 * truncated plan silently dropped is a range nobody asks for again."
	 *
	 * That last clause is what made this worse than an untidy API. The scan
	 * runs in journal order, so the entries past the bound are THE SAME
	 * entries on every exchange. A host whose digest did not fit therefore
	 * never advertised its position on those streams -- not this round and
	 * not any round -- so the peer never learned it was behind on them and
	 * never sent them. They do not sync late; they do not sync. */
	for (size_t i = 0; i < journal->used; i++) {
		if (n >= out_cap) {
			(*dropped)++;
			continue;
		}
		memcpy(out[n].issuer, journal->entries[i].issuer, FZN_PUBKEY_LEN);
		out[n].stream = journal->entries[i].stream;
		out[n].received = journal->entries[i].received;
		n++;
	}

	return n;
}

/* Both directions are the same comparison with the operands swapped, so they
 * share it: for each issuer, if `ahead` is past `behind`, that is a range. */
static void add_range(const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t behind,
                      uint64_t ahead,
                      uint64_t max_per_request, fzn_sync_request_t *out, size_t out_cap,
                      fzn_sync_plan_t *plan)
{
	uint64_t want;

	if (ahead <= behind)
		return;

	if (plan->request_count >= out_cap) {
		/* COUNTED, NOT DROPPED. A plan that quietly returned a short
		 * list would look complete, and the ranges left out would never
		 * be asked for again.
		 *
		 * Both callers now reach this at most once per entry in THIS
		 * host's journal, so it counts the caller's own sizing and
		 * nothing the peer chose. sync.h's `truncated` says what that
		 * buys and why it is a separate number from
		 * `positions_ignored`. */
		plan->truncated++;
		return;
	}

	want = ahead - behind;
	if (want > max_per_request)
		want = max_per_request;

	memcpy(out[plan->request_count].issuer, issuer, FZN_PUBKEY_LEN);
	out[plan->request_count].stream = stream;
	out[plan->request_count].from = behind + 1u;
	out[plan->request_count].count = want;
	plan->request_count++;
}

static int args_ok(const fzn_journal_t *journal, const fzn_sync_position_t *theirs,
                   size_t their_count, uint64_t max_per_request, const fzn_sync_request_t *out,
                   const fzn_sync_plan_t *plan)
{
	if (!journal || !journal->entries || !out || !plan)
		return 0;
	if (!theirs && their_count != 0)
		return 0;
	if (max_per_request == 0)
		return 0;
	return journal->used <= journal->capacity;
}

/* CLEAR THE PLAN BEFORE VALIDATING ANYTHING, which is what `fzn_sync_digest`
 * above already does with `*dropped` and what `fzn_link_snapshot` copied from
 * it, citing it by name. The two planners were the odd ones out: they
 * validated first and returned MALFORMED with the caller's plan untouched.
 *
 * sync.h insists every bound is reported THROUGH THE PLAN, so a caller that
 * reuses one plan per round -- the obvious way to write the loop -- read last
 * round's `truncated` and `request_count` after a refusal and could not tell
 * them from this round's. Measured: a plan pre-filled with 0x33 came back from
 * a refused call with `request_count = 3689348814741910323`, which is a length
 * a caller iterates.
 *
 * `plan` is the one argument that cannot be checked afterwards, so its own
 * NULL test lives here rather than being left to `args_ok`. */
static int clear_plan(fzn_sync_plan_t *plan)
{
	if (!plan)
		return 0;

	memset(plan, 0, sizeof(*plan));
	return 1;
}

fzn_sync_err_t fzn_sync_plan_fetch(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan)
{
	size_t look;

	if (!clear_plan(plan))
		return FZN_SYNC_ERR_MALFORMED;
	if (!args_ok(journal, theirs, their_count, max_per_request, out, plan))
		return FZN_SYNC_ERR_MALFORMED;

	look = to_examine(their_count, plan);

	/* First pass: what they follow and this host does not. See sync.h --
	 * reported, never requested. Adopting an issuer because a peer
	 * mentioned it is how one peer fills every journal in the network.
	 *
	 * It is a second walk rather than a by-product of the one below, and
	 * that is affordable only because `look` is bounded: the two passes
	 * together cost twice `look` times `journal->used`, and twice a ceiling
	 * is still a ceiling. Unbounded it would have doubled a cost that was
	 * already the peer's to set. */
	for (size_t i = 0; i < look; i++) {
		if (!follows(journal, theirs[i].issuer, theirs[i].stream))
			plan->unknown_issuers++;
	}

	/* Second pass: the plan itself, walking THIS HOST'S JOURNAL.
	 *
	 * The old loop walked `theirs`, so the peer chose both the order of the
	 * plan and how many slots one stream could take -- five copies of one
	 * position were five requests. sync.h has the two measurements and the
	 * rejected alternatives; what the shape below guarantees is the part
	 * worth restating at the code: at most one range per entry in this
	 * journal, in this journal's order, so an `out_cap` of `journal->used`
	 * cannot be made to truncate by anything arriving from outside. */
	for (size_t k = 0; k < journal->used; k++) {
		const fzn_journal_entry_t *mine = &journal->entries[k];
		const fzn_sync_position_t *t;

		t = theirs_for(theirs, look, mine->issuer, mine->stream);
		if (!t)
			continue;

		add_range(mine->issuer, mine->stream, mine->received, t->received,
		          max_per_request, out, out_cap, plan);
	}

	return FZN_SYNC_OK;
}

fzn_sync_err_t fzn_sync_plan_offer(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan)
{
	size_t look;

	if (!clear_plan(plan))
		return FZN_SYNC_ERR_MALFORMED;
	if (!args_ok(journal, theirs, their_count, max_per_request, out, plan))
		return FZN_SYNC_ERR_MALFORMED;

	look = to_examine(their_count, plan);

	/* Walk OUR positions, because an offer is about what we have. */
	for (size_t i = 0; i < journal->used; i++) {
		const fzn_sync_position_t *t;

		t = theirs_for(theirs, look, journal->entries[i].issuer,
		               journal->entries[i].stream);
		if (!t) {
			/* AN ABSENT POSITION IS NOT A POSITION OF ZERO.
			 *
			 * This used to read `behind = 0` and offer from the
			 * start, so a digest containing NOTHING asked for
			 * everything: 64 ranges over 32,768 records, measured,
			 * from a message with no content in it. "Reply to a
			 * digest with an offer" is the most innocent-sounding
			 * operation in the file and it was the amplifier.
			 *
			 * Counted rather than offered, which makes this the
			 * exact mirror of the fetch rule above -- and the peer
			 * keeps the ability to ask for a whole history, because
			 * `fzn_journal_anchor` at sequence zero puts a position
			 * of ZERO in its digest and that is still offered from
			 * 1. A silence is not that statement.
			 *
			 * It is also wasted bandwidth even against an honest
			 * peer now. `fzn_journal_admit` refuses a stream the
			 * peer does not follow outright, so every record of
			 * such an offer would be answered with
			 * FZN_JOURNAL_ERR_UNKNOWN_ISSUER. */
			plan->unknown_issuers++;
			continue;
		}

		add_range(journal->entries[i].issuer, journal->entries[i].stream, t->received,
		          journal->entries[i].received, max_per_request, out, out_cap, plan);
	}

	return FZN_SYNC_OK;
}

const char *fzn_sync_err_str(fzn_sync_err_t err)
{
	switch (err) {
	case FZN_SYNC_OK:
		return "ok";
	case FZN_SYNC_ERR_MALFORMED:
		return "malformed argument";
	}

	return "unknown";
}
