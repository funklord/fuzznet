/* See sync.h. */

#include "sync.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* The peer's position for `issuer`, or NULL. Scans all of them rather than
 * stopping at the first, so a peer that sent the same issuer twice cannot
 * change the answer by ordering. */
static const fzn_sync_position_t *theirs_for(const fzn_sync_position_t *theirs,
                                              size_t their_count,
                                              const uint8_t issuer[FZN_PUBKEY_LEN],
                                              uint32_t stream)
{
	const fzn_sync_position_t *hit = NULL;

	for (size_t i = 0; i < their_count; i++) {
		if (theirs[i].stream == stream &&
		    fzn_ct_memeq(theirs[i].issuer, issuer, FZN_PUBKEY_LEN))
			hit = &theirs[i];
	}

	return hit;
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
		if (!journal->entries[i].live)
			continue;
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
		 * be asked for again. */
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

fzn_sync_err_t fzn_sync_plan_fetch(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan)
{
	if (!args_ok(journal, theirs, their_count, max_per_request, out, plan))
		return FZN_SYNC_ERR_MALFORMED;

	memset(plan, 0, sizeof(*plan));

	/* Walk THEIR positions, because a fetch is about what they have. An
	 * issuer this host follows and they do not is not a gap here; it is
	 * something to offer, which is the other function. */
	for (size_t i = 0; i < their_count; i++) {
		const fzn_journal_entry_t *mine = NULL;

		for (size_t k = 0; k < journal->used; k++) {
			if (journal->entries[k].live &&
			    journal->entries[k].stream == theirs[i].stream &&
			    fzn_ct_memeq(journal->entries[k].issuer, theirs[i].issuer,
			                 FZN_PUBKEY_LEN))
				mine = &journal->entries[k];
		}

		if (!mine) {
			/* See sync.h: reported, never requested. Adopting an
			 * issuer because a peer mentioned it is how one peer
			 * fills every journal in the network. */
			plan->unknown_issuers++;
			continue;
		}

		add_range(theirs[i].issuer, theirs[i].stream, mine->received,
		          theirs[i].received, max_per_request, out, out_cap, plan);
	}

	return FZN_SYNC_OK;
}

fzn_sync_err_t fzn_sync_plan_offer(const fzn_journal_t *journal,
                                    const fzn_sync_position_t *theirs, size_t their_count,
                                    uint64_t max_per_request, fzn_sync_request_t *out,
                                    size_t out_cap, fzn_sync_plan_t *plan)
{
	if (!args_ok(journal, theirs, their_count, max_per_request, out, plan))
		return FZN_SYNC_ERR_MALFORMED;

	memset(plan, 0, sizeof(*plan));

	/* Walk OUR positions, because an offer is about what we have. */
	for (size_t i = 0; i < journal->used; i++) {
		const fzn_sync_position_t *t;
		uint64_t behind;

		if (!journal->entries[i].live)
			continue;

		t = theirs_for(theirs, their_count, journal->entries[i].issuer,
		               journal->entries[i].stream);
		/* An issuer they have never seen is offered from the start.
		 * Offering is not adopting: they still decide, and
		 * `fzn_journal_admit` will refuse anything past their own
		 * position anyway. */
		behind = t ? t->received : 0u;
		if (!t)
			plan->unknown_issuers++;

		add_range(journal->entries[i].issuer, journal->entries[i].stream, behind,
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
