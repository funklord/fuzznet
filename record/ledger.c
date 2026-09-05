/* The delivery ledger. See ledger.h for what it is and for what stays with
 * the consumer. */

#include "ledger.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* A ledger whose count exceeds its array, or whose count is nonzero with no
 * array at all, describes rows that cannot be scanned.
 *
 * Every reader answers it in the direction that resends. `fzn_ledger_behind`
 * says yes, `fzn_ledger_confirmed` says zero, `fzn_ledger_count` says zero,
 * and `fzn_ledger_confirm` refuses rather than writing into an array it
 * cannot bound. The polarity is the opposite of `fzn_revocation_covers`'s
 * and the reason is opposite too: an unreadable revocation store must not
 * silently authorise, and an unreadable ledger must not silently withhold. */
static int corrupt(const fzn_ledger_t *ledger)
{
	return ledger->used > ledger->capacity || (ledger->used > 0 && !ledger->entries);
}

/* The row for this triple, or `used` when there is none.
 *
 * Constant-time on the peer and the subject, because a caller's timing
 * should not say who this host has been talking to or about what. The kind
 * is a namespace rather than a secret and is compared plainly. */
static size_t find_row(const fzn_ledger_t *ledger, const uint8_t *peer,
                       const uint8_t *subject, uint32_t kind)
{
	size_t at;

	for (at = 0; at < ledger->used; at++) {
		const fzn_ledger_entry_t *e = &ledger->entries[at];

		if (e->kind == kind && fzn_ct_memeq(e->peer, peer, FZN_PUBKEY_LEN)
		    && fzn_ct_memeq(e->subject, subject, FZN_SUBJECT_LEN))
			return at;
	}
	return ledger->used;
}

fzn_ledger_err_t fzn_ledger_init(fzn_ledger_t *ledger, fzn_ledger_entry_t *entries,
                                 size_t capacity)
{
	if (!ledger || !entries || capacity == 0)
		return FZN_LEDGER_ERR_MALFORMED;

	/* sec 39's convention: a fresh table must not hold what the caller's
	 * memory held. */
	memset(entries, 0, capacity * sizeof(*entries));

	ledger->entries = entries;
	ledger->capacity = capacity;
	ledger->used = 0;
	return FZN_LEDGER_OK;
}

fzn_ledger_err_t fzn_ledger_confirm(fzn_ledger_t *ledger, const uint8_t peer[FZN_PUBKEY_LEN],
                                    const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind,
                                    uint64_t version)
{
	size_t at;

	if (!ledger || !peer || !subject)
		return FZN_LEDGER_ERR_MALFORMED;
	/* Zero is what an absent row answers, so storing it would make
	 * "confirmed nothing" and "never heard of" one state. */
	if (version == 0u)
		return FZN_LEDGER_ERR_MALFORMED;
	if (corrupt(ledger) || !ledger->entries)
		return FZN_LEDGER_ERR_MALFORMED;

	at = find_row(ledger, peer, subject, kind);
	if (at < ledger->used) {
		/* NEVER BACKWARDS. A late acknowledgement is reordering rather
		 * than retraction: both numbers were real when they were sent,
		 * so the higher is the better evidence. Reported rather than
		 * absorbed, because "my acks are arriving out of order" is a
		 * fact about the network and the table is the same either way. */
		if (version <= ledger->entries[at].version)
			return FZN_LEDGER_ERR_STALE;
		ledger->entries[at].version = version;
		return FZN_LEDGER_OK;
	}

	/* A ROW IS NEVER RECLAIMED AND THE STORE REFUSES WHEN FULL. Nothing
	 * here expires -- a confirmation is true for ever -- so unlike
	 * `chain/chain_store.c` there is no dead entry to spend, and that
	 * module's eviction does not carry. `chain/revocation.c` refuses for
	 * the same reason: a revocation never expires either. */
	if (ledger->used >= ledger->capacity)
		return FZN_LEDGER_ERR_FULL;

	memcpy(ledger->entries[ledger->used].peer, peer, FZN_PUBKEY_LEN);
	memcpy(ledger->entries[ledger->used].subject, subject, FZN_SUBJECT_LEN);
	ledger->entries[ledger->used].kind = kind;
	ledger->entries[ledger->used].version = version;
	ledger->used++;
	return FZN_LEDGER_OK;
}

uint64_t fzn_ledger_confirmed(const fzn_ledger_t *ledger, const uint8_t peer[FZN_PUBKEY_LEN],
                              const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind)
{
	size_t at;

	if (!ledger || !peer || !subject)
		return 0u;
	if (corrupt(ledger) || !ledger->entries)
		return 0u;

	at = find_row(ledger, peer, subject, kind);
	if (at == ledger->used)
		return 0u;
	return ledger->entries[at].version;
}

int fzn_ledger_behind(const fzn_ledger_t *ledger, const uint8_t peer[FZN_PUBKEY_LEN],
                      const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind, uint64_t current)
{
	/* A peer never heard from, a subject never sent, and a ledger too
	 * corrupt to scan all answer zero above and therefore YES here. Each
	 * resolves to "send it again", which costs bytes rather than
	 * correctness. */
	return fzn_ledger_confirmed(ledger, peer, subject, kind) < current;
}

size_t fzn_ledger_count(const fzn_ledger_t *ledger)
{
	if (!ledger || corrupt(ledger))
		return 0u;
	return ledger->used;
}

const char *fzn_ledger_err_str(fzn_ledger_err_t err)
{
	switch (err) {
	case FZN_LEDGER_OK:
		return "ok";
	case FZN_LEDGER_ERR_MALFORMED:
		return "malformed";
	case FZN_LEDGER_ERR_FULL:
		return "ledger full";
	case FZN_LEDGER_ERR_STALE:
		return "stale confirmation";
	}
	return "unknown";
}
