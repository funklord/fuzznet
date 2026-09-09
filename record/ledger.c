/* The delivery ledger. See ledger.h for what it is and for what stays with
 * the consumer. */

#include "ledger.h"

/* Diagnostics through flog, vendored and possibly absent. sec 209. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define LEDGER_LOG(l, sub, sev, ...)                                                       \
	do {                                                                               \
		if ((l) && (l)->log)                                                       \
			flog_printf((l)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);        \
	} while (0)
#else
#define LEDGER_LOG(l, sub, sev, ...) ((void)0)
#endif

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
/* The predicate itself, and it says nothing.
 *
 * SPLIT FROM `corrupt` IN sec 227, when `fzn_ledger_sound` was added. That one
 * IS an error channel -- it returns the answer -- so logging from it would
 * contradict the argument the line below rests on, and a consumer refreshing a
 * screen would emit the same ERR every frame. One implementation of the
 * question, two behaviours around it: `corrupt` for the readers that cannot
 * report, this for the caller that asked. */
static int unscannable(const fzn_ledger_t *ledger)
{
	return ledger->used > ledger->capacity || (ledger->used > 0 && !ledger->entries);
}

static int corrupt(const fzn_ledger_t *ledger)
{
	if (!unscannable(ledger))
		return 0;

	/*
	 * SAID HERE RATHER THAN AT THE THREE CALLERS, because two of them have
	 * nowhere to say it. `fzn_ledger_confirmed` returns a version and
	 * `fzn_ledger_count` returns a count -- neither has an error channel,
	 * so both answer zero, and zero is what an honest "never heard of this
	 * peer" answers. No caller can tell the two apart and none ever will.
	 *
	 * What follows is the whole table reading as unconfirmed, so every
	 * subject is resent to every peer for as long as the condition lasts.
	 * That is the safe direction by design -- see `fzn_ledger_behind` --
	 * and it is silent, which is the part a log fixes.
	 */
	LEDGER_LOG(ledger, "record/ledger", FLOG_ERR,
	           "ledger cannot be scanned: %zu row(s) claimed in %zu slot(s)%s, so "
	           "every read answers as if nothing were confirmed and every subject "
	           "is resent",
	           ledger->used, ledger->capacity,
	           ledger->entries ? "" : " with no array at all");
	return 1;
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

void fzn_ledger_set_log(fzn_ledger_t *ledger, struct flog_t *log)
{
	if (!ledger)
		return;

	ledger->log = log;
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
	/* Quiet unless somebody asks. */
	ledger->log = NULL;
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
		if (version <= ledger->entries[at].version) {
			/* HOW FAR BACK, which FZN_LEDGER_ERR_STALE cannot
			 * say. One reordered datagram and a peer whose view
			 * has fallen a long way behind return the same value
			 * and are different problems. At INFO because the
			 * header above is right that this is neither a fault
			 * nor nothing: the table is identical either way. */
			LEDGER_LOG(ledger, "record/ledger", FLOG_INFO,
			           "a confirmation for kind %lu arrived at version %llu, "
			           "%llu behind the %llu already held, so acknowledgements "
			           "are being reordered",
			           (unsigned long)kind, (unsigned long long)version,
			           (unsigned long long)(ledger->entries[at].version - version),
			           (unsigned long long)ledger->entries[at].version);
			return FZN_LEDGER_ERR_STALE;
		}
		ledger->entries[at].version = version;
		return FZN_LEDGER_OK;
	}

	/* A ROW IS NEVER RECLAIMED AND THE STORE REFUSES WHEN FULL. Nothing
	 * here expires -- a confirmation is true for ever -- so unlike
	 * `chain/chain_store.c` there is no dead entry to spend, and that
	 * module's eviction does not carry. `chain/revocation.c` refuses for
	 * the same reason: a revocation never expires either. */
	if (ledger->used >= ledger->capacity) {
		/* WHICH SUBJECT WENT UNRECORDED, and that it stays that way.
		 * The comment above says no row is ever reclaimed, so this is
		 * not pressure that recovers: from here on this peer reads as
		 * behind on this kind for ever and is resent for ever. At ERR
		 * rather than the CRIT `chain/revocation.c` takes, because a
		 * full revocation store can fail to WITHHOLD an authority and
		 * a full ledger can only fail to notice a delivery. */
		LEDGER_LOG(ledger, "record/ledger", FLOG_ERR,
		           "ledger full at %zu row(s) and none is ever reclaimed, so "
		           "version %llu of kind %lu is not recorded and this peer will "
		           "be resent it for ever",
		           ledger->capacity, (unsigned long long)version,
		           (unsigned long)kind);
		return FZN_LEDGER_ERR_FULL;
	}

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

int fzn_ledger_sound(const fzn_ledger_t *ledger)
{
	/* A NULL LEDGER IS SOUND, and this is not a null check -- the header
	 * says so and the three siblings answer the same way. `corrupt()` is
	 * the private predicate every guard in this file already uses, and
	 * exposing its negation rather than a second implementation is what
	 * keeps a caller's answer and this module's the same answer. */
	if (!ledger)
		return 1;

	return !unscannable(ledger);
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
