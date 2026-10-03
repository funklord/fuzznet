/* Emptying the trash: a deletion queued until every pinned host consents.
 * sec 427, phase 3 of the notes move.
 *
 * Ported from fuzzypickles' `notes_purge` and the purge half of their
 * `core.c` at 1e002a9, with the three defects their sec 20 survey found
 * (2026-09-17) closed here by construction where this layer can close them.
 *
 * WHY A QUEUE. A trashed note is a flag (`notes/note.h`), so a note removed
 * on one host reappears as trashed rather than vanishing when an older host
 * syncs. Emptying the trash has to actually free the space, and the obvious
 * answers are wrong the same way: a local delete is undone by the next sibling
 * to sync, and a tombstone kept for ever is a smaller permanent thing, not a
 * saving. The copyright holder's answer (fuzzypickles, 2026-09-05): a deletion
 * is a QUEUED COMMAND, eliminated once consensus is attained, over a set
 * DEFINED BEFOREHAND -- pinned when the purge is queued, never recomputed as
 * hosts come and go, since a set that grew while consent was gathered would
 * never close.
 *
 * AN ANSWER IS "ERASED" OR "I DO NOT RETAIN NOTES", AND BOTH COUNT. A host
 * that keeps no notes would never answer otherwise, and waiting for it is a
 * deadlock that looks like a slow network. Silence is the one thing that keeps
 * a purge waiting, because silence is what a switched-off host looks like.
 *
 * THE THREE DEFECTS, AND WHERE EACH IS CLOSED:
 *
 *   - A host named twice in the pinned set could never be fully answered, so
 *     the purge waited for ever. `fzn_notes_purge_add` deduplicates the set.
 *   - A sibling list that could not be read became an empty set, and an empty
 *     set is immediate consent -- every trashed note erased with nobody asked.
 *     Here the set is SPELLED, as a notes policy is: a zeroed one is refused
 *     rather than read as "nobody to ask", so a caller that failed to read its
 *     hosts cannot reach the empty-set path by accident. A spelled empty set
 *     is still immediate consent, which is the single-host case.
 *   - A sibling briefly behind could be sent the purge, erase, answer, and be
 *     sent the note's record again in the same tick, re-admitting it. That is
 *     carriage's to close, and fuzzypickles closed it there: the pusher skips
 *     a note `fzn_notes_purge_pending` names. Phase 4 must keep that rule.
 *
 * THE ORDER OF THE LAST STEP: every claim on the note is erased, then the
 * queue entry is dropped. The entry is what remembers the note is still to
 * go, so dropping it first would lose the purge on a crash.
 */

#ifndef FZN_NOTES_PURGE_H
#define FZN_NOTES_PURGE_H

#include <stddef.h>
#include <stdint.h>

#include "view.h"

/* Purges awaiting consent at once, and hosts one may ask. */
#define FZN_NOTES_PURGE_MAX 32u
#define FZN_NOTES_PURGE_ASK_MAX 32u

/* Re-ask a host that has not answered no more often than this. */
#define FZN_NOTES_PURGE_RETRY_MS 60000u

/* The hosts a purge must hear from, SPELLED: see the header. */
typedef struct fzn_notes_asking {
	int spelled;
	const fzn_notes_writer_t *hosts;
	size_t count;
} fzn_notes_asking_t;

/* The only constructor. `hosts` is this host's siblings, read successfully;
 * none at all is a host on its own, and a spelled empty set. */
static inline fzn_notes_asking_t fzn_notes_asking(const fzn_notes_writer_t *hosts, size_t count)
{
	fzn_notes_asking_t a;

	a.spelled = 1;
	a.hosts = hosts;
	a.count = hosts ? count : 0u;
	return a;
}

/* One queued purge, as held. */
typedef struct fzn_notes_purge {
	uint8_t id[FZN_TREE_ID_LEN];
	uint64_t queued_at_ms;
	/* Wall clock, so it compares across a restart. */
	uint64_t last_push_ms;
	size_t asked_count;
	uint8_t asked[FZN_NOTES_PURGE_ASK_MAX][FZN_PUBKEY_LEN];
	uint8_t answered[FZN_NOTES_PURGE_ASK_MAX];
} fzn_notes_purge_t;

/*
 * Queue a purge of note `id`, to be consented to by `asking`, deduplicated.
 * MALFORMED for an unspelled set or one past FZN_NOTES_PURGE_ASK_MAX; FULL past
 * FZN_NOTES_PURGE_MAX. `*complete` is 1 when nobody is to be asked: nothing is
 * queued then, and the caller finishes it with `fzn_notes_purge_finish`. A
 * purge already queued for `id` keeps its pinned set and is not re-pinned.
 */
fzn_notes_err_t fzn_notes_purge_add(const fzn_notes_store_t *store,
                                    const uint8_t id[FZN_TREE_ID_LEN], fzn_notes_asking_t asking,
                                    uint64_t now_ms, int *complete);

/* Read one queued purge. ABSENT when none is queued for `id`. */
fzn_notes_err_t fzn_notes_purge_get(const fzn_notes_store_t *store,
                                    const uint8_t id[FZN_TREE_ID_LEN], fzn_notes_purge_t *out);

/* Whether a purge is queued for `id`: such a note is kept out of what a user
 * is shown, and out of what is pushed to siblings (see the header). */
int fzn_notes_purge_pending(const fzn_notes_store_t *store, const uint8_t id[FZN_TREE_ID_LEN]);

/* `host` answered for `id`, whichever way. A host outside the pinned set is
 * ignored rather than refused: it cannot advance or block consent. `*complete`
 * is 1 once every pinned host has answered. */
fzn_notes_err_t fzn_notes_purge_answer(const fzn_notes_store_t *store,
                                       const uint8_t id[FZN_TREE_ID_LEN],
                                       const uint8_t host[FZN_PUBKEY_LEN], int *complete);

/* Erase every claim on `id` -- a node can carry one per writer, and erasing
 * one would leave it readable -- and report how many. What a host asked to
 * purge does, and what the asker does once consent is complete. */
fzn_notes_err_t fzn_notes_erase_note(const fzn_notes_store_t *store,
                                     const uint8_t id[FZN_TREE_ID_LEN], size_t *erased);

/* Consent is complete: erase every claim on `id`, THEN drop the entry. */
fzn_notes_err_t fzn_notes_purge_finish(const fzn_notes_store_t *store,
                                       const uint8_t id[FZN_TREE_ID_LEN]);

/* Every queued purge's note id, `cap` of them; BACKEND when the store cannot
 * list. For a caller asking each pinned host in turn. */
fzn_notes_err_t fzn_notes_purge_list(const fzn_notes_store_t *store,
                                     uint8_t (*ids)[FZN_TREE_ID_LEN], size_t cap, size_t *count);

/* The queued purges due to be asked again -- never asked, or last asked
 * FZN_NOTES_PURGE_RETRY_MS or more before `now_ms` -- into `ids`, `cap` of
 * them, each marked asked at `now_ms`. The caller asks each one's hosts that
 * have not answered (`fzn_notes_purge_get`). */
fzn_notes_err_t fzn_notes_purge_due(const fzn_notes_store_t *store, uint64_t now_ms,
                                    uint8_t (*ids)[FZN_TREE_ID_LEN], size_t cap, size_t *count);

/* Whether `host` has been heard from lately, by the caller's measure. */
typedef int (*fzn_notes_purge_heard_fn)(void *ctx, const uint8_t host[FZN_PUBKEY_LEN],
                                        uint64_t now_ms);

/*
 * RELEASE WHAT THE SILENT PIN, sec 472: the holder's answer to a purge
 * pinned to a node that never comes back. A purge queued more than `age_ms`
 * before `now_ms` counts each host that has not answered, and that `heard`
 * says has not been heard from lately, as answered; a purge so completed is
 * finished, every claim erased. The cost accepted is sec 434's: a host gone
 * that long may still hold an old copy of what is erased.
 *
 * A PURGE QUEUED "IN THE FUTURE" was stamped by a clock since set back, and
 * aging it from that stamp would pin it for as long as the clock was wrong:
 * it is stamped again from `now_ms`, as sec 470 does a partner's time.
 *
 * `*released` counts hosts released, `*finished` purges completed.
 */
fzn_notes_err_t fzn_notes_purge_release(const fzn_notes_store_t *store, uint64_t now_ms,
                                        uint64_t age_ms, fzn_notes_purge_heard_fn heard,
                                        void *heard_ctx, size_t *released, size_t *finished);

/*
 * Empty the trash: queue a purge of every note whose claim by `self` is
 * trashed, asking `asking`, and finish at once those nobody need consent to.
 * Only this host's own trashed claims start a purge, as in fuzzypickles: a
 * sibling's trash is the sibling's to empty. `*queued` counts purges started
 * or already pending.
 */
fzn_notes_err_t fzn_notes_purge_trash(const fzn_notes_store_t *store, fzn_notes_view_t *view,
                                      const uint8_t self[FZN_PUBKEY_LEN],
                                      fzn_notes_asking_t asking, uint64_t now_ms,
                                      size_t *queued);

#endif /* FZN_NOTES_PURGE_H */
