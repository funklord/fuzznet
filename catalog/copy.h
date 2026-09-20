/* COPY: what to fetch, what to announce, what to serve. project.md sec 317
 * step 5, and sec 322.
 *
 * IT DECIDES AND DOES NOT SEND, which is catalog/copy.h's property and is
 * kept. The byte transfer is `spool/`'s; this answers three questions about
 * which bytes, and a caller that never calls a transport still gets correct
 * answers out of it.
 *
 *     want      what this host should fetch
 *     holdings  what this host can serve, to announce to peers
 *     offer     of a peer's wants, which this host will serve
 *
 * WHAT CHANGED FROM catalog/copy.h IS THE DATA SOURCE. The old module asked a
 * holdings callback "do I have these bytes"; the answer is now derived from
 * the records, because a HOLDER-capability assertion can only be issued by a
 * host that holds them (C5e/C8a). So `self` -- this host's key -- replaces the
 * seam, and a consumer can no longer answer the question wrongly because it is
 * no longer asked.
 *
 * WANT DEPENDS ON RETENTION AND THAT IS LOAD-BEARING. It is retained AND
 * referenced AND not-held, not merely referenced-and-not-held: a host that
 * fetched everything the estate curates would fill its disk with an estate's
 * worth of bytes it had already decided not to keep. sec 317 records this as a
 * correction to its own first cut, which had dropped the retention term.
 *
 * HOLDINGS ASKS NOTHING ABOUT POLICY, deliberately, and the difference from
 * `want` is the difference between a fact and an intention. What this host can
 * serve is what it has; whether it means to go on keeping it is its own
 * business and is not a peer's to read. A holdings walk that filtered by
 * retention would announce less than it can serve and would leak the policy
 * while doing it.
 *
 * THERE IS NO LOCK, as in catalog/sweep.h and for the same reason: this
 * model owns no container to hold one. The old module refused while a refile
 * or sweep held the catalogue. What that protected still has to hold -- the
 * set must not change under a walk -- and it is the caller's, stated rather
 * than enforced.
 */

#ifndef FZN_CATALOG_COPY_H
#define FZN_CATALOG_COPY_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"
#include "retention.h"

/*
 * What a walk produced, including everything it could not fit or would not
 * take.
 *
 * ZEROED BEFORE THE ARGUMENTS ARE CHECKED, so a plan never holds the previous
 * round's numbers -- a caller that reads the counters after an error would
 * otherwise read the last successful walk's.
 *
 * `written` and `truncated` are the two a caller acts on. The rest say why the
 * rest of the set is not in the list, and they are kept apart rather than
 * summed because they call for different actions: `not_retained` is this
 * host's own policy working, `not_referenced` is an entity nothing curates any
 * more, `already_held` is the copy making progress, `unknown` is a peer asking
 * for something outside this host's view, and `incomplete` is partial data.
 *
 * THE COUNTERS ARE TWO GROUPS AND THE SUITE ASSERTS BOTH SUMS, because a count
 * that does not have to add up is a count nobody can check.
 *
 * CLASSIFICATION partitions what was examined, and every item lands in exactly
 * one counter:
 *
 *     examined = not_retained + not_referenced + already_held + missing
 *              + unknown + incomplete
 *
 * WHAT IS EXAMINED DIFFERS AND THE SUM DOES NOT. A want or holdings walk
 * examines the distinct entities this host's set names; an offer examines the
 * peer's wants. So `not_retained`, `not_referenced` and `incomplete` are zero
 * in an offer's arithmetic where the peer named something unknown, and
 * `unknown` is zero in a walk -- one arithmetic covers all three, which is
 * what makes it worth asserting rather than three that each hold in one place.
 *
 * EMISSION is the second group, over whatever the walk chose to emit:
 *
 *     emitted = written + duplicates + truncated
 */
typedef struct fzn_catalog_copy {
	/* Entities written to `out`. */
	size_t written;
	/* A repeat of something already written. A walk dedupes by entity
	 * before classifying, so this can only rise in an offer, where the
	 * list being examined is the peer's and may name one entity twice. */
	size_t duplicates;
	/* Wanted or offered, and `out_cap` had no room.
	 *
	 * IT IS AN UPPER BOUND ONCE THE ARRAY IS FULL, NOT A COUNT, and the
	 * difference is worth a sentence because a bound quoted as a value is
	 * how a number stops being checkable. Deduplication compares against
	 * what has been WRITTEN, so two references arriving after the array
	 * filled are two truncations rather than one duplicate -- there is
	 * nowhere to remember the first, the caller's array being the only
	 * storage this module has. So `written + truncated` sizes an array
	 * that is certainly big enough and may be bigger than needed. */
	size_t truncated;
	/* Want only: this host has chosen not to keep it. */
	size_t not_retained;
	/* Want only: no live curated assertion names it, so nothing wants it
	 * fetched. A holder assertion is not one -- see
	 * fzn_catalog_referenced, and sec 321 for what counting it did. */
	size_t not_referenced;
	/* This host has the bytes. */
	size_t already_held;
	/* This host does not have the bytes. In a want walk this is the set
	 * that gets emitted; in a holdings walk it is how far the copy still
	 * has to go, which is worth a number rather than an absence. */
	size_t missing;
	/* Offer only: the peer named an entity this host's set says nothing
	 * about. THE SCOPE CHECK, and it is the point rather than a detail --
	 * without it a want list is a request for any bytes whose hash a peer
	 * can name. */
	size_t unknown;
	/* The holders could not be determined, so nothing was decided. sec
	 * 316's asymmetry, as in catalog/sweep.h: on partial data, decide
	 * nothing. For a fetch the conservative answer would be to ask again,
	 * which is what a caller does by sweeping the same set once it has
	 * caught up with its sources. */
	size_t incomplete;
} fzn_catalog_copy_t;

/* What this host should fetch: retained, referenced, and not held here. */
fzn_catalog_err_t fzn_catalog_copy_want(const fzn_catalog_assertion_t *set,
                                            size_t count,
                                            const fzn_catalog_holds_t *holds,
                                            const uint8_t *self, size_t self_len,
                                            uint64_t now,
                                            fzn_catalog_entity_t *out,
                                            size_t out_cap, fzn_catalog_copy_t *plan);

/* What this host can serve, for announcing to peers. No retention term: see
 * the header comment, where the difference between a fact and an intention is
 * argued. */
fzn_catalog_err_t fzn_catalog_copy_holdings(const fzn_catalog_assertion_t *set,
                                                size_t count,
                                                const uint8_t *self, size_t self_len,
                                                fzn_catalog_entity_t *out,
                                                size_t out_cap,
                                                fzn_catalog_copy_t *plan);

/* Of a peer's `wants`, the ones this host knows about and holds.
 *
 * An entity known here and not held is neither an error nor a refusal: the
 * peer asks again next round, which is `record/sync.h`'s pull shape. It is
 * counted so an offer's arithmetic closes the same way a walk's does. */
fzn_catalog_err_t fzn_catalog_copy_offer(const fzn_catalog_assertion_t *set,
                                             size_t count,
                                             const uint8_t *self, size_t self_len,
                                             const fzn_catalog_entity_t *wants,
                                             size_t want_count,
                                             fzn_catalog_entity_t *out,
                                             size_t out_cap, fzn_catalog_copy_t *plan);

#endif /* FZN_CATALOG_COPY_H */
