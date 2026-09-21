/* THE QUEUED PURGE: how an estate-wide deletion actually happens. C19a, and
 * project.md sec 335.
 *
 * C17 to C19 say a deletion must be EXPLICIT without saying by what mechanism.
 * C19a settles the mechanism, from fuzzypickles' `notes_purge_internal.h`, and
 * their statement of why the obvious answers fail is the useful half: "A local
 * delete is undone by the next sibling to sync. A tombstone that lives for
 * ever trades a note for a smaller permanent thing, which is not a saving --
 * and deleting exists to save space, so an answer that keeps something
 * indefinitely has missed the point."
 *
 * SO A DELETION IS A QUEUED COMMAND, ELIMINATED ONCE CONSENSUS IS ATTAINED.
 * "No earlier, because a host that has not yet agreed still holds a copy and
 * will re-send it. No later, because the queue entry is itself the thing being
 * paid for."
 *
 * THIS IS THE EXPLICIT GESTURE AND NOTHING REACHES IT BY ITSELF. sec 330
 * settled that there is no automatic reclamation: a zero reference count is
 * reported and never triggers anything, and catalog/sweep.h PLANS. A person
 * queues a purge here, deliberately, for an entity they have decided the
 * estate should not keep. Nothing in this library calls
 * `fzn_catalog_purge_queue`.
 *
 * AND IT REMOVES NO BYTES, like every other module in this catalogue. It
 * carries the agreement, so a consumer knows when every host that held the
 * entity has agreed and the queue entry can go. Removing the bytes is the
 * consumer's, on each host, as C17 requires.
 *
 * ===========================================================================
 * THE TWO THINGS AN IMPLEMENTATION GETS WRONG BY BEING HELPFUL
 * ===========================================================================
 *
 * THE CONSENSUS SET IS PINNED WHEN THE PURGE IS QUEUED, not recomputed as
 * hosts come and go. C19a names this as the detail that goes wrong, and both
 * directions of the wrongness are worth keeping: a set recomputed against the
 * current estate CAN NEVER CLOSE while a host is away, and CLOSES EARLY when
 * one leaves. The first symptom is a queue that grows for ever while every
 * host in it behaves correctly; the second is bytes dropped while a host that
 * still holds them was simply not looked at.
 *
 * So `fzn_catalog_purge_queue` copies the holder set into the row and nothing
 * afterwards consults the assertion set again. A host that starts holding the
 * entity after the purge was queued is NOT waited on -- it never agreed to
 * anything -- and a host that stops holding it IS still waited on, because it
 * had a copy when the question was asked.
 *
 * THE PINNED SET IS THE HOSTS THAT ACTUALLY HOLD, not every sibling. C19a
 * takes this from their settlement policy and the reason transfers exactly:
 * "relay and retention are independent, host-by-host choices, so a host that
 * only forwards never stores and MUST NEVER BE WAITED ON." A consensus set
 * including hosts that never hold anything is a set that cannot close, and the
 * symptom is a purge queue growing for ever while every host in it behaves
 * correctly. The set therefore comes from `fzn_catalog_holders` (C8/C5e),
 * which derives holding from HOLDER-capability assertions and nothing else.
 */

#ifndef FZN_CATALOG_PURGE_H
#define FZN_CATALOG_PURGE_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"
#include "retention.h"

/* The longest host key a pinned row carries, and how many fit.
 *
 * BOUNDED BECAUSE A ROW OUTLIVES THE CALL, the same reason retention.h bounds
 * its key. An entity held by more hosts than fit cannot have its consensus set
 * pinned, and that is refused rather than truncated: a set missing a host
 * CLOSES EARLY, which is the worse of C19a's two failures -- it drops bytes a
 * host still holds. */
#define FZN_CATALOG_PURGE_HOST_LEN 32u
#define FZN_CATALOG_PURGE_HOSTS_MAX 8u

/* One host key, by value.
 *
 * A STRUCT FOR THE SAME REASON `fzn_catalog_entity_t` is one: a `uint8_t[N]`
 * decays to a pointer that does not implicitly acquire `const`, so an
 * interface taking `const uint8_t x[][N]` cannot be handed a caller's ordinary
 * array without a cast, and -Wpedantic says so. It is a DISTINCT type from an
 * entity rather than a reuse of it -- both are 32 bytes and they are not the
 * same thing, and one type for two concepts is what code-style.md forbids. */
typedef struct fzn_catalog_host {
	uint8_t b[FZN_CATALOG_PURGE_HOST_LEN];
} fzn_catalog_host_t;

/* One queued purge, with its consensus set pinned at the moment it was
 * queued. */
typedef struct fzn_catalog_purge {
	uint8_t entity[FZN_CATALOG_ENTITY_LEN];
	fzn_catalog_host_t host[FZN_CATALOG_PURGE_HOSTS_MAX];
	/* Parallel to `host`: nonzero once that host has agreed. */
	uint8_t agreed[FZN_CATALOG_PURGE_HOSTS_MAX];
	size_t  hosts;
} fzn_catalog_purge_t;

typedef struct fzn_catalog_purges {
	fzn_catalog_purge_t *rows;
	size_t capacity;
	size_t used;
} fzn_catalog_purges_t;

/* Point a queue at caller-owned rows. */
fzn_catalog_err_t fzn_catalog_purges_init(fzn_catalog_purges_t *purges,
                                          fzn_catalog_purge_t *rows, size_t capacity);

/*
 * Queue an estate-wide purge of `entity`, pinning the hosts that hold it NOW
 * as the set that must agree.
 *
 * FZN_CATALOG_ERR_ABSENT when nothing in `set` holds the entity: there is no
 * consensus set to pin, and a purge whose set is empty would close instantly
 * while some host nobody asked still had the bytes.
 *
 * FZN_CATALOG_ERR_RANGE when the queue is full, or when more hosts hold it
 * than a row can pin. The second is refused rather than truncated, because a
 * short set closes early -- see the header comment.
 *
 * QUEUEING THE SAME ENTITY TWICE IS REFUSED with FZN_CATALOG_ERR_KIND rather
 * than re-pinning, because re-pinning would silently discard the agreement
 * already collected and restart against a different set.
 */
fzn_catalog_err_t fzn_catalog_purge_queue(fzn_catalog_purges_t *purges,
                                          const fzn_catalog_assertion_t *set,
                                          size_t count, const uint8_t *entity,
                                          size_t entity_len);

/*
 * Record that `host` agrees to the purge of `entity`.
 *
 * FZN_CATALOG_ERR_ABSENT when that host is not in the pinned set -- which is
 * the point rather than a nuisance. A host that began holding the entity after
 * the purge was queued is not part of the consensus, and counting its
 * agreement would let the queue close while a PINNED host had still not
 * answered. Agreeing twice is not an error; it is what a re-delivered message
 * looks like.
 */
fzn_catalog_err_t fzn_catalog_purge_agree(fzn_catalog_purges_t *purges,
                                          const uint8_t *entity, size_t entity_len,
                                          const uint8_t *host, size_t host_len);

/* Has every pinned host agreed? Zero for an entity with no queued purge, which
 * a caller must not read as "closed" -- ask `fzn_catalog_purge_queued` first if
 * the difference matters. */
int fzn_catalog_purge_closed(const fzn_catalog_purges_t *purges, const uint8_t *entity,
                             size_t entity_len);

/* Is there a queued purge for this entity at all? */
int fzn_catalog_purge_queued(const fzn_catalog_purges_t *purges, const uint8_t *entity,
                             size_t entity_len);

/*
 * Eliminate the queue entry, which is the whole point of the mechanism: the
 * entry is the thing being paid for, and it goes when consensus closes.
 *
 * FZN_CATALOG_ERR_BUSY while any pinned host has not agreed. "No earlier,
 * because a host that has not yet agreed still holds a copy and will re-send
 * it" -- eliminating early does not merely lose bookkeeping, it undoes the
 * deletion the next time that host syncs.
 */
fzn_catalog_err_t fzn_catalog_purge_eliminate(fzn_catalog_purges_t *purges,
                                              const uint8_t *entity, size_t entity_len);

/* How many hosts are pinned for this entity, and how many have agreed. Both
 * outputs are required: a caller that wanted only one would be computing a
 * fraction from a number it did not ask for. */
fzn_catalog_err_t fzn_catalog_purge_progress(const fzn_catalog_purges_t *purges,
                                             const uint8_t *entity, size_t entity_len,
                                             size_t *pinned_out, size_t *agreed_out);

/* ===========================================================================
 * THE WIRE FORM
 * ===========================================================================
 *
 * A PURGE COMMAND IS ITS OWN OBJECT, and an AGREEMENT is an attribute. The
 * split is not symmetry for its own sake; the two are different kinds of
 * thing.
 *
 * A command has a LIFECYCLE -- queued, agreed, eliminated -- where an
 * attribute is an assertion with merge semantics, and C2's three classes
 * (LABEL, FACT, IDENTIFIER: what a person asserted, what the bytes determine,
 * what a register determines) have no slot for "not an assertion at all".
 * Carrying a command in an attribute record would be two concepts sharing one
 * record, which is what code-style.md forbids for a word.
 *
 * AN AGREEMENT NEEDS NO NEW WIRE, because it is exactly C8's shape. C8 settled
 * that "the set of issuers for a root IS the set of holders" and sec 315 used
 * the same move to conclude there is no membership record; the set of issuers
 * of an agreement attribute naming a purge IS the set of agreements. So one
 * new object, not two.
 *
 * THE COMMAND CARRIES THE PINNED SET, which is the whole reason it is a
 * record rather than a flag. If each host derived the set from its own view
 * of who holds the entity, the hosts would disagree about which set must
 * close -- C19a's recomputing failure arriving over the network instead of in
 * memory, and harder to see there. The set is pinned once, by whoever queues
 * the purge, and travels.
 *
 * Body layout, and the canonical-encoding rules are the attribute codec's:
 *
 *     0   object   FZN_CATALOG_OBJECT_PURGE
 *     1   hosts    how many keys follow, 1..FZN_CATALOG_PURGE_HOSTS_MAX
 *     2   host[0]  FZN_CATALOG_PURGE_HOST_LEN bytes
 *     ... host[n]
 *
 * The entity is the RECORD's subject and whoever queued it is the RECORD's
 * issuer, so neither is in the body -- the same division the attribute codec
 * makes.
 */

/* The object tag. ATTRIBUTE is 1; this is the second object this model
 * defines, and sec 315's "the direction is toward LESS wire, not more" is why
 * there is not a third for the agreement. */
#define FZN_CATALOG_OBJECT_PURGE 2u

/* object + host count. */
#define FZN_CATALOG_PURGE_HEAD_LEN 2u

/* Lay out a purge command's body: the pinned set, in the order given.
 *
 * FZN_CATALOG_ERR_MALFORMED for a null, and FZN_CATALOG_ERR_ABSENT for an
 * EMPTY set -- a purge with nothing to wait for closes instantly, which is the
 * same refusal `fzn_catalog_purge_queue` makes and for the same reason.
 * FZN_CATALOG_ERR_RANGE when the body does not fit `cap` or a record body, or
 * when more hosts are given than a command can carry. Writes nothing unless
 * the whole body fits. */
fzn_catalog_err_t fzn_catalog_purge_encode(const fzn_catalog_host_t *hosts,
                                           size_t host_count, uint8_t *out, size_t cap,
                                           size_t *len_out);

/* Read a purge command's body into `row`, taking the entity from the caller's
 * pointer as the attribute codec takes issuer and entity from the record.
 * `row->agreed` is zeroed: agreement is read-time state derived from other
 * records, never carried in the command.
 *
 * Enforces the one canonical encoding: FZN_CATALOG_ERR_MALFORMED for a wrong
 * object tag, a truncated head, a count of zero, or a body whose length does
 * not match its count exactly -- a trailing byte is refused rather than
 * ignored, because the signature is over these bytes and two spellings of one
 * command would let a peer re-sign a different one. */
fzn_catalog_err_t fzn_catalog_purge_decode(const uint8_t *entity, size_t entity_len,
                                           const uint8_t *body, size_t body_len,
                                           fzn_catalog_purge_t *row);

/* The hosts that have AGREED to the purge identified by `purge_id`, derived
 * from the assertion set exactly as `fzn_catalog_holders` derives holders.
 *
 * An agreement is a live attribute whose issuer is the agreeing host, whose
 * entity is the entity, and whose VALUE is `purge_id` -- the identity of the
 * command being agreed to. The value binds it: without one, an agreement to
 * last week's purge of the same entity would count towards this week's.
 *
 * `out`, `out_cap`, `out_count` and `dropped` behave as
 * `fzn_catalog_holders`'. FZN_CATALOG_OK unless an argument is null. */
fzn_catalog_err_t fzn_catalog_purge_agreements(const fzn_catalog_assertion_t *set,
                                               size_t count, const uint8_t *entity,
                                               size_t entity_len,
                                               const uint8_t *purge_id,
                                               size_t purge_id_len,
                                               fzn_catalog_source_t *out, size_t out_cap,
                                               size_t *out_count, size_t *dropped);

/* How many purges are queued. */
size_t fzn_catalog_purge_count(const fzn_catalog_purges_t *purges);

#endif /* FZN_CATALOG_PURGE_H */
